#include "install/install.hpp"

#include <switch.h>
#include <cstring>
#include <memory>
#include "error.hpp"

#include "nx/ncm.hpp"
#include "util/title_util.hpp"

#ifdef __cplusplus
extern "C" {
#endif
    #include <nca.h>
    #include <pki.h>
    #include <extkeys.h>
    #include <rsa.h>
    #include <sha.h>
#ifdef __cplusplus
}
#endif

// TODO: Check NCA files are present
// TODO: Check tik/cert is present
namespace tin::install
{
    Install::Install(FsStorageId destStorageId, bool ignoreReqFirmVersion) :
        m_destStorageId(destStorageId), m_ignoreReqFirmVersion(ignoreReqFirmVersion), m_contentMeta()
    {
        appletSetMediaPlaybackState(true);
    }

    Install::~Install()
    {
        appletSetMediaPlaybackState(false);
    }

    // TODO: Implement RAII on NcmContentMetaDatabase
    void Install::InstallContentMetaRecords(tin::data::ByteBuffer& installContentMetaBuf)
    {
        NcmContentMetaDatabase contentMetaDatabase;
        NcmContentMetaKey contentMetaKey = m_contentMeta.GetContentMetaKey();

        try
        {
            ASSERT_OK(ncmOpenContentMetaDatabase(&contentMetaDatabase, m_destStorageId), "Failed to open content meta database");
            ASSERT_OK(ncmContentMetaDatabaseSet(&contentMetaDatabase, &contentMetaKey, (NcmContentMetaHeader*)installContentMetaBuf.GetData(), installContentMetaBuf.GetSize()), "Failed to set content records");
            ASSERT_OK(ncmContentMetaDatabaseCommit(&contentMetaDatabase), "Failed to commit content records");
        }
        catch (std::runtime_error& e)
        {
            serviceClose(&contentMetaDatabase.s);
            throw e;
        }
        
        serviceClose(&contentMetaDatabase.s);
        consoleUpdate(NULL);
    }

    void Install::InstallApplicationRecord()
    {
        Result rc = 0;
        std::vector<ContentStorageRecord> storageRecords;
        u64 baseTitleId = tin::util::GetBaseTitleId(this->GetTitleId(), this->GetContentMetaType());
        u32 contentMetaCount = 0;

        LOG_DEBUG("Base title Id: 0x%lx", baseTitleId);

        // TODO: Make custom error with result code field
        // 0x410: The record doesn't already exist
        if (R_FAILED(rc = nsCountApplicationContentMeta(baseTitleId, &contentMetaCount)) && rc != 0x410)
        {
            throw std::runtime_error("Failed to count application content meta");
        }
        rc = 0;

        LOG_DEBUG("Content meta count: %u\n", contentMetaCount);

        // Obtain any existing app record content meta and append it to our vector
        if (contentMetaCount > 0)
        {
            storageRecords.resize(contentMetaCount);
            size_t contentStorageBufSize = contentMetaCount * sizeof(ContentStorageRecord);
            auto contentStorageBuf = std::make_unique<ContentStorageRecord[]>(contentMetaCount);
            u32 entriesRead;

            ASSERT_OK(nsListApplicationRecordContentMeta(0, baseTitleId, contentStorageBuf.get(), contentStorageBufSize, &entriesRead), "Failed to list application record content meta");

            if (entriesRead != contentMetaCount)
            {
                throw std::runtime_error("Mismatch between entries read and content meta count");
            }

            memcpy(storageRecords.data(), contentStorageBuf.get(), contentStorageBufSize);
        }

        // Add our new content meta
        ContentStorageRecord storageRecord;
        storageRecord.metaRecord = m_contentMeta.GetContentMetaKey();
        storageRecord.storageId = m_destStorageId;
        storageRecords.push_back(storageRecord);

        // Replace the existing application records with our own
        try
        {
            nsDeleteApplicationRecord(baseTitleId);
        }
        catch (...) {}

        printf("Pushing application record...\n");
        ASSERT_OK(nsPushApplicationRecord(baseTitleId, 0x3, storageRecords.data(), storageRecords.size() * sizeof(ContentStorageRecord)), "Failed to push application record");
        consoleUpdate(NULL);
    }

    bool Install::VerifyNCA(const NcmContentId &ncaId, nca_ctx_t *ctx)
    {
        this->GetBuffer(ncaId, &ctx->header, 0, 0xC00);

        /* Try to support decrypted NCA headers. */
        if (ctx->header.magic == MAGIC_NCA3 || ctx->header.magic == MAGIC_NCA2) {
            if (ctx->header._0x340[0] == 0 && !memcmp(ctx->header._0x340, ctx->header._0x340 + 1, 0xBF)) {
                ctx->is_decrypted = 1;
                if (ctx->header.magic == MAGIC_NCA3) {
                    ctx->format_version = NCAVERSION_NCA3;
                } else {
                    ctx->format_version = NCAVERSION_NCA2;
                }
                return true;
            }
        }

        ctx->is_decrypted = 0;

        nca_header_t dec_header;

        aes_ctx_t *hdr_aes_ctx = new_aes_ctx(ctx->tool_ctx->settings.keyset.header_key, 32, AES_MODE_XTS);
        aes_xts_decrypt(hdr_aes_ctx, &dec_header, &ctx->header, 0x400, 0, 0x200);

        if (dec_header.magic == MAGIC_NCA3) {
            ctx->format_version = NCAVERSION_NCA3;
            aes_xts_decrypt(hdr_aes_ctx, &dec_header, &ctx->header, 0xC00, 0, 0x200);
            ctx->header = dec_header;
        } else if (dec_header.magic == MAGIC_NCA2) {
            ctx->format_version = NCAVERSION_NCA2;
            for (unsigned int i = 0; i < 4; i++) {
                if (dec_header.fs_headers[i]._0x148[0] != 0 || memcmp(dec_header.fs_headers[i]._0x148, dec_header.fs_headers[i]._0x148 + 1, 0xB7)) {
                    aes_xts_decrypt(hdr_aes_ctx, &dec_header.fs_headers[i], &ctx->header.fs_headers[i], 0x200, 0, 0x200);
                } else {
                    memset(&dec_header.fs_headers[i], 0, sizeof(nca_fs_header_t));
                }
            }
            ctx->header = dec_header;
        } else if (dec_header.magic == MAGIC_NCA0) {
            memset(ctx->decrypted_keys, 0, 0x40);
            unsigned char out_keydata[0x100];
            size_t out_len = 0;
            if (rsa2048_oaep_decrypt_verify(out_keydata, sizeof(out_keydata), (const unsigned char *)dec_header.encrypted_keys, pki_get_beta_nca0_modulus(), pki_get_beta_nca0_exponent(), 0x100, pki_get_beta_nca0_label_hash(), &out_len)) {
                if (out_len >= 0x20) {
                    memcpy(ctx->decrypted_keys, out_keydata, 0x20);
                    ctx->format_version = NCAVERSION_NCA0_BETA;
                }
            } else {
                unsigned char calc_hash[0x20];
                static const unsigned char expected_hash[0x20] = {0x9A, 0xBB, 0xD2, 0x11, 0x86, 0x00, 0x21, 0x9D, 0x7A, 0xDC, 0x5B, 0x43, 0x95, 0xF8, 0x4E, 0xFD, 0xFF, 0x6B, 0x25, 0xEF, 0x9F, 0x96, 0x85, 0x28, 0x18, 0x9E, 0x76, 0xB0, 0x92, 0xF0, 0x6A, 0xCB};
                sha256_hash_buffer(calc_hash, dec_header.encrypted_keys, 0x20);
                if (memcmp(calc_hash, expected_hash, sizeof(calc_hash)) == 0) {
                    ctx->format_version = NCAVERSION_NCA0;
                    memcpy(ctx->decrypted_keys, dec_header.encrypted_keys, 0x40);
                } else {
                    ctx->format_version = NCAVERSION_NCA0;
                    aes_ctx_t *aes_ctx = new_aes_ctx(ctx->tool_ctx->settings.keyset.key_area_keys[ctx->crypto_type][dec_header.kaek_ind], 16, AES_MODE_ECB);
                    aes_decrypt(aes_ctx, ctx->decrypted_keys, dec_header.encrypted_keys, 0x20);
                    free_aes_ctx(aes_ctx);
                }
            }
            if (ctx->format_version != NCAVERSION_UNKNOWN) {
                memset(dec_header.fs_headers, 0, sizeof(dec_header.fs_headers));
                aes_ctx_t *aes_ctx = new_aes_ctx(ctx->decrypted_keys, 32, AES_MODE_XTS);
                for (unsigned int i = 0; i < 4; i++) {
                    if (dec_header.section_entries[i].media_start_offset) { /* Section exists. */
                        uint64_t offset = media_to_real(dec_header.section_entries[i].media_start_offset);
                        this->GetBuffer(ncaId, &dec_header.fs_headers[i], offset, sizeof(dec_header.fs_headers[i]));
                        aes_xts_decrypt(aes_ctx, &dec_header.fs_headers[i], &dec_header.fs_headers[i], sizeof(dec_header.fs_headers[i]), (offset - 0x400ULL) >> 9ULL, 0x200);
                    }
                }
                free_aes_ctx(aes_ctx);
                ctx->header = dec_header;
            }
        }

        free_aes_ctx(hdr_aes_ctx);

        return rsa2048_pss_verify(&ctx->header.magic, 0x200, ctx->header.fixed_key_sig, ctx->tool_ctx->settings.keyset.nca_hdr_fixed_key_modulus) == 1;
    }

    // Validate and obtain all data needed for install
    void Install::Prepare()
    {
        tin::data::ByteBuffer cnmtBuf;
        auto cnmtTuple = this->ReadCNMT();
        m_contentMeta = std::get<0>(cnmtTuple);
        NcmContentInfo cnmtContentRecord = std::get<1>(cnmtTuple);

        nx::ncm::ContentStorage contentStorage(m_destStorageId);

        if (!contentStorage.Has(cnmtContentRecord.content_id))
        {
            printf("Installing CNMT NCA...\n");
            this->InstallNCA(cnmtContentRecord.content_id);
        }
        else
        {
            printf("CNMT NCA already installed. Proceeding...\n");
        }

        // Parse data and create install content meta
        if (m_ignoreReqFirmVersion)
            printf("WARNING: Required system firmware version is being IGNORED!\n");

        tin::data::ByteBuffer installContentMetaBuf;
        m_contentMeta.GetInstallContentMeta(installContentMetaBuf, cnmtContentRecord, m_ignoreReqFirmVersion);

        this->InstallContentMetaRecords(installContentMetaBuf);
        this->InstallApplicationRecord();

        printf("Installing ticket and cert...\n");
        try
        {
            this->InstallTicketCert();
        }
        catch (std::runtime_error& e)
        {
            printf("WARNING: Ticket installation failed! This may not be an issue, depending on your use case.\nProceed with caution!\n");
        }

        consoleUpdate(NULL);
    }

    void Install::Begin()
    {
        printf("Installing NCAs...\n");
        consoleUpdate(NULL);
        for (auto& record : m_contentMeta.GetContentInfos())
        {
            LOG_DEBUG("Installing from %s\n", tin::util::GetNcaIdString(record.content_id).c_str());
            consoleUpdate(NULL);
            this->InstallNCA(record.content_id);
        }

        LOG_DEBUG("Post Install Records: \n");
        this->DebugPrintInstallData();
    }

    u64 Install::GetTitleId()
    {
        return m_contentMeta.GetContentMetaKey().id;
    }

    NcmContentMetaType Install::GetContentMetaType()
    {
        return static_cast<NcmContentMetaType>(m_contentMeta.GetContentMetaKey().type);
    }

    bool Install::VerifyContent() {
        nca_ctx_t nca_ctx;

        hactool_ctx_t tool_ctx;
        nca_ctx.tool_ctx = &tool_ctx;

        nca_ctx.tool_ctx->file_type = FILETYPE_NCA;

        FILE *keyfile = open_key_file("prod");
        LOG_DEBUG("opened keyfile %ssuccessfully\n", keyfile != NULL? "": "un");

        if (keyfile != NULL) {
            pki_initialize_keyset(&nca_ctx.tool_ctx->settings.keyset, KEYSET_RETAIL);
            extkeys_initialize_settings(&tool_ctx.settings, keyfile);
            pki_derive_keys(&tool_ctx.settings.keyset);
            fclose(keyfile);
        }
        LOG_DEBUG("retrieved keys\n");

        printf("Verifying NCAs...\n");
        consoleUpdate(NULL);
        for (auto& record : m_contentMeta.GetContentInfos())
        {
            LOG_DEBUG("Verifying %s\n", tin::util::GetNcaIdString(record.content_id).c_str());
            consoleUpdate(NULL);
            if (!this->VerifyNCA(record.content_id, &nca_ctx))
                return false;
        }

        nca_free_section_contexts(&nca_ctx);

        LOG_DEBUG("NCA's appear fine\n");
        return true;
    }

    void Install::DebugPrintInstallData()
    {
        #ifdef NXLINK_DEBUG

        NcmContentMetaDatabase contentMetaDatabase;
        NcmContentMetaKey metaRecord = m_contentMeta.GetContentMetaKey();
        u64 baseTitleId = tin::util::GetBaseTitleId(metaRecord.id, static_cast<NcmContentMetaType>(metaRecord.type));
        u64 updateTitleId = baseTitleId ^ 0x800;
        bool hasUpdate = true;

        try
        {
            NcmContentMetaKey latestApplicationContentMetaKey;
            NcmContentMetaKey latestPatchContentMetaKey;

            ASSERT_OK(ncmOpenContentMetaDatabase(&contentMetaDatabase, m_destStorageId), "Failed to open content meta database");
            ASSERT_OK(ncmContentMetaDatabaseGetLatestContentMetaKey(&contentMetaDatabase, &latestApplicationContentMetaKey, baseTitleId), "Failed to get latest application content meta key");
            
            try
            {
                ASSERT_OK(ncmContentMetaDatabaseGetLatestContentMetaKey(&contentMetaDatabase, &latestPatchContentMetaKey, updateTitleId), "Failed to get latest patch content meta key");
            }
            catch (std::exception& e)
            {
                hasUpdate = false;
            }

            u64 appContentRecordSize;
            u64 appContentRecordSizeRead;
            ASSERT_OK(ncmContentMetaDatabaseGetSize(&contentMetaDatabase, &appContentRecordSize,  &latestApplicationContentMetaKey), "Failed to get application content record size");
            
            auto appContentRecordBuf = std::make_unique<u8[]>(appContentRecordSize);
            ASSERT_OK(ncmContentMetaDatabaseGet(&contentMetaDatabase, &latestApplicationContentMetaKey, &appContentRecordSizeRead, (NcmContentMetaHeader*)appContentRecordBuf.get(), appContentRecordSizeRead), "Failed to get app content record size");

            if (appContentRecordSize != appContentRecordSizeRead)
            {
                throw std::runtime_error("Mismatch between app content record size and content record size read");
            }

            LOG_DEBUG("Application content meta key: \n");
            printBytes(nxlinkout, (u8*)&latestApplicationContentMetaKey, sizeof(NcmContentMetaKey), true);
            LOG_DEBUG("Application content meta: \n");
            printBytes(nxlinkout, appContentRecordBuf.get(), appContentRecordSize, true);

            if (hasUpdate)
            {
                u64 patchContentRecordsSize;
                u64 patchContentRecordSizeRead;
                ASSERT_OK(ncmContentMetaDatabaseGetSize(&contentMetaDatabase, &patchContentRecordsSize, &latestPatchContentMetaKey), "Failed to get patch content record size");
            
                auto patchContentRecordBuf = std::make_unique<u8[]>(patchContentRecordsSize);
                ASSERT_OK(ncmContentMetaDatabaseGet(&contentMetaDatabase, &latestPatchContentMetaKey, &patchContentRecordSizeRead, (NcmContentMetaHeader*)patchContentRecordBuf.get(), patchContentRecordsSize), "Failed to get patch content record size");
            
                if (patchContentRecordsSize != patchContentRecordSizeRead)
                {
                    throw std::runtime_error("Mismatch between app content record size and content record size read");
                }

                LOG_DEBUG("Patch content meta key: \n");
                printBytes(nxlinkout, (u8*)&latestPatchContentMetaKey, sizeof(NcmContentMetaKey), true);
                LOG_DEBUG("Patch content meta: \n");
                printBytes(nxlinkout, patchContentRecordBuf.get(), patchContentRecordsSize, true);
            }
            else
            {
                LOG_DEBUG("No update records found, or an error occurred.\n");
            }

            auto appRecordBuf = std::make_unique<u8[]>(0x100);
            u32 numEntriesRead;
            ASSERT_OK(nsListApplicationRecordContentMeta(0, baseTitleId, appRecordBuf.get(), 0x100, &numEntriesRead), "Failed to list application record content meta");

            LOG_DEBUG("Application record content meta: \n");
            printBytes(nxlinkout, appRecordBuf.get(), 0x100, true);
        }
        catch (std::runtime_error& e)
        {
            serviceClose(&contentMetaDatabase.s);
            LOG_DEBUG("Failed to log install data. Error: %s", e.what());
        }

        #endif
    }
}
