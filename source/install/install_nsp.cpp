#include "install/install_nsp.hpp"

#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <memory>
#include <string>
#include <machine/endian.h>

#include "nx/ncm.hpp"
#include "util/file_util.hpp"
#include "util/title_util.hpp"
#include "debug.h"
#include "error.hpp"

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

namespace tin::install::nsp
{
    NSPInstallTask::NSPInstallTask(tin::install::nsp::SimpleFileSystem& simpleFileSystem, FsStorageId destStorageId, bool ignoreReqFirmVersion) :
        Install(destStorageId, ignoreReqFirmVersion), m_simpleFileSystem(&simpleFileSystem)
    {

    }

    std::tuple<nx::ncm::ContentMeta, NcmContentInfo> NSPInstallTask::ReadCNMT()
    {
        NcmContentInfo cnmtRecord = tin::util::CreateNSPCNMTContentRecord(this->m_simpleFileSystem->m_absoluteRootPath.substr(0, this->m_simpleFileSystem->m_absoluteRootPath.size() - 1));
        nx::ncm::ContentStorage contentStorage(m_destStorageId);
        this->InstallNCA(cnmtRecord.content_id);
        std::string cnmtNCAFullPath = contentStorage.GetPath(cnmtRecord.content_id);
        return { tin::util::GetContentMetaFromNCA(cnmtNCAFullPath), cnmtRecord };
    }
    
    void NSPInstallTask::InstallTicketCert()
    {
        // Read the tik file and put it into a buffer
        auto tikName = m_simpleFileSystem->GetFileNameFromExtension("", "tik");
        printf("> Getting tik size\n");
        auto tikFile = m_simpleFileSystem->OpenFile(tikName);
        u64 tikSize = tikFile.GetSize();
        auto tikBuf = std::make_unique<u8[]>(tikSize);
        printf("> Reading tik\n");
        tikFile.Read(0x0, tikBuf.get(), tikSize);

        // Read the cert file and put it into a buffer
        auto certName = m_simpleFileSystem->GetFileNameFromExtension("", "cert");
        printf("> Getting cert size\n");
        auto certFile = m_simpleFileSystem->OpenFile(certName);
        u64 certSize = certFile.GetSize();
        auto certBuf = std::make_unique<u8[]>(certSize);
        printf("> Reading cert\n");
        certFile.Read(0x0, certBuf.get(), certSize);

        // Finally, let's actually import the ticket
        ASSERT_OK(esImportTicket(tikBuf.get(), tikSize, certBuf.get(), certSize), "Failed to import ticket");
        consoleUpdate(NULL);
    }

    bool NSPInstallTask::VerifyNCA(const NcmContentId &ncaId)
    {
        std::string ncaName = tin::util::GetNcaIdString(ncaId);

        if (m_simpleFileSystem->HasFile(ncaName + ".nca"))
            ncaName += ".nca";
        else if (m_simpleFileSystem->HasFile(ncaName + ".cnmt.nca"))
            ncaName += ".cnmt.nca";
        else
        {
            throw std::runtime_error(("Failed to find NCA file " + ncaName + ".nca/.cnmt.nca").c_str());
        }

        LOG_DEBUG("Verifying NcaId: %s\n", ncaName.c_str());

        auto ncaFile = m_simpleFileSystem->OpenFile(ncaName);
        //auto readBuffer = std::make_unique<u8[]>(0xC00);

        nca_ctx_t *ctx = new nca_ctx_t();

        hactool_ctx_t tool_ctx;
        ctx->tool_ctx = &tool_ctx;

        ctx->tool_ctx->file_type = FILETYPE_NCA;

        FILE *keyfile = open_key_file("prod");
        LOG_DEBUG("opened keyfile %ssuccessfully\n", keyfile != NULL? "": "un");

        if (keyfile != NULL) {
            pki_initialize_keyset(&ctx->tool_ctx->settings.keyset, KEYSET_RETAIL);
            extkeys_initialize_settings(&tool_ctx.settings, keyfile);
            pki_derive_keys(&tool_ctx.settings.keyset);
            fclose(keyfile);
        }
        LOG_DEBUG("retrieved keys\n");

        ncaFile.Read(0, &ctx->header, 0xC00);

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
                        ncaFile.Read(offset, &dec_header.fs_headers[i], sizeof(dec_header.fs_headers[i]));
                        aes_xts_decrypt(aes_ctx, &dec_header.fs_headers[i], &dec_header.fs_headers[i], sizeof(dec_header.fs_headers[i]), (offset - 0x400ULL) >> 9ULL, 0x200);
                    }
                }
                free_aes_ctx(aes_ctx);
                ctx->header = dec_header;
            }
        }

        free_aes_ctx(hdr_aes_ctx);

        nca_free_section_contexts(ctx);

        return rsa2048_pss_verify(&ctx->header.magic, 0x200, ctx->header.fixed_key_sig, ctx->tool_ctx->settings.keyset.nca_hdr_fixed_key_modulus) == 1;
    }

    void NSPInstallTask::InstallNCA(const NcmContentId &ncaId)
    {
        std::string ncaName = tin::util::GetNcaIdString(ncaId);

        if (m_simpleFileSystem->HasFile(ncaName + ".nca"))
            ncaName += ".nca";
        else if (m_simpleFileSystem->HasFile(ncaName + ".cnmt.nca"))
            ncaName += ".cnmt.nca";
        else
        {
            throw std::runtime_error(("Failed to find NCA file " + ncaName + ".nca/.cnmt.nca").c_str());
        }

        LOG_DEBUG("NcaId: %s\n", ncaName.c_str());
        LOG_DEBUG("Dest storage Id: %u\n", m_destStorageId);

        nx::ncm::ContentStorage contentStorage(m_destStorageId);

        // Attempt to delete any leftover placeholders
        try
        {
            contentStorage.DeletePlaceholder(*(NcmPlaceHolderId*)&ncaId);
        }
        catch (...) {}

        auto ncaFile = m_simpleFileSystem->OpenFile(ncaName);
        size_t ncaSize = ncaFile.GetSize();
        u64 fileOff = 0;
        size_t readSize = 0x400000; // 4MB buff
        auto readBuffer = std::make_unique<u8[]>(readSize);

        if (readBuffer == NULL) 
            throw std::runtime_error(("Failed to allocate read buffer for " + ncaName).c_str());

        LOG_DEBUG("Size: 0x%lx\n", ncaSize);
        contentStorage.CreatePlaceholder(*(NcmPlaceHolderId*)&ncaId, ncaId, ncaSize);
                
        float progress;

        consoleUpdate(NULL);
                
        while (fileOff < ncaSize) 
        {   
            // Clear the buffer before we read anything, just to be sure    
            progress = (float)fileOff / (float)ncaSize;

            if (fileOff % (0x400000 * 3) == 0)
                printf("> Progress: %lu/%lu MB (%d%s)\r", (fileOff / 1000000), (ncaSize / 1000000), (int)(progress * 100.0), "%");

            if (fileOff + readSize >= ncaSize) readSize = ncaSize - fileOff;

            ncaFile.Read(fileOff, readBuffer.get(), readSize);
            contentStorage.WritePlaceholder(*(NcmPlaceHolderId*)&ncaId, fileOff, readBuffer.get(), readSize);
            fileOff += readSize;
            consoleUpdate(NULL);
        }

        // Clean up the line for whatever comes next
        printf("                                                           \r");
        printf("Registering placeholder...\n");
        
        try
        {
            contentStorage.Register(*(NcmPlaceHolderId*)&ncaId, ncaId);
        }
        catch (...)
        {
            printf(("Failed to register " + ncaName + ". It may already exist.\n").c_str());
        }

        try
        {
            contentStorage.DeletePlaceholder(*(NcmPlaceHolderId*)&ncaId);
        }
        catch (...) {}

        consoleUpdate(NULL);
    }
}