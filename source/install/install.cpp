#include "install/install.hpp"

#include <switch.h>
#include <cstring>
#include <memory>
#include "error.hpp"

#include "nx/ncm.hpp"
#include "util/title_util.hpp"


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
        return m_contentMeta.GetContentMetaKey().title_id;
    }

    NcmContentMetaType Install::GetContentMetaType()
    {
        return static_cast<NcmContentMetaType>(m_contentMeta.GetContentMetaKey().type);
    }

    void Install::DebugPrintInstallData()
    {
        #ifdef NXLINK_DEBUG

        NcmContentMetaDatabase contentMetaDatabase;
        NcmContentMetaKey metaRecord = m_contentMeta.GetContentMetaKey();
        u64 baseTitleId = tin::util::GetBaseTitleId(metaRecord.title_id, static_cast<NcmContentMetaType>(metaRecord.type));
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
