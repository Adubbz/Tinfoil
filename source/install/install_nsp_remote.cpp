#include "install/install_nsp_remote.hpp"

#include <machine/endian.h>
#include "nx/fs.hpp"
#include "nx/ncm.hpp"
#include "util/file_util.hpp"
#include "util/title_util.hpp"
#include "debug.h"
#include "error.hpp"

namespace tin::install::nsp
{
    RemoteNSPInstall::RemoteNSPInstall(FsStorageId destStorageId, bool ignoreReqFirmVersion, RemoteNSP* remoteNSP) :
        Install(destStorageId, ignoreReqFirmVersion), m_remoteNSP(remoteNSP)
    {
        m_remoteNSP->RetrieveHeader();
    }

    std::tuple<nx::ncm::ContentMeta, NcmContentInfo> RemoteNSPInstall::ReadCNMT()
    {
        const PFS0FileEntry* fileEntry = m_remoteNSP->GetFileEntryByExtension("cnmt.nca");

        if (fileEntry == nullptr)
            THROW_FORMAT("Failed to find cnmt file entry!\n");

        std::string cnmtNcaName(m_remoteNSP->GetFileEntryName(fileEntry));
        NcmNcaId cnmtContentId = tin::util::GetNcaIdFromString(cnmtNcaName);
        size_t cnmtNcaSize = fileEntry->fileSize;

        nx::ncm::ContentStorage contentStorage(m_destStorageId);

        printf("CNMT Name: %s\n", cnmtNcaName.c_str());

        // We install the cnmt nca early to read from it later
        this->InstallNCA(cnmtContentId);
        std::string cnmtNCAFullPath = contentStorage.GetPath(cnmtContentId);

        NcmContentInfo cnmtContentInfo;
        cnmtContentInfo.content_id = cnmtContentId;
        *(u64*)&cnmtContentInfo.size = cnmtNcaSize & 0xFFFFFFFFFFFF;
        cnmtContentInfo.content_type = NcmContentType_Meta;
        consoleUpdate(NULL);

        return { tin::util::GetContentMetaFromNCA(cnmtNCAFullPath), cnmtContentInfo };
    }

    void RemoteNSPInstall::InstallNCA(const NcmNcaId& ncaId)
    {
        const PFS0FileEntry* fileEntry = m_remoteNSP->GetFileEntryByNcaId(ncaId);
        std::string ncaFileName = m_remoteNSP->GetFileEntryName(fileEntry);
        size_t ncaSize = fileEntry->fileSize;

        printf("Installing %s to storage Id %u\n", ncaFileName.c_str(), m_destStorageId);

        nx::ncm::ContentStorage contentStorage(m_destStorageId);

        // Attempt to delete any leftover placeholders
        try
        {
            contentStorage.DeletePlaceholder(ncaId);
        }
        catch (...) {}

        LOG_DEBUG("Size: 0x%lx\n", ncaSize);
        contentStorage.CreatePlaceholder(ncaId, ncaId, ncaSize);
        m_remoteNSP->StreamToPlaceholder(contentStorage, ncaId);

        // Clean up the line for whatever comes next
        printf("                                                           \r");
        printf("Registering placeholder...\n");
        
        try
        {
            contentStorage.Register(ncaId, ncaId);
        }
        catch (...)
        {
            printf(("Failed to register " + ncaFileName + ". It may already exist.\n").c_str());
        }

        try
        {
            contentStorage.DeletePlaceholder(ncaId);
        }
        catch (...) {}

        consoleUpdate(NULL);
    }

    void RemoteNSPInstall::InstallTicketCert()
    {        
        // Read the tik file and put it into a buffer
        const PFS0FileEntry* tikFileEntry = m_remoteNSP->GetFileEntryByExtension("tik");

        if (tikFileEntry == nullptr)
        {
            LOG_DEBUG("Remote tik file is missing.\n");
            throw std::runtime_error("Remote tik file is not present!");
        }

        u64 tikSize = tikFileEntry->fileSize;
        auto tikBuf = std::make_unique<u8[]>(tikSize);
        printf("> Reading tik\n");
        m_remoteNSP->BufferData(tikBuf.get(), m_remoteNSP->GetDataOffset() + tikFileEntry->dataOffset, tikSize);

        // Read the cert file and put it into a buffer
        const PFS0FileEntry* certFileEntry = m_remoteNSP->GetFileEntryByExtension("cert");

        if (certFileEntry == nullptr)
        {
            LOG_DEBUG("Remote cert file is missing.\n");
            throw std::runtime_error("Remote cert file is not present!");
        }

        u64 certSize = certFileEntry->fileSize;
        auto certBuf = std::make_unique<u8[]>(certSize);
        printf("> Reading cert\n");
        m_remoteNSP->BufferData(certBuf.get(), m_remoteNSP->GetDataOffset() + certFileEntry->dataOffset, certSize);

        // Finally, let's actually import the ticket
        ASSERT_OK(esImportTicket(tikBuf.get(), tikSize, certBuf.get(), certSize), "Failed to import ticket");
        consoleUpdate(NULL);
    }
}