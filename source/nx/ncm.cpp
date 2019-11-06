#include "nx/ncm.hpp"
#include "error.hpp"

namespace nx::ncm
{
    ContentStorage::ContentStorage(FsStorageId storageId) 
    {
        ASSERT_OK(ncmOpenContentStorage(&m_contentStorage, storageId), "Failed to open NCM ContentStorage");
    }

    ContentStorage::~ContentStorage()
    {
        serviceClose(&m_contentStorage.s);
    }

    void ContentStorage::CreatePlaceholder(const NcmPlaceHolderId &placeholderId, const NcmContentId &registeredId, size_t size)
    {
        ASSERT_OK(ncmContentStorageCreatePlaceHolder(&m_contentStorage, &registeredId, &placeholderId, size), "Failed to create placeholder");
    }
            
    void ContentStorage::DeletePlaceholder(const NcmPlaceHolderId &placeholderId)
    {
        ASSERT_OK(ncmContentStorageDeletePlaceHolder(&m_contentStorage, &placeholderId), "Failed to delete placeholder");
    }

    void ContentStorage::WritePlaceholder(const NcmPlaceHolderId &placeholderId, u64 offset, void *buffer, size_t bufSize)
    {
        ASSERT_OK(ncmContentStorageWritePlaceHolder(&m_contentStorage, &placeholderId, offset, buffer, bufSize), "Failed to write to placeholder");
    }

    void ContentStorage::Register(const NcmPlaceHolderId &placeholderId, const NcmContentId &registeredId)
    {
        ASSERT_OK(ncmContentStorageRegister(&m_contentStorage, &registeredId, &placeholderId), "Failed to register placeholder NCA");
    }

    void ContentStorage::Delete(const NcmContentId &registeredId)
    {
        ASSERT_OK(ncmContentStorageDelete(&m_contentStorage, &registeredId), "Failed to delete registered NCA");
    }

    bool ContentStorage::Has(const NcmContentId &registeredId)
    {
        bool hasNCA = false;
        ASSERT_OK(ncmContentStorageHas(&m_contentStorage, &hasNCA, &registeredId), "Failed to check if NCA is present");
        return hasNCA;
    }

    std::string ContentStorage::GetPath(const NcmContentId &registeredId)
    {
        char pathBuf[FS_MAX_PATH] = {0};
        ASSERT_OK(ncmContentStorageGetPath(&m_contentStorage, pathBuf, FS_MAX_PATH, &registeredId), "Failed to get installed NCA path");
        return std::string(pathBuf);
    }
}