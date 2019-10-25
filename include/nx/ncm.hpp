#pragma once

#include <string>

extern "C"
{
#include <switch/services/fs.h>
#include <switch/services/ncm.h>
}

#include "nx/ipc/tin_ipc.h"

namespace nx::ncm
{
    class ContentStorage final
    {
        private:
            NcmContentStorage m_contentStorage;

        public:
            // Don't allow copying, or garbage may be closed by the destructor
            ContentStorage& operator=(const ContentStorage&) = delete;
            ContentStorage(const ContentStorage&) = delete;   

            ContentStorage(FsStorageId storageId);
            ~ContentStorage();

            void CreatePlaceholder(const NcmContentId &placeholderId, const NcmContentId &registeredId, size_t size);
            void DeletePlaceholder(const NcmContentId &placeholderId);
            void WritePlaceholder(const NcmContentId &placeholderId, u64 offset, void *buffer, size_t bufSize);
            void Register(const NcmContentId &placeholderId, const NcmContentId &registeredId);
            void Delete(const NcmContentId &registeredId);
            bool Has(const NcmContentId &registeredId);
            std::string GetPath(const NcmContentId &registeredId);
    };
}