#pragma once

#include <functional>
#include <vector>

#include <switch/types.h>
#include "install/pfs0.hpp"
#include "nx/ncm.hpp"
#include "util/network_util.hpp"

namespace tin::install::nsp
{
    class RemoteNSP
    {
        protected:
            std::vector<u8> m_headerBytes;

            RemoteNSP();

        public:
            virtual void StreamToPlaceholder(nx::ncm::ContentStorage& contentStorage, NcmContentId placeholderId) = 0;
            virtual void BufferData(void* buf, off_t offset, size_t size) = 0;

            virtual void RetrieveHeader();
            virtual const PFS0BaseHeader* GetBaseHeader();
            virtual u64 GetDataOffset();

            virtual const PFS0FileEntry* GetFileEntry(unsigned int index);
            virtual const PFS0FileEntry* GetFileEntryByName(std::string name);
            virtual const PFS0FileEntry* GetFileEntryByNcaId(const NcmContentId& ncaId);
            virtual const PFS0FileEntry* GetFileEntryByExtension(std::string extension);

            virtual const char* GetFileEntryName(const PFS0FileEntry* fileEntry);
    };
}