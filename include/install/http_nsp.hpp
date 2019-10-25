#pragma once

#include "install/remote_nsp.hpp"

namespace tin::install::nsp
{
    class HTTPNSP : public RemoteNSP
    {
        public:
            tin::network::HTTPDownload m_download;

            HTTPNSP(std::string url);

            virtual void StreamToPlaceholder(nx::ncm::ContentStorage& contentStorage, NcmContentId placeholderId) override;
            virtual void BufferData(void* buf, off_t offset, size_t size) override;
    };
}