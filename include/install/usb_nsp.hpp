#pragma once

#include <string>
#include "install/remote_nsp.hpp"

namespace tin::install::nsp
{
    class USBNSP : public RemoteNSP
    {
        private:
            std::string m_nspName;

        public:
            USBNSP(std::string nspName);

            virtual void StreamToPlaceholder(std::shared_ptr<nx::ncm::ContentStorage>& contentStorage, NcmNcaId placeholderId) override;
            virtual void BufferData(void* buf, off_t offset, size_t size) override;
    };
}