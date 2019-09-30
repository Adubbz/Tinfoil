#pragma once

#include <switch.h>
#include <string>
#include "install/install.hpp"
#include "install/remote_nsp.hpp"

namespace tin::install::nsp
{
    class RemoteNSPInstall : public Install
    {
        private:
            RemoteNSP* m_remoteNSP;

        protected:
            std::tuple<nx::ncm::ContentMeta, NcmContentInfo> ReadCNMT() override;
            void InstallNCA(const NcmNcaId& ncaId) override;
            void InstallTicketCert() override;

        public:
            RemoteNSPInstall(FsStorageId destStorageId, bool ignoreReqFirmVersion, RemoteNSP* remoteNSP);
    };
}