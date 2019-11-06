#pragma once

extern "C"
{
#include <switch/services/fs.h>
}

#include <memory>
#include <tuple>
#include <vector>

#include "install/simple_filesystem.hpp"
#include "data/byte_buffer.hpp"

#include "nx/content_meta.hpp"
#include "nx/ipc/tin_ipc.h"

#ifdef __cplusplus
extern "C" {
#endif
    #include <nca.h>
#ifdef __cplusplus
}
#endif

namespace tin::install
{
    class Install
    {
        protected:
            const FsStorageId m_destStorageId;
            bool m_ignoreReqFirmVersion = false;

            nx::ncm::ContentMeta m_contentMeta;

            Install(FsStorageId destStorageId, bool ignoreReqFirmVersion);
            virtual ~Install();

            virtual std::tuple<nx::ncm::ContentMeta, NcmContentInfo> ReadCNMT() = 0;

            virtual void InstallContentMetaRecords(tin::data::ByteBuffer& installContentMetaBuf);
            virtual void InstallApplicationRecord();
            virtual void InstallTicketCert() = 0;
            virtual void GetBuffer(const NcmContentId &ncaId, void * out_header, size_t offset, size_t size) = 0;
            virtual bool VerifyNCA(const NcmContentId &ncaId, nca_ctx_t *nca_ctx);
            virtual void InstallNCA(const NcmContentId &ncaId) = 0;
        public:
            virtual void Prepare();
            virtual void Begin();

            virtual u64 GetTitleId();
            virtual NcmContentMetaType GetContentMetaType();
            virtual bool VerifyContent();

            virtual void DebugPrintInstallData();
    };
}