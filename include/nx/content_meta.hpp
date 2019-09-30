#pragma once

#include <switch/services/ncm.h>
#include <switch/types.h>
#include <vector>

#include "data/byte_buffer.hpp"

namespace nx::ncm
{
    struct PackagedContentInfo
    {
        u8 hash[0x20];
        NcmContentInfo content_info;
    } PACKED;

    struct PackagedContentMetaHeader
    {
        u64 title_id;
        u32 version;
        u8 type;
        u8 _0xd;
        u16 extended_header_size;
        u16 content_count;
        u16 content_meta_count;
        u8 attributes;
        u8 storage_id;
        u8 install_type;
        bool comitted;
        u32 required_system_version;
        u32 _0x1c;
    };

    static_assert(sizeof(PackagedContentMetaHeader) == 0x20, "PackagedContentMetaHeader must be 0x20!");

    class ContentMeta final
    {
        private:
            tin::data::ByteBuffer m_bytes;

        public:
            ContentMeta();
            ContentMeta(u8* data, size_t size);

            PackagedContentMetaHeader GetPackagedContentMetaHeader();
            NcmContentMetaKey GetContentMetaKey();
            std::vector<NcmContentInfo> GetContentInfos();

            void GetInstallContentMeta(tin::data::ByteBuffer& installContentMetaBuffer, NcmContentInfo& cnmtContentInfo, bool ignoreReqFirmVersion);
    };
}