#pragma once

#include <switch.h>
#include <string>

namespace tin::util
{
    enum USBCmdType : u8
    {
        REQUEST = 0,
        RESPONSE = 1
    };

    struct USBCmdHeader
    {
        u32 magic;
        USBCmdType type;
        u8 padding[0x3] = {0};
        u32 cmdId;
        u64 dataSize;
        u8 reserved[0xC] = {0};
    } PACKED;

    static_assert(sizeof(USBCmdHeader) == 0x20, "USBCmdHeader must be 0x20!");

    class USBCmdManager
    {
        public:
            static void SendCmdHeader(u32 cmdId, size_t dataSize);

            static void SendExitCmd();
            static USBCmdHeader SendFileRangeCmd(std::string nspName, u64 offset, u64 size);
    };

    size_t USBRead(void* out, size_t len);
    size_t USBWrite(const void* in, size_t len);
}