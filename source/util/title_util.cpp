#include "util/title_util.hpp"

#include <machine/endian.h>
#include "error.hpp"

namespace tin::util
{
    u64 GetRightsIdTid(RightsId rightsId)
    {
        return __bswap64(*(u64 *)rightsId.c);
    }

    u64 GetRightsIdKeyGen(RightsId rightsId)
    {
        return __bswap64(*(u64 *)(rightsId.c + 8));
    }

    std::string GetNcaIdString(const NcmNcaId& ncaId)
    {
        char ncaIdStr[FS_MAX_PATH] = {0};
        u64 ncaIdLower = __bswap64(*(u64 *)ncaId.c);
        u64 ncaIdUpper = __bswap64(*(u64 *)(ncaId.c + 0x8));
        snprintf(ncaIdStr, FS_MAX_PATH, "%016lx%016lx", ncaIdLower, ncaIdUpper);
        return std::string(ncaIdStr);
    }

    NcmNcaId GetNcaIdFromString(std::string ncaIdStr)
    {
        NcmNcaId ncaId = {0};
        char lowerU64[17] = {0};
        char upperU64[17] = {0};
        memcpy(lowerU64, ncaIdStr.c_str(), 16);
        memcpy(upperU64, ncaIdStr.c_str() + 16, 16);

        *(u64 *)ncaId.c = __bswap64(strtoul(lowerU64, NULL, 16));
        *(u64 *)(ncaId.c + 8) = __bswap64(strtoul(upperU64, NULL, 16));

        return ncaId;
    }

    u64 GetBaseTitleId(u64 titleId, NcmContentMetaType contentMetaType)
    {
        switch (contentMetaType)
        {
            case NcmContentMetaType_Patch:
                return titleId ^ 0x800;

            case NcmContentMetaType_AddOnContent:
                return (titleId ^ 0x1000) & ~0xFFF;

            default:
                return titleId;
        }
    }

    std::string GetBaseTitleName(u64 baseTitleId)
    {
        Result rc = 0;
        NsApplicationControlData appControlData;
        size_t sizeRead;

        if (R_FAILED(rc = nsGetApplicationControlData(NsApplicationControlSource_Storage, baseTitleId, &appControlData, sizeof(NsApplicationControlData), &sizeRead)))
        {
            LOG_DEBUG("Failed to get application control data. Error code: 0x%08x\n", rc);
            return "Unknown";
        }

        if (sizeRead < sizeof(appControlData.nacp))
        {
            LOG_DEBUG("Incorrect size for nacp\n");
            return "Unknown";
        }

        NacpLanguageEntry *languageEntry;

        if (R_FAILED(rc = nacpGetLanguageEntry(&appControlData.nacp, &languageEntry)))
        {
            LOG_DEBUG("Failed to get language entry. Error code: 0x%08x\n", rc);
            return "Unknown";
        }

        if (languageEntry == NULL)
        {
            LOG_DEBUG("Language entry is null! Error code: 0x%08x\n", rc);
            return "Unknown";
        }

        return languageEntry->name;
    }

    std::string GetTitleName(u64 titleId, NcmContentMetaType contentMetaType)
    {
        u64 baseTitleId = GetBaseTitleId(titleId, contentMetaType);
        std::string titleName = GetBaseTitleName(baseTitleId);

        switch (contentMetaType)
        {
            case NcmContentMetaType_Patch:
                titleName += " (Update)";
                break;

            case NcmContentMetaType_AddOnContent:
                titleName += " (DLC)";
                break;

            default:
                break;
        }

        return titleName;
    }
}