#pragma once

#include <switch/types.h>
#include <string>
#include "nx/content_meta.hpp"
#include "nx/ipc/tin_ipc.h"

namespace tin::util
{
    u64 GetRightsIdTid(RightsId rightsId);
    u64 GetRightsIdKeyGen(RightsId rightsId);

    std::string GetNcaIdString(const NcmContentId& ncaId);
    NcmContentId GetNcaIdFromString(std::string ncaIdStr);

    u64 GetBaseTitleId(u64 titleId, NcmContentMetaType contentMetaType);
    std::string GetBaseTitleName(u64 baseTitleId);
    std::string GetTitleName(u64 titleId, NcmContentMetaType contentMetaType);
}