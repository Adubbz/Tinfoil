#pragma once

#include <string>
#include <tuple>
#include <vector>

#include "nx/content_meta.hpp"

namespace tin::util
{
    NcmContentInfo CreateNSPCNMTContentRecord(const std::string& nspPath);
    nx::ncm::ContentMeta GetContentMetaFromNCA(const std::string& ncaPath);
    std::vector<std::string> GetNSPList();
}