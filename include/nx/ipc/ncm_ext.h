#pragma once

#include <switch/services/ncm.h>

Result ncmextInitialize(void);
void ncmextExit(void);

Result ncmCreatePlaceHolder(NcmContentStorage* cs, const NcmNcaId* placeholderId, const NcmNcaId* registeredId, u64 size);
Result ncmDeletePlaceHolder(NcmContentStorage* cs, const NcmNcaId* placeholderId);
Result ncmWritePlaceHolder(NcmContentStorage* cs, const NcmNcaId* placeholderId, u64 offset, void* buffer, size_t bufSize);
Result ncmDelete(NcmContentStorage* cs, const NcmNcaId* registeredId);