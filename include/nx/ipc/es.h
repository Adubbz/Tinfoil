#pragma once

#include <switch/services/ncm.h>

typedef struct {
    u8 c[0x10];
} RightsId;

Result esInitialize();
void esExit();
Service* esGetServiceSession();

Result esImportTicket(void const *tikBuf, size_t tikSize, void const *certBuf, size_t certSize); //1
Result esDeleteTicket(const RightsId *rightsIdBuf, size_t bufSize); //3
Result esGetTitleKey(const RightsId *rightsId, u8 *outBuf, size_t bufSize); //8
Result esCountCommonTicket(u32 *numTickets); //9
Result esCountPersonalizedTicket(u32 *numTickets); // 10
Result esListCommonTicket(u32 *numRightsIdsWritten, RightsId *outBuf, size_t bufSize);
Result esListPersonalizedTicket(u32 *numRightsIdsWritten, RightsId *outBuf, size_t bufSize);
Result esGetCommonTicketData(u64 *unkOut, void *outBuf1, size_t bufSize1, const RightsId* rightsId);