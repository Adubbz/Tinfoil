#include "nx/ipc/es.h"

#include <string.h>

#include <switch.h>
#include "service_guard.h"

static Service g_esSrv;

NX_GENERATE_SERVICE_GUARD(es);

Result _esInitialize() {
    return smGetService(&g_esSrv, "es");
}

void _esCleanup() {
    serviceClose(&g_esSrv);
}

Service* esGetServiceSession() {
    return &g_esSrv;
}

Result esImportTicket(void const *tikBuf, size_t tikSize, void const *certBuf, size_t certSize) {
    return serviceDispatch(&g_esSrv, 1,
        .buffer_attrs = {
            SfBufferAttr_HipcMapAlias | SfBufferAttr_In,
            SfBufferAttr_HipcMapAlias | SfBufferAttr_In,
        },
        .buffers = {
            { tikBuf,   tikSize },
            { certBuf,  certSize },
        },
    );
}

Result esDeleteTicket(const RightsId *rightsIdBuf, size_t bufSize) {
    return serviceDispatch(&g_esSrv, 3,
        .buffer_attrs = { SfBufferAttr_HipcMapAlias | SfBufferAttr_In },
        .buffers = { { rightsIdBuf, bufSize }, },
    );
}

Result esGetTitleKey(const RightsId *rightsId, u8 *outBuf, size_t bufSize) {
    return serviceDispatchIn(&g_esSrv, 8, *rightsId,
        .buffer_attrs = { SfBufferAttr_HipcMapAlias | SfBufferAttr_Out },
        .buffers = { { outBuf, bufSize } },
    );
}

Result esCountCommonTicket(u32 *numTickets) {
    struct {
        u32 num_tickets;
    } out;

    Result rc = serviceDispatchOut(&g_esSrv, 9, out);
    if (R_SUCCEEDED(rc) && numTickets) *numTickets = out.num_tickets;
    
    return rc;
}

Result esCountPersonalizedTicket(u32 *numTickets) {
    struct {
        u32 num_tickets;
    } out;

    Result rc = serviceDispatchOut(&g_esSrv, 10, out);
    if (R_SUCCEEDED(rc) && numTickets) *numTickets = out.num_tickets;
    
    return rc;
}

Result esListCommonTicket(u32 *numRightsIdsWritten, RightsId *outBuf, size_t bufSize) {
    struct {
        u32 num_rights_ids_written;
    } out;
    
    Result rc = serviceDispatchInOut(&g_esSrv, 11, *numRightsIdsWritten, out,
        .buffer_attrs = { SfBufferAttr_HipcMapAlias | SfBufferAttr_Out },
        .buffers = { { outBuf, bufSize } },
    );
    if (R_SUCCEEDED(rc) && numRightsIdsWritten) *numRightsIdsWritten = out.num_rights_ids_written;
    
    return rc;
}

Result esListPersonalizedTicket(u32 *numRightsIdsWritten, RightsId *outBuf, size_t bufSize) {
    struct {
        u32 num_rights_ids_written;
    } out;
    
    Result rc = serviceDispatchInOut(&g_esSrv, 12, *numRightsIdsWritten, out,
        .buffer_attrs = { SfBufferAttr_HipcMapAlias | SfBufferAttr_Out },
        .buffers = { { outBuf, bufSize } },
    );
    if (R_SUCCEEDED(rc) && numRightsIdsWritten) *numRightsIdsWritten = out.num_rights_ids_written;
    
    return rc;
}

Result esGetCommonTicketData(u64 *unkOut, void *outBuf1, size_t bufSize1, const RightsId* rightsId) {
    struct {
        u64 unk;
    } out;

    Result rc = serviceDispatchInOut(&g_esSrv, 16, rightsId, out,
        .buffer_attrs = { SfBufferAttr_HipcMapAlias | SfBufferAttr_Out },
        .buffers = { { outBuf1, bufSize1 } },
    );
    return rc;
}