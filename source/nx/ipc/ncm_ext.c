#include "nx/ipc/ncm_ext.h"

#include <string.h>
#include <switch/arm/atomics.h>

static Service g_ncmSrv;
static u64 g_ncmRefCnt;

Result ncmextInitialize(void) 
{
    Result rc;
    atomicIncrement64(&g_ncmRefCnt);

    if (serviceIsActive(&g_ncmSrv))
        return 0;

    rc = smGetService(&g_ncmSrv, "ncm");

    if (R_SUCCEEDED(rc))
        smAddOverrideHandle(smEncodeName("ncm"), g_ncmSrv.own_handle);

    return rc;
}

void ncmextExit(void) {
    if (atomicDecrement64(&g_ncmRefCnt) == 0) 
    {
        serviceClose(&g_ncmSrv);
    }
}

Result ncmCreatePlaceHolder(NcmContentStorage* cs, const NcmNcaId* placeholderId, const NcmNcaId* registeredId, u64 size)
{
    IpcCommand c;
    ipcInitialize(&c);
    
    struct {
        u64 magic;
        u64 cmd_id;
        NcmNcaId placeholder_id;
        NcmNcaId registered_id;
        u64 size;
    } *raw;
    
    raw = ipcPrepareHeader(&c, sizeof(*raw));
    raw->magic = SFCI_MAGIC;
    raw->cmd_id = 1;
    raw->size = size;
    memcpy(&raw->placeholder_id, placeholderId, sizeof(NcmNcaId));
    memcpy(&raw->registered_id, registeredId, sizeof(NcmNcaId));
    
    Result rc = serviceIpcDispatch(&cs->s);

    if (R_SUCCEEDED(rc)) {
        IpcParsedCommand r;
        ipcParse(&r);

        struct {
            u64 magic;
            u64 result;
        } *resp = r.Raw;

        rc = resp->result;
    }
    
    return rc;
}

Result ncmDeletePlaceHolder(NcmContentStorage* cs, const NcmNcaId* placeholderId)
{
    IpcCommand c;
    ipcInitialize(&c);
    
    struct {
        u64 magic;
        u64 cmd_id;
        NcmNcaId placeholder_id;
    } *raw;
    
    raw = ipcPrepareHeader(&c, sizeof(*raw));
    raw->magic = SFCI_MAGIC;
    raw->cmd_id = 2;
    memcpy(&raw->placeholder_id, placeholderId, sizeof(NcmNcaId));
    
    Result rc = serviceIpcDispatch(&cs->s);

    if (R_SUCCEEDED(rc)) {
        IpcParsedCommand r;
        ipcParse(&r);

        struct {
            u64 magic;
            u64 result;
        } *resp = r.Raw;

        rc = resp->result;
    }
    
    return rc;
}

Result ncmWritePlaceHolder(NcmContentStorage* cs, const NcmNcaId* placeholderId, u64 offset, void* buffer, size_t bufSize)
{
    IpcCommand c;
    ipcInitialize(&c);
    ipcAddSendBuffer(&c, buffer, bufSize, BufferType_Normal);
    
    struct {
        u64 magic;
        u64 cmd_id;
        NcmNcaId placeholder_id;
        u64 offset;
    } *raw;
    
    raw = ipcPrepareHeader(&c, sizeof(*raw));
    raw->magic = SFCI_MAGIC;
    raw->cmd_id = 4;
    raw->offset = offset;
    memcpy(&raw->placeholder_id, placeholderId, sizeof(NcmNcaId));
    
    Result rc = serviceIpcDispatch(&cs->s);

    if (R_SUCCEEDED(rc)) {
        IpcParsedCommand r;
        ipcParse(&r);

        struct {
            u64 magic;
            u64 result;
        } *resp = r.Raw;

        rc = resp->result;
    }
    
    return rc;
}

Result ncmDelete(NcmContentStorage* cs, const NcmNcaId* registeredId)
{
    IpcCommand c;
    ipcInitialize(&c);
    
    struct {
        u64 magic;
        u64 cmd_id;
        NcmNcaId placeholder_id;
    } *raw;
    
    raw = ipcPrepareHeader(&c, sizeof(*raw));
    raw->magic = SFCI_MAGIC;
    raw->cmd_id = 6;
    memcpy(&raw->placeholder_id, registeredId, sizeof(NcmNcaId));
    
    Result rc = serviceIpcDispatch(&cs->s);

    if (R_SUCCEEDED(rc)) {
        IpcParsedCommand r;
        ipcParse(&r);

        struct {
            u64 magic;
            u64 result;
        } *resp = r.Raw;

        rc = resp->result;
    }
    
    return rc;
}