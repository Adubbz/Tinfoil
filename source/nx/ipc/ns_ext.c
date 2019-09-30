#include "nx/ipc/ns_ext.h"

#include <stdio.h>
#include <string.h>
#include <switch.h>
#include <switch/arm/atomics.h>

static Service g_nsAppManSrv, g_nsGetterSrv;
static u64 g_nsRefCnt;

static Result _nsGetInterface(Service* srv_out, u64 cmd_id);

Result nsextInitialize(void)
{
    Result rc=0;

    atomicIncrement64(&g_nsRefCnt);

    if (serviceIsActive(&g_nsGetterSrv) || serviceIsActive(&g_nsAppManSrv))
        return 0;

    if(!kernelAbove300())
        return smGetService(&g_nsAppManSrv, "ns:am");

    rc = smGetService(&g_nsGetterSrv, "ns:am2");//TODO: Support the other services?(Only useful when ns:am2 isn't accessible)
    if (R_FAILED(rc)) return rc;

    rc = _nsGetInterface(&g_nsAppManSrv, 7996);

    if (R_FAILED(rc)) serviceClose(&g_nsGetterSrv);

    return rc;
}

void nsextExit(void)
{
    if (atomicDecrement64(&g_nsRefCnt) == 0) {
        serviceClose(&g_nsAppManSrv);
        if(!kernelAbove300()) return;

        serviceClose(&g_nsGetterSrv);
    }
}

static Result _nsGetInterface(Service* srv_out, u64 cmd_id) {
    IpcCommand c;
    ipcInitialize(&c);

    struct {
        u64 magic;
        u64 cmd_id;
    } *raw;

    raw = ipcPrepareHeader(&c, sizeof(*raw));

    raw->magic = SFCI_MAGIC;
    raw->cmd_id = cmd_id;

    Result rc = serviceIpcDispatch(&g_nsGetterSrv);

    if (R_SUCCEEDED(rc)) {
        IpcParsedCommand r;
        ipcParse(&r);

        struct {
            u64 magic;
            u64 result;
        } *resp = r.Raw;

        rc = resp->result;

        if (R_SUCCEEDED(rc)) {
            serviceCreate(srv_out, r.Handles[0]);
        }
    }

    return rc;
}

Result nsPushApplicationRecord(u64 title_id, u8 last_modified_event, ContentStorageRecord *content_records_buf, size_t buf_size)
{
    IpcCommand c;
    ipcInitialize(&c);
    ipcAddSendBuffer(&c, content_records_buf, buf_size, 0);

    struct {
        u64 magic;
        u64 cmd_id;
        u8 last_modified_event;
        u8 padding[0x7];
        u64 title_id;
    } *raw;
    
    raw = ipcPrepareHeader(&c, sizeof(*raw));
    
    raw->magic = SFCI_MAGIC;
    raw->cmd_id = 16;
    raw->last_modified_event = last_modified_event;
    raw->title_id = title_id;

    Result rc = serviceIpcDispatch(&g_nsAppManSrv);
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

Result nsCalculateApplicationOccupiedSize(u64 titleID, void *out_buf)
{
    IpcCommand c;
    ipcInitialize(&c);

    struct {
        u64 magic;
        u64 cmd_id;
        u64 titleID;
    } *raw;
    
    raw = ipcPrepareHeader(&c, sizeof(*raw));
    
    raw->magic = SFCI_MAGIC;
    raw->cmd_id = 11;
    raw->titleID = titleID;
    
    Result rc = serviceIpcDispatch(&g_nsAppManSrv);
    if (R_SUCCEEDED(rc)) {
        IpcParsedCommand r;
        ipcParse(&r);

        struct {
            u64 magic;
            u64 result;
            u8 out[0x80];
        } *resp = r.Raw;

        rc = resp->result;

        if (R_SUCCEEDED(rc)) {
            memcpy(out_buf, resp->out, 0x80);
        }
    }
    
    return rc;
}

Result nsListApplicationRecordContentMeta(u64 offset, u64 titleID, void *out_buf, size_t out_buf_size, u32 *entries_read_out)
{
    IpcCommand c;
    ipcInitialize(&c);
    ipcAddRecvBuffer(&c, out_buf, out_buf_size, 0);

    struct {
        u64 magic;
        u64 cmd_id;
        u64 offset;
        u64 titleID;
    } *raw;
    
    raw = ipcPrepareHeader(&c, sizeof(*raw));
    
    raw->magic = SFCI_MAGIC;
    raw->cmd_id = 17;
    raw->titleID = titleID;
    raw->offset = offset;
    
    Result rc = serviceIpcDispatch(&g_nsAppManSrv);
    if (R_SUCCEEDED(rc)) {
        IpcParsedCommand r;
        ipcParse(&r);

        struct {
            u64 magic;
            u64 result;
            u32 entries_read;
        } *resp = r.Raw;

        rc = resp->result;

        
        if (R_SUCCEEDED(rc)) {
            if (entries_read_out) *entries_read_out = resp->entries_read;
        }
    }
    
    return rc;
}

Result nsTouchApplication(u64 titleID)
{
    IpcCommand c;
    ipcInitialize(&c);

    struct {
        u64 magic;
        u64 cmd_id;
        u64 titleID;
    } *raw;
    
    raw = ipcPrepareHeader(&c, sizeof(*raw));
    
    raw->magic = SFCI_MAGIC;
    raw->cmd_id = 904;
    raw->titleID = titleID;
    
    Result rc = serviceIpcDispatch(&g_nsAppManSrv);
    if (R_SUCCEEDED(rc)) {
        IpcParsedCommand r;
        ipcParse(&r);

        struct {
            u64 magic;
            u64 result;
            u32 entries_read;
        } *resp = r.Raw;

        rc = resp->result;
    }
    
    return rc;
}

Result nsDeleteApplicationRecord(u64 titleID)
{
    IpcCommand c;
    ipcInitialize(&c);

    struct {
        u64 magic;
        u64 cmd_id;
        u64 titleID;
    } *raw;
    
    raw = ipcPrepareHeader(&c, sizeof(*raw));
    
    raw->magic = SFCI_MAGIC;
    raw->cmd_id = 27;
    raw->titleID = titleID;
    
    Result rc = serviceIpcDispatch(&g_nsAppManSrv);
    if (R_SUCCEEDED(rc)) {
        IpcParsedCommand r;
        ipcParse(&r);

        struct {
            u64 magic;
            u64 result;
            u32 entries_read;
        } *resp = r.Raw;

        rc = resp->result;
    }
    
    return rc;
}

Result nsLaunchApplication(u64 titleID)
{
    IpcCommand c;
    ipcInitialize(&c);

    struct {
        u64 magic;
        u64 cmd_id;
        u64 titleID;
    } *raw;
    
    raw = ipcPrepareHeader(&c, sizeof(*raw));
    
    raw->magic = SFCI_MAGIC;
    raw->cmd_id = 19;
    raw->titleID = titleID;
    
    Result rc = serviceIpcDispatch(&g_nsAppManSrv);
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

Result nsPushLaunchVersion(u64 titleID, u32 version)
{
    IpcCommand c;
    ipcInitialize(&c);

    struct {
        u64 magic;
        u64 cmd_id;
        u64 title_id;
        u32 version;
        u32 padding;
    } *raw;
    
    raw = ipcPrepareHeader(&c, sizeof(*raw));
    
    raw->magic = SFCI_MAGIC;
    raw->cmd_id = 36;
    raw->title_id = titleID;
    raw->version = version;
    
    Result rc = serviceIpcDispatch(&g_nsAppManSrv);
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

Result nsCheckApplicationLaunchVersion(u64 titleID)
{
    IpcCommand c;
    ipcInitialize(&c);

    struct {
        u64 magic;
        u64 cmd_id;
        u64 title_id;
    } *raw;
    
    raw = ipcPrepareHeader(&c, sizeof(*raw));
    
    raw->magic = SFCI_MAGIC;
    raw->cmd_id = 38;
    raw->title_id = titleID;
    
    Result rc = serviceIpcDispatch(&g_nsAppManSrv);
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

Result nsCountApplicationContentMeta(u64 titleId, u32* countOut)
{
    IpcCommand c;
    ipcInitialize(&c);

    struct {
        u64 magic;
        u64 cmd_id;
        u64 title_id;
    } *raw;
    
    raw = ipcPrepareHeader(&c, sizeof(*raw));
    
    raw->magic = SFCI_MAGIC;
    raw->cmd_id = 600;
    raw->title_id = titleId;
    
    Result rc = serviceIpcDispatch(&g_nsAppManSrv);
    if (R_SUCCEEDED(rc)) {
        IpcParsedCommand r;
        ipcParse(&r);

        struct {
            u64 magic;
            u64 result;
            u32 count;
        } *resp = r.Raw;

        rc = resp->result;

        if (R_SUCCEEDED(rc)) {
            if (countOut) *countOut = resp->count;
        }
    }
    
    return rc;
}

Result nsGetContentMetaStorage(const NcmContentMetaKey *record, u8 *out)
{
    IpcCommand c;
    ipcInitialize(&c);

    struct {
        u64 magic;
        u64 cmd_id;
        NcmContentMetaKey metaRecord;
    } *raw;
    
    raw = ipcPrepareHeader(&c, sizeof(*raw));
    
    raw->magic = SFCI_MAGIC;
    raw->cmd_id = 606;
    memcpy(&raw->metaRecord, record, sizeof(NcmContentMetaKey));
    
    Result rc = serviceIpcDispatch(&g_nsAppManSrv);
    if (R_SUCCEEDED(rc)) {
        IpcParsedCommand r;
        ipcParse(&r);

        struct {
            u64 magic;
            u64 result;
            u8 out;
        } *resp = r.Raw;

        rc = resp->result;

        if (R_SUCCEEDED(rc)) {
            if (out) *out = resp->out;
        }
    }
    
    return rc;
}

Result nsBeginInstallApplication(u64 tid, u32 unk, u8 storageId) {
    IpcCommand c;
    ipcInitialize(&c);

    struct {
        u64 magic;
        u64 cmd_id;
        u32 storageId;
        u32 unk;
        u64 tid;
    } *raw;

    raw = ipcPrepareHeader(&c, sizeof(*raw));

    raw->magic = SFCI_MAGIC;
    raw->cmd_id = 26;
    raw->storageId = storageId;
    raw->unk = unk;
    raw->tid = tid;

    Result rc = serviceIpcDispatch(&g_nsAppManSrv);

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

Result nsInvalidateAllApplicationControlCache(void) {
    IpcCommand c;
    ipcInitialize(&c);

    struct {
        u64 magic;
        u64 cmd_id;
    } *raw;

    raw = ipcPrepareHeader(&c, sizeof(*raw));

    raw->magic = SFCI_MAGIC;
    raw->cmd_id = 401;

    Result rc = serviceIpcDispatch(&g_nsAppManSrv);

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

Result nsInvalidateApplicationControlCache(u64 tid) {
    IpcCommand c;
    ipcInitialize(&c);

    struct {
        u64 magic;
        u64 cmd_id;
        u64 tid;
    } *raw;

    raw = ipcPrepareHeader(&c, sizeof(*raw));

    raw->magic = SFCI_MAGIC;
    raw->cmd_id = 404;
    raw->tid = tid;

    Result rc = serviceIpcDispatch(&g_nsAppManSrv);

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

Result nsCheckApplicationLaunchRights(u64 tid)
{
    IpcCommand c;
    ipcInitialize(&c);

    struct {
        u64 magic;
        u64 cmd_id;
        u64 tid;
    } *raw;

    raw = ipcPrepareHeader(&c, sizeof(*raw));

    raw->magic = SFCI_MAGIC;
    raw->cmd_id = 39;
    raw->tid = tid;

    Result rc = serviceIpcDispatch(&g_nsAppManSrv);

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

Result nsGetApplicationContentPath(u64 tid, u8 type, char *out, size_t buf_size) {
    IpcCommand c;
    ipcInitialize(&c);
    ipcAddRecvBuffer(&c, out, buf_size, 0);

    struct {
        u64 magic;
        u64 cmd_id;
        u8 padding[0x7];
        u8 type;
        u64 tid;
    } *raw;

    raw = ipcPrepareHeader(&c, sizeof(*raw));

    raw->magic = SFCI_MAGIC;
    raw->cmd_id = 21;
    raw->type = type;
    raw->tid = tid;

    Result rc = serviceIpcDispatch(&g_nsAppManSrv);

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

Result nsDisableApplicationAutoUpdate(u64 titleID)
{
    IpcCommand c;
    ipcInitialize(&c);

    struct {
        u64 magic;
        u64 cmd_id;
        u64 title_id;
    } *raw;
    
    raw = ipcPrepareHeader(&c, sizeof(*raw));
    
    raw->magic = SFCI_MAGIC;
    raw->cmd_id = 903;
    raw->title_id = titleID;
    
    Result rc = serviceIpcDispatch(&g_nsAppManSrv);
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

Result nsWithdrawApplicationUpdateRequest(u64 titleId)
{
    IpcCommand c;
    ipcInitialize(&c);

    struct {
        u64 magic;
        u64 cmd_id;
        u64 title_id;
    } *raw;
    
    raw = ipcPrepareHeader(&c, sizeof(*raw));
    
    raw->magic = SFCI_MAGIC;
    raw->cmd_id = 907;
    raw->title_id = titleId;
    
    Result rc = serviceIpcDispatch(&g_nsAppManSrv);
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
