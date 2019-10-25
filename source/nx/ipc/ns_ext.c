#include "nx/ipc/ns_ext.h"

#include <stdio.h>
#include <string.h>
#include <switch.h>
#include "service_guard.h"

static Service g_nsAppManSrv, g_nsGetterSrv;

static Result _nsextGetSession(Service* srv, Service* srv_out, u32 cmd_id);

NX_GENERATE_SERVICE_GUARD(nsext);

Result _nsextInitialize(void) {
    Result rc=0;

    if(hosversionBefore(3,0,0))
        return smGetService(&g_nsAppManSrv, "ns:am");

    rc = smGetService(&g_nsGetterSrv, "ns:am2");//TODO: Support the other services?(Only useful when ns:am2 isn't accessible)
    if (R_FAILED(rc)) return rc;

    rc = _nsextGetSession(&g_nsGetterSrv, &g_nsAppManSrv, 7996);

    if (R_FAILED(rc)) serviceClose(&g_nsGetterSrv);

    return rc;
}

void _nsextCleanup(void) {
    serviceClose(&g_nsAppManSrv);
    if(hosversionBefore(3,0,0)) return;

    serviceClose(&g_nsGetterSrv);
}

static Result _nsextGetSession(Service* srv, Service* srv_out, u32 cmd_id) {
    return serviceDispatch(srv, cmd_id,
        .out_num_objects = 1,
        .out_objects = srv_out,
    );
}

Result nsPushApplicationRecord(u64 title_id, u8 last_modified_event, ContentStorageRecord *content_records_buf, size_t buf_size) {

    struct {
        u8 last_modified_event;
        u8 padding[0x7];
        u64 title_id;
    } in = { last_modified_event, {0}, title_id };
    
    return serviceDispatchIn(&g_nsAppManSrv, 16, in,
        .buffer_attrs = { SfBufferAttr_HipcMapAlias | SfBufferAttr_In },
        .buffers = { { content_records_buf, buf_size } });
}

Result nsCalculateApplicationOccupiedSize(u64 titleID, void *out_buf) {

    struct {
        u64 titleID;
    } in = { titleID };

    struct {
        u8 out[0x80];
    } out;

    Result rc = serviceDispatchInOut(&g_nsAppManSrv, 11, in, out);

    if (R_SUCCEEDED(rc) && out_buf) memcpy(out_buf, out.out, 0x80);

    return rc;
}

Result nsListApplicationRecordContentMeta(u64 offset, u64 titleID, void *out_buf, size_t out_buf_size, u32 *entries_read_out) {

    struct {
        u64 offset;
        u64 titleID;
    } in = { offset, titleID };

    struct {
        u32 entries_read;
    } out;

    Result rc = serviceDispatchInOut(&g_nsAppManSrv, 17, in, out,
        .buffer_attrs = { SfBufferAttr_HipcMapAlias | SfBufferAttr_Out },
        .buffers = { { out_buf, out_buf_size } });
    
    if (R_SUCCEEDED(rc) && entries_read_out) *entries_read_out = out.entries_read;

    return rc;
}

Result nsTouchApplication(u64 titleID) {
    struct {
        u64 titleID;
    } in = { titleID };
    
    return serviceDispatchIn(&g_nsAppManSrv, 904, in);
}

Result nsDeleteApplicationRecord(u64 titleID) {
    struct {
        u64 titleID;
    } in = { titleID };
    
    return serviceDispatchIn(&g_nsAppManSrv, 27, in);
}

Result nsLaunchApplication(u64 titleID) {
    struct {
        u64 titleID;
    } in = { titleID };
    
    return serviceDispatchIn(&g_nsAppManSrv, 19, in);
}

Result nsPushLaunchVersion(u64 titleID, u32 version) {
    struct {
        u64 titleID;
        u32 version;
        u32 padding;
    } in = { titleID, version, 0 };
    
    return serviceDispatchIn(&g_nsAppManSrv, 36, in);
}

Result nsCheckApplicationLaunchVersion(u64 titleID) {
    struct {
        u64 titleID;
    } in = { titleID };
    
    return serviceDispatchIn(&g_nsAppManSrv, 38, in);
}

Result nsCountApplicationContentMeta(u64 titleId, u32* countOut) {

    struct {
        u64 titleId;
    } in = { titleId };

    struct {
        u32 count;
    } out;

    Result rc = serviceDispatchInOut(&g_nsAppManSrv, 600, in, out);

    if (R_SUCCEEDED(rc) && countOut) *countOut = out.count;

    return rc;
}

Result nsGetContentMetaStorage(const NcmContentMetaKey *record, u8 *storageOut) {

    struct {
        NcmContentMetaKey metaRecord;
    } in = { *record };

    struct {
        u8 out;
    } out;

    Result rc = serviceDispatchInOut(&g_nsAppManSrv, 606, in, out);

    if (R_SUCCEEDED(rc) && storageOut) *storageOut = out.out;

    return rc;
}

Result nsBeginInstallApplication(u64 tid, u32 unk, u8 storageId) {

    struct {
        u32 storageId;
        u32 unk;
        u64 tid;
    } in = { storageId, unk, tid };

    return serviceDispatchIn(&g_nsAppManSrv, 26, in);
}

Result nsInvalidateAllApplicationControlCache(void) {
    return serviceDispatch(&g_nsAppManSrv, 401);
}

Result nsInvalidateApplicationControlCache(u64 tid) {

    struct {
        u64 tid;
    } in = { tid };
    
    return serviceDispatchIn(&g_nsAppManSrv, 404, in);
}

Result nsCheckApplicationLaunchRights(u64 tid) {

    struct {
        u64 tid;
    } in = { tid };
    
    return serviceDispatchIn(&g_nsAppManSrv, 39, in);
}

Result nsGetApplicationContentPath(u64 tid, u8 type, char *out, size_t buf_size) {

    struct {
        u8 padding[0x7];
        u8 type;
        u64 tid;
    } in = { {0}, type, tid };

    return serviceDispatchIn(&g_nsAppManSrv, 21, in,
        .buffer_attrs = { SfBufferAttr_HipcMapAlias | SfBufferAttr_Out },
        .buffers = { { out, buf_size } }
    );
}

Result nsDisableApplicationAutoUpdate(u64 titleID) {

    struct {
        u64 title_id;
    } in = { titleID };
    
    return serviceDispatchIn(&g_nsAppManSrv, 903, in);
}

Result nsWithdrawApplicationUpdateRequest(u64 titleId) {

    struct {
        u64 title_id;
    } in = { titleId };
    
    return serviceDispatchIn(&g_nsAppManSrv, 907, in);
}
