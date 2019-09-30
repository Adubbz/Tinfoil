#pragma once

#include <switch/services/ns.h>
#include <switch/services/ncm.h>

typedef struct {
    u64 titleID;
    u64 unk;
    u64 size;
} PACKED ApplicationRecord;

typedef struct {
    NcmContentMetaKey metaRecord;
    u64 storageId;
} PACKED ContentStorageRecord;

Result nsextInitialize(void);
void nsextExit(void);

Result nsCalculateApplicationOccupiedSize(u64 titleID, void *out_buf);
Result nsPushApplicationRecord(u64 title_id, u8 last_modified_event, ContentStorageRecord *content_records_buf, size_t buf_size);
Result nsListApplicationRecordContentMeta(u64 offset, u64 titleID, void *out_buf, size_t out_buf_size, u32 *entries_read_out);
Result nsDeleteApplicationRecord(u64 titleID);
Result nsTouchApplication(u64 titleID);
Result nsLaunchApplication(u64 titleID);
Result nsPushLaunchVersion(u64 titleID, u32 version);
Result nsCountApplicationContentMeta(u64 titleId, u32* countOut);
Result nsCheckApplicationLaunchVersion(u64 titleID);
Result nsDisableApplicationAutoUpdate(u64 titleID);
Result nsGetContentMetaStorage(const NcmContentMetaKey *record, u8 *out);
Result nsBeginInstallApplication(u64 tid, u32 unk, u8 storageId);
Result nsInvalidateAllApplicationControlCache(void);
Result nsInvalidateApplicationControlCache(u64 tid);
Result nsCheckApplicationLaunchRights(u64 tid);
Result nsGetApplicationContentPath(u64 titleId, u8 type, char *outBuf, size_t bufSize);
Result nsWithdrawApplicationUpdateRequest(u64 titleId);
