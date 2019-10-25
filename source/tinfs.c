#include "tinfs.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

Result createTinfoilDirs(void)
{
    Result rc = 0;
    FsFileSystem sdFs;

    if (R_FAILED(rc = fsOpenSdCardFileSystem(&sdFs)))
    {
        printf("createTinfoilDirs: Failed to mount sd card. Error code: 0x%08x\n", rc);
        return rc;
    }

    rc = 0;

    if (R_FAILED(rc = fsFsCreateDirectory(&sdFs, "/tinfoil")) && rc != 0x402)
    {
        printf("createTinfoilDirs: Failed to create /tinfoil. Error code: 0x%08x\n", rc);
        goto CLEANUP;
    }

    rc = 0;

    if (R_FAILED(rc = fsFsCreateDirectory(&sdFs, "/tinfoil/extracted")) && rc != 0x402)
    {
        printf("createTinfoilDirs: Failed to create /tinfoil/extracted. Error code: 0x%08x\n", rc);
        goto CLEANUP;
    }

    rc = 0;

    if (R_FAILED(rc = fsFsCreateDirectory(&sdFs, "/tinfoil/nsp")) && rc != 0x402)
    {
        printf("createTinfoilDirs: Failed to create /tinfoil/nsp. Error code: 0x%08x\n", rc);
        goto CLEANUP;
    }

    rc = 0;

    if (R_FAILED(rc = fsFsCreateDirectory(&sdFs, "/tinfoil/ticket")) && rc != 0x402)
    {
        printf("createTinfoilDirs: Failed to create /tinfoil/ticket. Error code: 0x%08x\n", rc);
        goto CLEANUP;
    }

    rc = 0;

    CLEANUP:
    fsFsClose(&sdFs);
    return rc;
}