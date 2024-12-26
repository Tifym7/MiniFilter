#ifndef _GLOBALDATA_H_
#define _GLOBALDATA_H_
//
//   Author(s)    : Radu PORTASE(rportase@bitdefender.com)
//

#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <stdio.h>

#include "driver_communication.h"

#ifndef _NTDEF_
typedef _Return_type_success_(return >= 0) LONG NTSTATUS;
typedef NTSTATUS *PNTSTATUS;
#endif

#pragma region Global structure definition
//
// APP_GLOBAL_DATA
//
typedef struct _APP_GLOBAL_DATA
{
    struct {
        DWORD   ProcessId;
        HMODULE ImageBase;
        ULONG Version;
    }Self;

    struct {
        ULONG Version;
    }Server;
    DRIVER_COMMUNICATION Communication;

}APP_GLOBAL_DATA, *PAPP_GLOBAL_DATA;

extern APP_GLOBAL_DATA gApp;
#pragma endregion Global structure definition

#endif//_GLOBALDATA_H_