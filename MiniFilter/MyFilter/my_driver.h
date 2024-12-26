#ifndef _MY_DRIVER_H_INCLUDED_
#define _MY_DRIVER_H_INCLUDED_
//
//   Author(s)    : Radu PORTASE(rportase@bitdefender.com)
//
#include "communication.h"

typedef
NTSTATUS
(NTAPI* PFUNC_ZwQueryInformationProcess) (
    _In_      HANDLE           ProcessHandle,
    _In_      PROCESSINFOCLASS ProcessInformationClass,
    _Out_     PVOID            ProcessInformation,
    _In_      ULONG            ProcessInformationLength,
    _Out_opt_ PULONG           ReturnLength
    );

typedef struct _GLOBLA_DATA
{
    PDRIVER_OBJECT DriverObject;
    PFLT_FILTER FilterHandle;
    APP_COMMUNICATION Communication;

    UNICODE_STRING Altitude;
    LARGE_INTEGER  RegistryCookie;

    ULONG MonitoringStarted;
    UINT8 NotificationType;

    PFUNC_ZwQueryInformationProcess pfnZwQueryInformationProcess;
}GLOBLA_DATA, *PGLOBLA_DATA;

extern GLOBLA_DATA gDrv;

#endif