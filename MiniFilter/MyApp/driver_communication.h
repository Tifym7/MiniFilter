#ifndef _DRIVER_COMMUNICATION_H_INCLUDED_
#define _DRIVER_COMMUNICATION_H_INCLUDED_
//
//   Author(s)    : Radu PORTASE(rportase@bitdefender.com)
//

#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include "driver_communication.h"

#ifndef _NTDEF_
typedef _Return_type_success_(return >= 0) LONG NTSTATUS;
typedef NTSTATUS *PNTSTATUS;
#endif

#define COMM_NUMBER_OF_LISTENER_THREADS 5
#define COMM_MAX_MESSAGE_SIZE           4*1024 // 4Kb = 1 page

typedef struct _DRIVER_COMMUNICATION
{
    HANDLE DriverPort;                             // handle to the DRIVER communication port
    HANDLE ListenerThreads[COMM_NUMBER_OF_LISTENER_THREADS]; //handles for the listener threads
    HANDLE ThreadsTerminationEvent;             // handle for the thread termination event
}DRIVER_COMMUNICATION, *PDRIVER_COMMUNICATION;

//
// CommDriverPreinitialize
//
VOID
CommDriverPreinitialize(
    );

//
// CommDriverInitialize
//
NTSTATUS
CommDriverInitialize(
    );

//
// CommDriverUninitialize
//
NTSTATUS
CommDriverUninitialize(
    );

#endif//_COMMDRIVER_H_