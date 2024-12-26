#ifndef _COMMMUNICATION_H_
#define _COMMMUNICATION_H_
//

//   Author(s)    : Radu PORTASE(rportase@bitdefender.com)
//
#include <fltKernel.h>

//
// APP_COMMUNICATION
//
typedef struct _APP_COMMUNICATION
{
    EX_PUSH_LOCK Lock;                       // Lock protecting the communication structure
    _Guarded_by_(Lock) PFLT_PORT ServerPort; // The server port
    _Guarded_by_(Lock) HANDLE ClientId;      // PID of the client process
    _Guarded_by_(Lock) PFLT_PORT ClientPort; // The client port
}APP_COMMUNICATION, *PAPP_COMMUNICATION;

//
// CommInitializeFilterCommunicationPort
//
_Must_inspect_result_
_No_competing_thread_
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
CommInitializeFilterCommunicationPort(); // uses implicit global parameter

  
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
CommUninitializeFilterCommunicationPort(); // uses implicit global parameter

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
CommSendMessage(
    _In_     PVOID  InputBuffer,
    _In_     ULONG  InputBufferSize,
    _Out_    PVOID  OutputBuffer,
    _Inout_  PULONG OutputBufferSize
);

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
CommSendString(
    _In_ PUNICODE_STRING StringToSend
);

#endif//_COMMCORE_H_