//

//   Author(s)    : Radu PORTASE(rportase@bitdefender.com)
//

#include "Communication.h"
#include <fltKernel.h>
#include "Trace.h"
#include "communication.tmh"
#include "communication_protocol.h"
#include "my_driver.h"

#pragma region FLT_PORT Commands
/*++
This region contains implementations for all the commands received by MY_DRIVER.sys from MY_DRIVERCORE trough the FLT Port

All commands defined here must have the following prototype:

NTSTATUS
Hccp<Command>(
_In_reads_bytes_(InputBufferLength) PVOID InputBuffer,
_In_ ULONG InputBufferLength,
_Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
_In_ ULONG OutputBufferLength,
_Out_ PULONG BytesWritten
)

Note: Hccp stands for Handler for Core Command Private, keep this in mind when naming a command
--*/
/// The parameters of the function are outside of our trust domain.The parameters are checked to not be null
/// before entering the handlers.This may not be enough for commands with variable buffer sizes.Make sure all
/// commands check the parameters correctly.
/// Probing is also done for the parameters.

//
// HccpNotImplementedOrInvalidCommandCode
//

#pragma warning(disable:4996)


NTSTATUS
HccpNotImplementedOrInvalidCommandCode(
    _In_reads_bytes_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *BytesWritten) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG BytesWritten
)
{
    PMY_DRIVER_COMMAND_HEADER pHeader = (PMY_DRIVER_COMMAND_HEADER)InputBuffer;

    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(OutputBuffer);
    UNREFERENCED_PARAMETER(OutputBufferLength);
    UNREFERENCED_PARAMETER(BytesWritten);

    LogError(L"Command %u is not implemented.", pHeader->CommandCode);
    return STATUS_NOT_IMPLEMENTED;
}

//
// HccpNotImplementedOrInvalidCommandCode
//
NTSTATUS
HccpGetVersion(
    _In_reads_bytes_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *BytesWritten) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG BytesWritten
)
{
    PCOMM_CMD_GET_VERSION pCmdOut = (PCOMM_CMD_GET_VERSION)OutputBuffer;
    UNREFERENCED_PARAMETER(InputBuffer);

    if (InputBufferLength < sizeof(COMM_CMD_GET_VERSION))
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (OutputBufferLength < sizeof(COMM_CMD_GET_VERSION))
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (NULL == OutputBuffer)
    {
        return STATUS_INVALID_PARAMETER;
    }

    pCmdOut->Version = 1;
    *BytesWritten = sizeof(*pCmdOut);

    return STATUS_SUCCESS;
}

//
// HccpStartMonitoring
//
NTSTATUS
HccpStartMonitoring(
    _In_reads_bytes_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *BytesWritten) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG BytesWritten
)
{
    UNREFERENCED_PARAMETER(InputBuffer);
    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(OutputBuffer);
    UNREFERENCED_PARAMETER(OutputBufferLength);
    UNREFERENCED_PARAMETER(BytesWritten);

    PCOMM_CMD_START_MONITORING pCmdIn = (PCOMM_CMD_START_MONITORING)InputBuffer;
    if (InputBufferLength < sizeof(COMM_CMD_START_MONITORING))
    {
        return STATUS_INVALID_PARAMETER;
    }

    *BytesWritten = 0;
    //gDrv.MonitoringStarted = 1;
    gDrv.NotificationType |= pCmdIn->NotificationType;
   
    return STATUS_SUCCESS;
}

//
// HccpStopMonitoring
//
NTSTATUS
HccpStopMonitoring(
    _In_reads_bytes_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *BytesWritten) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG BytesWritten
)
{
    UNREFERENCED_PARAMETER(InputBuffer);
    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(OutputBuffer);
    UNREFERENCED_PARAMETER(OutputBufferLength);
    UNREFERENCED_PARAMETER(BytesWritten);

    PCOMM_CMD_STOP_MONITORING pCmdIn = (PCOMM_CMD_STOP_MONITORING)InputBuffer;
    if (InputBufferLength < sizeof(COMM_CMD_STOP_MONITORING))
    {
        return STATUS_INVALID_PARAMETER;
    }

    *BytesWritten = 0;
   // gDrv.MonitoringStarted = 0;
   
    pCmdIn;
    //gDrv.NotificationType &= ~pCmdIn->NotificationType;
    gDrv.NotificationType = 0;

    //gDrv.NotificationType = pCmdIn->NotificationType;

    return STATUS_SUCCESS;
}

#pragma endregion FLT_PORT Commands

#pragma region FLT_PORT callbacks
/*++
This region contains the callbacks given to FltCreateCommunicationPort.
Relying on SAL for parameter validation here is not ok. The parameters received are out of our trust domain.
Also we keep the defines from the documentation
--*/

//
// CommpCoreCallbackConnect
//
NTSTATUS
CommpCoreCallbackConnect(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID *ConnectionPortCookie
)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    BOOLEAN bLockAcquired = FALSE;

    PFLT_PORT_CONNECTION_CONTEXT pConnectionContext = (PFLT_PORT_CONNECTION_CONTEXT)ConnectionContext;

    UNREFERENCED_PARAMETER(ServerPortCookie);

    NT_ASSERT(NULL != ClientPort);
    if (NULL == ClientPort)
    {
        // this is critical. It must never happen
        return STATUS_INVALID_PARAMETER_1;
    }

    __try
    {
        if (NULL == ConnectionContext || SizeOfContext < sizeof(FLT_PORT_CONNECTION_CONTEXT))
        {
            // invalid client attempting to connect
            status = STATUS_INVALID_PARAMETER_3;
            __leave;
        }

        if (NULL == ConnectionPortCookie)
        {
            status = STATUS_INVALID_PARAMETER_5;
            __leave;
        }

        if (pConnectionContext->Version != 1)
        {
            status = STATUS_INVALID_PARAMETER_3;
            __leave;
        }

        // we are currently not using a connection port cookie
        *ConnectionPortCookie = NULL;


        FltAcquirePushLockExclusive(&gDrv.Communication.Lock);
        bLockAcquired = TRUE;

        NT_ASSERT(NULL == gDrv.Communication.ClientPort);// assert here to assist debug
        if (NULL != gDrv.Communication.ClientPort)
        {
            status = STATUS_CONNECTION_ABORTED;
            __leave;
        }

        gDrv.Communication.ClientId = PsGetCurrentProcessId();
        gDrv.Communication.ClientPort = ClientPort;

        FltReleasePushLock(&gDrv.Communication.Lock);
        bLockAcquired = FALSE;

        status = STATUS_SUCCESS;
    }
    __finally
    {
        if (bLockAcquired)
        {
            FltReleasePushLock(&gDrv.Communication.Lock);
        }
    }

    return status;
}

//
// CommpCoreCallbackDisconnect
//
void
CommpCoreCallbackDisconnect(
    _In_opt_ PVOID ConnectionCookie
)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    BOOLEAN bLockAcquired = FALSE;
    // we are currently not using a connection cookie
    UNREFERENCED_PARAMETER(ConnectionCookie);

    __try
    {
        FltAcquirePushLockExclusive(&gDrv.Communication.Lock);
        bLockAcquired = TRUE;

        NT_ASSERT(NULL != gDrv.Communication.ClientPort); // assert here to assist debug
        if (NULL == gDrv.Communication.ClientPort)
        {
            status = STATUS_ALREADY_DISCONNECTED;
            __leave;
        }

        FltCloseClientPort(gDrv.FilterHandle, &gDrv.Communication.ClientPort);

        gDrv.Communication.ClientId = 0;

        FltReleasePushLock(&gDrv.Communication.Lock);
        bLockAcquired = FALSE;

        status = STATUS_SUCCESS;
    }
    __finally
    {
        if (bLockAcquired)
        {
            FltReleasePushLock(&gDrv.Communication.Lock);
        }
    }

    return;
}

//
// CommpCoreCallbackMessageReceived
//
NTSTATUS
CommpCoreCallbackMessageReceived(
    _In_opt_ PVOID PortCookie,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    PMY_DRIVER_COMMAND_HEADER  pCommandHeader = NULL;
    ULONG ulBytesWritten = 0;

    // We are currently not using the port cookie
    UNREFERENCED_PARAMETER(PortCookie);

    __try
    {
        //
        // Do some high level validation of our parameters here
        //
        if (NULL == InputBuffer || 0 == InputBufferLength)
        {
            status = STATUS_INVALID_PARAMETER;
            __leave;
        }

        if (InputBufferLength < sizeof(MY_DRIVER_COMMAND_HEADER))
        {
            status = STATUS_INVALID_PARAMETER;
            __leave;
        }

        if (NULL == OutputBuffer &&
            0 != OutputBufferLength)
        {
            status = STATUS_INVALID_PARAMETER;
            __leave;
        }

        //
        // Select the command handler from our list of command handlers
        //
        pCommandHeader = (PMY_DRIVER_COMMAND_HEADER)InputBuffer;
        LogTrace(L"Received command with code 0x%X (%u) from user mode.\n", pCommandHeader->CommandCode, pCommandHeader->CommandCode);
        switch (pCommandHeader->CommandCode)
        {
        case commGetVersion:
            status = HccpGetVersion(InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength, &ulBytesWritten);
            break;
        case commStartMonitoring:
            status = HccpStartMonitoring(InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength, &ulBytesWritten);
            break;
        case commStopMonitoring:
            status = HccpStopMonitoring(InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength, &ulBytesWritten);
            break;
        default:
            status = HccpNotImplementedOrInvalidCommandCode(InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength, &ulBytesWritten);
        }
    }
    __finally
    {
    }

    if (NT_SUCCESS(status))
    {
        LogTrace(L"Command successfully handled\n");
        // success. We return the results to the caller
        *ReturnOutputBufferLength = ulBytesWritten;
    }
    else
    {
        LogTrace(L"Handling command failed with status = 0x%X\n", status);
        // fail. Zero the buffers
        if (NULL != OutputBuffer)
        {
            RtlZeroMemory(OutputBuffer, OutputBufferLength);
        }

        *ReturnOutputBufferLength = 0;
    }

    return status;
}

#pragma endregion FLT_PORT callbacks

//
// CommInitializeFilterCommunicationPort
//
_Use_decl_annotations_
NTSTATUS
CommInitializeFilterCommunicationPort() // uses implicit global parameter
{
    NTSTATUS      status = STATUS_UNSUCCESSFUL;
    UNICODE_STRING ustrPortName;
    OBJECT_ATTRIBUTES objAttr;
    PSECURITY_DESCRIPTOR pSecurityDescriptor = NULL;
    BOOLEAN        bFreeSecurityDescriptor = FALSE;
    BOOLEAN        bLocked = FALSE;

    RtlInitUnicodeString(&ustrPortName, MY_FILTER_PORT_NAME);

    __try
    {
        //
        // Init the lock protecting our structure
        //
        FltInitializePushLock(&gDrv.Communication.Lock);
        FltAcquirePushLockExclusive(&gDrv.Communication.Lock);
        bLocked = TRUE;

        //
        // Build a security descriptor
        //
        status = FltBuildDefaultSecurityDescriptor(&pSecurityDescriptor, FLT_PORT_ALL_ACCESS);
        if (!NT_SUCCESS(status))
        {
            __leave;
        }
        bFreeSecurityDescriptor = TRUE;

        InitializeObjectAttributes(&objAttr,
            &ustrPortName,
            OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
            NULL,
            pSecurityDescriptor);

        //
        // Create the communication port
        //
        status = FltCreateCommunicationPort(gDrv.FilterHandle,
            &gDrv.Communication.ServerPort,
            &objAttr,
            NULL,    // currently not using a communication cookie
            CommpCoreCallbackConnect,
            CommpCoreCallbackDisconnect,
            CommpCoreCallbackMessageReceived,
            1       // using only one connection
        );
        if (!NT_SUCCESS(status))
        {
            __leave;
        }

        FltReleasePushLock(&gDrv.Communication.Lock);
        bLocked = FALSE;

        //
        // Free the security descriptor
        //
        FltFreeSecurityDescriptor(pSecurityDescriptor);
        bFreeSecurityDescriptor = FALSE;

        status = STATUS_SUCCESS;
    }
    __finally
    {
        if (bLocked)
        {
            FltReleasePushLock(&gDrv.Communication.Lock);
        }

        if (bFreeSecurityDescriptor)
        {
            FltFreeSecurityDescriptor(pSecurityDescriptor);
        }
    }

    return status;
}

//
// CommUninitializeFilterCommunicationPort
//
_Use_decl_annotations_
NTSTATUS
CommUninitializeFilterCommunicationPort() // uses implicit global parameter
{
    FltAcquirePushLockExclusive(&gDrv.Communication.Lock);
    if (NULL != gDrv.Communication.ClientPort)
    {
        FltCloseClientPort(gDrv.FilterHandle, &gDrv.Communication.ClientPort);
        gDrv.Communication.ClientPort = NULL;
        gDrv.Communication.ClientId = 0;
    }

    FltCloseCommunicationPort(gDrv.Communication.ServerPort);
    FltReleasePushLock(&gDrv.Communication.Lock);
    FltDeletePushLock(&gDrv.Communication.Lock);

    return STATUS_SUCCESS;
}

#define MSG_DELAY_ONE_MICROSECOND               (-10)
#define MSG_DELAY_ONE_MILLISECOND               (MSG_DELAY_ONE_MICROSECOND*1000)
#define MSG_DELAY_ONE_SECOND                    (MSG_DELAY_ONE_MILLISECOND*1000)

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS 
CommSendMessage(
    _In_ PVOID InputBuffer, 
    _In_ ULONG InputBufferSize,
    _Out_ PVOID OutputBuffer,
    _Inout_ PULONG OutputBufferSize
)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    LARGE_INTEGER timeout;
    timeout.QuadPart = 60 * MSG_DELAY_ONE_SECOND; // 60 seconds

    FltAcquirePushLockShared(&gDrv.Communication.Lock);
    __try
    {
        LogTrace("Sending message to app. Input: 0x%p size %u Output: 0x%p size 0x%u",
            InputBuffer, InputBufferSize, OutputBuffer, *OutputBufferSize);

        status = FltSendMessage(gDrv.FilterHandle,
            &gDrv.Communication.ClientPort,
            InputBuffer,
            InputBufferSize,
            OutputBuffer,
            OutputBufferSize,
            &timeout);
        if (!NT_SUCCESS(status))
        {
            LogError("FltSendMessage failed with status 0x%X", status);
            // not success
            __leave;
        }

        if (status == STATUS_TIMEOUT)
        {
            status = STATUS_MESSAGE_LOST;
            __leave;
        }

        status = STATUS_SUCCESS;
    }
    __finally
    {
        FltReleasePushLock(&gDrv.Communication.Lock);
    }

    return status;
}

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
CommSendString(
    _In_ PUNICODE_STRING StringToSend
)
{
    PMY_DRIVER_MESSAGE_SEND_STRING pMsg = NULL;
    MY_DRIVER_MESSAGE_SEND_STRING_REPLY reply = { 0 };

    ULONG msgSize = sizeof(MY_DRIVER_MESSAGE_SEND_STRING) + StringToSend->Length;

    pMsg = ExAllocatePoolWithTag(PagedPool, msgSize, 'GSM+');
    if (!pMsg)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    pMsg->Header.MessageCode = msgSendString;
    pMsg->StringLengthInBytes = msgSize;
    
    RtlCopyMemory(&pMsg->Data[0], StringToSend->Buffer, StringToSend->Length);
    
    ULONG replySize = sizeof(reply);
    NTSTATUS status = CommSendMessage(pMsg, msgSize, &reply, &replySize);
    if (!NT_SUCCESS(status))
    {
        LogError("CommSendMessage failed with status = 0x%X", status);
    }

    ExFreePoolWithTag(pMsg, 'GSM+');
    return STATUS_SUCCESS;
}