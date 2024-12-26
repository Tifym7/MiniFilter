//
//   Author(s)    : Radu PORTASE(rportase@bitdefender.com)
//
#include "process_filter.h"
#include "communication.h"
#include "communication_protocol.h"
#include "trace.h"
#include "process_filter.tmh"
#include <ntstrsafe.h>
#include "utils.h"


#pragma warning(disable:4996)


void
ProcFltSendMessageProcessCreate(
    _In_ HANDLE ProcessId,
    _In_ PPS_CREATE_NOTIFY_INFO CreateInfo
)
{
    UNICODE_STRING message;
    ULONG32 msgSize = 4*PAGE_SIZE; 
    message.Buffer = ExAllocatePoolWithTag(PagedPool, msgSize, UTILS_TAG_UNICODE_STRING);
    if (!message.Buffer)
    {
        return;
    }
    message.MaximumLength = 4 * PAGE_SIZE;
    message.Length = 0;

    LARGE_INTEGER timestamp = { 0 };
    KeQuerySystemTime(&timestamp);

    RtlUnicodeStringPrintf(&message, L"[%llu] [ProcessCreate] [PID:%p] Path = %wZ, CommandLine = %wZ",
        timestamp.QuadPart, HandleToUlong(ProcessId), CreateInfo->ImageFileName, CreateInfo->CommandLine);


    CommSendString(&message);
    ExFreePoolWithTag(message.Buffer, UTILS_TAG_UNICODE_STRING);
}

static VOID
ProcFltSendMessageProcessTerminate(
    _In_ HANDLE ProcessId
)
{
    UNICODE_STRING message;
    ULONG32 msgSize = 4 * PAGE_SIZE;
    message.Buffer = ExAllocatePoolWithTag(PagedPool, msgSize, UTILS_TAG_UNICODE_STRING);
    if (!message.Buffer)
    {
        return;
    }
    message.MaximumLength = 4 * PAGE_SIZE;
    message.Length = 0;

    LARGE_INTEGER timestamp = { 0 };
    KeQuerySystemTime(&timestamp);

    PUNICODE_STRING ImageFileName = NULL;
    NTSTATUS status = GetImagePathFromPid(ProcessId, &ImageFileName);
    if (NT_SUCCESS(status))
    {
        RtlUnicodeStringPrintf(&message, L"[%llu] [ProcessTerminate] [%p] Path = %wZ",
            timestamp.QuadPart, HandleToUlong(ProcessId), ImageFileName);

        ExFreePoolWithTag(ImageFileName, UTILS_TAG_UNICODE_STRING);
    }
    else
    {
        RtlUnicodeStringPrintf(&message, L"[%llu] [ProcessTerminate] [%p] Path = ERROR",
            timestamp.QuadPart, HandleToUlong(ProcessId));
    }

    CommSendString(&message);
    ExFreePoolWithTag(message.Buffer, UTILS_TAG_UNICODE_STRING);

}

static VOID
ProcFltNotifyRoutine(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
)
{
    UNREFERENCED_PARAMETER(Process);

    if (!(gDrv.NotificationType == ProcessType))
    {
        // Monitoring is not started. We will simply exit the routine
        return;
    }

    if (CreateInfo)
    {
        ProcFltSendMessageProcessCreate(ProcessId, CreateInfo);
    }
    else
    {
        ProcFltSendMessageProcessTerminate(ProcessId);
    }
}

NTSTATUS
ProcessFilterInitialize()
{
    return PsSetCreateProcessNotifyRoutineEx(ProcFltNotifyRoutine, FALSE);
}

NTSTATUS
ProcessFilterUninitialize()
{
    return PsSetCreateProcessNotifyRoutineEx(ProcFltNotifyRoutine, TRUE);
}