//
//   Author(s)    : Radu PORTASE(rportase@bitdefender.com)
//
#include "thread_filter.h"
#include "communication.h"
#include "communication_protocol.h"
#include "trace.h"
#include "thread_filter.tmh"
#include <ntstrsafe.h>
#include "utils.h"

#pragma warning(disable:4996)

void
ThFltSendMessageThreadOperation(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _In_ PUNICODE_STRING Path,
    _In_ BOOLEAN Create

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
    if (Create) {
        RtlUnicodeStringPrintf(&message, L"[%llu] [ThreadCreate] [%p] in Process [%p] Path = %wZ",
            timestamp.QuadPart, HandleToUlong(ThreadId), HandleToUlong(ProcessId), Path);
    }
    else {
        RtlUnicodeStringPrintf(&message, L"[%llu] [ThreadTerminate] [%p] from Process [%p] Path = %wZ",
         timestamp.QuadPart, HandleToUlong(ThreadId), HandleToUlong(ProcessId), Path);
    }
    CommSendString(&message);
    ExFreePoolWithTag(message.Buffer, UTILS_TAG_UNICODE_STRING);
}



VOID
ThreadFilterNotifyRoutine(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _In_ BOOLEAN Create
)
{
    //psgetcurrentpid -> anomalie -> de obicei e la fel ca celalalt , dar la injectarae e diferit.

    UNREFERENCED_PARAMETER(ProcessId);
    UNREFERENCED_PARAMETER(ThreadId);
    UNREFERENCED_PARAMETER(Create);

    if (!(gDrv.NotificationType == ThreadType))
    {
        return;
    }

    PUNICODE_STRING pProcessPath = NULL;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    __try
    {
        status = GetImagePathFromPid(ProcessId , &pProcessPath);
        if (!NT_SUCCESS(status))
        {
            LogError("GetCurrentProcessImagePath failed with status 0x%X\n", status);
            __leave;
        }

        LogInfo("Thread Notification for process %wZ", pProcessPath);
        ThFltSendMessageThreadOperation(ProcessId, ThreadId, pProcessPath, Create);
    }
    __finally
    {
        if (pProcessPath)
        {
            ExFreePoolWithTag(pProcessPath, UTILS_TAG_UNICODE_STRING);
        }
    }
}

NTSTATUS ThreadFilterInitialize()
{
    return PsSetCreateThreadNotifyRoutine(ThreadFilterNotifyRoutine);

}

NTSTATUS ThreadFilterUninitialize()
{
    return PsRemoveCreateThreadNotifyRoutine(ThreadFilterNotifyRoutine);
}
