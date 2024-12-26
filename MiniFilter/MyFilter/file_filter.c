
//
//   Author(s)    : Radu PORTASE(rportase@bitdefender.com)
//
#include "file_filter.h"
#include "trace.h"
#include "file_filter.tmh"
#include "my_driver.h"
#include "communication_protocol.h"
#include "utils.h"
#include <ntstrsafe.h>

#pragma warning( disable: 4996 )

//
// Functions to deal with instance management
//

// pentru a implementa functiile am folosit drept model implementarile de pe teams pt create si read
typedef struct _FILE_CONTEXT_RW {
    UINT32 bytesToRW;
    HANDLE Pid;
    LARGE_INTEGER Offset;
    BOOLEAN isRead;
} FILE_CONTEXT_RW, * PFILE_CONTEXT_RW;


typedef struct _FILE_CONTEXT_SET_INFORMATION {
    WCHAR* newName;
    UNICODE_STRING oldName;
    LONGLONG allocationSize;
} FILE_CONTEXT_SET_INFORMATION, * PFILE_CONTEXT_SET_INFORMATION;

NTSTATUS
OnInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeDeviceType);
    UNREFERENCED_PARAMETER(VolumeFilesystemType);

    PAGED_CODE();

    LogInfo("MyFilter!MyFilterInstanceSetup: Entered");

    return STATUS_SUCCESS;
}


NTSTATUS
OnQueryTeardown(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    PAGED_CODE();

    LogInfo("MyFilter!MyFilterInstanceQueryTeardown: Entered");

    return STATUS_SUCCESS;
}


VOID
OnInstanceTeardownStart(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    PAGED_CODE();

    LogInfo("MyFilter!MyFilterInstanceTeardownStart: Entered");
}


VOID
OnInstanceTeardownComplete(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    PAGED_CODE();

    LogInfo("MyFilter!MyFilterInstanceTeardownComplete: Entered");
}

//
// Functions to monitor filesystem activity
//

FLT_PREOP_CALLBACK_STATUS
MyFilterPreOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
  
    if (gDrv.NotificationType == FileType)
    {
        LogInfo("MyFilter!MyFilterPreOperation: Entered. Pid = 0x%X", 
            HandleToUlong(FltGetRequestorProcessIdEx(Data)));
    }
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS
MyFilterPreOperationSynchronize(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (gDrv.NotificationType == FileType)
    {
        LogInfo("MyFilter!MyFilterPreOperationSynchronize: Entered. Pid = 0x%X",
            HandleToUlong(FltGetRequestorProcessIdEx(Data)));
    }
    return FLT_PREOP_SYNCHRONIZE;
}


FLT_POSTOP_CALLBACK_STATUS
MyFilterPostOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);

    if (gDrv.NotificationType == FileType)
    {
        LogInfo("MyFilter!MyFilterPostOperation: Entered. Pid = 0x%X",
            HandleToUlong(FltGetRequestorProcessIdEx(Data)));
    }

    return FLT_POSTOP_FINISHED_PROCESSING;
}


FLT_PREOP_CALLBACK_STATUS
MyFilterPreOperationNoPostOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (gDrv.NotificationType ==  FileType)
    {
        LogInfo("MyFilter!MyFilterPreOperationNoPostOperation: Entered");
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}


FLT_PREOP_CALLBACK_STATUS
MyFilterPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (gDrv.NotificationType == FileType)
    {
        UNICODE_STRING message;
        ULONG32 msgSize = 4 * PAGE_SIZE;
        message.Buffer = ExAllocatePoolWithTag(PagedPool, msgSize, UTILS_TAG_UNICODE_STRING);
        if (!message.Buffer)
        {
            goto cleanup_and_exit;

        }
        message.MaximumLength = 4 * PAGE_SIZE;
        message.Length = 0;

        LARGE_INTEGER timestamp = { 0 };
        KeQuerySystemTime(&timestamp);
        PUNICODE_STRING fileName = NULL;
        fileName = ExAllocatePoolWithTag(NonPagedPool, sizeof(UNICODE_STRING), 'tag'); // Allocate memory for fileName

        if (Data->Iopb->Parameters.Create.Options == FILE_OPEN_BY_FILE_ID) {
            RtlUnicodeStringPrintf(&message,
                L"[%llu] [PreFileCreate] [PID: %p] [FileName: unnamed] [Status: %X]",
                timestamp.QuadPart, HandleToUlong(FltGetRequestorProcessIdEx(Data)), Data->IoStatus.Status);
        }
        else {
            RtlUnicodeStringPrintf(&message,
                L"[%llu] [PreFileCreate] [PID: %p] [FileName: %wZ] [Status: %X]",
                timestamp.QuadPart, HandleToUlong(FltGetRequestorProcessIdEx(Data)), &FltObjects->FileObject->FileName, Data->IoStatus.Status);
        }
        CommSendString(&message);

    cleanup_and_exit:
        ExFreePoolWithTag(message.Buffer, UTILS_TAG_UNICODE_STRING);
    }
   
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS
MyFilterPostCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);

    if (gDrv.NotificationType == FileType)
    {

        UNICODE_STRING message;
        ULONG32 msgSize = 4 * PAGE_SIZE;
        message.Buffer = ExAllocatePoolWithTag(PagedPool, msgSize, UTILS_TAG_UNICODE_STRING);
        if (!message.Buffer)
        {
            goto cleanup_and_exit;
        }
        message.MaximumLength = 4 * PAGE_SIZE;
        message.Length = 0;

        LARGE_INTEGER timestamp = { 0 };
        KeQuerySystemTime(&timestamp);
        PUNICODE_STRING fileName = NULL;
        fileName = ExAllocatePoolWithTag(NonPagedPool, sizeof(UNICODE_STRING), 'tag'); // Allocate memory for fileName

        if (Data->Iopb->Parameters.Create.Options == FILE_OPEN_BY_FILE_ID) {
            RtlUnicodeStringPrintf(&message,
                L"[%llu] [PostFileCreate] [PID: %p] [FileName: unnamed] [Status: %X]\n",
                timestamp.QuadPart, HandleToUlong(FltGetRequestorProcessIdEx(Data)),Data->IoStatus.Status);
        }
        else {
            if (Data->Iopb->Parameters.Create.Options & FILE_DELETE_ON_CLOSE) {
                RtlUnicodeStringPrintf(&message,
                    L"[%llu] [PostFileCreateDelete] [PID: %p] [FileName: %wZ] [Status: %X]\n",
                    timestamp.QuadPart, HandleToUlong(FltGetRequestorProcessIdEx(Data)), &FltObjects->FileObject->FileName, Data->IoStatus.Status);
            }
            else {
                RtlUnicodeStringPrintf(&message,
                    L"[%llu] [PostFileCreate] [PID: %p] [FileName: %wZ] [Status: %X]\n",
                    timestamp.QuadPart, HandleToUlong(FltGetRequestorProcessIdEx(Data)), &FltObjects->FileObject->FileName, Data->IoStatus.Status);
            }
        }
        CommSendString(&message);

    cleanup_and_exit:
        ExFreePoolWithTag(message.Buffer, UTILS_TAG_UNICODE_STRING);
    }
    
    return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_PREOP_CALLBACK_STATUS
MyFilterPreClose(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (gDrv.NotificationType == FileType)
    {
        UNICODE_STRING message;
        ULONG32 msgSize = 4 * PAGE_SIZE;
        message.Buffer = ExAllocatePoolWithTag(PagedPool, msgSize, UTILS_TAG_UNICODE_STRING);
        if (!message.Buffer)
        {
            goto cleanup_and_exit;

        }
        message.MaximumLength = 4 * PAGE_SIZE;
        message.Length = 0;

        LARGE_INTEGER timestamp = { 0 };
        KeQuerySystemTime(&timestamp);
        PUNICODE_STRING fileName = NULL;
        fileName = ExAllocatePoolWithTag(NonPagedPool, sizeof(UNICODE_STRING), 'tag'); // Allocate memory for fileName

        if (Data->Iopb->Parameters.Create.Options == FILE_OPEN_BY_FILE_ID) {
            RtlUnicodeStringPrintf(&message,
                L"[%llu] [PreFileClose] [PID: %p] [FileName: unnamed] [Status: %X]",
                timestamp.QuadPart, HandleToUlong(FltGetRequestorProcessIdEx(Data)), Data->IoStatus.Status);
        }
        else {
            RtlUnicodeStringPrintf(&message,
                L"[%llu] [PreFileClose] [PID: %p] [FileName: %wZ] [Status: %X]",
                timestamp.QuadPart, HandleToUlong(FltGetRequestorProcessIdEx(Data)), &FltObjects->FileObject->FileName, Data->IoStatus.Status);
        }
        CommSendString(&message);

    cleanup_and_exit:
        ExFreePoolWithTag(message.Buffer, UTILS_TAG_UNICODE_STRING);
    }

    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS
MyFilterPostClose(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);

    if (gDrv.NotificationType == FileType)
    {

        UNICODE_STRING message;
        ULONG32 msgSize = 4 * PAGE_SIZE;
        message.Buffer = ExAllocatePoolWithTag(PagedPool, msgSize, UTILS_TAG_UNICODE_STRING);
        if (!message.Buffer)
        {
            goto cleanup_and_exit;
        }
        message.MaximumLength = 4 * PAGE_SIZE;
        message.Length = 0;

        LARGE_INTEGER timestamp = { 0 };
        KeQuerySystemTime(&timestamp);
        PUNICODE_STRING fileName = NULL;
        fileName = ExAllocatePoolWithTag(NonPagedPool, sizeof(UNICODE_STRING), 'tag'); // Allocate memory for fileName

        if (Data->Iopb->Parameters.Create.Options == FILE_OPEN_BY_FILE_ID) {
            RtlUnicodeStringPrintf(&message,
                L"[%llu] [PostFileClose] [PID: %p] [FileName: unnamed] [Status: %X]\n",
                timestamp.QuadPart, HandleToUlong(FltGetRequestorProcessIdEx(Data)), Data->IoStatus.Status);
        }
        else {
            RtlUnicodeStringPrintf(&message,
                L"[%llu] [PostFileClose] [PID: %p] [FileName: %wZ] [Status: %X]\n",
                timestamp.QuadPart, HandleToUlong(FltGetRequestorProcessIdEx(Data)), &FltObjects->FileObject->FileName, Data->IoStatus.Status);
        }
        CommSendString(&message);

    cleanup_and_exit:
        ExFreePoolWithTag(message.Buffer, UTILS_TAG_UNICODE_STRING);
    }
    return FLT_POSTOP_FINISHED_PROCESSING;
}
FLT_PREOP_CALLBACK_STATUS
MyFilterPreCleanup(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (gDrv.NotificationType == FileType)
    {
        UNICODE_STRING message;
        ULONG32 msgSize = 4 * PAGE_SIZE;
        message.Buffer = ExAllocatePoolWithTag(PagedPool, msgSize, UTILS_TAG_UNICODE_STRING);
        if (!message.Buffer)
        {
            goto cleanup_and_exit;

        }
        message.MaximumLength = 4 * PAGE_SIZE;
        message.Length = 0;

        LARGE_INTEGER timestamp = { 0 };
        KeQuerySystemTime(&timestamp);
        PUNICODE_STRING fileName = NULL;
        fileName = ExAllocatePoolWithTag(NonPagedPool, sizeof(UNICODE_STRING), 'tag'); // Allocate memory for fileName

        if (Data->Iopb->Parameters.Create.Options == FILE_OPEN_BY_FILE_ID) {
            RtlUnicodeStringPrintf(&message,
                L"[%llu] [PreFileCleanUp] [PID: %p] [FileName: unnamed] [Status: %X]",
                timestamp.QuadPart, HandleToUlong(FltGetRequestorProcessIdEx(Data)), Data->IoStatus.Status);
        }
        else {
            RtlUnicodeStringPrintf(&message,
                L"[%llu] [PreFileCleanUp] [PID: %p] [FileName: %wZ] [Status: %X]",
                timestamp.QuadPart, HandleToUlong(FltGetRequestorProcessIdEx(Data)), &FltObjects->FileObject->FileName, Data->IoStatus.Status);
        }
        CommSendString(&message);

    cleanup_and_exit:
        ExFreePoolWithTag(message.Buffer, UTILS_TAG_UNICODE_STRING);
    }

    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS
MyFilterPostCleanup(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);

    if (gDrv.NotificationType == FileType)
    {

        UNICODE_STRING message;
        ULONG32 msgSize = 4 * PAGE_SIZE;
        message.Buffer = ExAllocatePoolWithTag(PagedPool, msgSize, UTILS_TAG_UNICODE_STRING);
        if (!message.Buffer)
        {
            goto cleanup_and_exit;
        }
        message.MaximumLength = 4 * PAGE_SIZE;
        message.Length = 0;

        LARGE_INTEGER timestamp = { 0 };
        KeQuerySystemTime(&timestamp);
        PUNICODE_STRING fileName = NULL;
        fileName = ExAllocatePoolWithTag(NonPagedPool, sizeof(UNICODE_STRING), 'tag'); // Allocate memory for fileName

        if (Data->Iopb->Parameters.Create.Options == FILE_OPEN_BY_FILE_ID) {
            RtlUnicodeStringPrintf(&message,
                L"[%llu] [PostFileCleanup] [PID: %p] [FileName: unnamed] [Status: %X]\n",
                timestamp.QuadPart, HandleToUlong(FltGetRequestorProcessIdEx(Data)), Data->IoStatus.Status);
        }
        else {
            RtlUnicodeStringPrintf(&message,
                L"[%llu] [PostFileCleanup] [PID: %p] [FileName: %wZ] [Status: %X]\n",
                timestamp.QuadPart, HandleToUlong(FltGetRequestorProcessIdEx(Data)), &FltObjects->FileObject->FileName, Data->IoStatus.Status);
        }
        CommSendString(&message);

    cleanup_and_exit:
        ExFreePoolWithTag(message.Buffer, UTILS_TAG_UNICODE_STRING);
    }
    return FLT_POSTOP_FINISHED_PROCESSING;
}
FLT_PREOP_CALLBACK_STATUS
MyFilterPreOperationReadWriteSynchronize(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{
    UNREFERENCED_PARAMETER(FltObjects);

    PFILE_CONTEXT_RW context = ExAllocatePoolWithTag(PagedPool, sizeof(FILE_CONTEXT_RW), 'FILE');
    if (!context) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    context->isRead = (Data->Iopb->MajorFunction == IRP_MJ_READ);
    context->bytesToRW = context->isRead ? Data->Iopb->Parameters.Read.Length : Data->Iopb->Parameters.Write.Length;
    context->Pid = FltGetRequestorProcessIdEx(Data);
    context->Offset = context->isRead ? Data->Iopb->Parameters.Read.ByteOffset : Data->Iopb->Parameters.Write.ByteOffset;

    *CompletionContext = context;
    return FLT_PREOP_SYNCHRONIZE;
}

FLT_POSTOP_CALLBACK_STATUS
MyFilterPostReadWriteSafe(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    if (!(gDrv.NotificationType == FileType)) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    PFILE_CONTEXT_RW context = (PFILE_CONTEXT_RW)CompletionContext;
    if (!context) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    UNICODE_STRING message;
    ULONG32 msgSize = 4 * PAGE_SIZE;
    message.Buffer = ExAllocatePoolWithTag(PagedPool, msgSize, UTILS_TAG_UNICODE_STRING);
    if (!message.Buffer)
    {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
    message.MaximumLength = 4 * PAGE_SIZE;
    message.Length = 0;

    LARGE_INTEGER timestamp = { 0 };
    KeQuerySystemTime(&timestamp);

    PFLT_FILE_NAME_INFORMATION fileNameInfo;
    NTSTATUS status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &fileNameInfo);
    if (!NT_SUCCESS(status)) {
        LogInfo("MyFilter!MyFilterPostOperation: Entered. Pid = 0x%X",
            HandleToUlong(FltGetRequestorProcessIdEx(Data)));
        ExFreePoolWithTag(message.Buffer, UTILS_TAG_UNICODE_STRING);
    }
    else {
        if (context->isRead) {
            RtlUnicodeStringPrintf(&message,
                L"[%llu] [FileRead] [PID: %p] [Path: %wZ] [BytesToRead: %d] [Offset: %I64d] [BytesRead: %d] [IRQLLVL: %d] [Status: %X]",
                timestamp.QuadPart, HandleToUlong(FltGetRequestorProcessIdEx(Data)), &fileNameInfo->Name, context->bytesToRW, context->Offset.QuadPart,
                Data->Iopb->Parameters.Read.Length, (ULONG)KeGetCurrentIrql(), Data->IoStatus.Status);
        }
        else {
            RtlUnicodeStringPrintf(&message,
                L"[%llu] [FileWrite] [PID: %p] [Path: %wZ] [BytesToWrite: %d] [Offset: %I64d] [BytesWritten: %d]  [IRQLLVL: %d] [Status: %X]",
                timestamp.QuadPart, HandleToUlong(FltGetRequestorProcessIdEx(Data)), &fileNameInfo->Name, context->bytesToRW, context->Offset.QuadPart,
                Data->Iopb->Parameters.Write.Length, (ULONG)KeGetCurrentIrql(), Data->IoStatus.Status);
        }

        FltReleaseFileNameInformation(fileNameInfo);

        CommSendString(&message);
        ExFreePoolWithTag(message.Buffer, UTILS_TAG_UNICODE_STRING);
    }

    ExFreePoolWithTag(context, 'FILE');
    return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_POSTOP_CALLBACK_STATUS
MyFilterPostReadWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
)
{
    if (Flags & FLTFL_POST_OPERATION_DRAINING) {
        if (CompletionContext) {
            ExFreePoolWithTag(CompletionContext, 'FILE');
        }
        UNICODE_STRING message;
        ULONG32 msgSize = 4 * PAGE_SIZE;
        message.Buffer = ExAllocatePoolWithTag(PagedPool, msgSize, UTILS_TAG_UNICODE_STRING);
        if (!message.Buffer)
        {
            return FLT_POSTOP_FINISHED_PROCESSING;
        }
        message.MaximumLength = 4 * PAGE_SIZE;
        message.Length = 0;

        LARGE_INTEGER timestamp = { 0 };
        KeQuerySystemTime(&timestamp);
        RtlUnicodeStringPrintf(&message,
            L"[%llu] [FileDraining] [PID: %p] [IRQLLVL: %d]",
            timestamp.QuadPart, HandleToULong(FltGetRequestorProcessIdEx(Data)), (ULONG)KeGetCurrentIrql());
        CommSendString(&message);
        ExFreePoolWithTag(message.Buffer, UTILS_TAG_UNICODE_STRING);

        return FLT_POSTOP_FINISHED_PROCESSING;
    }
    FLT_POSTOP_CALLBACK_STATUS status;
    BOOLEAN ret = FltDoCompletionProcessingWhenSafe(Data, FltObjects, CompletionContext, Flags, MyFilterPostReadWriteSafe, &status);
    if (ret) {
        return status;
    }
    if (CompletionContext) {
        ExFreePoolWithTag(CompletionContext, 'FILE');
    }
    return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_PREOP_CALLBACK_STATUS
MyFilterPreOperationSetAttributesSynchronize(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{
    UNREFERENCED_PARAMETER(FltObjects);

    PFILE_CONTEXT_SET_INFORMATION context = ExAllocatePoolWithTag(PagedPool, sizeof(FILE_CONTEXT_SET_INFORMATION), 'FILE');
    if (!context) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    
    FILE_INFORMATION_CLASS infoClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;

    switch (infoClass) {
    case FileRenameInformation: //rename
        context->newName = ((PFILE_RENAME_INFORMATION)Data->Iopb->Parameters.SetFileInformation.InfoBuffer)->FileName;
        context->oldName.Length = FltObjects->FileObject->FileName.Length;
        context->oldName.MaximumLength = FltObjects->FileObject->FileName.Length;
        context->oldName.Buffer = ExAllocatePoolWithTag(PagedPool, context->oldName.Length, UTILS_TAG_UNICODE_STRING);
        RtlCopyUnicodeString(&context->oldName, &FltObjects->FileObject->FileName);
        break;
    case FileDispositionInformation://delete
        context->oldName.Length = FltObjects->FileObject->FileName.Length;
        context->oldName.MaximumLength = FltObjects->FileObject->FileName.Length;
        context->oldName.Buffer = ExAllocatePoolWithTag(PagedPool, context->oldName.Length, UTILS_TAG_UNICODE_STRING);
        RtlCopyUnicodeString(&context->oldName, &FltObjects->FileObject->FileName);
        break;
    case FileAllocationInformation:
        context->oldName.Length = FltObjects->FileObject->FileName.Length;
        context->oldName.MaximumLength = FltObjects->FileObject->FileName.Length;
        context->oldName.Buffer = ExAllocatePoolWithTag(PagedPool, context->oldName.Length, UTILS_TAG_UNICODE_STRING);
        RtlCopyUnicodeString(&context->oldName, &FltObjects->FileObject->FileName);
        if (Data->Iopb->Parameters.SetFileInformation.InfoBuffer != NULL &&
            Data->Iopb->Parameters.SetFileInformation.Length >= sizeof(FILE_ALLOCATION_INFORMATION))
        {
            PFILE_ALLOCATION_INFORMATION allocationInfo = (PFILE_ALLOCATION_INFORMATION)Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
            context->allocationSize = allocationInfo->AllocationSize.QuadPart;
        }

    }
    *CompletionContext = context;
    return FLT_PREOP_SYNCHRONIZE;
}
FLT_POSTOP_CALLBACK_STATUS
MyFilterPostSetInformation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
) {
    //UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    //UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);
    if (!(gDrv.NotificationType == FileType)) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
    PFILE_CONTEXT_SET_INFORMATION context = CompletionContext;
    if (context == NULL) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
    FILE_INFORMATION_CLASS infoClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;

    UNICODE_STRING message;
    ULONG32 msgSize = 4 * PAGE_SIZE;
    message.Buffer = ExAllocatePoolWithTag(PagedPool, msgSize, UTILS_TAG_UNICODE_STRING);
    if (!message.Buffer)
    {
        goto cleanup_and_exit;
    }
    message.MaximumLength = 4 * PAGE_SIZE;
    message.Length = 0;

    LARGE_INTEGER timestamp = { 0 };
    KeQuerySystemTime(&timestamp);

    switch (infoClass) {
    case FileRenameInformation:
        RtlUnicodeStringPrintf(&message,
            L"[%llu] [PostFileRename] [PID: %p] [FileName: %wZ] [NewName:%s] [Status: %X]",
            timestamp.QuadPart, HandleToUlong(FltGetRequestorProcessIdEx(Data)), context->oldName, context->newName, Data->IoStatus.Status);
        break;
    case FileDispositionInformation://delete
        RtlUnicodeStringPrintf(&message,
            L"[%llu] [PostFileDelete] [PID: %p] [FileName: %wZ] [Status: %X]",
            timestamp.QuadPart, HandleToUlong(FltGetRequestorProcessIdEx(Data)), context->oldName, Data->IoStatus.Status);
        break;
    case FileAllocationInformation:
        RtlUnicodeStringPrintf(&message,
            L"[%llu] [PostFileAllocationInfo] [PID: %p] [FileName: %wZ] [AllocationSize: %llu] [Status: %X]",
            timestamp.QuadPart, HandleToUlong(FltGetRequestorProcessIdEx(Data)), context->oldName, context->allocationSize, Data->IoStatus.Status);
        break;
    default:
        RtlUnicodeStringPrintf(&message,
            L"[%llu] [PostFileDefaultSetInfo] [PID: %p] [FileName: %wZ]  [Status: %X]",
            timestamp.QuadPart, HandleToUlong(FltGetRequestorProcessIdEx(Data)), &FltObjects->FileObject->FileName,Data->IoStatus.Status);
    }
    CommSendString(&message);

cleanup_and_exit:
    ExFreePoolWithTag(message.Buffer, UTILS_TAG_UNICODE_STRING);
    return FLT_POSTOP_FINISHED_PROCESSING;

}