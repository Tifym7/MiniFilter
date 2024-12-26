//
//   Author(s)    : Radu PORTASE(rportase@bitdefender.com)
//
#include "registry_filter.h"
#include "communication.h"
#include "communication_protocol.h"
#include "trace.h"
#include "registry_filter.tmh"
#include <ntstrsafe.h>
#include "utils.h"


#pragma warning( disable: 4996 )

// pentru a implementa functiile am folosit drept model implementarile de pe teams


typedef struct _REG_CONTEXT
{
    PUNICODE_STRING Old;
    PUNICODE_STRING KeyName;
    UNICODE_STRING New;
    
    HANDLE Pid;
} REG_CONTEXT, * PREG_CONTEXT;

#define POOL_TAG_REG_CONTEXT '#GER'


 // apucasem sa fac astea si dupa mi-am amintit ca precreate era comentat 
NTSTATUS PreCreateKey(
    _In_ PREG_CREATE_KEY_INFORMATION Info
) {
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    PREG_CONTEXT context = NULL;

    context = ExAllocatePoolWithTag(PagedPool, sizeof(*context), POOL_TAG_REG_CONTEXT);
    if (context == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto cleanup_and_exit;
    }
    context->Old = NULL; // For key creation, there's no old name
    context->New.Length = Info->CompleteName->Length;
    context->New.MaximumLength = Info->CompleteName->Length;
    RtlCopyUnicodeString(&context->New, Info->CompleteName);

    Info->CallContext = context;
    status = STATUS_SUCCESS;
cleanup_and_exit:
    if (!NT_SUCCESS(status)) {
        if (context != NULL) {
            if (context->New.Buffer != NULL) {
                ExFreePoolWithTag(context->New.Buffer, UTILS_TAG_UNICODE_STRING);
            }
            ExFreePoolWithTag(context, POOL_TAG_REG_CONTEXT);
        }
    }

    return status;
}


NTSTATUS PostCreateKey(
    _In_ PREG_POST_OPERATION_INFORMATION Info
) {
    PREG_CONTEXT context = Info->CallContext;
    if (context == NULL) {
        return STATUS_CONTEXT_MISMATCH;
    }


    // Log information
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "[Registry create key] ProcessID = %llu, Key Name = %wZ\n",
        HandleToULong(context->Pid), &context->New
    );

    if (context->New.Buffer != NULL) {
        ExFreePoolWithTag(context->New.Buffer, UTILS_TAG_UNICODE_STRING);
    }
    ExFreePoolWithTag(context, POOL_TAG_REG_CONTEXT);

    return STATUS_SUCCESS;
}

NTSTATUS PostCreateKeyWithoutContext(
    _In_ PREG_POST_CREATE_KEY_INFORMATION Info
) {
  
    UNICODE_STRING message;
    ULONG32 msgSize = 4 * PAGE_SIZE;
    message.Buffer = ExAllocatePoolWithTag(PagedPool, msgSize, UTILS_TAG_UNICODE_STRING);
    if (!message.Buffer)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    message.MaximumLength = 4 * PAGE_SIZE;
    message.Length = 0;

    LARGE_INTEGER timestamp = { 0 };
    KeQuerySystemTime(&timestamp);

    RtlUnicodeStringPrintf(&message, L"[%llu] [Registry create key] inside Process: [PID:%p] [KeyName: %wZ]\n", timestamp.QuadPart, HandleToUlong(PsGetCurrentProcessId()),Info->CompleteName);


    CommSendString(&message);
    ExFreePoolWithTag(message.Buffer, UTILS_TAG_UNICODE_STRING);

    return STATUS_SUCCESS;
}


NTSTATUS
PreSetValue(
    _In_ PREG_SET_VALUE_KEY_INFORMATION Info
)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    PREG_CONTEXT context = NULL;

    context = ExAllocatePoolWithTag(PagedPool, sizeof(*context), POOL_TAG_REG_CONTEXT);
    if (context == NULL)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto cleanup_and_exit;
    }

    RtlZeroMemory(context, sizeof(*context));

    context->New.Buffer = ExAllocatePoolWithTag(PagedPool, Info->ValueName->Length, UTILS_TAG_UNICODE_STRING); // aici salvez valoarea setata
    if (context->New.Buffer == NULL)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto cleanup_and_exit;
    }
    context->New.Length = Info->ValueName->Length;
    context->New.MaximumLength = Info->ValueName->Length;
    RtlCopyUnicodeString(&context->New, Info->ValueName);
    context->Pid = PsGetCurrentProcessId();

    status = CmCallbackGetKeyObjectIDEx(
        &gDrv.RegistryCookie,
        Info->Object,
        NULL,
        &context->Old, // aici sa o salvez key name
        0
    );
    if (!NT_SUCCESS(status)) {
        goto cleanup_and_exit;
    }


    Info->CallContext = context;

    status = STATUS_SUCCESS;

cleanup_and_exit:
    if (!NT_SUCCESS(status))
    {
        if (context != NULL)
        {
            if (context->Old != NULL)
            {
                ExFreePoolWithTag(context->Old, POOL_TAG_REG_CONTEXT);
            }
            ExFreePoolWithTag(context, POOL_TAG_REG_CONTEXT);
        }
    }
    return status;
}

NTSTATUS
PostSetValue(
    _In_ PREG_POST_OPERATION_INFORMATION Info
)
{
    PREG_CONTEXT context = NULL;
    context = Info->CallContext;
    if (context == NULL)
    {
        return STATUS_CONTEXT_MISMATCH;
    }

    UNICODE_STRING message;
    ULONG32 msgSize = 4 * PAGE_SIZE;
    message.Buffer = ExAllocatePoolWithTag(PagedPool, msgSize, UTILS_TAG_UNICODE_STRING);
    if (!message.Buffer)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    message.MaximumLength = 4 * PAGE_SIZE;
    message.Length = 0;

    LARGE_INTEGER timestamp = { 0 };
    KeQuerySystemTime(&timestamp);

    RtlUnicodeStringPrintf(&message, L"[%llu] [RegistrySetValue] inside Process: [PID:%p] [KeyName: %wZ] [NewValue:%wZ]\n", timestamp.QuadPart, HandleToUlong(PsGetCurrentProcessId()), context->Old, &context->New);


    CommSendString(&message);
    ExFreePoolWithTag(message.Buffer, UTILS_TAG_UNICODE_STRING);

   

    // Free allocated resources
    if (context->New.Buffer!= NULL)
    {
        ExFreePoolWithTag(context->Old, POOL_TAG_REG_CONTEXT);
    }
    ExFreePoolWithTag(context, POOL_TAG_REG_CONTEXT);

    return STATUS_SUCCESS;
}



NTSTATUS PreRenameKey(
    _In_ PREG_RENAME_KEY_INFORMATION Info
) {

    NTSTATUS status = STATUS_UNSUCCESSFUL;
    PREG_CONTEXT context = NULL;


    context = ExAllocatePoolWithTag(PagedPool, sizeof(*context), POOL_TAG_REG_CONTEXT);
    if (context == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto cleanup_and_exit;
    }
    status = CmCallbackGetKeyObjectIDEx(
        &gDrv.RegistryCookie,
        Info->Object,
        NULL,
        &context->Old,
        0
    );
    if (!NT_SUCCESS(status)) {
        goto cleanup_and_exit;
    }

    context->New.Length = Info->NewName->Length;
    context->New.MaximumLength = Info->NewName->Length;
    context->New.Buffer = ExAllocatePoolWithTag(PagedPool, context->New.Length, UTILS_TAG_UNICODE_STRING);
    if (context->New.Buffer == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto cleanup_and_exit;
    }
    RtlCopyUnicodeString(&context->New, Info->NewName);
    context->Pid = PsGetCurrentProcessId();

    Info->CallContext = context;
    status = STATUS_SUCCESS;

cleanup_and_exit:
    if (!NT_SUCCESS(status))
    {
        if (context != NULL)
        {
            if (context->New.Buffer == NULL)
            {
                ExFreePoolWithTag(context->New.Buffer, UTILS_TAG_UNICODE_STRING);
            }

            if (context->Old != NULL)
            {
                CmCallbackReleaseKeyObjectIDEx(context->Old);
            }

            ExFreePoolWithTag(context, POOL_TAG_REG_CONTEXT);
        }
    }

    return status;
}

NTSTATUS
PostRenameKey(
    _In_ PREG_POST_OPERATION_INFORMATION Info
)
{
    PREG_CONTEXT context = NULL;
    context = Info->CallContext;
    if (context == NULL)
    {
        return STATUS_CONTEXT_MISMATCH;
    }

    UNICODE_STRING message;
    ULONG32 msgSize = 4 * PAGE_SIZE;
    message.Buffer = ExAllocatePoolWithTag(PagedPool, msgSize, UTILS_TAG_UNICODE_STRING);
    if (!message.Buffer)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
        
    }
    message.MaximumLength = 4 * PAGE_SIZE;
    message.Length = 0;

    LARGE_INTEGER timestamp = { 0 };
    KeQuerySystemTime(&timestamp);

    RtlUnicodeStringPrintf(&message, L"[%llu] [Registry rename] Status = %d [PID:%p], Old name = %wZ, New name = %wZ\n", timestamp.QuadPart, Info->Status,context->Pid,
        context->Old,
        &context->New);

    CommSendString(&message);
    ExFreePoolWithTag(message.Buffer, UTILS_TAG_UNICODE_STRING);
    ExFreePoolWithTag(context->New.Buffer, UTILS_TAG_UNICODE_STRING);
    CmCallbackReleaseKeyObjectIDEx(context->Old);
    ExFreePoolWithTag(context, POOL_TAG_REG_CONTEXT);

    return STATUS_SUCCESS;
}

NTSTATUS
PreDeleteKey(
    _In_ PREG_DELETE_KEY_INFORMATION Info
)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    PREG_CONTEXT context = NULL;

    context = ExAllocatePoolWithTag(PagedPool, sizeof(*context), POOL_TAG_REG_CONTEXT);
    if (context == NULL)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto cleanup_and_exit;
    }

    RtlZeroMemory(context, sizeof(*context));

    status = CmCallbackGetKeyObjectIDEx(
        &gDrv.RegistryCookie,
        Info->Object,
        NULL,
        &context->Old, // aici sa o salvez key name
        0
    );
    //am salvat aici ce key s-a sters
    if (!NT_SUCCESS(status))
    {
        goto cleanup_and_exit;
    }
    context->Pid = PsGetCurrentProcessId();

    Info->CallContext = context;

    status = STATUS_SUCCESS;

cleanup_and_exit:
    if (!NT_SUCCESS(status))
    {
        if (context != NULL)
        {
            ExFreePoolWithTag(context, POOL_TAG_REG_CONTEXT);
        }
    }
    return status;
}

NTSTATUS
PostDeleteKey(
    _In_ PREG_POST_OPERATION_INFORMATION Info
)
{
    PREG_CONTEXT context = NULL;
    context = Info->CallContext;
    if (context == NULL)
    {
        return STATUS_CONTEXT_MISMATCH;
    }

    UNICODE_STRING message;
    ULONG32 msgSize = 4 * PAGE_SIZE;
    message.Buffer = ExAllocatePoolWithTag(PagedPool, msgSize, UTILS_TAG_UNICODE_STRING);
    if (!message.Buffer)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    message.MaximumLength = 4 * PAGE_SIZE;
    message.Length = 0;

    LARGE_INTEGER timestamp = { 0 };
    KeQuerySystemTime(&timestamp);

    RtlUnicodeStringPrintf(&message, L"[% llu][RegistryDeleteKey] inside Process : [PID:% p] [KeyName:% wZ] [Status:% 08X] \n", timestamp.QuadPart, HandleToUlong(context->Pid), context->Old,Info->Status);


    CommSendString(&message);
    ExFreePoolWithTag(message.Buffer, UTILS_TAG_UNICODE_STRING);

  
 
    ExFreePoolWithTag(context, POOL_TAG_REG_CONTEXT);

    return STATUS_SUCCESS;
}
NTSTATUS
PreDeleteValue(
    _In_ PREG_DELETE_VALUE_KEY_INFORMATION Info
)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    PREG_CONTEXT context = NULL;

    context = ExAllocatePoolWithTag(PagedPool, sizeof(*context), POOL_TAG_REG_CONTEXT);
    if (context == NULL)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto cleanup_and_exit;
    }

    RtlZeroMemory(context, sizeof(*context));

    status = CmCallbackGetKeyObjectIDEx(&gDrv.RegistryCookie, Info->Object, NULL, &context->KeyName, 0);
    if (!NT_SUCCESS(status))
    {
        goto cleanup_and_exit;
    }

    context->New.Length = Info->ValueName->Length;
    context->New.MaximumLength = Info->ValueName->Length;
    context->New.Buffer = ExAllocatePoolWithTag(PagedPool, context->New.Length, UTILS_TAG_UNICODE_STRING);
    if (context->New.Buffer == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto cleanup_and_exit;
    }
    RtlCopyUnicodeString(&context->New, Info->ValueName);
    
    context->Pid = PsGetCurrentProcessId();

    Info->CallContext = context;

    status = STATUS_SUCCESS;

cleanup_and_exit:
    if (!NT_SUCCESS(status))
    {
        if (context != NULL)
        {
            if (context->New.Buffer == NULL)
            {
                ExFreePoolWithTag(context->New.Buffer, UTILS_TAG_UNICODE_STRING);
            }
            ExFreePoolWithTag(context, POOL_TAG_REG_CONTEXT);
        }
    }
    return status;
}

NTSTATUS
PostDeleteValue(
    _In_ PREG_POST_OPERATION_INFORMATION Info
)
{
    PREG_CONTEXT context = NULL;
    context = Info->CallContext;
    if (context == NULL)
    {
        return STATUS_CONTEXT_MISMATCH;
    }



    UNICODE_STRING message;
    ULONG32 msgSize = 4 * PAGE_SIZE;
    message.Buffer = ExAllocatePoolWithTag(PagedPool, msgSize, UTILS_TAG_UNICODE_STRING);
    if (!message.Buffer)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    message.MaximumLength = 4 * PAGE_SIZE;
    message.Length = 0;

    LARGE_INTEGER timestamp = { 0 };
    KeQuerySystemTime(&timestamp);

    RtlUnicodeStringPrintf(&message, L"[% llu][RegistryDeleteValue] inside Process : [PID:% p] [KeyName:% wZ] [DeletedValue: %wz] [Status:% 08X]\n", timestamp.QuadPart, HandleToUlong(context->Pid), context->KeyName, context->New, Info->Status);


    CommSendString(&message);
    ExFreePoolWithTag(message.Buffer, UTILS_TAG_UNICODE_STRING);

    if (context->New.Buffer != NULL)
    {
        ExFreePoolWithTag(context->New.Buffer, POOL_TAG_REG_CONTEXT);
    }
    ExFreePoolWithTag(context, POOL_TAG_REG_CONTEXT);

    return STATUS_SUCCESS;
}


NTSTATUS
PreLoadKey(
    _In_ PREG_LOAD_KEY_INFORMATION Info
)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    PREG_CONTEXT context = NULL;

    context = ExAllocatePoolWithTag(PagedPool, sizeof(*context), POOL_TAG_REG_CONTEXT);
    if (context == NULL)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto cleanup_and_exit;
    }

    RtlZeroMemory(context, sizeof(*context));

    context->KeyName->Length = Info->KeyName->Length;
    context->KeyName->MaximumLength = Info->KeyName->Length;
    context->KeyName->Buffer = ExAllocatePoolWithTag(PagedPool, context->New.Length, UTILS_TAG_UNICODE_STRING);
    if (context->KeyName->Buffer == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto cleanup_and_exit;
    }
    RtlCopyUnicodeString(&context->New, Info->KeyName);

    context->New.Length = Info->SourceFile->Length;
    context->New.MaximumLength = Info->SourceFile->Length;
    context->New.Buffer = ExAllocatePoolWithTag(PagedPool, context->New.Length, UTILS_TAG_UNICODE_STRING);
    if (context->New.Buffer == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto cleanup_and_exit;
    }
    RtlCopyUnicodeString(&context->New, Info->SourceFile);
    context->Pid = PsGetCurrentProcessId();

    Info->CallContext = context;

    status = STATUS_SUCCESS;

cleanup_and_exit:
    if (!NT_SUCCESS(status))
    {
        if (context != NULL)
        {
            if (context->KeyName != NULL)
            {
                ExFreePoolWithTag(context->KeyName, POOL_TAG_REG_CONTEXT);
            }
            ExFreePoolWithTag(context, POOL_TAG_REG_CONTEXT);
        }
    }
    return status;
}

NTSTATUS
PostLoadKey(
    _In_ PREG_POST_OPERATION_INFORMATION Info
)
{
    PREG_CONTEXT context = NULL;
    context = Info->CallContext;
    if (context == NULL)
    {
        return STATUS_CONTEXT_MISMATCH;
    }

    UNICODE_STRING message;
    ULONG32 msgSize = 4 * PAGE_SIZE;
    message.Buffer = ExAllocatePoolWithTag(PagedPool, msgSize, UTILS_TAG_UNICODE_STRING);
    if (!message.Buffer)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    message.MaximumLength = 4 * PAGE_SIZE;
    message.Length = 0;

    LARGE_INTEGER timestamp = { 0 };
    KeQuerySystemTime(&timestamp);

    RtlUnicodeStringPrintf(&message, L"[% llu][RegistryLoadKey] inside Process : [PID:% p] [Status:% 08X] [KeyName:% wZ] [SourceFile: %wz] \n", timestamp.QuadPart, HandleToUlong(PsGetCurrentProcessId()), Info->Status, context->KeyName,context->New );


    CommSendString(&message);
    ExFreePoolWithTag(message.Buffer, UTILS_TAG_UNICODE_STRING);


    if (context->KeyName != NULL)
    {
        ExFreePoolWithTag(context->KeyName, POOL_TAG_REG_CONTEXT);
    }
    if (context->New.Buffer != NULL)
    {
        ExFreePoolWithTag(context->New.Buffer, POOL_TAG_REG_CONTEXT);
    }
    ExFreePoolWithTag(context, POOL_TAG_REG_CONTEXT);

    return STATUS_SUCCESS;
}


//
// Registry notification
//
NTSTATUS
CmRegistryCallback(
    _In_     PVOID CallbackContext,
    _In_opt_ PVOID Argument1,
    _In_opt_ PVOID Argument2
)
/*++
    Class                            ||  Structure:
    ===============================================================
    RegNtDeleteKey                   ||  REG_DELETE_KEY_INFORMATION
    RegNtPreDeleteKey                ||  REG_DELETE_KEY_INFORMATION
    RegNtPostDeleteKey               ||  REG_POST_OPERATION_INFORMATION
    RegNtSetValueKey                 ||  REG_SET_VALUE_KEY_INFORMATION
    RegNtPreSetValueKey              ||  REG_SET_VALUE_KEY_INFORMATION
    RegNtPostSetValueKey             ||  REG_POST_OPERATION_INFORMATION
    RegNtDeleteValueKey              ||  REG_DELETE_VALUE_KEY_INFORMATION
    RegNtPreDeleteValueKey           ||  REG_DELETE_VALUE_KEY_INFORMATION
    RegNtPostDeleteValueKey          ||  REG_POST_OPERATION_INFORMATION
    RegNtSetInformationKey           ||  REG_SET_INFORMATION_KEY_INFORMATION
    RegNtPreSetInformationKey        ||  REG_SET_INFORMATION_KEY_INFORMATION
    RegNtPostSetInformationKey       ||  REG_POST_OPERATION_INFORMATION
    RegNtRenameKey                   ||  REG_RENAME_KEY_INFORMATION
    RegNtPreRenameKey                ||  REG_RENAME_KEY_INFORMATION
    RegNtPostRenameKey               ||  REG_POST_OPERATION_INFORMATION
    RegNtEnumerateKey                ||  REG_ENUMERATE_KEY_INFORMATION
    RegNtPreEnumerateKey             ||  REG_ENUMERATE_KEY_INFORMATION
    RegNtPostEnumerateKey            ||  REG_POST_OPERATION_INFORMATION
    RegNtEnumerateValueKey           ||  REG_ENUMERATE_VALUE_KEY_INFORMATION
    RegNtPreEnumerateValueKey        ||  REG_ENUMERATE_VALUE_KEY_INFORMATION
    RegNtPostEnumerateValueKey       ||  REG_POST_OPERATION_INFORMATION
    RegNtQueryKey                    ||  REG_QUERY_KEY_INFORMATION
    RegNtPreQueryKey                 ||  REG_QUERY_KEY_INFORMATION
    RegNtPostQueryKey                ||  REG_POST_OPERATION_INFORMATION
    RegNtQueryValueKey               ||  REG_QUERY_VALUE_KEY_INFORMATION
    RegNtPreQueryValueKey            ||  REG_QUERY_VALUE_KEY_INFORMATION
    RegNtPostQueryValueKey           ||  REG_POST_OPERATION_INFORMATION
    RegNtQueryMultipleValueKey       ||  REG_QUERY_MULTIPLE_VALUE_KEY_INFORMATION
    RegNtPreQueryMultipleValueKey    ||  REG_QUERY_MULTIPLE_VALUE_KEY_INFORMATION
    RegNtPostQueryMultipleValueKey   ||  REG_POST_OPERATION_INFORMATION
    RegNtPreCreateKey                ||  REG_PRE_CREATE_KEY_INFORMATION
    RegNtPreCreateKeyEx              ||  REG_CREATE_KEY_INFORMATION**
    RegNtPostCreateKey               ||  REG_POST_CREATE_KEY_INFORMATION
    RegNtPostCreateKeyEx             ||  REG_POST_OPERATION_INFORMATION
    RegNtPreOpenKey                  ||  REG_PRE_OPEN_KEY_INFORMATION**
    RegNtPreOpenKeyEx                ||  REG_OPEN_KEY_INFORMATION
    RegNtPostOpenKey                 ||  REG_POST_OPEN_KEY_INFORMATION
    RegNtPostOpenKeyEx               ||  REG_POST_OPERATION_INFORMATION
    RegNtKeyHandleClose              ||  REG_KEY_HANDLE_CLOSE_INFORMATION
    RegNtPreKeyHandleClose           ||  REG_KEY_HANDLE_CLOSE_INFORMATION
    RegNtPostKeyHandleClose          ||  REG_POST_OPERATION_INFORMATION
    RegNtPreFlushKey                 ||  REG_FLUSH_KEY_INFORMATION
    RegNtPostFlushKey                ||  REG_POST_OPERATION_INFORMATION
    RegNtPreLoadKey                  ||  REG_LOAD_KEY_INFORMATION
    RegNtPostLoadKey                 ||  REG_POST_OPERATION_INFORMATION
    RegNtPreUnLoadKey                ||  REG_UNLOAD_KEY_INFORMATION
    RegNtPostUnLoadKey               ||  REG_POST_OPERATION_INFORMATION
    RegNtPreQueryKeySecurity         ||  REG_QUERY_KEY_SECURITY_INFORMATION
    RegNtPostQueryKeySecurity        ||  REG_POST_OPERATION_INFORMATION
    RegNtPreSetKeySecurity           ||  REG_SET_KEY_SECURITY_INFORMATION
    RegNtPostSetKeySecurity          ||  REG_POST_OPERATION_INFORMATION
    RegNtCallbackObjectContextCleanup||  REG_CALLBACK_CONTEXT_CLEANUP_INFORMATION
    RegNtPreRestoreKey               ||  REG_RESTORE_KEY_INFORMATION
    RegNtPostRestoreKey              ||  REG_RESTORE_KEY_INFORMATION
    RegNtPreSaveKey                  ||  REG_SAVE_KEY_INFORMATION
    RegNtPostSaveKey                 ||  REG_SAVE_KEY_INFORMATION
    RegNtPreReplaceKey               ||  REG_REPLACE_KEY_INFORMATION
    RegNtPostReplaceKey              ||  REG_REPLACE_KEY_INFORMATION
    RegNtPostCreateKeyEx             ||  REG_POST_OPERATION_INFORMATION
--*/
{
    UNREFERENCED_PARAMETER(CallbackContext); // not using a context yet

    REG_NOTIFY_CLASS regNotifyClass = (REG_NOTIFY_CLASS)(SIZE_T)Argument1;
    PVOID pParameters = Argument2;
    PVOID object = NULL;

    if (!(gDrv.NotificationType == RegistryType))
    {
        return STATUS_SUCCESS;
    }

    switch (regNotifyClass)
    {
    case RegNtPreSetValueKey:
        PreSetValue((PREG_SET_VALUE_KEY_INFORMATION)pParameters);
        break;
    case RegNtPostSetValueKey:
        PostSetValue((PREG_POST_OPERATION_INFORMATION)pParameters);
        break;
    case RegNtPreDeleteValueKey:
        PreDeleteValue((PREG_DELETE_VALUE_KEY_INFORMATION)pParameters);
        break;
    case RegNtPostDeleteValueKey:
        PostDeleteValue((PREG_POST_OPERATION_INFORMATION)pParameters);
        break;
    case RegNtPreDeleteKey:
        PreDeleteKey((PREG_DELETE_KEY_INFORMATION)pParameters);
        break;
    case RegNtPostDeleteKey:
        PostDeleteKey((PREG_POST_OPERATION_INFORMATION)pParameters);
        break;
    case RegNtPostLoadKey:
        object = ((PREG_POST_OPERATION_INFORMATION)pParameters)->Object;
        break;
    case RegNtPostUnLoadKey:
        object = ((PREG_POST_OPERATION_INFORMATION)pParameters)->Object;
        break;
    case RegNtPreRenameKey:
        PreRenameKey((PREG_RENAME_KEY_INFORMATION)pParameters);
        break;
    case RegNtPostRenameKey:
        PostRenameKey((PREG_POST_OPERATION_INFORMATION)pParameters);
        break;
    case RegNtPostQueryValueKey:
        object = ((PREG_POST_OPERATION_INFORMATION)pParameters)->Object;
        break;
    case RegNtPostCreateKeyEx:
        object = ((PREG_POST_OPERATION_INFORMATION)pParameters)->Object;
        PostCreateKey((PREG_POST_OPERATION_INFORMATION)pParameters);
        break;
    case RegNtPostOpenKeyEx:
        object = ((PREG_POST_OPERATION_INFORMATION)pParameters)->Object;
        break;
    case RegNtPreSaveKey:
        object = ((PREG_SAVE_KEY_INFORMATION)pParameters)->Object;
        break;

    case RegNtPostSaveKey:
        object = ((PREG_POST_OPERATION_INFORMATION)pParameters)->Object;

        break;
    case RegNtPreQueryValueKey:
        object = ((PREG_QUERY_VALUE_KEY_INFORMATION)pParameters)->Object;
        break;
    case RegNtPreCreateKey:
        // object = ((PREG_PRE_CREATE_KEY_INFORMATION)pParameters)->Object;
        // object is not created yet
        break;
    case RegNtPreCreateKeyEx:
        // object = ((PREG_CREATE_KEY_INFORMATION)pParameters)->Object;
        // object is not created yet
        break;
    case RegNtPostCreateKey:
        PostCreateKeyWithoutContext((PREG_POST_CREATE_KEY_INFORMATION)pParameters);
        break;
    case RegNtPreSetInformationKey:
        object = ((PREG_SET_INFORMATION_KEY_INFORMATION)pParameters)->Object;
        break;
    case RegNtPostSetInformationKey:
        object = ((PREG_POST_OPERATION_INFORMATION)pParameters)->Object;
        break;
    case RegNtPreEnumerateKey:
        object = ((PREG_ENUMERATE_KEY_INFORMATION)pParameters)->Object;
        break;
    case RegNtPostEnumerateKey:
        object = ((PREG_POST_OPERATION_INFORMATION)pParameters)->Object;
        break;
    case RegNtPreEnumerateValueKey:
        object = ((PREG_ENUMERATE_VALUE_KEY_INFORMATION)pParameters)->Object;
        break;
    case RegNtPostEnumerateValueKey:
        object = ((PREG_POST_OPERATION_INFORMATION)pParameters)->Object;
        break;
    case RegNtPreQueryKey:
        object = ((PREG_QUERY_KEY_INFORMATION)pParameters)->Object;
        break;
    case RegNtPostQueryKey:
        object = ((PREG_POST_OPERATION_INFORMATION)pParameters)->Object;
        break;
    case RegNtPreQueryMultipleValueKey:
        object = ((PREG_QUERY_MULTIPLE_VALUE_KEY_INFORMATION)pParameters)->Object;
        break;
    case RegNtPostQueryMultipleValueKey:
        object = ((PREG_POST_OPERATION_INFORMATION)pParameters)->Object;
        break;
    case RegNtPreOpenKey:
        // object = ((PREG_PRE_OPEN_KEY_INFORMATION)pParameters)->Object;
        // object is not created yet
        break;
    case RegNtPreOpenKeyEx:
        // object = ((PREG_OPEN_KEY_INFORMATION)pParameters)->Object;
        // object is not created yet
        break;
    case RegNtPostOpenKey:
        object = ((PREG_POST_OPEN_KEY_INFORMATION)pParameters)->Object;
        break;
    case RegNtPreKeyHandleClose:
        object = ((PREG_KEY_HANDLE_CLOSE_INFORMATION)pParameters)->Object;
        break;
    case RegNtPostKeyHandleClose:
        object = ((PREG_POST_OPERATION_INFORMATION)pParameters)->Object;
        break;
    case RegNtPreFlushKey:
        object = ((PREG_FLUSH_KEY_INFORMATION)pParameters)->Object;
        break;
    case RegNtPostFlushKey:
        object = ((PREG_POST_OPERATION_INFORMATION)pParameters)->Object;
        break;
    case RegNtPreLoadKey:
        object = ((PREG_LOAD_KEY_INFORMATION)pParameters)->Object;
        break;
    case RegNtPreUnLoadKey:
        object = ((PREG_UNLOAD_KEY_INFORMATION)pParameters)->Object;
        break;
    case RegNtPreQueryKeySecurity:
        object = ((PREG_QUERY_KEY_SECURITY_INFORMATION)pParameters)->Object;
        break;
    case RegNtPostQueryKeySecurity:
        object = ((PREG_POST_OPERATION_INFORMATION)pParameters)->Object;
        break;
    case RegNtPreSetKeySecurity:
        object = ((PREG_SET_KEY_SECURITY_INFORMATION)pParameters)->Object;
        break;
    case RegNtPostSetKeySecurity:
        object = ((PREG_POST_OPERATION_INFORMATION)pParameters)->Object;
        break;
    case RegNtCallbackObjectContextCleanup:
        object = ((PREG_CALLBACK_CONTEXT_CLEANUP_INFORMATION)pParameters)->Object;
        break;
    case RegNtPreRestoreKey:
        object = ((PREG_RESTORE_KEY_INFORMATION)pParameters)->Object;
        break;
    case RegNtPostRestoreKey:
        object = ((PREG_RESTORE_KEY_INFORMATION)pParameters)->Object;
        break;
    case RegNtPreReplaceKey:
        object = ((PREG_REPLACE_KEY_INFORMATION)pParameters)->Object;
        break;
    case RegNtPostReplaceKey:
        object = ((PREG_REPLACE_KEY_INFORMATION)pParameters)->Object;
        break;
    default:
        break;
    }

    if (regNotifyClass == RegNtQueryValueKey ||
        regNotifyClass == RegNtPreQueryValueKey ||
        regNotifyClass == RegNtPostQueryValueKey)
    {
        // registry query is too spammy to display in debugger
        return STATUS_SUCCESS;
    }

    if (object)
    {
        ULONG_PTR objectId;
        PUNICODE_STRING objectName;
        NTSTATUS status = STATUS_UNSUCCESSFUL;
        status = CmCallbackGetKeyObjectIDEx(&gDrv.RegistryCookie, object, &objectId, &objectName, 0);
        if (!NT_SUCCESS(status))
        {
            LogError("CmCallbackGetKeyObjectIDEx failed with status = 0x%X\n", status);
        }
        else
        {
            LogInfo("Key: %wZ\n", objectName);
            CmCallbackReleaseKeyObjectIDEx(objectName);
        }
    }

    return STATUS_SUCCESS;
}


NTSTATUS RegistryFilterInitialize()
{
    return CmRegisterCallbackEx(CmRegistryCallback,
        &gDrv.Altitude, gDrv.DriverObject, NULL, &gDrv.RegistryCookie, NULL);
}

NTSTATUS RegistryFilterUninitialize()
{
    return CmUnRegisterCallback(gDrv.RegistryCookie);
}
