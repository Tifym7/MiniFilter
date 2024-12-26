//
//   Author(s)    : Radu PORTASE(rportase@bitdefender.com)
//
#include "utils.h"
#include "trace.h"
#include "utils.tmh"

#pragma warning(disable:4996)


NTSTATUS
GetImagePathFromOpenHandle(
    _In_  HANDLE hProcess,
    _Out_ PUNICODE_STRING* ProcessPath
)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    ULONG dwObjectNameSize = 0;
    PUNICODE_STRING pProcessPath = NULL;

    __try
    {
        // get the size of the process name
        status = gDrv.pfnZwQueryInformationProcess(hProcess,
            ProcessImageFileName, NULL,
            dwObjectNameSize, &dwObjectNameSize);
        if (STATUS_INFO_LENGTH_MISMATCH != status)
        {
            __leave;
        }

        // allocate required space
        pProcessPath = (PUNICODE_STRING)ExAllocatePoolWithTag(NonPagedPool,
            dwObjectNameSize, UTILS_TAG_UNICODE_STRING);
        if (!pProcessPath)
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
            __leave;
        }

        // get the name
        status = gDrv.pfnZwQueryInformationProcess(hProcess, ProcessImageFileName,
            pProcessPath, dwObjectNameSize, &dwObjectNameSize);
        if (!NT_SUCCESS(status))
        {
            __leave;
        }
        *ProcessPath = pProcessPath;
        status = STATUS_SUCCESS;
    }
    __finally
    {
        if (!NT_SUCCESS(status))
        {
            if (pProcessPath)
            {
                ExFreePoolWithTag(pProcessPath, UTILS_TAG_UNICODE_STRING);
            }
        }
    }
    return status;
}

NTSTATUS
GetImagePathFromPid(
    _In_  HANDLE Pid,
    _Out_ PUNICODE_STRING* ProcessPath
)
{
    HANDLE hProcess;
    OBJECT_ATTRIBUTES objattr;
    CLIENT_ID clientId;

    clientId.UniqueProcess = Pid;
    clientId.UniqueThread = NULL;

    InitializeObjectAttributes(&objattr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

    NTSTATUS status = ZwOpenProcess(&hProcess, GENERIC_ALL, &objattr, &clientId);
    if (!NT_SUCCESS(status))
    {
        LogError("ZwOpenProcess failed. Status = 0x%x", status);
        return status;
    }

    status = GetImagePathFromOpenHandle(hProcess, ProcessPath);
    ZwClose(hProcess);
    return status;
}

NTSTATUS GetCurrentProcessImagePath(_Out_ PUNICODE_STRING* ProcessPath)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    HANDLE hProcess = NULL;

    __try
    {
        PEPROCESS currentProcess = PsGetCurrentProcess();
        if (!currentProcess)
        {
            __leave;
        }

        status = ObOpenObjectByPointer(currentProcess, OBJ_KERNEL_HANDLE,
            NULL, PROCESS_ALL_ACCESS, *PsProcessType, KernelMode,
            &hProcess);
        if (!NT_SUCCESS(status))
        {
            LogError("ObOpenObjectByPointer failed with status 0x%X\n", status);
            __leave;
        }

        status = GetImagePathFromOpenHandle(hProcess, ProcessPath);
        if (!NT_SUCCESS(status))
        {
            LogError("GetImagePathFromOpenHandle failed with status 0x%X\n", status);
            __leave;
        }

    }
    __finally
    {
        if (hProcess)
        {
            ZwClose(hProcess);
        }
    }

    return status;
}
