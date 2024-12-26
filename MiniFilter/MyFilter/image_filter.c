//
//   Copyright (C) 2022 BitDefender S.R.L.
//   Author(s)    : Radu PORTASE(rportase@bitdefender.com)
//
#include "image_filter.h"
#include "communication.h"
#include "communication_protocol.h"
#include "trace.h"
#include "image_filter.tmh"
#include <ntstrsafe.h>
#include "utils.h"

#pragma warning( disable: 4996 )

VOID
ImgFltSendMessageImageLoad(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_     HANDLE ProcessId,   // pid into which image is being mapped
    _In_     PIMAGE_INFO ImageInfo
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

    PUNICODE_STRING ProcessPath = NULL;
    NTSTATUS status = GetImagePathFromPid(ProcessId, &ProcessPath);

    if (NT_SUCCESS(status)) {
        RtlUnicodeStringPrintf(&message, L"[%llu] [ImageLoad] for process: [PID: %p] [ProcessName: %wz] [ImagePath: %wZ] [ImageBase: %p] [Image Size: %lu]",
            timestamp.QuadPart, HandleToUlong(ProcessId), ProcessPath, FullImageName, ImageInfo->ImageBase, ImageInfo->ImageSize);
        ExFreePoolWithTag(ProcessPath, UTILS_TAG_UNICODE_STRING);
    }
    else {
        RtlUnicodeStringPrintf(&message, L"[%llu] [ImageLoad] for process: [PID: %p] [ProcessName: %wz] [ImagePath: %wZ] [ImageBase: %p] [Image Size: %lu]",
            timestamp.QuadPart, HandleToUlong(ProcessId), "ERROR", FullImageName, ImageInfo->ImageBase, ImageInfo->ImageSize);
    }

    CommSendString(&message);
    ExFreePoolWithTag(message.Buffer, UTILS_TAG_UNICODE_STRING);
}


VOID
ImageLoadNotifyRoutine(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_     HANDLE ProcessId,   // pid into which image is being mapped
    _In_     PIMAGE_INFO ImageInfo
)
{
    UNREFERENCED_PARAMETER(ProcessId);
    UNREFERENCED_PARAMETER(ImageInfo);

    if (!(gDrv.NotificationType == ImageType) || !ProcessId)
    {
        return;
    }

    ImgFltSendMessageImageLoad(FullImageName, ProcessId, ImageInfo);
}

NTSTATUS ImageFilterInitialize()
{
    return PsSetLoadImageNotifyRoutine(ImageLoadNotifyRoutine);
}

NTSTATUS ImageFilterUninitialize()
{
    return PsRemoveLoadImageNotifyRoutine(ImageLoadNotifyRoutine);
}
