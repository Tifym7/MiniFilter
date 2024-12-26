//
//   Author(s)    : Radu PORTASE(rportase@bitdefender.com)
//

#include "message_handlers.h"
#include <ntstatus.h>
#include "global_data.h"
#include "communication_protocol.h"
#include <malloc.h>

//
// MsgHandleUnknownMessage
//
_Pre_satisfies_(InputBufferSize >= sizeof(FILTER_MESSAGE_HEADER))
_Pre_satisfies_(OutputBufferSize >= sizeof(FILTER_REPLY_HEADER))
NTSTATUS
MsgHandleUnknownMessage(
    _In_bytecount_(InputBufferSize) PFILTER_MESSAGE_HEADER InputBuffer,
    _In_ DWORD InputBufferSize,
    _Out_writes_bytes_to_opt_(OutputBufferSize, *BytesWritten) PFILTER_REPLY_HEADER OutputBuffer,
    _In_ DWORD OutputBufferSize,
    _Out_ PDWORD BytesWritten
)
{
    UNREFERENCED_PARAMETER(InputBufferSize);
    UNREFERENCED_PARAMETER(OutputBuffer);
    UNREFERENCED_PARAMETER(OutputBufferSize);
    PMY_DRIVER_MESSAGE_HEADER pHeader = (PMY_DRIVER_MESSAGE_HEADER)(InputBuffer + 1);

    wprintf(L"[Error] Unknown message received form driver. Id = %u", pHeader->MessageCode);

    *BytesWritten = 0;
    return STATUS_SUCCESS;
}

//
// MsgHandleSendString
//
_Pre_satisfies_(InputBufferSize >= sizeof(FILTER_MESSAGE_HEADER))
_Pre_satisfies_(OutputBufferSize >= sizeof(FILTER_REPLY_HEADER))
NTSTATUS
MsgHandleSendString(
    _In_bytecount_(InputBufferSize) PFILTER_MESSAGE_HEADER InputBuffer,
    _In_ DWORD InputBufferSize,
    _Out_writes_bytes_to_opt_(OutputBufferSize, *BytesWritten) PFILTER_REPLY_HEADER OutputBuffer,
    _In_ DWORD OutputBufferSize,
    _Out_ PDWORD BytesWritten
)
{
    PMY_DRIVER_MESSAGE_SEND_STRING_FULL pInput = (PMY_DRIVER_MESSAGE_SEND_STRING_FULL)InputBuffer;
    PMY_DRIVER_MESSAGE_SEND_STRING_REPLY_FULL  pOutput = (PMY_DRIVER_MESSAGE_SEND_STRING_REPLY_FULL)OutputBuffer;

    *BytesWritten = 0;
    if (InputBufferSize < sizeof(*pInput))
    {
        return STATUS_INVALID_USER_BUFFER;
    }

    if (OutputBufferSize < sizeof(*pOutput))
    {
        return STATUS_INVALID_USER_BUFFER;
    }

    if (sizeof(*pInput) + pInput->Message.StringLengthInBytes < sizeof(*pInput))
    {
        return STATUS_INTEGER_OVERFLOW;
    }

    if (InputBufferSize < sizeof(*pInput) + pInput->Message.StringLengthInBytes)
    {
        return STATUS_INVALID_USER_BUFFER;
    }

    *BytesWritten = sizeof(*pOutput);
    pOutput->Reply.Status = STATUS_SUCCESS;

    if (!pInput->Message.StringLengthInBytes)
    {
        wprintf(L"\n");
        return STATUS_SUCCESS;
    }

    PWCHAR message = malloc(pInput->Message.StringLengthInBytes + sizeof(WCHAR));
    if (!message)
    {
        wprintf(L"[ERROR] BAD_ALLOC\n");
        return STATUS_SUCCESS;
    }

    memcpy(message, &pInput->Message.Data[0], pInput->Message.StringLengthInBytes);
    message[pInput->Message.StringLengthInBytes >> 1] = L'\0';
    wprintf(L"%s\n", message);
    free(message);

    return STATUS_SUCCESS;
}

//
// MsgDispatchNewMessage
//
_Pre_satisfies_(InputBufferSize >= sizeof(FILTER_MESSAGE_HEADER))
_Pre_satisfies_(OutputBufferSize >= sizeof(FILTER_REPLY_HEADER))
NTSTATUS
MsgDispatchNewMessage(
    _In_bytecount_(InputBufferSize) PFILTER_MESSAGE_HEADER InputBuffer,
    _In_ DWORD InputBufferSize,
    _Out_writes_bytes_to_opt_(OutputBufferSize, *BytesWritten) PFILTER_REPLY_HEADER OutputBuffer,
    _In_ DWORD OutputBufferSize,
    _Out_ PDWORD BytesWritten
    )
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    if (InputBufferSize < sizeof(FILTER_MESSAGE_HEADER) + sizeof(MY_DRIVER_COMMAND_HEADER))
    {
        wprintf(L"[Error] Message size is too small to dispatch. Size = %d\n", InputBufferSize);
        return STATUS_BUFFER_TOO_SMALL;
    }

    PMY_DRIVER_MESSAGE_HEADER pHeader = (PMY_DRIVER_MESSAGE_HEADER)(InputBuffer + 1);

    switch (pHeader->MessageCode)
    {
    case msgSendString:
        status = MsgHandleSendString(InputBuffer, InputBufferSize, OutputBuffer, OutputBufferSize, BytesWritten);
        break;
    default:
        status = MsgHandleUnknownMessage(InputBuffer, InputBufferSize, OutputBuffer, OutputBufferSize, BytesWritten);
        break;
    }
    
    return status;
}
