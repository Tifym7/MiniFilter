//
//   Author(s)    : Radu PORTASE(rportase@bitdefender.com)
//

#include "driver_communication.h"
#include "global_data.h"
#include <fltUser.h>
#include "communication_protocol.h"
#include "driver_commands.h"
#include "message_handlers.h"
#include <malloc.h>

#pragma region Message handling

//
// COMM_MESSAGE_LISTNER_CONTEXT
//
typedef struct _COMM_MESSAGE_LISTNER_CONTEXT
{
    HANDLE TerminationEvent;
}COMM_MESSAGE_LISTNER_CONTEXT, *PCOMM_MESSAGE_LISTNER_CONTEXT;

//
// CommpMessageListner
//
VOID
CommpMessageListner(
    _In_ PVOID Context
)
/*++
Routine description:

--*/
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    PCOMM_MESSAGE_LISTNER_CONTEXT pContext = (PCOMM_MESSAGE_LISTNER_CONTEXT)Context;
    PVOID pInputBuffer = NULL;
    DWORD dwInputBufferSize = 0;
    PVOID pOutputBuffer = NULL;
    DWORD dwOutputBufferSize = 0;
    DWORD dwBytesWritten = 0;
    HANDLE hOverlappedEvent = NULL;
    HRESULT result = S_FALSE;
    OVERLAPPED overlapped;
    HANDLE hWaitEvents[2];
    BOOLEAN bTerminationEventSignaled = FALSE;
    DWORD waitResult = 0;
    BOOLEAN bOverlappedWait = FALSE;

    DBG_UNREFERENCED_LOCAL_VARIABLE(pContext);
    RtlZeroMemory(&overlapped, sizeof(overlapped));

    __try
    {
        //
        // Allocate space for our buffers
        //

        // input buffer
        dwInputBufferSize = COMM_MAX_MESSAGE_SIZE;
        pInputBuffer = malloc(dwInputBufferSize);
        if (!pInputBuffer)
        {
            __leave;
        }

        // output buffer
        dwOutputBufferSize = COMM_MAX_MESSAGE_SIZE;
        pOutputBuffer = malloc(dwOutputBufferSize);
        if (!pOutputBuffer)
        {
            __leave;
        }

        //
        // Prepare an event for the overlapped structure
        //
        hOverlappedEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
        if (!hOverlappedEvent)
        {
            status = NTSTATUS_FROM_WIN32(GetLastError());
            wprintf(L"[Error] CreateEvent failed. Status = 0x%X\n", status);
            __leave;
        }

        //
        // Prepare the overlapped structure
        //
        overlapped.hEvent = hOverlappedEvent;
        overlapped.Offset = 0;
        overlapped.OffsetHigh = 0;

        //
        // Prepare the wait array
        //
        hWaitEvents[0] = gApp.Communication.ThreadsTerminationEvent;
        hWaitEvents[1] = hOverlappedEvent;

        while (!bTerminationEventSignaled)
        {
            //
            // Start getting messages
            //
            bOverlappedWait = FALSE;
            result = FilterGetMessage(gApp.Communication.DriverPort,
                (PFILTER_MESSAGE_HEADER)pInputBuffer,
                dwInputBufferSize,
                &overlapped);
            if (S_OK == result)
            {
                // we managed to get a message
                status = STATUS_WAIT_0 + 1; // corresponds to signaling of the hOverlappedEvent                

            }
            else if (ERROR_IO_PENDING == (result & 0x7FFF))
            {
                // we have to wait for messages
                bOverlappedWait = TRUE;
                status = WaitForMultipleObjects(2, hWaitEvents, FALSE, INFINITE);
            }
            else if (ERROR_INVALID_HANDLE == (result & 0x7FFF))
            {
                // The communication port was closed
                // This should never happen while the service is active
                // terminating the thread
                status = STATUS_WAIT_0;
            }
            else
            {
                // unexpected status returned
                status = FILTER_FLT_NTSTATUS_FROM_HRESULT(result);
                wprintf(L"[Error] FilterGetMessage returned unexpected result. Status = 0x%X\n", status);
                continue;
            }

            if (status == STATUS_WAIT_0)
            {
                // termination event
                CancelIo(gApp.Communication.DriverPort);
                bTerminationEventSignaled = TRUE;
                status = STATUS_SUCCESS;
                continue;
            }
            else if (status == STATUS_WAIT_0 + 1)
            {
                // message received
                // check the status
                if (bOverlappedWait)
                {
                    if (!GetOverlappedResult(gApp.Communication.DriverPort, &overlapped, &dwBytesWritten, FALSE))
                    {
                        status = NTSTATUS_FROM_WIN32(GetLastError());
                        wprintf(L"[Error] GetOverlappedResult failed with status = 0x%X\n", status);
                        __leave;
                    }
                }

                //
                // Dispatch the message
                //

                dwBytesWritten = sizeof(FILTER_REPLY_HEADER);

                status = MsgDispatchNewMessage(
                    (PFILTER_MESSAGE_HEADER)pInputBuffer,
                    dwInputBufferSize,
                    (PFILTER_REPLY_HEADER)pOutputBuffer,
                    dwOutputBufferSize,
                    &dwBytesWritten);
                if (status < 0)
                {
                    wprintf(L"[Error] MsgDispatchNewMessage failed with status = 0x%X\n", status);
                }

                //
                // Send the reply
                //
                if (dwBytesWritten != 0)
                {
                    ((PFILTER_REPLY_HEADER)pOutputBuffer)->Status = status;
                    ((PFILTER_REPLY_HEADER)pOutputBuffer)->MessageId = ((PFILTER_MESSAGE_HEADER)pInputBuffer)->MessageId;
                    result = FilterReplyMessage(gApp.Communication.DriverPort,
                        (PFILTER_REPLY_HEADER)pOutputBuffer,
                        dwBytesWritten);
                    if (S_OK != result && ERROR_FLT_NO_WAITER_FOR_REPLY != result)
                    {
                        status = FILTER_FLT_NTSTATUS_FROM_HRESULT(result);
                        wprintf(L"[Error] FilterReplyMessage failed with status = 0x%X\n", status);
                    }
                }
                waitResult = WaitForSingleObject(gApp.Communication.ThreadsTerminationEvent, 0);
                if (WAIT_OBJECT_0 == waitResult)
                {
                    // termination signaled
                    bTerminationEventSignaled = TRUE;
                }
                else if (WAIT_FAILED == waitResult)
                {
                    status = NTSTATUS_FROM_WIN32(GetLastError());
                    wprintf(L"[Error] WaitForSingleObject failed with status = 0x%X\n", status);
                }

            }
            else
            {
                // something failed
                wprintf(L"[Error] WaitForMultipleObjects returned unexpected result. Status = 0x%X\n", status);
            }
        }
    }
    __finally
    {
        if (pInputBuffer)
        {
            free(pInputBuffer);
        }

        if (pOutputBuffer)
        {
            free(pOutputBuffer);
        }

        if (hOverlappedEvent)
        {
            CloseHandle(hOverlappedEvent);
        }
    }

    return;
}

#pragma endregion Message handling

//
// CommDriverPreinitialize
//
_Use_decl_annotations_
VOID
CommDriverPreinitialize(
    )
{
    gApp.Communication.DriverPort = INVALID_HANDLE_VALUE;
}

//
// CommDriverInitialize
//
_Use_decl_annotations_
NTSTATUS
CommDriverInitialize(
    )
{
    HRESULT   result = S_FALSE;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    FLT_PORT_CONNECTION_CONTEXT connectContext;
    BOOLEAN bConnected = FALSE;
    BOOLEAN bGotVersion = FALSE;
    DWORD i;

    __try
    {
        //
        // Begin initialization
        //
        wprintf(L"[Info] Initializing communication.\n");

        connectContext.Version = 1;

        //
        // Connect to the communication port
        //
        result = FilterConnectCommunicationPort(MY_FILTER_PORT_NAME,
            0,
            &connectContext,
            sizeof(connectContext),
            NULL,
            &gApp.Communication.DriverPort
            );
        if (S_OK != result)
        {
            status = FILTER_FLT_NTSTATUS_FROM_HRESULT(result);
            wprintf(L"[Error] FilterConnectCommunicationPort failed with status 0x%X\n", status);
            gApp.Communication.DriverPort = INVALID_HANDLE_VALUE; // make sure this is not garbage
            __leave;
        }

        bConnected = TRUE;

        //
        // Get Driver version using a simple command
        //
        status = CmdGetDriverVersion(&gApp.Server.Version);
        if (status < 0)
        {
            wprintf(L"[Error] CmdGetDriverVersion failed with status 0x%X\n", status);
            __leave;
        }
        wprintf(L"[Info] Driver version is %u\n", gApp.Server.Version);

        bGotVersion = TRUE;
        //
        // Create the termination event
        //
        gApp.Communication.ThreadsTerminationEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
        if (NULL == gApp.Communication.ThreadsTerminationEvent)
        {
            status = NTSTATUS_FROM_WIN32(GetLastError());
            wprintf(L"CreateEvent failed with status = 0x%X\n", status);
            __leave;
        }

        //
        // Start the listener threads - this must be the last thing we do
        //
        for (i = 0; i < COMM_NUMBER_OF_LISTENER_THREADS; i++)
        {
            gApp.Communication.ListenerThreads[i] = CreateThread( NULL, 
                0,
                (LPTHREAD_START_ROUTINE)CommpMessageListner,
                NULL, 
                0,
                NULL
                );
            if (NULL == gApp.Communication.ListenerThreads[i])
            {
                status = NTSTATUS_FROM_WIN32(GetLastError());
                wprintf(L"CreateThread failed with status = 0x%X\n", status);
            }
        }

        status = STATUS_SUCCESS;
    }
    __finally
    {
        if (status < 0)
        {
            //
            // Communication initialization failed. Do cleanup here 
            //
            if (NULL != gApp.Communication.ThreadsTerminationEvent)
            {
                CloseHandle(gApp.Communication.ThreadsTerminationEvent);
                gApp.Communication.ThreadsTerminationEvent = NULL;
            }

            if (bConnected)
            {
                CloseHandle(gApp.Communication.DriverPort);
                gApp.Communication.DriverPort = INVALID_HANDLE_VALUE;
            }
        }
    }

    return status;
}

//
// CommDriverUninitialize
//
_Use_decl_annotations_
NTSTATUS
CommDriverUninitialize(
    )
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    DWORD i;

    //
    // Begin uninit sequence
    //
    wprintf(L"Uninitializing communication.\n");

    //
    // Try to signal the threads for termination
    //
    if (NULL != gApp.Communication.ThreadsTerminationEvent)
    {
        SetEvent(gApp.Communication.ThreadsTerminationEvent);

        //
        // Wait for the threads to terminate
        //
        for (i = 0; i < COMM_NUMBER_OF_LISTENER_THREADS; i++)
        {
            if (NULL != gApp.Communication.ListenerThreads[i])
            {
                WaitForSingleObject(gApp.Communication.ListenerThreads[i], INFINITE);
                //
                // Close the handles
                //
                CloseHandle(gApp.Communication.ListenerThreads[i]);
                gApp.Communication.ListenerThreads[i] = NULL;
            }
        }
    }

    //
    // End the communication
    //
    if (INVALID_HANDLE_VALUE != gApp.Communication.DriverPort)
    {
        CloseHandle(gApp.Communication.DriverPort);
        gApp.Communication.DriverPort = NULL;
    }


    status = STATUS_SUCCESS;

    return status;
}