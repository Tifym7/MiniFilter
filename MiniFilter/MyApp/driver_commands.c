//
//   Author(s)    : Radu PORTASE(rportase@bitdefender.com)
//

#include "driver_commands.h"
#include "global_data.h"
#include "communication_protocol.h"

//
// CmdGetDriverVersion
//
NTSTATUS
CmdGetDriverVersion(
    _Out_ PULONG DriverVersion
    )
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    COMM_CMD_GET_VERSION cmd;
    DWORD dwBytesReturned = 0;
    HRESULT result = S_FALSE;

    __try
    {
        //
        // Prepare our command
        //
        RtlZeroMemory(&cmd, sizeof(cmd));
        cmd.Header.CommandCode = commGetVersion;
        
        //
        // Send the command to KM
        //
        result = FilterSendMessage(gApp.Communication.DriverPort,
            &cmd,
            sizeof(cmd),
            &cmd,           // use same buffer for output
            sizeof(cmd),
            &dwBytesReturned
            );
        if(S_OK != result)
        {
            status = FILTER_FLT_NTSTATUS_FROM_HRESULT(result);
            wprintf(L"FilterSendMessage failed with status = 0x%X\n", status);
            __leave;
        }
        if (sizeof(cmd) != dwBytesReturned)
        {
            status = STATUS_INVALID_USER_BUFFER;
            __leave;
        }

        *DriverVersion = cmd.Version;

        //
        // return the version to our caller
        //
        status = STATUS_SUCCESS;
    }
    __finally
    {
    }

    return status;
}


//
// CmdStartMonitoring
//
NTSTATUS
CmdStartMonitoring(UINT32 NotificationType
    )
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    COMM_CMD_START_MONITORING cmd;
    DWORD dwBytesReturned = 0;
    HRESULT result = S_FALSE;

    __try
    {
        //
        // Prepare our command
        //
        RtlZeroMemory(&cmd, sizeof(cmd));
        cmd.Header.CommandCode = commStartMonitoring;
        cmd.NotificationType |= NotificationType;

        //
        // Send the command to KM
        //
        result = FilterSendMessage(gApp.Communication.DriverPort,
            &cmd,
            sizeof(cmd),
            &cmd,           // use same buffer for output
            sizeof(cmd),
            &dwBytesReturned
            );
        if (S_OK != result)
        {
            status = FILTER_FLT_NTSTATUS_FROM_HRESULT(result);
            wprintf(L"FilterSendMessage failed with status = 0x%X\n", status);
            __leave;
        }

        status = STATUS_SUCCESS;
    }
    __finally
    {
    }

    return status;
}

//
// CmdStopMonitoring
//
NTSTATUS
CmdStopMonitoring(UINT32 NotificationType
    )
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    COMM_CMD_STOP_MONITORING cmd;
    DWORD dwBytesReturned = 0;
    HRESULT result = S_FALSE;

    __try
    {
        //
        // Prepare our command
        //
        RtlZeroMemory(&cmd, sizeof(cmd));
        NotificationType;
        cmd.Header.CommandCode = commStopMonitoring;
        cmd.NotificationType = 0;

        //
        // Send the command to KM
        //
        result = FilterSendMessage(gApp.Communication.DriverPort,
            &cmd,
            sizeof(cmd),
            &cmd,           // use same buffer for output
            sizeof(cmd),
            &dwBytesReturned
            );
        if (S_OK != result)
        {
            status = FILTER_FLT_NTSTATUS_FROM_HRESULT(result);
            wprintf(L"FilterSendMessage failed with status = 0x%X\n", status);
            __leave;
        }

        status = STATUS_SUCCESS;
    }
    __finally
    {
    }

    return status;
}