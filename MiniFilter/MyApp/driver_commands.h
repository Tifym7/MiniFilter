#ifndef _DRIVER_COMMANDS_H_
#define _DRIVER_COMMANDS_H_
//
//   Author(s)    : Radu PORTASE(rportase@bitdefender.com)
//
#include "communication_protocol.h"

//
// CmdGetDriverVersion
//
NTSTATUS
CmdGetDriverVersion(
    _Out_ PULONG DriverVersion
    );

//
// CmdStartMonitoring
//

NTSTATUS
CmdStartMonitoring(UINT32 NotificationType
    );

//
// CmdStopMonitoring
//

NTSTATUS
CmdStopMonitoring(UINT32 NotificationType
    );

#endif//_DRIVER_COMMANDS_H_