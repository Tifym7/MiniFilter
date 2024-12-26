//
//   Author(s)    : Radu PORTASE(rportase@bitdefender.com)
//

#include "driver_commands.h"
#include "global_data.h"
#include <stdio.h>

APP_GLOBAL_DATA gApp;

int 
__cdecl
main(
    int argc,
    char *argv[]
)
{
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    CommDriverPreinitialize();
    NTSTATUS status = CommDriverInitialize();
    if (status < 0)
    {
        return status;
    }
    

    char command[30];

    while (1) {
        fgets(command, sizeof(command), stdin);

        if (strstr(command, "start")) {
            UINT32 NotificationType = 0;
            if (strstr(command, "process")) {
                NotificationType |= ProcessType;
            }
            else if (strstr(command, "thread")) {
                NotificationType |= ThreadType;
            }
            else if (strstr(command, "image")) {
                NotificationType |= ImageType;
            }
            else if (strstr(command, "registry")) {
                NotificationType |= RegistryType;
            }
            else if (strstr(command, "file")) {
                NotificationType |= FileType;
            }
            else {
                NotificationType |= All;
            }
            status = CmdStartMonitoring(NotificationType);
            printf("Start monitoring returned status = 0x%X\n", status);
        }
        else if (strstr(command, "end")) {
            UINT8 NotificationType = 0;
            if (strstr(command, "process")) {
                NotificationType |= ProcessType;
            }
            else if (strstr(command, "thread")) {
                NotificationType |= ThreadType;
            }
            else if (strstr(command, "image")) {
                NotificationType |= ImageType;
            }
            else if (strstr(command, "registry")) {
                NotificationType |= RegistryType;
            }
            else if (strstr(command, "file")) {
                NotificationType |= FileType;
            }
            else {
                NotificationType |= All;
            }
            status = CmdStopMonitoring(NotificationType);
            printf("Stop monitoring returned status = 0x%X\n", status);
        }
        else if (strstr(command, "exit")) {
            break;
        }

       /* printf("Waiting for key...\n");
        char c;
        scanf_s("%c", &c, 1);*/

        
    }
   

    CommDriverUninitialize();
}