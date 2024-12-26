
#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#include "trace.h"
#include "driver_entry.tmh"
#include "my_driver.h"
#include "communication.h"
#include "process_filter.h"
#include "file_filter.h"
#include "thread_filter.h"
#include "image_filter.h"
#include "registry_filter.h"

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")
/*************************************************************************
    Globals
*************************************************************************/
GLOBLA_DATA gDrv;


/*************************************************************************
    Prototypes
*************************************************************************/

DRIVER_INITIALIZE DriverEntry;
NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    );

NTSTATUS
DriverUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
);

//
//  Assign text sections for each relevant routine.
//
#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, DriverUnload)
#endif

//
//  operation registration
//
CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE,
      0,
      MyFilterPreCreate,
      MyFilterPostCreate },

    { IRP_MJ_CLOSE,
      0,
      MyFilterPreClose,
      MyFilterPostClose },

    { IRP_MJ_CLEANUP,
      0,
      MyFilterPreCleanup,
      MyFilterPostCleanup },

    { IRP_MJ_READ,
      0,
      MyFilterPreOperationReadWriteSynchronize,
      MyFilterPostReadWrite },

    { IRP_MJ_WRITE,
      0,
      MyFilterPreOperationReadWriteSynchronize,
      MyFilterPostReadWrite },

    { IRP_MJ_SET_INFORMATION,
      0,
      MyFilterPreOperationSetAttributesSynchronize,
      MyFilterPostSetInformation },

    { IRP_MJ_OPERATION_END }
};

//
//  This defines what we want to filter with FltMgr
//
CONST FLT_REGISTRATION FilterRegistration = {

    sizeof(FLT_REGISTRATION),         //  Size
    FLT_REGISTRATION_VERSION,           //  Version
    0,                                  //  Flags

    NULL,                               //  Context
    Callbacks,                          //  Operation callbacks

    DriverUnload,                       //  MiniFilterUnload

    OnInstanceSetup,                    //  InstanceSetup
    OnQueryTeardown,                    //  InstanceQueryTeardown
    OnInstanceTeardownStart,            //  InstanceTeardownStart
    OnInstanceTeardownComplete,         //  InstanceTeardownComplete

    NULL,                               //  GenerateFileName
    NULL,                               //  GenerateDestinationFileName
    NULL                                //  NormalizeNameComponent
};


/*************************************************************************
    MiniFilter initialization and unload routines.
*************************************************************************/
NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER( RegistryPath );

    WPP_INIT_TRACING(DriverObject, RegistryPath);

    LogInfo("MyFilter!DriverEntry: Entered\n");

    // 
    // Initialize global data. 
    //

    gDrv.DriverObject = DriverObject;

    UNICODE_STRING altitude = RTL_CONSTANT_STRING(L"370030.1");
    gDrv.Altitude = altitude;

    //
    // We will need ZwQueryInformationProcess for process names
    //

    UNICODE_STRING ustrFunctionName = RTL_CONSTANT_STRING(L"ZwQueryInformationProcess");
    gDrv.pfnZwQueryInformationProcess = (PFUNC_ZwQueryInformationProcess)(SIZE_T)MmGetSystemRoutineAddress(&ustrFunctionName);

    if (!gDrv.pfnZwQueryInformationProcess)
    {
        LogError("Unable to resolve ZwQueryInformationProcess!");
        return STATUS_INSUFF_SERVER_RESOURCES;
    }


    //
    //  Register with FltMgr to tell it our callback routines
    //
    status = FltRegisterFilter( DriverObject,
                                &FilterRegistration,
                                &gDrv.FilterHandle );

    FLT_ASSERT( NT_SUCCESS( status ) );
    if (NT_SUCCESS(status))
    {
        //
        //  Prepare communication layer
        //
        status = CommInitializeFilterCommunicationPort();
        if (!NT_SUCCESS(status)) {

            FltUnregisterFilter(gDrv.FilterHandle);
            return status;
        }

        status = ProcessFilterInitialize();
        if (!NT_SUCCESS(status))
        {
            CommUninitializeFilterCommunicationPort();
            FltUnregisterFilter(gDrv.FilterHandle);
            return status;
        }

        status = ThreadFilterInitialize();
        if (!NT_SUCCESS(status))
        {
            ProcessFilterUninitialize();
            CommUninitializeFilterCommunicationPort();
            FltUnregisterFilter(gDrv.FilterHandle);
            return status;
        }

        status = ImageFilterInitialize();
        if (!NT_SUCCESS(status))
        {
            ThreadFilterUninitialize();
            ProcessFilterUninitialize();
            CommUninitializeFilterCommunicationPort();
            FltUnregisterFilter(gDrv.FilterHandle);
            return status;
        }

        status = RegistryFilterInitialize();
        if (!NT_SUCCESS(status))
        {
            ImageFilterUninitialize();
            ThreadFilterUninitialize();
            ProcessFilterUninitialize();
            CommUninitializeFilterCommunicationPort();
            FltUnregisterFilter(gDrv.FilterHandle);
            return status;
        }


        //
        //  Start filtering i/o
        //
        status = FltStartFiltering( gDrv.FilterHandle );
        if (!NT_SUCCESS( status ))
        {
            CommUninitializeFilterCommunicationPort();
            ProcessFilterUninitialize();
            FltUnregisterFilter( gDrv.FilterHandle );
        }
    }

    return status;
}

NTSTATUS
DriverUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    )
{
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    LogInfo("MyFilter!MyFilterUnload: Entered\n");
    RegistryFilterUninitialize();
    ImageFilterUninitialize();
    ThreadFilterUninitialize();
    ProcessFilterUninitialize();
    CommUninitializeFilterCommunicationPort();
    FltUnregisterFilter( gDrv.FilterHandle );
    WPP_CLEANUP(gDrv.DriverObject);
    return STATUS_SUCCESS;
}