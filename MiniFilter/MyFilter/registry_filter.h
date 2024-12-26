#ifndef _REGISTRY_FILTER_H_
#define _REGISTRY_FILTER_H_
//
//   Author(s)    : Radu PORTASE(rportase@bitdefender.com)
//

#include "my_driver.h"

NTSTATUS
RegistryFilterInitialize();

NTSTATUS
RegistryFilterUninitialize();

#endif // _REGISTRY_FILTER_H_