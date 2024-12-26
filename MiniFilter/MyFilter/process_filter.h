#ifndef _PROCESS_FILTER_HPP_INCLUDED_
#define _PROCESS_FILTER_HPP_INCLUDED_
//
//   Author(s)    : Radu PORTASE(rportase@bitdefender.com)
//

#include "my_driver.h"

NTSTATUS
ProcessFilterInitialize();

NTSTATUS
ProcessFilterUninitialize();

#endif