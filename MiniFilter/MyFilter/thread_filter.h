#ifndef _THREAD_FILTER_H_
#define _THREAD_FILTER_H_
//
//   Author(s)    : Radu PORTASE(rportase@bitdefender.com)
//

#include "my_driver.h"

NTSTATUS
ThreadFilterInitialize();

NTSTATUS
ThreadFilterUninitialize();

#endif//_THREAD_FILTER_H_