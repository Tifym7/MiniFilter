#ifndef _IMAGE_FILTER_H_
#define _IMAGE_FILTER_H_
//
//   Author(s)    : Radu PORTASE(rportase@bitdefender.com)
//
#include "my_driver.h"

NTSTATUS
ImageFilterInitialize();

NTSTATUS
ImageFilterUninitialize();

#endif//_IMAGE_FILTER_H_