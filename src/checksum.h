#ifndef CHECKSUM_H
#define CHECKSUM_H

#include "common.h" 

u16 inet_checksum(const void *data, size_t len);

#endif 
