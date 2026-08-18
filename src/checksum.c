#include "checksum.h"
#include "common.h"

u16 inet_checksum(const void *data, size_t len)
{
    const u8 *p = (const u8 *)data;
    u32 sum = 0;

    while (len > 1) {
        sum += ((u16)p[0] << 8) | p[1];
        p   += 2;
        len -= 2;
    }

    if (len == 1)
        sum += (u16)p[0] << 8;

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return (u16)(~sum & 0xFFFF);
}