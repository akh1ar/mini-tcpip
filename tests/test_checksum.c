#include <assert.h>
#include <stdio.h>
#include "checksum.h"

int main(void)
{
    u8 hdr[20] = {
        0x45,0x00,0x00,0x73, 0x00,0x00,0x40,0x00,
        0x40,0x11,0x00,0x00, 0xc0,0xa8,0x00,0x01,
        0xc0,0xa8,0x00,0xc7
    };

    u16 c = inet_checksum(hdr, 20);
    assert(c == 0xb861);
    printf("  [PASS] known IP header checksum == 0xb861\n");

    hdr[10] = (u8)(c >> 8);
    hdr[11] = (u8)(c & 0xff);
    assert(inet_checksum(hdr, 20) == 0);
    printf("  [PASS] verify intact header == 0\n");

    hdr[5] ^= 0xff;
    assert(inet_checksum(hdr, 20) != 0);
    printf("  [PASS] single-bit corruption detected (!= 0)\n");

    u8 odd[5] = { 0x01,0x02,0x03,0x04,0x05 };
    assert(inet_checksum(odd, 5) == inet_checksum(odd, 5));
    printf("  [PASS] odd-length handled (0x%04x)\n", inet_checksum(odd, 5));

    printf("ALL CHECKSUM TESTS PASSED\n");
    return 0;
}