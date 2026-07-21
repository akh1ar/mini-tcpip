#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

#define FRAME_BUF_SIZE 1600

#define die(msg)
    do{
        perror(msg);
        exit(EXIT_FAILURE);
    } while (0)

static inline void hexdump(const u8 *buf, size_t len){
    for(size_t i = 0; i < len; i += 16){
        printf("%04zx  ", i);
        for(size_t j = 0; j < 16; j++){
            if (i + j < len) printf("%02x ", buf[i + j]);
            else             printf("   ");
        }

        printf(" ");
        for(size_t j = 0; j < 16 && i + j < len; j++){
            u8 c = buf[i + j];
            printf("%c", (c >= 32 && c < 127) ? c : '.');
        }
        printf("\n");
    }
}
#endif