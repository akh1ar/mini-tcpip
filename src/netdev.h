#ifndef NETDEV_H
#define NETDEV_H
#include <linux/if.h>

#include "common.h"

#define MAC_LEN 6


struct netdev {
    char name[IFNAMSIZ];
    int  fd;
    u8   hwaddr[MAC_LEN];
    u32  ipv4;
};

#define MTCP_IPV4_STR  "10.0.0.2"
#define MTCP_HWADDR_INIT { 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 }
#endif
