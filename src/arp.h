#ifndef ARP_H
#define ARP_H

#include "common.h"
#include "netdev.h"

#define ARP_HDR_LEN 28

#define ARP_HTYPE_ETHERNET 0x0001

#define ARP_PTYPE_IPV4     0x0800

#define ARP_OP_REQUEST     0x0001
#define ARP_OP_REPLY       0x0002

struct arp_hdr {
    u16 htype;
    u16 ptype;
    u8  hlen;
    u8  plen;
    u16 opcode;
    u8  sha[MAC_LEN];
    u8  spa[4];
    u8  tha[MAC_LEN];
    u8  tpa[4];
} __attribute__((packed));

#define ARP_CACHE_SIZE 16

int arp_cache_insert(u32 ip, const u8 *mac);

int arp_cache_lookup(u32 ip, u8 *mac_out);

void arp_cache_dump(void);

void arp_recv(struct netdev *dev, const u8 *eth_src,
              const u8 *payload, size_t len);

#endif