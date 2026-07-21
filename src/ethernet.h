#ifndef ETHERNET_H
#define ETHERNET_H

#include "common.h"
#include "netdev.h"

#define ETH_ADDR_LEN 6
#define ETH_HDR_LEN  14

#define ETH_P_IPV4 0x0800
#define ETH_P_ARP  0x0806
#define ETH_P_IPV6 0x86DD

struct eth_hdr{
    u8  dst[ETH_ADDR_LEN];
    u8  src[ETH_ADDR_LEN];
    u16 ethertype;
    u8  payload[];
} __attribute__((packed));

void eth_dump(const u8 *frame, size_t len);

void eth_recv(struct netdev *dev, const u8 *frame, size_t len);

int eth_send(struct netdev *dev, const u8 *dst_mac, u16 ethertype,
             const u8 *payload, size_t payload_len);

#endif
