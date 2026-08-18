#ifndef UDP_H
#define UDP_H

#include "common.h"
#include "netdev.h"

#define UDP_HDR_LEN 8

#define UDP_PORT_ECHO 7

struct udp_hdr {
    u16 src_port;
    u16 dst_port;
    u16 length;
    u16 checksum;
} __attribute__((packed));

void udp_recv(struct netdev *dev, const u8 *eth_src,
              const u8 *src_ip, const u8 *dst_ip,
              const u8 *ip_datagram, size_t ip_datagram_len,
              const u8 *payload, size_t len);

int udp_send(struct netdev *dev, const u8 *dst_mac,
             const u8 *src_ip, const u8 *dst_ip,
             u16 src_port, u16 dst_port,
             const u8 *data, size_t data_len);

#endif