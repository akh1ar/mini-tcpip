#ifndef IP_H
#define IP_H

#include "common.h"
#include "netdev.h"

#define IP_HDR_LEN   20
#define IP_VERSION_4 4
#define IP_ADDR_LEN  4
#define IP_DEFAULT_TTL 64

#define IP_PROTO_ICMP 1
#define IP_PROTO_TCP  6
#define IP_PROTO_UDP  17

#define IP_FLAG_DF   0x4000
#define IP_FLAG_MF   0x2000
#define IP_FRAG_MASK 0x1FFF

struct ip_hdr {
    u8  ver_ihl;
    u8  tos;
    u16 total_len;
    u16 id;
    u16 flags_frag;
    u8  ttl;
    u8  protocol;
    u16 checksum;
    u8  saddr[IP_ADDR_LEN];
    u8  daddr[IP_ADDR_LEN];
} __attribute__((packed));

static inline u8 ip_version(const struct ip_hdr *ip)
{
    return ip->ver_ihl >> 4;
}

static inline u8 ip_ihl(const struct ip_hdr *ip)
{
    return ip->ver_ihl & 0x0F;
}

static inline u8 ip_hdr_bytes(const struct ip_hdr *ip)
{
    return ip_ihl(ip) * 4;
}

void ip_recv(struct netdev *dev, const u8 *eth_src,
             const u8 *payload, size_t len);

int ip_send(struct netdev *dev, const u8 *dst_mac, const u8 *dst_ip,
            u8 proto, const u8 *payload, size_t payload_len);

#endif