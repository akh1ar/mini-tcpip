#include <string.h>
#include <arpa/inet.h>
#include <stdio.h>

#include "ip.h"
#include "ethernet.h"
#include "icmp.h"
#include "udp.h"
#include "tcp.h"
#include "checksum.h"
#include "netdev.h"
#include "common.h"

void ip_recv(struct netdev *dev, const u8 *eth_src,
             const u8 *payload, size_t len)
{
    if (len < IP_HDR_LEN) {
        printf("  [ip] runt: %zu bytes (< %d), dropped\n", len, IP_HDR_LEN);
        return;
    }

    const struct ip_hdr *ip = (const struct ip_hdr *)payload;

    if (ip_version(ip) != IP_VERSION_4) {
        printf("  [ip] not IPv4 (version=%u), dropped\n", ip_version(ip));
        return;
    }

    u8 hlen = ip_hdr_bytes(ip);
    if (hlen < IP_HDR_LEN || (size_t)hlen > len) {
        printf("  [ip] bad IHL (hlen=%u), dropped\n", hlen);
        return;
    }

    if (inet_checksum(ip, hlen) != 0) {
        printf("  [ip] bad header checksum, dropped\n");
        return;
    }

    u16 ff = ntohs(ip->flags_frag);
    if ((ff & IP_FLAG_MF) || (ff & IP_FRAG_MASK)) {
        printf("  [ip] fragmented packet, dropped (not supported)\n");
        return;
    }

    if (memcmp(ip->daddr, &dev->ipv4, IP_ADDR_LEN) != 0)
        return;

    u16 total = ntohs(ip->total_len);
    if ((size_t)total > len || total < hlen) {
        printf("  [ip] bad total_len=%u (hlen=%u, avail=%zu), dropped\n",
               total, hlen, len);
        return;
    }

    const u8 *l4 = payload + hlen;
    size_t l4_len = total - hlen;

    switch (ip->protocol) {
        case IP_PROTO_ICMP:
            icmp_recv(dev, eth_src, ip->saddr, l4, l4_len);
            break;

        case IP_PROTO_UDP:
            udp_recv(dev, eth_src, ip->saddr, ip->daddr,
                     payload, total, l4, l4_len);
            break;

        case IP_PROTO_TCP:
            tcp_recv(dev, eth_src, ip->saddr, ip->daddr, l4, l4_len);
            break;

        default:
            printf("  [ip] unhandled protocol %u\n", ip->protocol);
            break;
    }
}

int ip_send(struct netdev *dev, const u8 *dst_mac, const u8 *dst_ip,
            u8 proto, const u8 *payload, size_t payload_len)
{
    u8 packet[FRAME_BUF_SIZE];

    if (IP_HDR_LEN + payload_len > sizeof(packet))
        return -1;

    struct ip_hdr *ip = (struct ip_hdr *)packet;
    memset(ip, 0, IP_HDR_LEN);

    ip->ver_ihl = (IP_VERSION_4 << 4) | (IP_HDR_LEN / 4);
    ip->tos = 0;
    ip->total_len = htons((u16)(IP_HDR_LEN + payload_len));
    ip->id = 0;
    ip->flags_frag = 0;
    ip->ttl = IP_DEFAULT_TTL;
    ip->protocol = proto;
    ip->checksum = 0;

    memcpy(ip->saddr, &dev->ipv4, IP_ADDR_LEN);
    memcpy(ip->daddr, dst_ip, IP_ADDR_LEN);

    u16 csum = inet_checksum(ip, IP_HDR_LEN);
    ip->checksum = htons(csum);

    memcpy(packet + IP_HDR_LEN, payload, payload_len);
    size_t packet_len = IP_HDR_LEN + payload_len;

    return eth_send(dev, dst_mac, ETH_P_IPV4, packet, packet_len);
}