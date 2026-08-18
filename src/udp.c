#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>

#include "udp.h"
#include "ip.h"
#include "icmp.h"
#include "checksum.h"
#include "netdev.h"
#include "common.h"

struct udp_pseudo_hdr {
    u8  src_ip[IP_ADDR_LEN];
    u8  dst_ip[IP_ADDR_LEN];
    u8  zero;
    u8  protocol;
    u16 udp_length;
} __attribute__((packed));

static u16 udp_checksum(const u8 *src_ip, const u8 *dst_ip,
                        const u8 *udp_seg, size_t udp_len)
{
    u8 buf[sizeof(struct udp_pseudo_hdr) + FRAME_BUF_SIZE];

    if (udp_len > FRAME_BUF_SIZE)
        return 0;

    struct udp_pseudo_hdr *ph = (struct udp_pseudo_hdr *)buf;

    memcpy(ph->src_ip, src_ip, IP_ADDR_LEN);
    memcpy(ph->dst_ip, dst_ip, IP_ADDR_LEN);

    ph->zero = 0;
    ph->protocol = IP_PROTO_UDP;
    ph->udp_length = htons((u16)udp_len);

    memcpy(buf + sizeof(*ph), udp_seg, udp_len);

    return inet_checksum(buf, sizeof(*ph) + udp_len);
}

void udp_recv(struct netdev *dev, const u8 *eth_src,
              const u8 *src_ip, const u8 *dst_ip,
              const u8 *ip_datagram, size_t ip_datagram_len,
              const u8 *payload, size_t len)
{
    if (len < UDP_HDR_LEN) {
        printf("  [udp] runt: %zu bytes (< %d), dropped\n", len, UDP_HDR_LEN);
        return;
    }

    const struct udp_hdr *uh = (const struct udp_hdr *)payload;

    u16 ulen = ntohs(uh->length);

    if (ulen < UDP_HDR_LEN || (size_t)ulen > len) {
        printf("  [udp] bad length=%u (avail=%zu), dropped\n", ulen, len);
        return;
    }

    if (uh->checksum != 0) {
        if (udp_checksum(src_ip, dst_ip, payload, ulen) != 0) {
            printf("  [udp] bad checksum, dropped\n");
            return;
        }
    }

    u16 dst_port = ntohs(uh->dst_port);
    u16 src_port = ntohs(uh->src_port);

    const u8 *data = payload + UDP_HDR_LEN;
    size_t data_len = (size_t)ulen - UDP_HDR_LEN;

    switch (dst_port) {
        case UDP_PORT_ECHO:
            printf("  [udp] echo :%u -> :%u, %zu bytes back\n",
                   src_port, dst_port, data_len);

            udp_send(dev, eth_src, dst_ip, src_ip,
                     dst_port, src_port,
                     data, data_len);
            break;

        default:
            printf("  [udp] no listener on port %u -> ICMP port unreachable\n",
                   dst_port);

            icmp_send(dev, eth_src, src_ip,
                      ICMP_TYPE_DEST_UNREACH, ICMP_CODE_PORT_UNREACH,
                      ip_datagram, ip_datagram_len);
            break;
    }
}

int udp_send(struct netdev *dev, const u8 *dst_mac,
             const u8 *src_ip, const u8 *dst_ip,
             u16 src_port, u16 dst_port,
             const u8 *data, size_t data_len)
{
    u8 segment[FRAME_BUF_SIZE];
    size_t seg_len = UDP_HDR_LEN + data_len;

    if (seg_len > sizeof(segment))
        return -1;

    struct udp_hdr *uh = (struct udp_hdr *)segment;

    uh->src_port = htons(src_port);
    uh->dst_port = htons(dst_port);
    uh->length = htons((u16)seg_len);
    uh->checksum = 0;

    memcpy(segment + UDP_HDR_LEN, data, data_len);

    u16 csum = udp_checksum(src_ip, dst_ip, segment, seg_len);

    if (csum == 0)
        csum = 0xFFFF;

    uh->checksum = htons(csum);

    return ip_send(dev, dst_mac, dst_ip, IP_PROTO_UDP, segment, seg_len);
}