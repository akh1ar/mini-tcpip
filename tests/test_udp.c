#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "ip.h"
#include "udp.h"
#include "icmp.h"
#include "ethernet.h"
#include "checksum.h"
#include "netdev.h"

static u16 udp_csum(const u8 *sip, const u8 *dip, const u8 *seg, size_t slen)
{
    u8 buf[12 + 2048];
    memcpy(buf + 0, sip, 4);
    memcpy(buf + 4, dip, 4);
    buf[8] = 0;
    buf[9] = IP_PROTO_UDP;
    u16 l = htons((u16)slen);
    memcpy(buf + 10, &l, 2);
    memcpy(buf + 12, seg, slen);
    return inet_checksum(buf, 12 + slen);
}

static struct netdev make_dev(int fd)
{
    struct netdev nd;
    memset(&nd, 0, sizeof(nd));
    strcpy(nd.name, "test0");
    nd.fd = fd;
    u8 mac[MAC_LEN] = MTCP_HWADDR_INIT;
    memcpy(nd.hwaddr, mac, MAC_LEN);
    inet_pton(AF_INET, "10.0.0.2", &nd.ipv4);
    return nd;
}

static size_t build_udp_packet(u8 *pkt, u16 src_port, u16 dst_port,
                               const char *data, size_t dlen)
{
    u8 sip[4], dip[4];
    inet_pton(AF_INET, "10.0.0.1", sip);
    inet_pton(AF_INET, "10.0.0.2", dip);

    u8 *seg = pkt + IP_HDR_LEN;
    struct udp_hdr *uh = (struct udp_hdr *)seg;
    size_t seglen = UDP_HDR_LEN + dlen;
    uh->src_port = htons(src_port);
    uh->dst_port = htons(dst_port);
    uh->length   = htons((u16)seglen);
    uh->checksum = 0;
    memcpy(seg + UDP_HDR_LEN, data, dlen);
    uh->checksum = htons(udp_csum(sip, dip, seg, seglen));

    struct ip_hdr *ip = (struct ip_hdr *)pkt;
    memset(ip, 0, IP_HDR_LEN);
    ip->ver_ihl   = (4 << 4) | 5;
    ip->ttl       = 64;
    ip->protocol  = IP_PROTO_UDP;
    ip->total_len = htons((u16)(IP_HDR_LEN + seglen));
    memcpy(ip->saddr, sip, 4);
    memcpy(ip->daddr, dip, 4);
    ip->checksum  = htons(inet_checksum(ip, IP_HDR_LEN));

    return IP_HDR_LEN + seglen;
}

int main(void)
{
    assert(sizeof(struct udp_hdr) == UDP_HDR_LEN);
    printf("  [PASS] struct size (udp=8)\n");

    const u8 reqmac[MAC_LEN] = { 0xaa,0xaa,0xaa,0xaa,0xaa,0xaa };
    u8 sip[4], dip[4];
    inet_pton(AF_INET, "10.0.0.1", sip);
    inet_pton(AF_INET, "10.0.0.2", dip);

    {
        u8 pkt[128];
        size_t plen = build_udp_packet(pkt, 40000, UDP_PORT_ECHO, "ABCD", 4);
        struct udp_hdr *uh = (struct udp_hdr *)(pkt + IP_HDR_LEN);
        assert(udp_csum(sip, dip, (u8 *)uh, ntohs(uh->length)) == 0);
        printf("  [PASS] pseudo-header checksum verifies to 0 (len=%zu)\n", plen);
    }

    {
        int p[2]; assert(pipe(p) == 0);
        struct netdev nd = make_dev(p[1]);
        const char *data = "UDPECHO!";
        size_t dlen = strlen(data);

        u8 pkt[128];
        size_t pktlen = build_udp_packet(pkt, 40000, UDP_PORT_ECHO, data, dlen);
        ip_recv(&nd, reqmac, pkt, pktlen);

        u8 frame[256];
        ssize_t n = read(p[0], frame, sizeof(frame));
        ssize_t want = ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN + (ssize_t)dlen;
        assert(n == want);
        printf("  [PASS] echo reply frame length = %zd (14+20+8+8)\n", n);

        struct eth_hdr *eth = (struct eth_hdr *)frame;
        struct ip_hdr  *rip = (struct ip_hdr  *)(frame + ETH_HDR_LEN);
        struct udp_hdr *rup = (struct udp_hdr *)(frame + ETH_HDR_LEN + IP_HDR_LEN);

        assert(memcmp(eth->dst, reqmac, MAC_LEN) == 0);
        assert(memcmp(eth->src, nd.hwaddr, MAC_LEN) == 0);
        assert(ntohs(eth->ethertype) == ETH_P_IPV4);
        printf("  [PASS] ethernet (unicast reply, EtherType IPv4)\n");

        assert(inet_checksum(rip, IP_HDR_LEN) == 0);
        assert(rip->protocol == IP_PROTO_UDP);
        assert(memcmp(rip->saddr, dip, 4) == 0);
        assert(memcmp(rip->daddr, sip, 4) == 0);
        printf("  [PASS] ip (valid checksum, addresses swapped)\n");

        assert(udp_csum(rip->saddr, rip->daddr, (u8 *)rup,
                        ntohs(rup->length)) == 0);
        assert(ntohs(rup->src_port) == UDP_PORT_ECHO);
        assert(ntohs(rup->dst_port) == 40000);
        assert(memcmp(frame + ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN,
                      data, dlen) == 0);
        printf("  [PASS] udp (valid checksum, ports swapped, data echoed)\n");

        close(p[0]); close(p[1]);
    }

    {
        int p[2]; assert(pipe(p) == 0);
        struct netdev nd = make_dev(p[1]);
        const char *data = "NOListen";
        size_t dlen = strlen(data);

        u8 pkt[128];
        size_t pktlen = build_udp_packet(pkt, 40000, 9999, data, dlen);
        ip_recv(&nd, reqmac, pkt, pktlen);

        u8 frame[256];
        ssize_t n = read(p[0], frame, sizeof(frame));

        struct ip_hdr   *rip = (struct ip_hdr   *)(frame + ETH_HDR_LEN);
        struct icmp_hdr *ric = (struct icmp_hdr *)(frame + ETH_HDR_LEN + IP_HDR_LEN);

        ssize_t quote = IP_HDR_LEN + 8;
        ssize_t want  = ETH_HDR_LEN + IP_HDR_LEN + ICMP_HDR_LEN + quote;
        assert(n == want);
        printf("  [PASS] error reply frame length = %zd (14+20+8+28)\n", n);

        assert(inet_checksum(rip, IP_HDR_LEN) == 0);
        assert(rip->protocol == IP_PROTO_ICMP);
        assert(memcmp(rip->saddr, dip, 4) == 0);
        assert(memcmp(rip->daddr, sip, 4) == 0);
        printf("  [PASS] ip (ICMP error, valid checksum, back to sender)\n");

        size_t icmplen = ICMP_HDR_LEN + quote;
        assert(inet_checksum(ric, icmplen) == 0);
        assert(ric->type == ICMP_TYPE_DEST_UNREACH);
        assert(ric->code == ICMP_CODE_PORT_UNREACH);
        assert(ric->id == 0 && ric->seq == 0);
        printf("  [PASS] icmp (type 3, code 3, unused=0, valid checksum)\n");

        u8 *quoted = frame + ETH_HDR_LEN + IP_HDR_LEN + ICMP_HDR_LEN;
        struct ip_hdr  *qip = (struct ip_hdr  *)quoted;
        struct udp_hdr *qup = (struct udp_hdr *)(quoted + IP_HDR_LEN);
        assert(qip->protocol == IP_PROTO_UDP);
        assert(ntohs(qup->dst_port) == 9999);
        printf("  [PASS] icmp quote (orig IP hdr + UDP hdr, dst_port=9999)\n");

        close(p[0]); close(p[1]);
    }

    printf("ALL UDP TESTS PASSED\n");
    return 0;
}