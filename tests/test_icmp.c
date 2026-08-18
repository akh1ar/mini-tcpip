#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "ip.h"
#include "icmp.h"
#include "ethernet.h"
#include "checksum.h"
#include "netdev.h"

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

int main(void)
{
    assert(sizeof(struct ip_hdr) == IP_HDR_LEN);
    assert(sizeof(struct icmp_hdr) == ICMP_HDR_LEN);
    printf("  [PASS] struct sizes (ip=20, icmp=8)\n");

    int p[2];
    assert(pipe(p) == 0);
    struct netdev nd = make_dev(p[1]);

    const u8 reqmac[MAC_LEN] = { 0xaa,0xaa,0xaa,0xaa,0xaa,0xaa };
    const char *data = "PINGDATA";
    size_t dlen = strlen(data);

    u8 icmpbuf[ICMP_HDR_LEN + 64];
    struct icmp_hdr *ic = (struct icmp_hdr *)icmpbuf;
    ic->type = ICMP_TYPE_ECHO_REQUEST;
    ic->code = 0;
    ic->checksum = 0;
    ic->id = htons(0x1234);
    ic->seq = htons(1);
    memcpy(icmpbuf + ICMP_HDR_LEN, data, dlen);

    size_t icmplen = ICMP_HDR_LEN + dlen;
    ic->checksum = htons(inet_checksum(icmpbuf, icmplen));

    u8 pkt[IP_HDR_LEN + sizeof(icmpbuf)];
    struct ip_hdr *ip = (struct ip_hdr *)pkt;
    memset(ip, 0, IP_HDR_LEN);

    ip->ver_ihl = (4 << 4) | 5;
    ip->ttl = 64;
    ip->protocol = IP_PROTO_ICMP;
    ip->total_len = htons((u16)(IP_HDR_LEN + icmplen));

    inet_pton(AF_INET, "10.0.0.1", ip->saddr);
    inet_pton(AF_INET, "10.0.0.2", ip->daddr);

    ip->checksum = htons(inet_checksum(ip, IP_HDR_LEN));
    memcpy(pkt + IP_HDR_LEN, icmpbuf, icmplen);

    size_t pktlen = IP_HDR_LEN + icmplen;

    ip_recv(&nd, reqmac, pkt, pktlen);

    u8 frame[256];
    ssize_t n = read(p[0], frame, sizeof(frame));

    assert(n == (ssize_t)(ETH_HDR_LEN + IP_HDR_LEN + icmplen));
    printf("  [PASS] reply frame length = %zd (14+20+16)\n", n);

    struct eth_hdr *eth = (struct eth_hdr *)frame;
    struct ip_hdr *rip = (struct ip_hdr *)(frame + ETH_HDR_LEN);
    struct icmp_hdr *ric =
        (struct icmp_hdr *)(frame + ETH_HDR_LEN + IP_HDR_LEN);

    assert(memcmp(eth->dst, reqmac, MAC_LEN) == 0);
    assert(memcmp(eth->src, nd.hwaddr, MAC_LEN) == 0);
    assert(ntohs(eth->ethertype) == ETH_P_IPV4);
    printf("  [PASS] ethernet (unicast reply, EtherType IPv4)\n");

    assert(inet_checksum(rip, IP_HDR_LEN) == 0);
    assert(ip_version(rip) == 4);
    assert(rip->protocol == IP_PROTO_ICMP);
    assert(memcmp(rip->saddr, &nd.ipv4, 4) == 0);

    u32 reqip;
    inet_pton(AF_INET, "10.0.0.1", &reqip);

    assert(memcmp(rip->daddr, &reqip, 4) == 0);
    printf("  [PASS] ip (valid checksum, addresses swapped)\n");

    assert(inet_checksum(ric, icmplen) == 0);
    assert(ric->type == ICMP_TYPE_ECHO_REPLY);
    assert(ntohs(ric->id) == 0x1234);
    assert(ntohs(ric->seq) == 1);

    assert(memcmp(
        frame + ETH_HDR_LEN + IP_HDR_LEN + ICMP_HDR_LEN,
        data,
        dlen
    ) == 0);

    printf("  [PASS] icmp (type 0, valid checksum, id/seq/data echoed)\n");

    close(p[0]);
    close(p[1]);

    printf("ALL ICMP TESTS PASSED\n");
    return 0;
}