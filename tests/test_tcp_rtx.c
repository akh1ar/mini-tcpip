#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "ip.h"
#include "tcp.h"
#include "ethernet.h"
#include "checksum.h"
#include "netdev.h"

static u16 tcp_csum(const u8 *sip, const u8 *dip, const u8 *seg, size_t slen)
{
    u8 buf[12 + 2048];
    memcpy(buf + 0, sip, 4);
    memcpy(buf + 4, dip, 4);
    buf[8] = 0;
    buf[9] = IP_PROTO_TCP;
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

static size_t build_tcp_packet(u8 *pkt, u16 src_port, u16 dst_port,
                               u32 seq, u32 ack, u8 flags,
                               const char *data, size_t dlen)
{
    u8 sip[4], dip[4];
    inet_pton(AF_INET, "10.0.0.1", sip);
    inet_pton(AF_INET, "10.0.0.2", dip);

    u8 *seg = pkt + IP_HDR_LEN;
    struct tcp_hdr *th = (struct tcp_hdr *)seg;
    size_t seglen = TCP_HDR_LEN + dlen;
    memset(th, 0, TCP_HDR_LEN);
    th->src_port = htons(src_port);
    th->dst_port = htons(dst_port);
    th->seq      = htonl(seq);
    th->ack      = htonl(ack);
    th->data_off = (TCP_HDR_LEN / 4) << 4;
    th->flags    = flags;
    th->window   = htons(8192);
    if (dlen) memcpy(seg + TCP_HDR_LEN, data, dlen);
    th->checksum = htons(tcp_csum(sip, dip, seg, seglen));

    struct ip_hdr *ip = (struct ip_hdr *)pkt;
    memset(ip, 0, IP_HDR_LEN);
    ip->ver_ihl   = (4 << 4) | 5;
    ip->ttl       = 64;
    ip->protocol  = IP_PROTO_TCP;
    ip->total_len = htons((u16)(IP_HDR_LEN + seglen));
    memcpy(ip->saddr, sip, 4);
    memcpy(ip->daddr, dip, 4);
    ip->checksum  = htons(inet_checksum(ip, IP_HDR_LEN));

    return IP_HDR_LEN + seglen;
}

static struct tcp_hdr *frame_tcp(u8 *frame)
{
    return (struct tcp_hdr *)(frame + ETH_HDR_LEN + IP_HDR_LEN);
}

int main(void)
{
    const u8 reqmac[MAC_LEN] = { 0xaa,0xaa,0xaa,0xaa,0xaa,0xaa };
    int p[2]; assert(pipe(p) == 0);
    struct netdev nd = make_dev(p[1]);
    u8 pkt[256], frame[256], first_echo[256];
    ssize_t n, echo_len;
    u64 now = 0;

    const u16 CP1   = 41000;
    const u32 CISN1 = 0x60000000u;

    tcp_set_now(now);

    size_t plen = build_tcp_packet(pkt, CP1, TCP_PORT_ECHO,
                                   CISN1, 0, TCP_SYN, NULL, 0);
    ip_recv(&nd, reqmac, pkt, plen);
    n = read(p[0], frame, sizeof(frame));
    assert(n == ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN);
    assert(frame_tcp(frame)->flags == (TCP_SYN | TCP_ACK));
    u32 siss = ntohl(frame_tcp(frame)->seq);
    assert(tcp_next_timeout_ms() == RTO_INIT_MS);
    printf("  [PASS] SYN+ACK enqueued: timer armed, budget=%d ms\n", RTO_INIT_MS);

    plen = build_tcp_packet(pkt, CP1, TCP_PORT_ECHO,
                            CISN1 + 1, siss + 1, TCP_ACK, NULL, 0);
    ip_recv(&nd, reqmac, pkt, plen);
    assert(tcp_next_timeout_ms() == -1);
    printf("  [PASS] handshake ACK: queue drained, timer cancelled (-1)\n");

    const char *msg = "HELLO";
    size_t mlen = strlen(msg);
    plen = build_tcp_packet(pkt, CP1, TCP_PORT_ECHO,
                            CISN1 + 1, siss + 1, TCP_ACK | TCP_PSH, msg, mlen);
    ip_recv(&nd, reqmac, pkt, plen);
    echo_len = read(p[0], first_echo, sizeof(first_echo));
    assert(echo_len == ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN + (ssize_t)mlen);

    assert(tcp_next_timeout_ms() == RTO_MIN_MS);
    printf("  [PASS] echo sent+queued: budget=RTO_MIN=%d (0ms RTT clamped)\n",
           RTO_MIN_MS);

    now += (u64)tcp_next_timeout_ms() + 1;
    tcp_set_now(now);
    tcp_tick();
    n = read(p[0], frame, sizeof(frame));
    assert(n == echo_len);
    assert(memcmp(frame, first_echo, (size_t)n) == 0);
    printf("  [PASS] RTO fired: retransmission is byte-identical (%zd bytes)\n", n);

    assert(tcp_next_timeout_ms() == 2 * RTO_MIN_MS);
    now += (u64)tcp_next_timeout_ms() + 1;
    tcp_set_now(now);
    tcp_tick();
    n = read(p[0], frame, sizeof(frame));
    assert(n == echo_len && memcmp(frame, first_echo, (size_t)n) == 0);
    assert(tcp_next_timeout_ms() == 4 * RTO_MIN_MS);
    printf("  [PASS] backoff: budget doubled %d -> %d -> %d\n",
           RTO_MIN_MS, 2 * RTO_MIN_MS, 4 * RTO_MIN_MS);

    plen = build_tcp_packet(pkt, CP1, TCP_PORT_ECHO,
                            CISN1 + 1 + (u32)mlen, siss + 1 + (u32)mlen,
                            TCP_ACK, NULL, 0);
    ip_recv(&nd, reqmac, pkt, plen);
    assert(tcp_next_timeout_ms() == -1);
    printf("  [PASS] late ACK: queue drained, timer cancelled\n");

    const char *msg2 = "AGAIN";
    size_t m2len = strlen(msg2);
    plen = build_tcp_packet(pkt, CP1, TCP_PORT_ECHO,
                            CISN1 + 1 + (u32)mlen, siss + 1 + (u32)mlen,
                            TCP_ACK | TCP_PSH, msg2, m2len);
    ip_recv(&nd, reqmac, pkt, plen);
    n = read(p[0], frame, sizeof(frame));
    assert(n == ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN + (ssize_t)m2len);
    assert(tcp_next_timeout_ms() == 4 * RTO_MIN_MS);
    printf("  [PASS] Karn: ambiguous ACK not sampled (next budget still %d)\n",
           4 * RTO_MIN_MS);

    plen = build_tcp_packet(pkt, CP1, TCP_PORT_ECHO,
                            CISN1 + 1 + (u32)(mlen + m2len),
                            siss + 1 + (u32)(mlen + m2len),
                            TCP_ACK, NULL, 0);
    ip_recv(&nd, reqmac, pkt, plen);
    assert(tcp_next_timeout_ms() == -1);

    const u16 CP2   = 42000;
    const u32 CISN2 = 0x70000000u;
    const char *die_msg = "GIVEUP!!";
    size_t dlen = strlen(die_msg);

    plen = build_tcp_packet(pkt, CP2, TCP_PORT_ECHO, CISN2, 0, TCP_SYN, NULL, 0);
    ip_recv(&nd, reqmac, pkt, plen);
    n = read(p[0], frame, sizeof(frame));
    u32 siss2 = ntohl(frame_tcp(frame)->seq);
    plen = build_tcp_packet(pkt, CP2, TCP_PORT_ECHO,
                            CISN2 + 1, siss2 + 1, TCP_ACK, NULL, 0);
    ip_recv(&nd, reqmac, pkt, plen);
    plen = build_tcp_packet(pkt, CP2, TCP_PORT_ECHO,
                            CISN2 + 1, siss2 + 1,
                            TCP_ACK | TCP_PSH, die_msg, dlen);
    ip_recv(&nd, reqmac, pkt, plen);
    n = read(p[0], frame, sizeof(frame));
    assert(n == ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN + (ssize_t)dlen);

    for (int i = 1; i <= RTO_GIVEUP; i++) {
        long budget = tcp_next_timeout_ms();
        assert(budget >= 0);
        now += (u64)budget + 1;
        tcp_set_now(now);
        tcp_tick();
        n = read(p[0], frame, sizeof(frame));
        assert(n == ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN + (ssize_t)dlen);
        assert(frame_tcp(frame)->flags == (TCP_ACK | TCP_PSH));
    }
    printf("  [PASS] give-up: %d silent timeouts each produced a resend\n",
           RTO_GIVEUP);

    now += (u64)tcp_next_timeout_ms() + 1;
    tcp_set_now(now);
    tcp_tick();
    n = read(p[0], frame, sizeof(frame));
    assert(n == ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN);
    assert(frame_tcp(frame)->flags == TCP_RST);
    assert(tcp_next_timeout_ms() == -1);
    printf("  [PASS] abort: RST emitted, all timers gone\n");

    plen = build_tcp_packet(pkt, CP2, TCP_PORT_ECHO,
                            CISN2 + 1 + (u32)dlen, siss2 + 1 + (u32)dlen,
                            TCP_ACK | TCP_PSH, "??", 2);
    ip_recv(&nd, reqmac, pkt, plen);
    n = read(p[0], frame, sizeof(frame));
    assert(frame_tcp(frame)->flags & TCP_RST);
    printf("  [PASS] slot freed: post-abort segment answered with RST\n");

    close(p[0]); close(p[1]);
    printf("ALL TCP RETRANSMISSION TESTS PASSED\n");
    return 0;
}