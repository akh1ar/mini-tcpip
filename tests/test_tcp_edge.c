#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <poll.h>
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

    if (dlen)
        memcpy(seg + TCP_HDR_LEN, data, dlen);

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

static void assert_no_frame(int fd)
{
    struct pollfd pfd = { .fd = fd, .events = POLLIN };
    assert(poll(&pfd, 1, 0) == 0);
}

static const u8 reqmac[MAC_LEN] = { 0xaa,0xaa,0xaa,0xaa,0xaa,0xaa };
static u64 fake_now = 0;

static u32 handshake(struct netdev *nd, int rfd, u16 cport, u32 cisn)
{
    u8 pkt[256], frame[256];

    size_t plen = build_tcp_packet(pkt, cport, TCP_PORT_ECHO,
                                   cisn, 0, TCP_SYN, NULL, 0);

    ip_recv(nd, reqmac, pkt, plen);

    ssize_t n = read(rfd, frame, sizeof(frame));
    assert(n == ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN);
    assert(frame_tcp(frame)->flags == (TCP_SYN | TCP_ACK));

    u32 siss = ntohl(frame_tcp(frame)->seq);

    plen = build_tcp_packet(pkt, cport, TCP_PORT_ECHO,
                            cisn + 1, siss + 1, TCP_ACK, NULL, 0);

    ip_recv(nd, reqmac, pkt, plen);

    return siss;
}

int main(void)
{
    int p[2];
    assert(pipe(p) == 0);

    struct netdev nd;
    memset(&nd, 0, sizeof(nd));
    strcpy(nd.name, "test0");
    nd.fd = p[1];

    u8 mac[MAC_LEN] = MTCP_HWADDR_INIT;
    memcpy(nd.hwaddr, mac, MAC_LEN);
    inet_pton(AF_INET, "10.0.0.2", &nd.ipv4);

    u8 pkt[256], frame[256], echo1[256];
    size_t plen;
    ssize_t n;

    tcp_set_now(fake_now);

    {
        const u16 CP = 44000;
        const u32 C = 0x20000000u;
        u32 siss = handshake(&nd, p[0], CP, C);

        plen = build_tcp_packet(pkt, CP, TCP_PORT_ECHO,
                                C + 1, siss + 1,
                                TCP_ACK | TCP_PSH, "AB", 2);
        ip_recv(&nd, reqmac, pkt, plen);

        n = read(p[0], echo1, sizeof(echo1));
        assert(n == 56 && ntohl(frame_tcp(echo1)->ack) == C + 3);

        plen = build_tcp_packet(pkt, CP, TCP_PORT_ECHO,
                                C + 3, siss + 1,
                                TCP_ACK | TCP_PSH, "CD", 2);
        ip_recv(&nd, reqmac, pkt, plen);

        n = read(p[0], frame, sizeof(frame));
        assert(n == 56);

        fake_now += (u64)tcp_next_timeout_ms() + 1;
        tcp_set_now(fake_now);
        tcp_tick();

        n = read(p[0], frame, sizeof(frame));
        assert(n == 56);
        assert(ntohl(frame_tcp(frame)->seq) == siss + 1);
        assert(memcmp(frame + ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN,
                      "AB", 2) == 0);
        assert(ntohl(frame_tcp(frame)->ack) == C + 5);
        assert(ntohl(frame_tcp(echo1)->ack) == C + 3);
        assert_no_frame(p[0]);

        printf("  [PASS] (1) oldest-only resend, ack refreshed C+3 -> C+5\n");

        plen = build_tcp_packet(pkt, CP, TCP_PORT_ECHO,
                                C + 5, siss + 5, TCP_ACK, NULL, 0);
        ip_recv(&nd, reqmac, pkt, plen);
        assert(tcp_next_timeout_ms() == -1);
    }

    {
        const u16 CP = 43000;
        const u32 C = 0x30000000u;
        u32 siss = handshake(&nd, p[0], CP, C);
        char m[3] = "X0";

        for (int i = 0; i < RTX_MAX; i++) {
            m[1] = (char)('0' + i);

            plen = build_tcp_packet(pkt, CP, TCP_PORT_ECHO,
                                    C + 1 + (u32)(2 * i),
                                    siss + 1,
                                    TCP_ACK | TCP_PSH, m, 2);

            ip_recv(&nd, reqmac, pkt, plen);

            n = read(p[0], frame, sizeof(frame));
            assert(n == 56);
        }

        plen = build_tcp_packet(pkt, CP, TCP_PORT_ECHO,
                                C + 1 + 2 * RTX_MAX,
                                siss + 1,
                                TCP_ACK | TCP_PSH, "Y!", 2);

        ip_recv(&nd, reqmac, pkt, plen);
        assert_no_frame(p[0]);

        printf("  [PASS] (2a) queue full: segment dropped silently (no ACK)\n");

        plen = build_tcp_packet(pkt, CP, TCP_PORT_ECHO,
                                C + 1 + 2 * RTX_MAX + 2,
                                siss + 1 + 2 * RTX_MAX,
                                TCP_ACK, NULL, 0);

        ip_recv(&nd, reqmac, pkt, plen);
        assert(tcp_next_timeout_ms() == -1);

        n = read(p[0], frame, sizeof(frame));
        assert(n == 54 && frame_tcp(frame)->flags == TCP_ACK);
        assert(ntohl(frame_tcp(frame)->ack) == C + 1 + 2 * RTX_MAX);

        printf("  [PASS] (2b) dup-ACK told the peer where we really are\n");

        plen = build_tcp_packet(pkt, CP, TCP_PORT_ECHO,
                                C + 1 + 2 * RTX_MAX,
                                siss + 1 + 2 * RTX_MAX,
                                TCP_ACK | TCP_PSH, "Y!", 2);

        ip_recv(&nd, reqmac, pkt, plen);

        n = read(p[0], frame, sizeof(frame));
        assert(n == 56);
        assert(memcmp(frame + ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN,
                      "Y!", 2) == 0);

        printf("  [PASS] (2c) rollback: retransmitted bytes accepted, echoed\n");

        plen = build_tcp_packet(pkt, CP, TCP_PORT_ECHO,
                                C + 3 + 2 * RTX_MAX,
                                siss + 3 + 2 * RTX_MAX,
                                TCP_ACK, NULL, 0);

        ip_recv(&nd, reqmac, pkt, plen);
        assert(tcp_next_timeout_ms() == -1);
    }

    const u16 CP3 = 45000;
    const u32 C3 = 0x40000000u;
    u32 siss3;

    {
        plen = build_tcp_packet(pkt, CP3, TCP_PORT_ECHO,
                                C3, 0, TCP_SYN, NULL, 0);

        ip_recv(&nd, reqmac, pkt, plen);

        n = read(p[0], frame, sizeof(frame));
        siss3 = ntohl(frame_tcp(frame)->seq);

        assert(tcp_next_timeout_ms() == RTO_INIT_MS);

        fake_now += 5000;
        tcp_set_now(fake_now);

        assert(tcp_next_timeout_ms() == 0);

        printf("  [PASS] (3) overdue deadline -> budget exactly 0\n");

        tcp_tick();

        n = read(p[0], frame, sizeof(frame));
        assert(n == 54 && frame_tcp(frame)->flags == (TCP_SYN | TCP_ACK));
        assert(ntohl(frame_tcp(frame)->seq) == siss3);

        plen = build_tcp_packet(pkt, CP3, TCP_PORT_ECHO,
                                C3 + 1, siss3 + 1, TCP_ACK, NULL, 0);

        ip_recv(&nd, reqmac, pkt, plen);
        assert(tcp_next_timeout_ms() == -1);
    }

    {
        u8 finack1[256];

        plen = build_tcp_packet(pkt, CP3, TCP_PORT_ECHO,
                                C3 + 1, siss3 + 1,
                                TCP_FIN | TCP_ACK, NULL, 0);

        ip_recv(&nd, reqmac, pkt, plen);

        n = read(p[0], finack1, sizeof(finack1));
        assert(n == 54 &&
               frame_tcp(finack1)->flags == (TCP_FIN | TCP_ACK));

        fake_now += (u64)tcp_next_timeout_ms() + 1;
        tcp_set_now(fake_now);
        tcp_tick();

        n = read(p[0], frame, sizeof(frame));
        assert(n == 54 && memcmp(frame, finack1, 54) == 0);

        printf("  [PASS] (4) lost FIN+ACK resent byte-identical (FIN intact)\n");

        plen = build_tcp_packet(pkt, CP3, TCP_PORT_ECHO,
                                C3 + 2, siss3 + 2, TCP_ACK, NULL, 0);

        ip_recv(&nd, reqmac, pkt, plen);

        assert(tcp_next_timeout_ms() == -1);
        assert_no_frame(p[0]);
    }

    close(p[0]);
    close(p[1]);

    printf("ALL TCP EDGE-CASE TESTS PASSED\n");
    return 0;
}