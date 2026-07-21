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
    memcpy(buf, sip, 4); memcpy(buf + 4, dip, 4);
    buf[8] = 0; buf[9] = IP_PROTO_TCP;
    u16 l = htons((u16)slen); memcpy(buf + 10, &l, 2);
    memcpy(buf + 12, seg, slen);
    return inet_checksum(buf, 12 + slen);
}

static size_t build_tcp_packet(u8 *pkt, u16 sport, u32 seq, u32 ack, u8 flags,
                               const char *data, size_t dlen)
{
    u8 sip[4], dip[4];
    inet_pton(AF_INET, "10.0.0.1", sip);
    inet_pton(AF_INET, "10.0.0.2", dip);
    u8 *seg = pkt + IP_HDR_LEN;
    struct tcp_hdr *th = (struct tcp_hdr *)seg;
    size_t seglen = TCP_HDR_LEN + dlen;
    memset(th, 0, TCP_HDR_LEN);
    th->src_port = htons(sport);
    th->dst_port = htons(TCP_PORT_ECHO);
    th->seq = htonl(seq); th->ack = htonl(ack);
    th->data_off = (TCP_HDR_LEN / 4) << 4;
    th->flags = flags; th->window = htons(8192);
    if (dlen) memcpy(seg + TCP_HDR_LEN, data, dlen);
    th->checksum = htons(tcp_csum(sip, dip, seg, seglen));

    struct ip_hdr *ip = (struct ip_hdr *)pkt;
    memset(ip, 0, IP_HDR_LEN);
    ip->ver_ihl = (4 << 4) | 5; ip->ttl = 64;
    ip->protocol = IP_PROTO_TCP;
    ip->total_len = htons((u16)(IP_HDR_LEN + seglen));
    memcpy(ip->saddr, sip, 4); memcpy(ip->daddr, dip, 4);
    ip->checksum = htons(inet_checksum(ip, IP_HDR_LEN));
    return IP_HDR_LEN + seglen;
}

static void dump_frame(const char *title, const u8 *b, size_t n)
{
    printf("%s (%zu bytes)\n", title, n);
    for (size_t i = 0; i < n; i += 16) {
        printf("  %04zx  ", i);
        for (size_t j = i; j < i + 16 && j < n; j++)
            printf("%02x %s", b[j], (j - i == 7) ? " " : "");
        printf("\n");
    }
}

int main(void){
    const u8 mac1[MAC_LEN] = { 0xaa,0xaa,0xaa,0xaa,0xaa,0xaa };
    int p[2]; assert(pipe(p) == 0);
    struct netdev nd;
    memset(&nd, 0, sizeof(nd));
    strcpy(nd.name, "cap0"); nd.fd = p[1];
    u8 m[MAC_LEN] = MTCP_HWADDR_INIT; memcpy(nd.hwaddr, m, MAC_LEN);
    inet_pton(AF_INET, "10.0.0.2", &nd.ipv4);

    u8 pkt[256], f[256], orig[256], rtx[256];
    const u16 CP = 47000; const u32 C = 0x50000000u;
    ssize_t n;

    tcp_set_now(0);

    //handshake
    size_t plen = build_tcp_packet(pkt, CP, C, 0, TCP_SYN, NULL, 0);
    ip_recv(&nd, mac1, pkt, plen);
    n = read(p[0], f, sizeof(f)); (void)n;
    u32 siss = ntohl(((struct tcp_hdr *)(f + ETH_HDR_LEN + IP_HDR_LEN))->seq);
    plen = build_tcp_packet(pkt, CP, C + 1, siss + 1, TCP_ACK, NULL, 0);
    ip_recv(&nd, mac1, pkt, plen);

    plen = build_tcp_packet(pkt, CP, C + 1, siss + 1, TCP_ACK | TCP_PSH, "AB", 2);
    ip_recv(&nd, mac1, pkt, plen);
    ssize_t olen = read(p[0], orig, sizeof(orig));

    plen = build_tcp_packet(pkt, CP, C + 3, siss + 1, TCP_ACK | TCP_PSH, "CD", 2);
    ip_recv(&nd, mac1, pkt, plen);
    n = read(p[0], f, sizeof(f)); (void)n;

    /*RTO expire -> RETRANSMISSION of E1 */
    tcp_set_now((u64)tcp_next_timeout_ms() + 1);
    tcp_tick();
    ssize_t rlen = read(p[0], rtx, sizeof(rtx));

    printf("=== server ISS=0x%08x  client ISN=0x%08x  echo seq=0x%08x ===\n\n",
           siss, C, siss + 1);
    dump_frame("ORIGINAL echo of \"AB\"   (sent at t=0ms, ack=C+3)", orig, (size_t)olen);
    printf("\n");
    dump_frame("RETRANSMISSION of same  (RTO fired at t=201ms, ack=C+5)", rtx, (size_t)rlen);

    printf("\nbyte-level diff (offset: orig -> rtx):\n");
    int diffs = 0;
    for (ssize_t i = 0; i < olen && i < rlen; i++)
        if (orig[i] != rtx[i]) {
            printf("  offset 0x%02zx: %02x -> %02x\n", (size_t)i, orig[i], rtx[i]);
            diffs++;
        }
    printf("  (%d bytes differ out of %zd)\n", diffs, olen);

    close(p[0]); close(p[1]);
    return 0;
}
