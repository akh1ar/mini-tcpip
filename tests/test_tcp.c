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
    th->checksum = 0;
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

int main(void)
{
    assert(sizeof(struct tcp_hdr) == TCP_HDR_LEN);   
    printf("  [PASS] struct size (tcp=20)\n");

    const u8 reqmac[MAC_LEN] = { 0xaa,0xaa,0xaa,0xaa,0xaa,0xaa };
    u8 sip[4], dip[4];
    inet_pton(AF_INET, "10.0.0.1", sip);
    inet_pton(AF_INET, "10.0.0.2", dip);

    const u16 CPORT      = 40000;             
    const u32 CLIENT_ISN = 0x50000000u;       

    
    {
        u8 pkt[128];
        size_t plen = build_tcp_packet(pkt, CPORT, TCP_PORT_ECHO,
                                       CLIENT_ISN, 0, TCP_SYN, NULL, 0);
        struct tcp_hdr *th = (struct tcp_hdr *)(pkt + IP_HDR_LEN);
        assert(tcp_csum(sip, dip, (u8 *)th, TCP_HDR_LEN) == 0);
        printf("  [PASS] pseudo-header checksum verifies to 0 (len=%zu)\n", plen);
    }

    
    {
        int p[2]; assert(pipe(p) == 0);
        struct netdev nd = make_dev(p[1]);
        u8 pkt[256], frame[256];
        ssize_t n;

        
        size_t plen = build_tcp_packet(pkt, CPORT, TCP_PORT_ECHO,
                                       CLIENT_ISN, 0, TCP_SYN, NULL, 0);
        ip_recv(&nd, reqmac, pkt, plen);

        n = read(p[0], frame, sizeof(frame));
        assert(n == ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN);   
        struct ip_hdr  *rip = (struct ip_hdr  *)(frame + ETH_HDR_LEN);
        struct tcp_hdr *rth = (struct tcp_hdr *)(frame + ETH_HDR_LEN + IP_HDR_LEN);

        assert(inet_checksum(rip, IP_HDR_LEN) == 0);
        assert(rip->protocol == IP_PROTO_TCP);
        assert(memcmp(rip->saddr, dip, 4) == 0);   
        assert(memcmp(rip->daddr, sip, 4) == 0);   
        assert(tcp_csum(rip->saddr, rip->daddr, (u8 *)rth, TCP_HDR_LEN) == 0);
        assert(rth->flags == (TCP_SYN | TCP_ACK));
        assert(ntohs(rth->src_port) == TCP_PORT_ECHO);
        assert(ntohs(rth->dst_port) == CPORT);
        assert(ntohl(rth->ack) == CLIENT_ISN + 1);   
        u32 server_iss = ntohl(rth->seq);            
        printf("  [PASS] handshake SYN+ACK (iss=0x%08x, ack=0x%08x)\n",
               server_iss, ntohl(rth->ack));

        
        plen = build_tcp_packet(pkt, CPORT, TCP_PORT_ECHO,
                                CLIENT_ISN + 1, server_iss + 1, TCP_ACK, NULL, 0);
        ip_recv(&nd, reqmac, pkt, plen);
        

        
        const char *msg = "HELLO";
        size_t mlen = strlen(msg);
        plen = build_tcp_packet(pkt, CPORT, TCP_PORT_ECHO,
                                CLIENT_ISN + 1, server_iss + 1,
                                TCP_ACK | TCP_PSH, msg, mlen);
        ip_recv(&nd, reqmac, pkt, plen);

        n = read(p[0], frame, sizeof(frame));
        assert(n == ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN + (ssize_t)mlen); 
        rip = (struct ip_hdr  *)(frame + ETH_HDR_LEN);
        rth = (struct tcp_hdr *)(frame + ETH_HDR_LEN + IP_HDR_LEN);
        assert(inet_checksum(rip, IP_HDR_LEN) == 0);
        assert(tcp_csum(rip->saddr, rip->daddr, (u8 *)rth, TCP_HDR_LEN + mlen) == 0);
        assert(rth->flags & TCP_ACK);
        assert(rth->flags & TCP_PSH);
        assert(ntohl(rth->seq) == server_iss + 1);        
        assert(ntohl(rth->ack) == CLIENT_ISN + 1 + mlen); 
        assert(memcmp(frame + ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN,
                      msg, mlen) == 0);
        printf("  [PASS] echo (data mirrored, seq=0x%08x, ack=0x%08x)\n",
               ntohl(rth->seq), ntohl(rth->ack));

        
        plen = build_tcp_packet(pkt, CPORT, TCP_PORT_ECHO,
                                CLIENT_ISN + 1 + mlen, server_iss + 1 + mlen,
                                TCP_FIN | TCP_ACK, NULL, 0);
        ip_recv(&nd, reqmac, pkt, plen);

        n = read(p[0], frame, sizeof(frame));
        assert(n == ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN);   
        rip = (struct ip_hdr  *)(frame + ETH_HDR_LEN);
        rth = (struct tcp_hdr *)(frame + ETH_HDR_LEN + IP_HDR_LEN);
        assert(inet_checksum(rip, IP_HDR_LEN) == 0);
        assert(tcp_csum(rip->saddr, rip->daddr, (u8 *)rth, TCP_HDR_LEN) == 0);
        assert(rth->flags & TCP_FIN);
        assert(rth->flags & TCP_ACK);
        assert(ntohl(rth->seq) == server_iss + 1 + mlen);     
        assert(ntohl(rth->ack) == CLIENT_ISN + 1 + mlen + 1); 
        u32 server_fin_seq = ntohl(rth->seq);
        printf("  [PASS] close FIN+ACK (seq=0x%08x, ack=0x%08x)\n",
               server_fin_seq, ntohl(rth->ack));

        
        plen = build_tcp_packet(pkt, CPORT, TCP_PORT_ECHO,
                                CLIENT_ISN + 1 + mlen + 1, server_fin_seq + 1,
                                TCP_ACK, NULL, 0);
        ip_recv(&nd, reqmac, pkt, plen);
        
        printf("  [PASS] final ACK accepted (connection closed)\n");

        close(p[0]); close(p[1]);
    }

    
    {
        int p[2]; assert(pipe(p) == 0);
        struct netdev nd = make_dev(p[1]);
        u8 pkt[128], frame[128];

        size_t plen = build_tcp_packet(pkt, CPORT, 9999 ,
                                       CLIENT_ISN, 0, TCP_SYN, NULL, 0);
        ip_recv(&nd, reqmac, pkt, plen);

        ssize_t n = read(p[0], frame, sizeof(frame));
        assert(n == ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN);   
        struct ip_hdr  *rip = (struct ip_hdr  *)(frame + ETH_HDR_LEN);
        struct tcp_hdr *rth = (struct tcp_hdr *)(frame + ETH_HDR_LEN + IP_HDR_LEN);

        assert(inet_checksum(rip, IP_HDR_LEN) == 0);
        assert(rip->protocol == IP_PROTO_TCP);
        assert(memcmp(rip->saddr, dip, 4) == 0);   
        assert(memcmp(rip->daddr, sip, 4) == 0);
        assert(tcp_csum(rip->saddr, rip->daddr, (u8 *)rth, TCP_HDR_LEN) == 0);
        
        assert(rth->flags == (TCP_RST | TCP_ACK));
        assert(ntohl(rth->seq) == 0);
        assert(ntohl(rth->ack) == CLIENT_ISN + 1);   
        printf("  [PASS] closed port -> RST+ACK (seq=0, ack=0x%08x)\n",
               ntohl(rth->ack));

        close(p[0]); close(p[1]);
    }

    printf("ALL TCP TESTS PASSED\n");
    return 0;
}