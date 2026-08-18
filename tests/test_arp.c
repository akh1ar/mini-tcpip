#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <errno.h>

#include "arp.h"
#include "ethernet.h"
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

static void make_request(struct arp_hdr *req, const u8 *reqmac)
{
    req->htype  = htons(ARP_HTYPE_ETHERNET);
    req->ptype  = htons(ARP_PTYPE_IPV4);
    req->hlen   = MAC_LEN;
    req->plen   = 4;
    req->opcode = htons(ARP_OP_REQUEST);
    memcpy(req->sha, reqmac, MAC_LEN);
    inet_pton(AF_INET, "10.0.0.1", req->spa);
    memset(req->tha, 0, MAC_LEN);
    inet_pton(AF_INET, "10.0.0.2", req->tpa);
}

static void test_layout(void)
{
    assert(sizeof(struct arp_hdr) == ARP_HDR_LEN);
    printf("  [PASS] test_layout (sizeof arp_hdr == 28)\n");
}

static void test_request_produces_reply(void)
{
    int p[2];
    assert(pipe(p) == 0);
    struct netdev nd = make_dev(p[1]);

    const u8 reqmac[MAC_LEN] = { 0xaa,0xaa,0xaa,0xaa,0xaa,0xaa };
    struct arp_hdr req;
    make_request(&req, reqmac);

    arp_recv(&nd, reqmac, (const u8 *)&req, ARP_HDR_LEN);

    u8 frame[128];
    ssize_t n = read(p[0], frame, sizeof(frame));
    assert(n == ETH_HDR_LEN + ARP_HDR_LEN);

    const struct eth_hdr *eth = (const struct eth_hdr *)frame;
    const struct arp_hdr *rep = (const struct arp_hdr *)(frame + ETH_HDR_LEN);

    assert(memcmp(eth->dst, reqmac, MAC_LEN) == 0);
    assert(memcmp(eth->src, nd.hwaddr, MAC_LEN) == 0);
    assert(ntohs(eth->ethertype) == ETH_P_ARP);

    assert(ntohs(rep->opcode) == ARP_OP_REPLY);
    assert(memcmp(rep->sha, nd.hwaddr, MAC_LEN) == 0);
    assert(memcmp(rep->spa, &nd.ipv4, 4) == 0);
    assert(memcmp(rep->tha, reqmac, MAC_LEN) == 0);
    assert(memcmp(rep->tpa, req.spa, 4) == 0);

    close(p[0]);
    close(p[1]);

    printf("  [PASS] test_request_produces_reply\n");
}

static void test_not_for_me_is_ignored(void)
{
    int p[2];
    assert(pipe(p) == 0);
    fcntl(p[0], F_SETFL, O_NONBLOCK);
    struct netdev nd = make_dev(p[1]);

    const u8 reqmac[MAC_LEN] = { 0xbb,0xbb,0xbb,0xbb,0xbb,0xbb };
    struct arp_hdr req;
    make_request(&req, reqmac);
    inet_pton(AF_INET, "10.0.0.99", req.tpa);

    arp_recv(&nd, reqmac, (const u8 *)&req, ARP_HDR_LEN);

    u8 frame[128];
    ssize_t n = read(p[0], frame, sizeof(frame));
    assert(n < 0 && errno == EAGAIN);

    close(p[0]);
    close(p[1]);

    printf("  [PASS] test_not_for_me_is_ignored\n");
}

static void test_cache_learns(void)
{
    int p[2];
    assert(pipe(p) == 0);
    struct netdev nd = make_dev(p[1]);

    const u8 reqmac[MAC_LEN] = { 0x11,0x22,0x33,0x44,0x55,0x66 };
    struct arp_hdr req;
    make_request(&req, reqmac);
    arp_recv(&nd, reqmac, (const u8 *)&req, ARP_HDR_LEN);

    u32 sender_ip;
    inet_pton(AF_INET, "10.0.0.1", &sender_ip);
    u8 got[MAC_LEN];

    assert(arp_cache_lookup(sender_ip, got) == 1);
    assert(memcmp(got, reqmac, MAC_LEN) == 0);

    close(p[0]);
    close(p[1]);

    printf("  [PASS] test_cache_learns\n");
}

int main(void)
{
    printf("Running ARP unit tests...\n");

    test_layout();
    test_request_produces_reply();
    test_not_for_me_is_ignored();
    test_cache_learns();

    printf("ALL ARP TESTS PASSED\n");

    return 0;
}