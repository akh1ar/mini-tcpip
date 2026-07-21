#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>

#include "ethernet.h"

/*broadcast ARP request frame*/
static void test_arp_broadcast(void)
{
    u8 frame[] = {
        0xff,0xff,0xff,0xff,0xff,0xff,   //dst = broadcast
        0x11,0x22,0x33,0x44,0x55,0x66, //src
        0x08,0x06, //ethertype = ARP (big-endian)
        0xaa,0xbb  //2 bytes of payload
    };
    const struct eth_hdr *e = (const struct eth_hdr *)frame;

    assert(e->dst[0] == 0xff && e->dst[5] == 0xff);
    assert((e->dst[0] & 0x01) == 0x01); // I/G bit set
    assert(e->src[0] == 0x11 && e->src[5] == 0x66);
    assert(ntohs(e->ethertype) == ETH_P_ARP);
    assert(ntohs(e->ethertype) != 0x0608);
    printf("  [PASS] test_arp_broadcast\n");
}

static void test_ipv4_unicast(void)
{
    u8 frame[] = {
        0xde,0xad,0xbe,0xef,0x00,0x01,
        0xca,0xfe,0xba,0xbe,0x00,0x02,
        0x08,0x00,
        0x45,0x00
    };
    const struct eth_hdr *e = (const struct eth_hdr *)frame;

    assert((e->dst[0] & 0x01) == 0x00);
    assert(ntohs(e->ethertype) == ETH_P_IPV4);
    assert(e->payload[0] == 0x45);
    printf("  [PASS] test_ipv4_unicast\n");
}

static void test_layout(void){
    assert(sizeof(struct eth_hdr) == ETH_HDR_LEN);
    assert(ETH_HDR_LEN == 14);
    assert(ETH_ADDR_LEN == 6);
    printf("  [PASS] test_layout (sizeof eth_hdr == 14)\n");
}

int main(void){
    printf("Running Ethernet parser unit tests...\n");
    test_layout();
    test_arp_broadcast();
    test_ipv4_unicast();
    printf("ALL TESTS PASSED\n");
    return 0;
}