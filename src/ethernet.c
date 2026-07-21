#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "ethernet.h"
#include "arp.h"
#include "ip.h"
#include "netdev.h"
#include "common.h"

static void mac_to_str(const u8 *mac, char *out){
    sprintf(out, "%02x:%02x:%02x:%02x:%02x:%02x",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}


static const char *ethertype_name(u16 type){
    switch(type){
        case ETH_P_IPV4: return "IPv4";
        case ETH_P_ARP:  return "ARP";
        case ETH_P_IPV6: return "IPv6";
        default:         return "Unknown";
    }
}

void eth_dump(const u8 *frame, size_t len){
    if(len<ETH_HDR_LEN){
        printf("[eth] runt frame: %zu bytes (< %d), dropped\n",
               len, ETH_HDR_LEN);
        return;
    }

    const struct eth_hdr *eth=(const struct eth_hdr *)frame;
    char dst[18], src[18];
    mac_to_str(eth->dst, dst);
    mac_to_str(eth->src, src);

    u16 type = ntohs(eth->ethertype);

    printf("--- Ethernet frame: %zu bytes ---\n", len);
    printf("  dst MAC   : %s%s\n", dst,
           (eth->dst[0] & 0x01) ? "  (multicast/broadcast)" : "");
    printf("  src MAC   : %s\n", src);
    printf("  ethertype : 0x%04x (%s)\n", type, ethertype_name(type));
    printf("  payload   : %zu bytes\n", len - ETH_HDR_LEN);
    hexdump(frame, len);
    printf("\n");
}

void eth_recv(struct netdev *dev, const u8 *frame, size_t len){
    if (len < ETH_HDR_LEN) {
        printf("[eth] runt frame: %zu bytes (< %d), dropped\n",
               len, ETH_HDR_LEN);
        return;
    }
    const struct eth_hdr *eth = (const struct eth_hdr *)frame;
    u16 type = ntohs(eth->ethertype);
    const u8 *payload = frame + ETH_HDR_LEN;
    size_t    plen    = len - ETH_HDR_LEN;

    eth_dump(frame, len);
    switch(type){
        case ETH_P_ARP:
            arp_recv(dev, eth->src, payload, plen);
            break;
        case ETH_P_IPV4:
            ip_recv(dev, eth->src, payload, plen);
            break;
        default:
            break;
    }
}
int eth_send(struct netdev *dev, const u8 *dst_mac, u16 ethertype,
             const u8 *payload, size_t payload_len)
{
    u8 frame[FRAME_BUF_SIZE];
    if (ETH_HDR_LEN + payload_len > sizeof(frame))
        return -1;
    struct eth_hdr *eth = (struct eth_hdr *)frame;
    memcpy(eth->dst, dst_mac,      ETH_ADDR_LEN);
    memcpy(eth->src, dev->hwaddr,  ETH_ADDR_LEN);
    eth->ethertype = htons(ethertype);
    memcpy(frame + ETH_HDR_LEN, payload, payload_len);
    size_t frame_len = ETH_HDR_LEN + payload_len;
    ssize_t n = write(dev->fd, frame, frame_len);
    if (n < 0) {
        perror("write(tap)");
        return -1;
    }
    return (int)n;
}
