#include <string.h>
#include <arpa/inet.h>
#include <stdio.h>

#include "arp.h"
#include "ethernet.h"
#include "netdev.h"
#include "common.h"

struct arp_entry {
    u32 ip;
    u8  mac[MAC_LEN];
    int valid;
};

static struct arp_entry cache[ARP_CACHE_SIZE];

int arp_cache_insert(u32 ip, const u8 *mac)
{
    for (int i = 0; i < ARP_CACHE_SIZE; i++)
        if (cache[i].valid && cache[i].ip == ip) {
            memcpy(cache[i].mac, mac, MAC_LEN);
            return 0;
        }

    for (int i = 0; i < ARP_CACHE_SIZE; i++)
        if (!cache[i].valid) {
            cache[i].ip = ip;
            memcpy(cache[i].mac, mac, MAC_LEN);
            cache[i].valid = 1;
            return 0;
        }

    return -1;
}

int arp_cache_lookup(u32 ip, u8 *mac_out)
{
    for (int i = 0; i < ARP_CACHE_SIZE; i++)
        if (cache[i].valid && cache[i].ip == ip) {
            memcpy(mac_out, cache[i].mac, MAC_LEN);
            return 1;
        }

    return 0;
}

void arp_cache_dump(void)
{
    printf("  [arp] cache:\n");

    for (int i = 0; i < ARP_CACHE_SIZE; i++) {
        if (!cache[i].valid) continue;

        const u8 *ip = (const u8 *)&cache[i].ip;
        const u8 *m  = cache[i].mac;

        printf("    %u.%u.%u.%u -> %02x:%02x:%02x:%02x:%02x:%02x\n",
               ip[0], ip[1], ip[2], ip[3],
               m[0], m[1], m[2], m[3], m[4], m[5]);
    }
}

void arp_recv(struct netdev *dev, const u8 *eth_src,
              const u8 *payload, size_t len)
{
    if (len < ARP_HDR_LEN) {
        printf("  [arp] runt: %zu bytes (< %d), dropped\n", len, ARP_HDR_LEN);
        return;
    }

    const struct arp_hdr *arp = (const struct arp_hdr *)payload;

    if (ntohs(arp->htype) != ARP_HTYPE_ETHERNET) return;
    if (ntohs(arp->ptype) != ARP_PTYPE_IPV4) return;

    u16 op = ntohs(arp->opcode);

    u32 spa_key;
    memcpy(&spa_key, arp->spa, 4);
    arp_cache_insert(spa_key, arp->sha);

    if (memcmp(arp->tpa, &dev->ipv4, 4) != 0)
        return;

    if (op != ARP_OP_REQUEST)
        return;

    struct arp_hdr reply;

    reply.htype  = htons(ARP_HTYPE_ETHERNET);
    reply.ptype  = htons(ARP_PTYPE_IPV4);
    reply.hlen   = MAC_LEN;
    reply.plen   = 4;
    reply.opcode = htons(ARP_OP_REPLY);

    memcpy(reply.sha, dev->hwaddr, MAC_LEN);
    memcpy(reply.spa, &dev->ipv4, 4);
    memcpy(reply.tha, arp->sha, MAC_LEN);
    memcpy(reply.tpa, arp->spa, 4);

    printf("  [arp] request for me -> sending reply\n");

    eth_send(dev, eth_src, ETH_P_ARP,
             (const u8 *)&reply, ARP_HDR_LEN);
}