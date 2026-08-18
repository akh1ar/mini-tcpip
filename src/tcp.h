#ifndef TCP_H
#define TCP_H

#include "common.h"
#include "netdev.h"

#define TCP_HDR_LEN 20

#define TCP_MSS       536
#define RTO_INIT_MS   1000
#define RTO_MIN_MS    200
#define RTO_MAX_MS    60000
#define RTO_GIVEUP    5
#define RTX_MAX       8

#define TCP_INIT_CWND     (4 * TCP_MSS)
#define TCP_DUPACK_THRESH 3

#define TCP_PORT_ECHO 7

#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20

struct tcp_hdr {
    u16 src_port;
    u16 dst_port;
    u32 seq;
    u32 ack;
    u8  data_off;
    u8  flags;
    u16 window;
    u16 checksum;
    u16 urg_ptr;
} __attribute__((packed));

static inline u8 tcp_data_off_bytes(const struct tcp_hdr *th)
{
    return (u8)((th->data_off >> 4) * 4);
}

void tcp_recv(struct netdev *dev, const u8 *eth_src,
              const u8 *src_ip, const u8 *dst_ip,
              const u8 *seg, size_t len);

void tcp_set_now(u64 now_ms);

void tcp_tick(void);

long tcp_next_timeout_ms(void);

#endif