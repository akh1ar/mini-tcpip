#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>

#include "tcp.h"
#include "ip.h"
#include "checksum.h"
#include "netdev.h"
#include "common.h"

#define TCP_DEFAULT_WINDOW 65535

static inline int seq_lt(u32 a, u32 b)  { return (int32_t)(a - b) <  0; }
static inline int seq_leq(u32 a, u32 b) { return (int32_t)(a - b) <= 0; }
static inline int seq_gt(u32 a, u32 b)  { return seq_lt(b, a); }
static inline int seq_geq(u32 a, u32 b) { return seq_leq(b, a); }

struct tcp_pseudo_hdr {
    u8  src_ip[IP_ADDR_LEN];
    u8  dst_ip[IP_ADDR_LEN];
    u8  zero;
    u8  protocol;
    u16 tcp_length;
} __attribute__((packed));

static u16 tcp_checksum(const u8 *src_ip, const u8 *dst_ip,
                        const u8 *tcp_seg, size_t tcp_len)
{
    u8 buf[sizeof(struct tcp_pseudo_hdr) + FRAME_BUF_SIZE];

    if (tcp_len > FRAME_BUF_SIZE)
        return 0;

    struct tcp_pseudo_hdr *ph = (struct tcp_pseudo_hdr *)buf;

    memcpy(ph->src_ip, src_ip, IP_ADDR_LEN);
    memcpy(ph->dst_ip, dst_ip, IP_ADDR_LEN);

    ph->zero = 0;
    ph->protocol = IP_PROTO_TCP;
    ph->tcp_length = htons((u16)tcp_len);

    memcpy(buf + sizeof(*ph), tcp_seg, tcp_len);

    return inet_checksum(buf, sizeof(*ph) + tcp_len);
}

static int tcp_send_segment(struct netdev *dev, const u8 *dst_mac,
                            const u8 *src_ip, const u8 *dst_ip,
                            u16 src_port, u16 dst_port,
                            u32 seq, u32 ack, u8 flags, u16 window,
                            const u8 *data, size_t data_len)
{
    u8 segment[FRAME_BUF_SIZE];
    size_t seg_len = TCP_HDR_LEN + data_len;

    if (seg_len > sizeof(segment))
        return -1;

    struct tcp_hdr *th = (struct tcp_hdr *)segment;

    th->src_port = htons(src_port);
    th->dst_port = htons(dst_port);
    th->seq = htonl(seq);
    th->ack = htonl(ack);
    th->data_off = (TCP_HDR_LEN / 4) << 4;
    th->flags = flags;
    th->window = htons(window);
    th->checksum = 0;
    th->urg_ptr = 0;

    if (data && data_len)
        memcpy(segment + TCP_HDR_LEN, data, data_len);

    th->checksum = htons(tcp_checksum(src_ip, dst_ip, segment, seg_len));

    return ip_send(dev, dst_mac, dst_ip, IP_PROTO_TCP, segment, seg_len);
}

#define TCP_MAX_CONNS 16
#define TCP_ISS       0x00001000u

enum tcp_state {
    TCP_CLOSED = 0,
    TCP_LISTEN,
    TCP_SYN_RCVD,
    TCP_ESTABLISHED,
    TCP_CLOSE_WAIT,
    TCP_LAST_ACK
};

struct rtx_seg {
    u32 seq;
    u16 seg_len;
    u8 flags;
    u8 retransmitted;
    u64 sent_ms;
    u16 data_len;
    u8 data[TCP_MSS];
};

struct tcb {
    enum tcp_state state;

    u8 local_ip[IP_ADDR_LEN];
    u8 remote_ip[IP_ADDR_LEN];
    u16 local_port;
    u16 remote_port;
    u8 remote_mac[MAC_LEN];
    struct netdev *dev;

    u32 snd_una;
    u32 snd_nxt;
    u32 iss;

    u32 rcv_nxt;
    u32 irs;

    int srtt;
    int rttvar;
    int rto;
    u8 rtt_sampling;
    u32 rtt_seq;
    u64 rtt_start_ms;

    struct rtx_seg rtx[RTX_MAX];
    int rtx_count;

    u8 rtx_timer_on;
    u64 rtx_deadline_ms;
    u8 rtx_backoff;
    u8 rtx_retries;

    u32 cwnd;
    u32 ssthresh;
    u32 snd_wnd;
    u8 dupacks;
    u8 in_recovery;
};

static struct tcb tcp_conns[TCP_MAX_CONNS];

static struct tcb *tcb_lookup(const u8 *seg_src_ip, const u8 *seg_dst_ip,
                              u16 seg_src_port, u16 seg_dst_port)
{
    for (int i = 0; i < TCP_MAX_CONNS; i++) {
        struct tcb *t = &tcp_conns[i];

        if (t->state == TCP_CLOSED)
            continue;

        if (t->remote_port == seg_src_port &&
            t->local_port == seg_dst_port &&
            memcmp(t->remote_ip, seg_src_ip, IP_ADDR_LEN) == 0 &&
            memcmp(t->local_ip, seg_dst_ip, IP_ADDR_LEN) == 0)
            return t;
    }

    return NULL;
}

static struct tcb *tcb_alloc(void)
{
    for (int i = 0; i < TCP_MAX_CONNS; i++) {
        if (tcp_conns[i].state == TCP_CLOSED) {
            memset(&tcp_conns[i], 0, sizeof(tcp_conns[i]));
            return &tcp_conns[i];
        }
    }

    return NULL;
}

static void tcb_free(struct tcb *t)
{
    memset(t, 0, sizeof(*t));
}

static u64 g_now_ms;

void tcp_set_now(u64 now_ms)
{
    g_now_ms = now_ms;
}

static int rto_clamp(int rto)
{
    if (rto < RTO_MIN_MS)
        return RTO_MIN_MS;

    if (rto > RTO_MAX_MS)
        return RTO_MAX_MS;

    return rto;
}

static void rtt_sample_start(struct tcb *t, u32 seq)
{
    if (t->rtt_sampling)
        return;

    t->rtt_sampling = 1;
    t->rtt_seq = seq;
    t->rtt_start_ms = g_now_ms;
}

static void rtt_update(struct tcb *t, int r_ms)
{
    if (r_ms < 0)
        return;

    if (t->srtt == 0) {
        t->srtt = r_ms;
        t->rttvar = r_ms / 2;
    } else {
        int err = t->srtt - r_ms;

        if (err < 0)
            err = -err;

        t->rttvar = (3 * t->rttvar + err) / 4;
        t->srtt = (7 * t->srtt + r_ms) / 8;
    }

    t->rto = rto_clamp(t->srtt + 4 * t->rttvar);
}

static void rtt_ack(struct tcb *t, u32 ack)
{
    if (!t->rtt_sampling)
        return;

    if (seq_gt(ack, t->rtt_seq)) {
        rtt_update(t, (int)(g_now_ms - t->rtt_start_ms));
        t->rtt_sampling = 0;
    }
}

static void timer_arm(struct tcb *t)
{
    if (t->rtx_timer_on)
        return;

    t->rtx_timer_on = 1;
    t->rtx_deadline_ms = g_now_ms + (u64)t->rto;
}

static void timer_restart(struct tcb *t)
{
    t->rtx_timer_on = 1;
    t->rtx_deadline_ms = g_now_ms + (u64)t->rto;
}

static void timer_cancel(struct tcb *t)
{
    t->rtx_timer_on = 0;
}

static int rtx_enqueue(struct tcb *t, u32 seq, u16 seg_len, u8 flags,
                       const u8 *data, u16 data_len)
{
    if (t->rtx_count >= RTX_MAX)
        return -1;

    if (data_len > TCP_MSS)
        return -1;

    struct rtx_seg *e = &t->rtx[t->rtx_count++];

    e->seq = seq;
    e->seg_len = seg_len;
    e->flags = flags;
    e->retransmitted = 0;
    e->sent_ms = g_now_ms;
    e->data_len = data_len;

    if (data_len)
        memcpy(e->data, data, data_len);

    rtt_sample_start(t, seq);
    timer_arm(t);

    return 0;
}

static void rtx_ack(struct tcb *t, u32 una)
{
    int kept = 0;

    for (int i = 0; i < t->rtx_count; i++) {
        struct rtx_seg *e = &t->rtx[i];
        u32 end = e->seq + e->seg_len;

        if (seq_leq(end, una))
            continue;

        if (kept != i)
            t->rtx[kept] = *e;

        kept++;
    }

    t->rtx_count = kept;

    if (t->rtx_count == 0)
        timer_cancel(t);
    else
        timer_restart(t);
}

static int tcp_output(struct tcb *t, u8 flags,
                      const u8 *data, u16 data_len)
{
    u32 seq = t->snd_nxt;

    u16 seg_len = data_len
                + ((flags & TCP_SYN) ? 1u : 0u)
                + ((flags & TCP_FIN) ? 1u : 0u);

    if (data_len > 0) {
        u32 flight = t->snd_nxt - t->snd_una;
        u32 wnd = (t->cwnd < t->snd_wnd) ? t->cwnd : t->snd_wnd;

        if (flight + seg_len > wnd)
            return -1;
    }

    if (seg_len > 0) {
        if (rtx_enqueue(t, seq, seg_len, flags, data, data_len) != 0)
            return -1;
    }

    tcp_send_segment(t->dev, t->remote_mac, t->local_ip, t->remote_ip,
                     t->local_port, t->remote_port,
                     seq, t->rcv_nxt, flags, TCP_DEFAULT_WINDOW,
                     data, data_len);

    t->snd_nxt = seq + seg_len;

    return 0;
}

static void tcp_send_ack(struct tcb *t)
{
    tcp_send_segment(t->dev, t->remote_mac, t->local_ip, t->remote_ip,
                     t->local_port, t->remote_port,
                     t->snd_nxt, t->rcv_nxt,
                     TCP_ACK, TCP_DEFAULT_WINDOW, NULL, 0);
}

static void tcp_process_ack(struct tcb *t, u32 seg_ack, u16 seg_wnd,
                            size_t data_len, u8 flags)
{
    if (seq_gt(seg_ack, t->snd_una) &&
        seq_leq(seg_ack, t->snd_nxt)) {

        u32 acked = seg_ack - t->snd_una;
        t->snd_una = seg_ack;

        if (t->in_recovery) {
            t->cwnd = t->ssthresh;
            t->in_recovery = 0;
        } else if (t->cwnd < t->ssthresh) {
            t->cwnd += (acked < TCP_MSS) ? acked : TCP_MSS;
        } else {
            u32 inc = (u32)TCP_MSS * TCP_MSS / t->cwnd;
            t->cwnd += inc ? inc : 1;
        }

        t->dupacks = 0;
        t->rtx_backoff = 0;
        t->rtx_retries = 0;

        rtt_ack(t, seg_ack);
        rtx_ack(t, seg_ack);

    } else if (seg_ack == t->snd_una &&
               t->snd_una != t->snd_nxt &&
               data_len == 0 &&
               !(flags & (TCP_SYN | TCP_FIN)) &&
               seg_wnd == t->snd_wnd) {

        if (t->dupacks < 255)
            t->dupacks++;

        if (t->dupacks == TCP_DUPACK_THRESH && t->rtx_count > 0) {
            u32 flight = t->snd_nxt - t->snd_una;
            u32 half = flight / 2;

            t->ssthresh = (half > 2 * TCP_MSS) ? half : 2 * TCP_MSS;

            printf("  [tcp] fast retransmit (3 dup ACKs, ack=0x%08x)\n",
                   seg_ack);

            rtx_resend_oldest(t);
            timer_restart(t);

            t->cwnd = t->ssthresh + TCP_DUPACK_THRESH * TCP_MSS;
            t->in_recovery = 1;

        } else if (t->in_recovery) {
            t->cwnd += TCP_MSS;
        }
    }

    t->snd_wnd = seg_wnd;
}

static int tcp_is_listening(u16 port)
{
    return port == TCP_PORT_ECHO;
}

static void tcp_send_rst(struct netdev *dev, const u8 *eth_src,
                         const u8 *src_ip, const u8 *dst_ip,
                         const struct tcp_hdr *th, size_t data_len)
{
    u8 flags = th->flags;
    u32 seg_seq = ntohl(th->seq);
    u32 seg_ack = ntohl(th->ack);

    u32 seg_len = (u32)data_len
                + ((flags & TCP_SYN) ? 1u : 0u)
                + ((flags & TCP_FIN) ? 1u : 0u);

    u16 our_port = ntohs(th->dst_port);
    u16 peer_port = ntohs(th->src_port);

    if (flags & TCP_ACK) {
        tcp_send_segment(dev, eth_src, dst_ip, src_ip,
                         our_port, peer_port,
                         seg_ack, 0, TCP_RST, 0, NULL, 0);
    } else {
        tcp_send_segment(dev, eth_src, dst_ip, src_ip,
                         our_port, peer_port,
                         0, seg_seq + seg_len,
                         TCP_RST | TCP_ACK, 0, NULL, 0);
    }
}

void tcp_recv(struct netdev *dev, const u8 *eth_src,
              const u8 *src_ip, const u8 *dst_ip,
              const u8 *seg, size_t len)
{
    if (len < TCP_HDR_LEN) {
        printf("  [tcp] runt: %zu bytes (< %d), dropped\n",
               len, TCP_HDR_LEN);
        return;
    }

    const struct tcp_hdr *th = (const struct tcp_hdr *)seg;

    u8 hlen = tcp_data_off_bytes(th);

    if (hlen < TCP_HDR_LEN || (size_t)hlen > len) {
        printf("  [tcp] bad data offset (hlen=%u, avail=%zu), dropped\n",
               hlen, len);
        return;
    }

    if (tcp_checksum(src_ip, dst_ip, seg, len) != 0) {
        printf("  [tcp] bad checksum, dropped\n");
        return;
    }

    u16 src_port = ntohs(th->src_port);
    u16 dst_port = ntohs(th->dst_port);
    u32 seg_seq = ntohl(th->seq);
    u32 seg_ack = ntohl(th->ack);
    u8 flags = th->flags;

    const u8 *data = seg + hlen;
    size_t data_len = len - hlen;

    struct tcb *t = tcb_lookup(src_ip, dst_ip, src_port, dst_port);

    if (!t) {
        if (flags & TCP_RST)
            return;

        if ((flags & TCP_SYN) && tcp_is_listening(dst_port)) {
            t = tcb_alloc();

            if (!t) {
                printf("  [tcp] table full, refusing :%u with RST\n",
                       dst_port);

                tcp_send_rst(dev, eth_src, src_ip, dst_ip, th, data_len);
                return;
            }

            memcpy(t->local_ip, dst_ip, IP_ADDR_LEN);
            memcpy(t->remote_ip, src_ip, IP_ADDR_LEN);
            memcpy(t->remote_mac, eth_src, MAC_LEN);

            t->dev = dev;
            t->local_port = dst_port;
            t->remote_port = src_port;
            t->state = TCP_LISTEN;
            t->rto = RTO_INIT_MS;
            t->cwnd = TCP_INIT_CWND;
            t->ssthresh = 0xFFFFFFFFu;
            t->snd_wnd = ntohs(th->window);

        } else {
            printf("  [tcp] no connection/listener on :%u -> RST\n",
                   dst_port);

            tcp_send_rst(dev, eth_src, src_ip, dst_ip, th, data_len);
            return;
        }
    }

    if (flags & TCP_RST) {
        printf("  [tcp] RST received -> connection reset\n");
        tcb_free(t);
        return;
    }

    if (flags & TCP_ACK)
        tcp_process_ack(t, seg_ack, ntohs(th->window), data_len, flags);

    switch (t->state) {
        case TCP_LISTEN:
            if (!(flags & TCP_SYN)) {
                tcb_free(t);
                return;
            }

            t->irs = seg_seq;
            t->rcv_nxt = seg_seq + 1;
            t->iss = TCP_ISS;
            t->snd_una = t->iss;
            t->snd_nxt = t->iss;
            t->state = TCP_SYN_RCVD;

            printf("  [tcp] SYN from :%u -> SYN+ACK (iss=0x%08x, ack=0x%08x)\n",
                   src_port, t->iss, t->rcv_nxt);

            tcp_output(t, TCP_SYN | TCP_ACK, NULL, 0);
            break;

        case TCP_SYN_RCVD:
            if (t->snd_una == t->snd_nxt) {
                t->state = TCP_ESTABLISHED;

                printf("  [tcp] handshake complete -> ESTABLISHED (:%u <-> :%u)\n",
                       t->local_port, t->remote_port);
            }
            break;

        case TCP_ESTABLISHED:
            if (seg_seq != t->rcv_nxt) {
                tcp_send_ack(t);
                break;
            }

            if (data_len > 0) {
                t->rcv_nxt += (u32)data_len;

                if (tcp_output(t, TCP_ACK | TCP_PSH,
                               data, (u16)data_len) < 0) {

                    t->rcv_nxt -= (u32)data_len;

                    printf("  [tcp] echo queue full: segment dropped, "
                           "peer will retransmit\n");

                    break;
                }

                printf("  [tcp] ESTABLISHED: echo %zu bytes (rcv_nxt=0x%08x)\n",
                       data_len, t->rcv_nxt);
            }

            if (flags & TCP_FIN) {
                t->rcv_nxt += 1;
                t->state = TCP_CLOSE_WAIT;

                printf("  [tcp] FIN received -> CLOSE_WAIT, sending our FIN\n");

                tcp_output(t, TCP_FIN | TCP_ACK, NULL, 0);
                t->state = TCP_LAST_ACK;
            }
            break;

        case TCP_CLOSE_WAIT:
            if (flags & TCP_FIN)
                tcp_send_ack(t);
            break;

        case TCP_LAST_ACK:
            if (t->snd_una == t->snd_nxt) {
                printf("  [tcp] final ACK -> CLOSED (:%u <-> :%u), slot freed\n",
                       t->local_port, t->remote_port);

                tcb_free(t);
            }
            break;

        default:
            break;
    }
}

static void rtx_resend_oldest(struct tcb *t)
{
    struct rtx_seg *e = &t->rtx[0];

    printf("  [tcp] retransmit seq=0x%08x len=%u\n",
           e->seq, e->seg_len);

    tcp_send_segment(t->dev, t->remote_mac,
                     t->local_ip, t->remote_ip,
                     t->local_port, t->remote_port,
                     e->seq, t->rcv_nxt,
                     e->flags, TCP_DEFAULT_WINDOW,
                     e->data_len ? e->data : NULL,
                     e->data_len);

    e->retransmitted = 1;
    t->rtt_sampling = 0;
}

void tcp_tick(void)
{
    for (int i = 0; i < TCP_MAX_CONNS; i++) {
        struct tcb *t = &tcp_conns[i];

        if (t->state == TCP_CLOSED || !t->rtx_timer_on)
            continue;

        if (g_now_ms < t->rtx_deadline_ms)
            continue;

        printf("  [tcp] RTO fired (rto was %d ms)\n", t->rto);

        if (++t->rtx_retries > RTO_GIVEUP) {
            printf("  [tcp] %d consecutive timeouts -> aborting (:%u <-> :%u)\n",
                   RTO_GIVEUP, t->local_port, t->remote_port);

            tcp_send_segment(t->dev, t->remote_mac,
                             t->local_ip, t->remote_ip,
                             t->local_port, t->remote_port,
                             t->snd_nxt, 0,
                             TCP_RST, 0, NULL, 0);

            tcb_free(t);
            continue;
        }

        {
            u32 flight = t->snd_nxt - t->snd_una;
            u32 half = flight / 2;

            t->ssthresh = (half > 2 * TCP_MSS) ? half : 2 * TCP_MSS;
            t->cwnd = TCP_MSS;
            t->dupacks = 0;
            t->in_recovery = 0;
        }

        rtx_resend_oldest(t);

        t->rtx_backoff++;
        t->rto = rto_clamp(t->rto * 2);
        t->rtx_deadline_ms = g_now_ms + (u64)t->rto;
    }
}

long tcp_next_timeout_ms(void)
{
    long best = -1;

    for (int i = 0; i < TCP_MAX_CONNS; i++) {
        struct tcb *t = &tcp_conns[i];

        if (t->state == TCP_CLOSED || !t->rtx_timer_on)
            continue;

        long wait = (t->rtx_deadline_ms > g_now_ms)
                  ? (long)(t->rtx_deadline_ms - g_now_ms)
                  : 0;

        if (best < 0 || wait < best)
            best = wait;
    }

    return best;
}