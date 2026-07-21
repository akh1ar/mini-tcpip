#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <time.h>

#include "tap.h"
#include "ethernet.h"
#include "tcp.h"
#include "netdev.h"
#include "common.h"

static u64 now_ms(void){
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (u64)ts.tv_sec * 1000u + (u64)(ts.tv_nsec / 1000000L);
}

int main(void){
    struct netdev nd;
    u8 buf[FRAME_BUF_SIZE];

    strcpy(nd.name, "tap0");
    nd.fd = tap_alloc(nd.name);

    /*locally-administered unicast, from netdev.h)*/
    memcpy(nd.hwaddr, (u8[])MTCP_HWADDR_INIT, MAC_LEN);

    if(inet_pton(AF_INET, MTCP_IPV4_STR, &nd.ipv4) != 1)
        die("inet_pton(MTCP_IPV4_STR)");

    printf("[+] TAP ready: %s (fd=%d)  ip=%s  mac=%02x:%02x:%02x:%02x:%02x:%02x\n",
           nd.name, nd.fd, MTCP_IPV4_STR,
           nd.hwaddr[0], nd.hwaddr[1], nd.hwaddr[2],
           nd.hwaddr[3], nd.hwaddr[4], nd.hwaddr[5]);
    printf("[+] In another terminal, run:\n");
    printf("      sudo ip addr add 10.0.0.1/24 dev %s\n", nd.name);
    printf("      sudo ip link set %s up\n", nd.name);
    printf("      ping 10.0.0.2       # kernel will ARP; WE reply\n");
    printf("      ip neigh show dev %s   # should show 10.0.0.2 -> our mac\n\n",
           nd.name);

    for(;;){
        tcp_set_now(now_ms());

        long budget = tcp_next_timeout_ms();
        struct timeval tv, *tvp = NULL;
        if (budget >= 0){
            tv.tv_sec  = budget / 1000;
            tv.tv_usec = (budget % 1000) * 1000;
            tvp = &tv;
        }
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(nd.fd, &rfds);

        int r = select(nd.fd + 1, &rfds, NULL, NULL, tvp);
        if(r < 0){
            if(errno == EINTR)
                continue;
            die("select(tap)");
        }
        tcp_set_now(now_ms());

        if(r>0 && FD_ISSET(nd.fd, &rfds)){
            ssize_t n = read(nd.fd, buf, sizeof(buf));
            if(n<0){
                if(errno==EINTR)
                    continue;
                die("read(tap)");
            }if(n==0)           
                break;
            eth_recv(&nd, buf, (size_t)n);
        }tcp_tick();
    }

    close(nd.fd);
    return 0;
}
