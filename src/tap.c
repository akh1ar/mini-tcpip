#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>

#include "tap.h"
#include "common.h"

int tap_alloc(char *dev)
{
    struct ifreq ifr;
    int fd;

    if ((fd = open("/dev/net/tun", O_RDWR)) < 0)
        die("open(/dev/net/tun)");

    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

    if (*dev)
        strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);

    if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) {
        close(fd);
        die("ioctl(TUNSETIFF)");
    }

    strcpy(dev, ifr.ifr_name);

    return fd;
}