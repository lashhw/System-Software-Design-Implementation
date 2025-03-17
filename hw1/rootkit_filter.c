#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include "rootkit.h"

int main(int argc, char *argv[]) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s [add|remove] <process_name> <syscall_nr>\n", argv[0]);
        return 1;
    }

    const char *action = argv[1];
    const char *process_name = argv[2];
    int syscall_nr = atoi(argv[3]);
    
    int fd = open("/dev/rootkit", O_RDWR);
    assert(fd != -1);

    struct filter_info filter = {
        .syscall_nr = syscall_nr
    };
    strncpy(filter.comm, process_name, TASK_FILTER_LEN - 1);
    filter.comm[TASK_FILTER_LEN - 1] = '\0';

    printf("before ioctl\n");
    if (strcmp(action, "add") == 0) {
        assert(ioctl(fd, IOCTL_ADD_FILTER, &filter) == 0);
    } else if (strcmp(action, "remove") == 0){
        assert(ioctl(fd, IOCTL_REMOVE_FILTER, &filter) == 0);
    } else {
        assert(0);
    }
    printf("after ioctl\n");

    assert(close(fd) == 0);
    return 0;
}