#ifndef __ROOTKIT_HW2_H
#define __ROOTKIT_HW2_H

#include <linux/string.h>

#define MASQ_LEN 0x20
#define TASK_FILTER_LEN 0x20


struct masq_proc {
    char new_name[MASQ_LEN];
    char orig_name[MASQ_LEN];
};

struct masq_proc_req {
    size_t len;
    struct masq_proc *list;
};

struct filter_info {
    int syscall_nr;
    char comm[TASK_FILTER_LEN];
};

#define MAGIC 'k'
#define IOCTL_MOD_HIDE _IO(MAGIC, 0)
#define IOCTL_MOD_MASQ _IOR(MAGIC, 1, struct masq_proc_req)
#define IOCTL_ADD_FILTER _IOR(MAGIC, 2, struct filter_info)
#define IOCTL_REMOVE_FILTER _IOR(MAGIC, 3, struct filter_info)

#endif /* __ROOTKIT_HW2_H */
