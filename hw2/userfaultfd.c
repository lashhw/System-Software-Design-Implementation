#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/userfaultfd.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#define PAGE_SHIFT 12
#define PAGE_SIZE (1UL << PAGE_SHIFT)
#define BIT_MASK ((1UL << 9) - 1)    // 9 bits for indexing (512 entries)

// Page table levels
#define LEVEL_PGD 0
#define LEVEL_PUD 1
#define LEVEL_PMD 2
#define LEVEL_PTE 3

// Arguments for exposing page tables
struct expose_pgtbl_args {
    pid_t pid;
    unsigned long remap_vaddr;
    unsigned long pfn;
    unsigned int level;
};

// Arguments for the fault handler thread
struct handler_args {
    int uffd;
};

unsigned long va_to_pa(unsigned long va) {
    return 0;
}

void map_fault_va_to_pa(unsigned long va, unsigned long pte) {
    return;
}

// Page fault handler thread
static void *fault_handler(void *arg) {
    struct handler_args *h = (struct handler_args *)arg;
    struct pollfd pfd = {.fd = h->uffd, .events = POLLIN};
    struct uffd_msg msg;

    for (;;) {
        if (poll(&pfd, 1, -1) <= 0) {
            continue;
        }

        if (read(h->uffd, &msg, sizeof(msg)) != sizeof(msg)) {
            continue;
        }

        if (msg.event != UFFD_EVENT_PAGEFAULT) {
            continue;
        }

        // Get fault address and page-aligned address
        unsigned long page_fault_addr = msg.arg.pagefault.address;
        unsigned long fault_addr = page_fault_addr & ~(PAGE_SIZE - 1);

        // TODO

        // Wake up the faulting thread
        struct uffdio_range ur = {
            .start = fault_addr,
            .len = PAGE_SIZE,
        };

        if (ioctl(h->uffd, UFFDIO_WAKE, &ur) == -1) {
            perror("ioctl(UFFDIO_WAKE) failed");
        }
    }

    return NULL;
}

int main(int argc, char **argv) {
    int uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
    if (uffd < 0) {
        perror("userfaultfd failed");
        return 1;
    }

    struct uffdio_api ua = {.api = UFFD_API};
    if (ioctl(uffd, UFFDIO_API, &ua) == -1) {
        perror("ioctl(UFFDIO_API) failed");
        return 1;
    }

    // Allocate memory region to be handled by userfaultfd
    char *region = mmap(NULL, 10 * PAGE_SIZE, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (region == MAP_FAILED) {
        perror("mmap failed for region");
        return 1;
    }

    // Register the region with userfaultfd
    struct uffdio_register ur = {
        .range.start = (unsigned long)region,
        .range.len = 10 * PAGE_SIZE,
        .mode = UFFDIO_REGISTER_MODE_MISSING,
    };

    if (ioctl(uffd, UFFDIO_REGISTER, &ur) == -1) {
        perror("ioctl(UFFDIO_REGISTER) failed");
        return 1;
    }

    struct handler_args h = {
        .uffd = uffd,
    };

    pthread_t tid;
    if (pthread_create(&tid, NULL, fault_handler, &h) != 0) {
        perror("Failed to create fault handler thread");
        return 1;
    }

    printf("Fault handler thread created\n");

    // Access pages to trigger faults
    for (size_t i = 0; i < 10 * PAGE_SIZE; i += PAGE_SIZE) {
        volatile char c = region[i]; // Read to trigger fault
        printf("Page %zu: First byte was %c\n", i / PAGE_SIZE, c);

        region[i] = 'A' + (i / PAGE_SIZE); // Write to page
        printf("Page %zu: First byte now %c\n", i / PAGE_SIZE, region[i]);
    }

    printf("All pages accessed successfully\n");

    printf("Cleaning up resources...\n");

    pthread_cancel(tid);
    pthread_join(tid, NULL);

    if (ioctl(uffd, UFFDIO_UNREGISTER, &ur) == -1) {
        perror("ioctl(UFFDIO_UNREGISTER) failed");
    }

    close(uffd);
    munmap(region, 10 * PAGE_SIZE);

    printf("Program completed successfully\n");
    return 0;
}