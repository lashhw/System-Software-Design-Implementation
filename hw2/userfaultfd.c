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
#include <stdbool.h>
#include <assert.h>

#define PAGE_SHIFT 12
#define PAGE_SIZE (1UL << PAGE_SHIFT)
#define PAGE_MASK (PAGE_SIZE - 1)

// Page table levels
#define LEVEL_PGD 0
#define LEVEL_PUD 1
#define LEVEL_PMD 2
#define LEVEL_PTE 3
#define NUM_LEVELS 4

#define __NR_remap_page_table 451

#define ENTRIES_PER_TABLE (PAGE_SIZE / sizeof(uint64_t))
#define VA_PGD_SHIFT      39
#define VA_PUD_SHIFT      30
#define VA_PMD_SHIFT      21
#define VA_PTE_SHIFT      12
#define VA_INDEX_MASK     0x1FF

#define TABLE_ENTRY_MASK    0x3
#define TABLE_ENTRY_VALUE   0x3
#define NEXT_LVL_ADDR_SHIFT 12
#define NEXT_LVL_ADDR_MASK  (((1UL << (48 - NEXT_LVL_ADDR_SHIFT)) - 1) << NEXT_LVL_ADDR_SHIFT)
#define PTE_FLAG            0x00E8000000000F43UL

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

struct pte_tracker_t {
    unsigned long table_pfn;
    unsigned long table_idx;
    uint64_t original_entry;
};

struct pte_tracker_t *trackers = NULL;
size_t tracker_size = 0;

unsigned long get_index(unsigned long va, unsigned int level) {
    int shift;
    switch (level) {
        case LEVEL_PGD: shift = VA_PGD_SHIFT; break;
        case LEVEL_PUD: shift = VA_PUD_SHIFT; break;
        case LEVEL_PMD: shift = VA_PMD_SHIFT; break;
        case LEVEL_PTE: shift = VA_PTE_SHIFT; break;
        default: assert(false);
    }
    return (va >> shift) & VA_INDEX_MASK;
}

uint64_t *remap_table(unsigned int level, unsigned long pfn) {
    void *mapped_addr = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    assert(mapped_addr != MAP_FAILED);

    struct expose_pgtbl_args args = {
        .pid = getpid(),
        .remap_vaddr = (unsigned long)mapped_addr,
        .pfn = pfn,
        .level = level
    };

    assert(syscall(__NR_remap_page_table, &args) == 0);
    return (uint64_t *)mapped_addr;
}

void add_tracker(struct pte_tracker_t tracker) {
    tracker_size++;
    trackers = realloc(trackers, tracker_size * sizeof(struct pte_tracker_t));
    trackers[tracker_size - 1] = tracker;
}

void unmap_user_pte() {
    for (int i = 0; i < tracker_size; i++) {
        struct pte_tracker_t tracker = trackers[i];
        uint64_t *table_ptr = remap_table(LEVEL_PTE, tracker.table_pfn);
        table_ptr[tracker.table_idx] = tracker.original_entry;
        munmap(table_ptr, PAGE_SIZE);
    }
    tracker_size = 0;
}

unsigned long parse_table_entry(uint64_t entry) {
    if ((entry & TABLE_ENTRY_MASK) == TABLE_ENTRY_VALUE) {
        unsigned long next_lvl_addr = entry & NEXT_LVL_ADDR_MASK;
        unsigned long next_pfn = next_lvl_addr >> NEXT_LVL_ADDR_SHIFT;
        return next_pfn;
    } else {
        return 0;
    }
}

unsigned long va_to_pa(unsigned long va) {
    // printf("va_to_pa(va=0x%lx) called\n", va);

    unsigned long current_pfn = 0;
    for (int level = 0; level < NUM_LEVELS; ++level) {
        uint64_t *table_ptr = remap_table(level, current_pfn);

        unsigned long index = get_index(va, level);
        uint64_t entry = table_ptr[index];
        current_pfn = parse_table_entry(entry);
        // printf(" -> next pfn (level %d): 0x%lx\n", level, current_pfn);

        munmap(table_ptr, PAGE_SIZE);
        assert(current_pfn);
    }

    return (current_pfn << PAGE_SHIFT) | (va & PAGE_MASK);
}

void map_fault_va_to_pa(unsigned long fault_va, unsigned long pa) {
    // printf("map_fault_va_to_pa(fault_va=0x%lx, pa=0x%lx) called\n", fault_va, pa);
    unsigned long target_pfn = pa >> PAGE_SHIFT;

    unsigned long current_pfn = 0;
    for (int level = 0; level < NUM_LEVELS; ++level) {
        unsigned long table_pfn = current_pfn;
        uint64_t *table_ptr = remap_table(level, current_pfn);

        unsigned long index = get_index(fault_va, level);
        uint64_t entry = table_ptr[index];
        current_pfn = parse_table_entry(entry);
        // printf(" -> next pfn (level %d): 0x%lx\n", level, current_pfn);

        if (!current_pfn) {
            assert(level == 3);
            table_ptr[index] = PTE_FLAG | (target_pfn << NEXT_LVL_ADDR_SHIFT);
            struct pte_tracker_t tracker = {
                .table_pfn = table_pfn,
                .table_idx = index,
                .original_entry = entry
            };
            add_tracker(tracker);
        }

        munmap(table_ptr, PAGE_SIZE);
    }
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
        char *template_page = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        template_page[0] = 0;  // trigger page fault
        unsigned long pa = va_to_pa((unsigned long)template_page);
        map_fault_va_to_pa(fault_addr, pa);

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
    unmap_user_pte();
    munmap(region, 10 * PAGE_SIZE);

    printf("Program completed successfully\n");
    return 0;
}
