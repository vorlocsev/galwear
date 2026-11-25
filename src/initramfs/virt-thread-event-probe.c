/* SPDX-License-Identifier: GPL-2.0-only */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/futex.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

static _Atomic uint32_t word;
static _Atomic int ready;
static _Thread_local int tls = 17;
static int child_ok;

static long futex(int op, uint32_t value, const struct timespec *timeout)
{
    return syscall(SYS_futex, &word, op, value, timeout, NULL, 0);
}

static void *worker(void *arg)
{
    const struct timespec timeout = { .tv_sec = 2 };
    if (tls != 17) return NULL;
    tls = 29;
    atomic_store(&ready, 1);
    long result = futex(FUTEX_WAIT_PRIVATE, 0, &timeout);
    child_ok = result == 0 && tls == 29;
    return arg;
}

static int thread_check(void)
{
    const struct timespec short_wait = { .tv_nsec = 10000000 };
    if (futex(FUTEX_WAIT_PRIVATE, 1, &short_wait) != -1 || errno != EAGAIN)
        return 1;
    if (futex(FUTEX_WAIT_PRIVATE, 0, &short_wait) != -1 || errno != ETIMEDOUT)
        return 2;
    pthread_t thread;
    int token = 42, woke = 0;
    void *result = NULL;
    if (pthread_create(&thread, NULL, worker, &token)) return 3;
    for (unsigned i = 0; i < 100 && !woke; ++i) {
        if (atomic_load(&ready)) {
            long n = futex(FUTEX_WAKE_PRIVATE, 1, NULL);
            if (n == 1) woke = 1;
            if (n < 0) break;
        }
        if (!woke) nanosleep(&short_wait, NULL);
    }
    if (pthread_join(thread, &result)) _exit(12);
    return !woke || !child_ok || result != &token || tls != 17 ? 4 : 0;
}

static int memory_check(void)
{
    long page = sysconf(_SC_PAGESIZE);
    if (page <= 0 || page > 65536) return 1;
#ifndef GALWEAR_HOST_TEST
    if (page != 4096) return 1;
#endif
    unsigned char *p = mmap(NULL, (size_t)page, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return 2;
    int failed = p[0] != 0 || p[page - 1] != 0;
    p[0] = 0x5a;
    p[page - 1] = 0xa5;
    if (mprotect(p, (size_t)page, PROT_READ)) failed = 1;
    if (p[0] != 0x5a || p[page - 1] != 0xa5) failed = 1;
    if (munmap(p, (size_t)page)) failed = 1;
    return failed;
}

static int event_check(void)
{
    int e = epoll_create1(EPOLL_CLOEXEC);
    if (e < 0) return 1;
    int fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    if (fd < 0) { close(e); return 2; }
    struct epoll_event ev = { .events = EPOLLIN, .data.u64 = 0x1234 };
    uint64_t value = 7, received = 0;
    int failed = epoll_ctl(e, EPOLL_CTL_ADD, fd, &ev) ||
                 epoll_wait(e, &ev, 1, 0) != 0 ||
                 write(fd, &value, sizeof(value)) != (ssize_t)sizeof(value) ||
                 epoll_wait(e, &ev, 1, 1000) != 1 ||
                 ev.data.u64 != 0x1234 || !(ev.events & EPOLLIN) ||
                 read(fd, &received, sizeof(received)) != (ssize_t)sizeof(received) ||
                 received != value || epoll_wait(e, &ev, 1, 0) != 0;
    if (close(fd)) failed = 1;
    if (close(e)) failed = 1;
    return failed;
}

int main(void)
{
#ifndef GALWEAR_HOST_TEST
    if (getpid() != 1) return 1;
#endif
    if (setvbuf(stdout, NULL, _IONBF, 0)) return 1;
    puts("r800-readonly-init: NON-RELEASE smoke image; no eMMC mount, no Wear OS handover");
    if (memory_check()) return 2;
    puts("r800-thread-event: mmap-mprotect=PASS");
    if (thread_check()) return 3;
    puts("r800-thread-event: futex-eagain-timeout-wake=PASS pthread-tls=PASS");
    if (event_check()) return 4;
    puts("r800-thread-event: epoll-eventfd=PASS");
    puts("r800-thread-event: PASS");
#ifndef GALWEAR_HOST_TEST
    for (unsigned i = 1; i != 0; ++i) {
        if (sleep(5)) return 5;
        printf("r800-readonly-init: heartbeat %08x\n", i);
    }
#endif
    return 0;
}
