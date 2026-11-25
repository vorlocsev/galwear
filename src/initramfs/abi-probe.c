/* SPDX-License-Identifier: GPL-2.0-only
 * Separate NON-RELEASE userspace ABI probe. Not an init or hardware test.
 */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <time.h>

enum { BYTES = 1024 * 1024 };
struct work {
    unsigned char *data;
    long tid;
    unsigned int mismatch;
};

static unsigned char pattern(size_t i)
{
    return (unsigned char)((i * 31U) ^ (i >> 8) ^ 0x5aU);
}

static void *worker(void *arg)
{
    struct work *w = arg;
    w->tid = syscall(SYS_gettid);
    for (size_t i = 0; i < BYTES; ++i) {
        if (w->data[i] != pattern(i))
            ++w->mismatch;
        w->data[i] = (unsigned char)(pattern(i) ^ 0xffU);
    }
    return NULL;
}

static int fail(const char *stage)
{
    fprintf(stderr, "r800-abi: FAIL %s\n", stage);
    return 1;
}

int main(void)
{
    struct timespec before, after, delay = {0, 20000000};
    pthread_t thread;
    struct work w = {0};
    const long parent = syscall(SYS_gettid);
    if (parent <= 0 || clock_gettime(CLOCK_MONOTONIC, &before))
        return fail("initial syscall");
    w.data = mmap(NULL, BYTES, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (w.data == MAP_FAILED)
        return fail("mmap");
    for (size_t i = 0; i < BYTES; ++i) {
        if (w.data[i] != 0)
            return fail("zero fill");
        w.data[i] = pattern(i);
    }
    puts("r800-abi: mmap-zero-fill PASS bytes=1048576");
    if (pthread_create(&thread, NULL, worker, &w))
        return fail("pthread_create");
    if (pthread_join(thread, NULL))
        return fail("pthread_join");
    if (w.tid <= 0 || w.tid == parent || w.mismatch)
        return fail("worker identity or memory");
    for (size_t i = 0; i < BYTES; ++i)
        if (w.data[i] != (unsigned char)(pattern(i) ^ 0xffU))
            return fail("shared memory");
    puts("r800-abi: pthread-shared-memory PASS distinct-tid=1");
    if (mprotect(w.data, BYTES, PROT_READ))
        return fail("mprotect");
    for (size_t i = 0; i < BYTES; ++i)
        if (w.data[i] != (unsigned char)(pattern(i) ^ 0xffU))
            return fail("read-only memory");
    if (munmap(w.data, BYTES))
        return fail("munmap");
    puts("r800-abi: mprotect-munmap PASS");
    if (clock_gettime(CLOCK_MONOTONIC, &before) || nanosleep(&delay, NULL)
            || clock_gettime(CLOCK_MONOTONIC, &after))
        return fail("clock or sleep");
    long long elapsed = (after.tv_sec - before.tv_sec) * 1000000000LL
                      + after.tv_nsec - before.tv_nsec;
    if (elapsed < 20000000)
        return fail("monotonic elapsed");
    puts("r800-abi: monotonic-sleep PASS");
    puts("r800-abi: PASS");
    return 0;
}
