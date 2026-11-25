/* SPDX-License-Identifier: GPL-2.0-only
 * Shared memory diagnostic for disposable QEMU virt only.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <linux/ashmem.h>

enum { REGION = 65536 };

static unsigned char pattern(size_t i)
{
    return (unsigned char)((i * 37U) ^ (i >> 8) ^ 0xa5U);
}

static int shared_roundtrip(int fd)
{
    unsigned char *p = mmap(NULL, REGION, PROT_READ | PROT_WRITE,
                            MAP_SHARED, fd, 0);
    if (p == MAP_FAILED)
        return -1;
    int rc = -1;
    for (size_t i = 0; i < REGION; ++i) {
        if (p[i] != 0)
            goto done;
        p[i] = pattern(i);
    }
    pid_t child = fork();
    if (child < 0)
        goto done;
    if (child == 0) {
        if (munmap(p, REGION))
            _exit(2);
        unsigned char *q = mmap(NULL, REGION, PROT_READ | PROT_WRITE,
                                MAP_SHARED, fd, 0);
        if (q == MAP_FAILED)
            _exit(3);
        for (size_t i = 0; i < REGION; ++i) {
            if (q[i] != pattern(i))
                _exit(4);
            q[i] = (unsigned char)(pattern(i) ^ 0xffU);
        }
        _exit(munmap(q, REGION) == 0 ? 0 : 5);
    }
    int status;
    pid_t waited;
    do {
        waited = waitpid(child, &status, 0);
    } while (waited < 0 && errno == EINTR);
    if (waited != child || !WIFEXITED(status) || WEXITSTATUS(status))
        goto done;
    for (size_t i = 0; i < REGION; ++i)
        if (p[i] != (unsigned char)(pattern(i) ^ 0xffU))
            goto done;
    rc = 0;
done:
    if (munmap(p, REGION))
        rc = -1;
    return rc;
}

static int ashmem_probe(void)
{
    int fd = open("/dev/ashmem", O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return -1;
    struct stat st;
    char name[ASHMEM_NAME_LEN] = "galwear-virt-diagnostic";
    char observed[ASHMEM_NAME_LEN] = {0};
    int rc = -1;
    if (fstat(fd, &st) || !S_ISCHR(st.st_mode) ||
        ioctl(fd, ASHMEM_SET_NAME, name) ||
        ioctl(fd, ASHMEM_GET_NAME, observed) ||
        memcmp(name, observed, strlen(name) + 1) ||
        ioctl(fd, ASHMEM_SET_SIZE, (size_t)REGION) ||
        ioctl(fd, ASHMEM_GET_SIZE) != REGION ||
        shared_roundtrip(fd))
        goto done;
    rc = 0;
done:
    if (close(fd))
        rc = -1;
    return rc;
}

static int memfd_probe(void)
{
    int fd = memfd_create("galwear-virt-diagnostic", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (fd < 0)
        return -1;
    int rc = -1;
    struct stat st;
    const int seals = F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE | F_SEAL_SEAL;
    if (ftruncate(fd, REGION) || fstat(fd, &st) ||
        !S_ISREG(st.st_mode) || st.st_size != REGION || shared_roundtrip(fd) ||
        fcntl(fd, F_ADD_SEALS, seals) || fcntl(fd, F_GET_SEALS) != seals)
        goto done;
    errno = 0;
    if (ftruncate(fd, REGION / 2) != -1 || errno != EPERM)
        goto done;
    errno = 0;
    if (ftruncate(fd, REGION * 2) != -1 || errno != EPERM)
        goto done;
    unsigned char byte = 0;
    errno = 0;
    if (pwrite(fd, &byte, 1, 0) != -1 || errno != EPERM)
        goto done;
    rc = 0;
done:
    if (close(fd))
        rc = -1;
    return rc;
}

int shared_memory_probe(void)
{
    if (getpid() != 1 || ashmem_probe()) {
        fputs("r800-shmem: FAIL ashmem\n", stderr);
        return 1;
    }
    puts("r800-shmem: ashmem size=65536 roundtrip=PASS");
    if (memfd_probe()) {
        fputs("r800-shmem: FAIL memfd\n", stderr);
        return 1;
    }
    puts("r800-shmem: memfd size=65536 roundtrip=PASS seals=PASS");
    puts("r800-shmem: PASS");
    return 0;
}
