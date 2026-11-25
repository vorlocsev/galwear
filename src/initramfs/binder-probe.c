/* SPDX-License-Identifier: GPL-2.0-only
 * Generic QEMU virt PID1 diagnostic, never for physical R800 deployment.
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

/* Exact pinned Linux 4.19.279 include/uapi/linux/android/binder.h ABI. */
struct binder_version { int32_t protocol_version; };
#define BINDER_VERSION _IOWR('b', 9, struct binder_version)
#define BINDER_SET_MAX_THREADS _IOW('b', 5, uint32_t)

int binder_probe(void)
{
    static const char *const paths[] = {
        "/dev/binder", "/dev/hwbinder", "/dev/vndbinder"
    };
    dev_t identities[3];
    if (getpid() != 1)
        return 1;
    /* RAM-backed virtual /dev only; stdout remains the inherited console. */
    if (mount("devtmpfs", "/dev", "devtmpfs", MS_NOSUID | MS_NOEXEC, NULL)) {
        perror("r800-binder: devtmpfs");
        return 1;
    }
    int rc = 1;
    for (unsigned int i = 0; i < 3; ++i) {
        int fd = open(paths[i], O_RDWR | O_CLOEXEC | O_NOFOLLOW);
        if (fd < 0) {
            perror(paths[i]);
            goto done;
        }
        struct stat st;
        struct binder_version version = {-1};
        uint32_t threads = 1;
        if (fstat(fd, &st) || !S_ISCHR(st.st_mode)
            || ioctl(fd, BINDER_VERSION, &version) || version.protocol_version != 8
            || ioctl(fd, BINDER_SET_MAX_THREADS, &threads)) {
            fprintf(stderr, "r800-binder: FAIL %s version/device/ioctl\n", paths[i]);
            close(fd);
            goto done;
        }
        identities[i] = st.st_rdev;
        for (unsigned int j = 0; j < i; ++j) {
            if (identities[j] == identities[i]) {
                close(fd);
                goto done;
            }
        }
        void *buf = mmap(NULL, 65536, PROT_READ, MAP_PRIVATE, fd, 0);
        if (buf == MAP_FAILED) {
            perror("r800-binder: mmap");
            close(fd);
            goto done;
        }
        /* Binder pages may be allocated lazily; do not dereference buffer. */
        int unmap_rc = munmap(buf, 65536);
        int close_rc = close(fd);
        if (unmap_rc || close_rc)
            goto done;
        printf("r800-binder: %s version=8 mmap=PASS\n", paths[i] + 5);
    }
    rc = 0;
done:
    if (umount("/dev"))
        rc = 1;
    if (rc == 0)
        puts("r800-binder: PASS");
    return rc;
}
