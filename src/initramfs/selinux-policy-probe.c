/* SPDX-License-Identifier: GPL-2.0-only
 * Generic virt only. Embedded diagnostic policy is not Android sepolicy.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>
#include "policy_blob.h"

static int enforcing(void)
{
    char value[8];
    int fd = open("/sys/fs/selinux/enforce", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    ssize_t n = read(fd, value, sizeof(value));
    return close(fd) == 0 && n == 1 && value[0] == '1';
}

static int load_policy(void)
{
    int fd = open("/sys/fs/selinux/load", O_WRONLY | O_CLOEXEC);
    if (fd < 0) return 1;
    ssize_t n = write(fd, policy_blob, sizeof(policy_blob));
    return close(fd) || n != (ssize_t)sizeof(policy_blob) || !enforcing();
}

static int check_access(void)
{
    const char allowed[] = "/data/allowed";
    const char denied[] = "/data/denied";
    const char label[] = "user_u:base_r:denied_t";
    char observed[128], value;
    int a = open(allowed, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
    int b = open(denied, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
    if (a < 0 || b < 0 || write(a, "A", 1) != 1 ||
        write(b, "B", 1) != 1 || fsetxattr(b, "security.selinux", label, sizeof(label), 0))
        return 1;
    if (close(a) || close(b)) return 1;
    ssize_t n = getxattr(denied, "security.selinux", observed, sizeof(observed));
    if (n != (ssize_t)sizeof(label) || memcmp(observed, label, sizeof(label)))
        return 1;
    struct stat sa, sb;
    if (stat(allowed, &sa) || stat(denied, &sb) ||
        sa.st_uid != sb.st_uid || sa.st_gid != sb.st_gid ||
        sa.st_mode != sb.st_mode || sa.st_size != sb.st_size || getuid() != 0)
        return 1;
    puts("r800-policy: label=PASS same-dac=PASS");
    a = open(allowed, O_RDONLY | O_CLOEXEC);
    if (a < 0 || read(a, &value, 1) != 1 || value != 'A' || close(a))
        return 1;
    puts("r800-policy: allowed-read=PASS");
    errno = 0;
    b = open(denied, O_RDONLY | O_CLOEXEC);
    if (b != -1 || errno != EACCES || !enforcing())
        return 1;
    puts("r800-policy: denied-read=EACCES enforce=1");
    return 0;
}

int main(void)
{
    if (getpid() != 1 || setvbuf(stdout, NULL, _IONBF, 0)) return 1;
    puts("r800-readonly-init: NON-RELEASE smoke image; no eMMC mount, no Wear OS handover");
    if (mount("sysfs", "/sys", "sysfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) ||
        mount("selinuxfs", "/sys/fs/selinux", "selinuxfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) ||
        !enforcing() || load_policy()) return 2;
    puts("r800-policy: load=PASS enforce=1 fixture-only");
    if (mount("tmpfs", "/data", "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, "size=1m") ||
        check_access()) return 3;
    puts("r800-policy: PASS");
    const struct timespec delay = {5, 0};
    unsigned int sequence = 0;
    for (;;) {
        if (!nanosleep(&delay, NULL) && sequence != 0xffffffffU)
            printf("r800-readonly-init: heartbeat %08x\n", ++sequence);
    }
}
