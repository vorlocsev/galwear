/* SPDX-License-Identifier: GPL-2.0-only
 * Disposable property-profile QEMU PID1; no real Android policy loaded.
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/vfs.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>

static const char socket_path[] = "/data/galwear-property-test.sock";

static int peer(int fd, pid_t expected)
{
    struct ucred cred;
    socklen_t n = sizeof(cred);
    return getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &n) ||
           n != sizeof(cred) || cred.pid != expected || cred.uid != 0 || cred.gid != 0;
}

static int unix_probe(void)
{
    struct sockaddr_un addr = {.sun_family = AF_UNIX};
    memcpy(addr.sun_path, socket_path, sizeof(socket_path));
    int listener = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (listener < 0 || bind(listener, (struct sockaddr *)&addr, sizeof(addr)) ||
        listen(listener, 1))
        return 1;
    pid_t parent = getpid(), child = fork();
    if (child < 0)
        return 1;
    if (child == 0) {
        close(listener);
        int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        char reply[4];
        if (fd < 0 || connect(fd, (struct sockaddr *)&addr, sizeof(addr)) ||
            peer(fd, parent) || send(fd, "ping", 4, MSG_NOSIGNAL) != 4 ||
            recv(fd, reply, sizeof(reply), MSG_WAITALL) != 4 ||
            memcmp(reply, "pong", 4))
            _exit(1);
        _exit(close(fd) != 0);
    }
    int fd = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
    char request[4];
    if (fd < 0 || peer(fd, child) ||
        recv(fd, request, sizeof(request), MSG_WAITALL) != 4 ||
        memcmp(request, "ping", 4) || send(fd, "pong", 4, MSG_NOSIGNAL) != 4)
        return 1;
    int status;
    if (close(fd) || close(listener) || waitpid(child, &status, 0) != child ||
        !WIFEXITED(status) || WEXITSTATUS(status) || unlink(socket_path))
        return 1;
    puts("r800-property-kernel: unix stream=PASS peercred=PASS");
    return 0;
}

static int read_number(const char *path, long *value)
{
    char bytes[32];
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return 1;
    ssize_t n = read(fd, bytes, sizeof(bytes) - 1);
    if (close(fd) || n <= 0 || n >= (ssize_t)sizeof(bytes) - 1)
        return 1;
    bytes[n] = '\0';
    char *end;
    *value = strtol(bytes, &end, 10);
    return end == bytes || (*end != '\0' && (*end != '\n' || end[1] != '\0'));
}

static int selinux_probe(void)
{
    struct statfs fs;
    long enforce, version;
    if (mount("sysfs", "/sys", "sysfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) ||
        mount("selinuxfs", "/sys/fs/selinux", "selinuxfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) ||
        statfs("/sys/fs/selinux", &fs) || (unsigned long)fs.f_type != 0xf97cff8cUL ||
        read_number("/sys/fs/selinux/enforce", &enforce) || enforce != 1 ||
        read_number("/sys/fs/selinux/policyvers", &version) || version <= 0 || version > 255)
        return 1;
    puts("r800-property-kernel: selinuxfs=PASS enforce=1 policy-not-loaded-by-probe");
    return 0;
}

static int xattr_probe(void)
{
    static const char value[] = "galwear-fixture";
    static const char label[] = "u:object_r:default_prop:s0";
    char observed[256];
    int fd = open("/data/xattr-test", O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0 || fsetxattr(fd, "trusted.galwear", value, sizeof(value), XATTR_CREATE) ||
        fgetxattr(fd, "trusted.galwear", observed, sizeof(observed)) != (ssize_t)sizeof(value) ||
        memcmp(observed, value, sizeof(value)) ||
        fremovexattr(fd, "trusted.galwear") ||
        fsetxattr(fd, "security.selinux", label, sizeof(label), 0) ||
        fgetxattr(fd, "security.selinux", observed, sizeof(observed)) <= 0 ||
        close(fd) || unlink("/data/xattr-test"))
        return 1;
    /* Before policy load, getsecurity can report an initial SID rather
     * than the requested label. Do not claim an effective label match. */
    puts("r800-property-kernel: tmpfs trusted-xattr=PASS security-label-io=PASS");
    return 0;
}

int main(void)
{
    if (getpid() != 1 || setvbuf(stdout, NULL, _IONBF, 0))
        return 1;
    puts("r800-readonly-init: NON-RELEASE smoke image; no eMMC mount, no Wear OS handover");
    if (mount("tmpfs", "/data", "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, "size=1m") ||
        unix_probe() || selinux_probe() || xattr_probe()) {
        fputs("r800-property-kernel: FAIL\n", stderr);
        return 2;
    }
    if (umount("/sys/fs/selinux") || umount("/sys") || umount("/data"))
        return 3;
    puts("r800-property-kernel: PASS");
    const struct timespec delay = {5, 0};
    unsigned int sequence = 0;
    for (;;) {
        if (!nanosleep(&delay, NULL) && sequence != 0xffffffffU)
            printf("r800-readonly-init: heartbeat %08x\n", ++sequence);
    }
}
