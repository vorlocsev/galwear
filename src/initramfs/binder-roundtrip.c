/* SPDX-License-Identifier: GPL-2.0-only
 * Isolated QEMU virt Binder roundtrip. Never deploy as Android service manager.
 * Compile against the pinned kernel UAPI header.
 */
#define _GNU_SOURCE
#include <linux/android/binder.h>
#include <fcntl.h>
#include <stdint.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

_Static_assert(sizeof(struct binder_transaction_data) == 64, "64-bit Binder ABI required");
_Static_assert(sizeof(struct binder_write_read) == 48, "64-bit Binder ABI required");
_Static_assert(BINDER_CURRENT_PROTOCOL_VERSION == 8, "Binder v8 required");

enum { MAP_BYTES = 65536, CODE = 0x4757 };
static const uint32_t request = 0x1234abcdU, response = 0xedcb5432U;

struct endpoint {
    int fd;
    void *map;
};

static int open_endpoint(struct endpoint *e)
{
    e->fd = open("/dev/binder", O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    if (e->fd < 0)
        return -1;
    struct binder_version v = {0};
    uint32_t threads = 0;
    if (ioctl(e->fd, BINDER_VERSION, &v) || v.protocol_version != 8 ||
        ioctl(e->fd, BINDER_SET_MAX_THREADS, &threads))
        return -1;
    e->map = mmap(NULL, MAP_BYTES, PROT_READ, MAP_PRIVATE, e->fd, 0);
    return e->map == MAP_FAILED ? -1 : 0;
}

static void close_endpoint(struct endpoint *e)
{
    if (e->map != MAP_FAILED)
        munmap(e->map, MAP_BYTES);
    if (e->fd >= 0)
        close(e->fd);
}

static int write_command(int fd, uint32_t cmd, const void *arg, size_t len)
{
    unsigned char bytes[4 + sizeof(struct binder_transaction_data)];
    if (len > sizeof(bytes) - 4)
        return -1;
    memcpy(bytes, &cmd, 4);
    if (len)
        memcpy(bytes + 4, arg, len);
    struct binder_write_read wr = {
        .write_size = 4 + len,
        .write_buffer = (uintptr_t)bytes,
    };
    return ioctl(fd, BINDER_WRITE_READ, &wr) == 0 &&
        wr.write_consumed == wr.write_size ? 0 : -1;
}

static int read_transaction(struct endpoint *e, uint32_t expected,
                            struct binder_transaction_data *tr)
{
    /* The host watchdog bounds a blocked ioctl; reject unknown protocol
     * commands instead of attempting to interpret arbitrary payloads. */
    for (unsigned int attempt = 0; attempt < 32; ++attempt) {
        unsigned char bytes[512];
        struct binder_write_read wr = {
            .read_size = sizeof(bytes),
            .read_buffer = (uintptr_t)bytes,
        };
        if (ioctl(e->fd, BINDER_WRITE_READ, &wr) ||
            wr.read_consumed > sizeof(bytes) || !wr.read_consumed)
            return -1;
        int found = 0;
        for (size_t pos = 0; pos < wr.read_consumed;) {
            uint32_t cmd;
            if (wr.read_consumed - pos < sizeof(cmd))
                return -1;
            memcpy(&cmd, bytes + pos, sizeof(cmd));
            pos += sizeof(cmd);
            if (cmd == BR_NOOP || cmd == BR_TRANSACTION_COMPLETE || cmd == BR_OK)
                continue;
            if (cmd != expected || found ||
                wr.read_consumed - pos < sizeof(*tr))
                return -1;
            memcpy(tr, bytes + pos, sizeof(*tr));
            pos += sizeof(*tr);
            found = 1;
        }
        if (found)
            return 0;
    }
    return -1;
}

static int check_payload(const struct endpoint *e,
                         const struct binder_transaction_data *tr,
                         uint32_t expected)
{
    uintptr_t base = (uintptr_t)e->map, ptr = tr->data.ptr.buffer;
    uint32_t value;
    if (tr->data_size != sizeof(value) || tr->offsets_size != 0 ||
        (tr->flags & (TF_STATUS_CODE | TF_ONE_WAY)) ||
        ptr < base || ptr - base > MAP_BYTES - sizeof(value))
        return -1;
    memcpy(&value, (const void *)ptr, sizeof(value));
    return value == expected ? 0 : -1;
}

static int send_payload(int fd, uint32_t cmd, uint32_t value)
{
    struct binder_transaction_data tr = {
        .target.handle = 0, .code = CODE, .data_size = sizeof(value),
        .data.ptr.buffer = (uintptr_t)&value,
    };
    return write_command(fd, cmd, &tr, sizeof(tr));
}

static int server(int ready, int done, pid_t client)
{
    struct endpoint e = {-1, MAP_FAILED};
    struct binder_transaction_data tr;
    int32_t unused = 0;
    char ack;
    int rc = 1;
    if (open_endpoint(&e) ||
        ioctl(e.fd, BINDER_SET_CONTEXT_MGR, &unused) ||
        write_command(e.fd, BC_ENTER_LOOPER, NULL, 0) ||
        write(ready, "R", 1) != 1)
        goto out;
    close(ready);
    ready = -1;
    if (read_transaction(&e, BR_TRANSACTION, &tr) ||
        tr.code != CODE || tr.sender_pid != client ||
        check_payload(&e, &tr, request))
        goto out;
    if (send_payload(e.fd, BC_REPLY, response) ||
        write_command(e.fd, BC_FREE_BUFFER, &tr.data.ptr.buffer, sizeof(tr.data.ptr.buffer)))
        goto out;
    /* Keep context manager alive until client verified and freed reply. */
    if (read(done, &ack, 1) != 1 || ack != 'D')
        goto out;
    if (write_command(e.fd, BC_EXIT_LOOPER, NULL, 0))
        goto out;
    rc = 0;
out:
    if (ready >= 0)
        close(ready);
    close(done);
    close_endpoint(&e);
    return rc;
}

int binder_roundtrip(void)
{
    int ready[2], done[2], status = 0, rc = 1;
    struct endpoint e = {-1, MAP_FAILED};
    struct binder_transaction_data tr;
    char ack;
    pid_t client = getpid();
    if (client != 1 || pipe(ready))
        return 1;
    if (pipe(done)) {
        close(ready[0]);
        close(ready[1]);
        return 1;
    }
    pid_t child = fork();
    if (child == 0) {
        close(ready[0]);
        close(done[1]);
        _exit(server(ready[1], done[0], client));
    }
    close(ready[1]);
    close(done[0]);
    if (child < 0)
        goto out;
    if (read(ready[0], &ack, 1) != 1 || ack != 'R' ||
        open_endpoint(&e) ||
        send_payload(e.fd, BC_TRANSACTION, request) ||
        read_transaction(&e, BR_REPLY, &tr) ||
        check_payload(&e, &tr, response) ||
        write_command(e.fd, BC_FREE_BUFFER, &tr.data.ptr.buffer, sizeof(tr.data.ptr.buffer)) ||
        write(done[1], "D", 1) != 1)
        goto out;
    if (waitpid(child, &status, 0) != child)
        goto out;
    child = -1;
    if (!WIFEXITED(status) || WEXITSTATUS(status))
        goto out;
    puts("r800-binder: transaction roundtrip=PASS distinct-processes=1");
    rc = 0;
out:
    close(ready[0]);
    close(done[1]);
    close_endpoint(&e);
    if (child > 0) {
        kill(child, SIGKILL);
        waitpid(child, NULL, 0);
    }
    return rc;
}
