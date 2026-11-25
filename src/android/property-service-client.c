/* SPDX-License-Identifier: GPL-2.0-only
 * Bionic public client API; original libinit property service required.
 */
#include <fcntl.h>
#include <dlfcn.h>
#include <math.h>
#include <pthread.h>
#include <stdlib.h>
#include <errno.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <stdio.h>
#include <string.h>
#include <sys/system_properties.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#ifndef __BIONIC__
#error "Android Bionic required"
#endif

struct property_check {
    const char *name;
    const char *expected;
    unsigned int calls;
    int matches;
    uint32_t serial;
};

static void receive(void *cookie, const char *name, const char *value, uint32_t serial)
{
    struct property_check *c = cookie;
    ++c->calls;
    c->matches = !strcmp(name, c->name) && !strcmp(value, c->expected);
    c->serial = serial;
}

static int check(const char *name, const char *value, uint32_t *serial)
{
    struct property_check c = {.name = name, .expected = value};
    const prop_info *pi = __system_property_find(name);
    if (!pi)
        return 1;
    __system_property_read_callback(pi, receive, &c);
    *serial = c.serial;
    return c.calls != 1 || !c.matches;
}

/* Android 11 protocol v2 status values, checked separately from Bionic's -1. */
static int transfer(int fd, void *buffer, size_t length, int sending)
{
    unsigned char *p = buffer;
    while (length) {
        ssize_t n = sending ? send(fd, p, length, MSG_NOSIGNAL) : recv(fd, p, length, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return 1;
        p += n;
        length -= (size_t)n;
    }
    return 0;
}

static int exact_rejection(const char *name, const char *value, uint32_t expected)
{
    struct sockaddr_un addr = {.sun_family = AF_UNIX, .sun_path = "/dev/socket/property_service"};
    struct timeval timeout = {.tv_sec = 5};
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return 1;
    uint32_t cmd = 0x00020001, nl = (uint32_t)strlen(name), vl = (uint32_t)strlen(value), status = 0;
    int failed = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) ||
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) ||
        connect(fd, (struct sockaddr *)&addr, sizeof(addr)) ||
        transfer(fd, &cmd, sizeof(cmd), 1) ||
        transfer(fd, &nl, sizeof(nl), 1) || transfer(fd, (void *)name, nl, 1) ||
        transfer(fd, &vl, sizeof(vl), 1) || transfer(fd, (void *)value, vl, 1) ||
        transfer(fd, &status, sizeof(status), 0) || status != expected;
    return close(fd) || failed;
}

static int correct_domain(void)
{
    const char expected[] = "u:r:galwear_property_client:s0";
    char buf[128];
    int fd = open("/proc/self/attr/current", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    ssize_t n = read(fd, buf, sizeof(buf));
    if (close(fd) || n <= 0 || n >= (ssize_t)sizeof(buf)) return 0;
    if (buf[n-1] == '\0' || buf[n-1] == '\n') --n;
    return n == (ssize_t)(sizeof(expected)-1) && !memcmp(buf, expected, (size_t)n);
}

/* Bounded functional checks in the disposable guest only. */
static int memory_probe(void)
{
    unsigned char *p = calloc(64, 1);
    if (!p) return 1;
    for (size_t i = 0; i < 64; ++i) {
        if (p[i] != 0) {
            free(p);
            return 1;
        }
        p[i] = (unsigned char)(i ^ 0x5a);
    }
    unsigned char *q = realloc(p, 128);
    if (!q) {
        free(p);
        return 1;
    }
    int failed = 0;
    for (size_t i = 0; i < 64; ++i)
        if (q[i] != (unsigned char)(i ^ 0x5a)) failed = 1;
    memset(q + 64, 0xa5, 64);
    for (size_t i = 64; i < 128; ++i)
        if (q[i] != 0xa5) failed = 1;
    free(q);
    return failed;
}

struct thread_probe {
    pthread_key_t key;
    int child_value;
    int failed;
};

static void *thread_worker(void *arg)
{
    struct thread_probe *p = arg;
    p->failed = pthread_getspecific(p->key) != NULL ||
                pthread_setspecific(p->key, &p->child_value) != 0 ||
                pthread_getspecific(p->key) != &p->child_value;
    errno = EDOM;
    if (errno != EDOM) p->failed = 1;
    return arg;
}

static int tls_probe(void)
{
    int parent = 17;
    struct thread_probe p = {.child_value = 29, .failed = 1};
    pthread_t thread;
    void *result = NULL;
    if (pthread_key_create(&p.key, NULL)) return 1;
    if (pthread_setspecific(p.key, &parent)) {
        pthread_key_delete(p.key);
        return 1;
    }
    if (pthread_create(&thread, NULL, thread_worker, &p)) {
        pthread_key_delete(p.key);
        return 1;
    }
    errno = ERANGE;
    if (pthread_join(thread, &result)) {
        /* Do not return with a potentially live worker referencing this stack. */
        _exit(22);
    }
    int failed = errno != ERANGE || result != &p || p.failed ||
                 pthread_getspecific(p.key) != &parent || parent != 17;
    return pthread_key_delete(p.key) || failed;
}

static int linker_probe(void)
{
    /* Explicit libm dependency, with a second call through libdl. */
    double (*volatile direct_sqrt)(double) = sqrt;
    if (direct_sqrt(81.0) != 9.0) return 1;
    void *handle = dlopen("libm.so", RTLD_NOW | RTLD_NOLOAD);
    if (!handle) return 1;
    dlerror();
    void *symbol = dlsym(handle, "sqrt");
    const char *error = dlerror();
    int failed = error != NULL || symbol == NULL;
    if (!failed) {
        double (*fn)(double) = (double (*)(double))symbol;
        Dl_info info = {0};
        if (fn(144.0) != 12.0 || !dladdr(symbol, &info) || !info.dli_fname ||
            (strcmp(info.dli_fname, "/system/lib64/bootstrap/libm.so") &&
             strcmp(info.dli_fname, "/system/lib64/libm.so") &&
             strcmp(info.dli_fname, "/apex/com.android.runtime/lib64/bionic/libm.so"))) {
            failed = 1;
        } else {
            printf("r800-bionic: libm-provider=%s\n", info.dli_fname);
        }
    }
    dlerror();
    void *missing = dlsym(handle, "galwear_missing_symbol_20261125");
    if (missing != NULL || dlerror() == NULL) failed = 1;
    return dlclose(handle) || failed;
}

int main(int argc, char **argv)
{
    const char *name = "debug.galwear.service";
    const char *version = "ro.property_service.version";
    const char *readonly = "ro.galwear.service.fixture";
    const char *denied = "debug.galwear.denied";
    uint32_t initial, changed, ignored;
    if (argc != 2 || strcmp(argv[1], "--virt-property-client") ||
        getpid() == 1 || getppid() != 1 || !correct_domain() ||
        setvbuf(stdout, NULL, _IONBF, 0) ||
        check(version, "2", &ignored))
        return 1;
    struct stat console_stat;
    if (fstat(STDOUT_FILENO, &console_stat) == 0 && S_ISCHR(console_stat.st_mode)) {
        printf("r800-console: stage=client device=%u:%u inode=%llu filesystem=%u:%u\n",
               (unsigned)major(console_stat.st_rdev), (unsigned)minor(console_stat.st_rdev),
               (unsigned long long)console_stat.st_ino,
               (unsigned)major(console_stat.st_dev), (unsigned)minor(console_stat.st_dev));
        fflush(stdout);
    } else {
        fputs("r800-console: stage=client descriptor-unavailable\n", stderr);
        fflush(stderr);
    }
    puts("r800-property-client: domain=u:r:galwear_property_client:s0 protocol=2");
    if (memory_probe()) return 20;
    puts("r800-bionic: memory=PASS");
    if (tls_probe()) return 21;
    puts("r800-bionic: pthread-tls=PASS");
    if (linker_probe()) return 23;
    puts("r800-bionic: libdl-libm=PASS missing-symbol=PASS");
    if (__system_property_find(name) ||
        __system_property_set(name, "ready") ||
        check(name, "ready", &initial))
        return 2;
    puts("r800-property-client: socket-set=PASS read=ready");
    if (__system_property_set(name, "updated") ||
        check(name, "updated", &changed) || changed == initial)
        return 3;
    puts("r800-property-client: socket-update=PASS serial-changed=PASS");
    if (__system_property_find(readonly) ||
        __system_property_set(readonly, "first") || check(readonly, "first", &ignored) ||
        __system_property_set(readonly, "second") == 0 ||
        exact_rejection(readonly, "second", 0x000B) || check(readonly, "first", &ignored))
        return 4;
    puts("r800-property-client: read-only-rejected=PASS status=0x000b");
    if (check(denied, "seeded", &ignored) ||
        __system_property_set(denied, "forbidden") == 0 ||
        exact_rejection(denied, "forbidden", 0x0018) ||
        check(denied, "seeded", &ignored) || check(version, "2", &ignored))
        return 5;
    puts("r800-property-client: denied-write=PASS status=0x0018 value-unchanged=PASS");
    return 0;
}
