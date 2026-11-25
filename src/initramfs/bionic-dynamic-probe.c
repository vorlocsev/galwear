/* SPDX-License-Identifier: GPL-2.0-only
 * Separate dynamic Android ABI probe. Not a PID1 or a production executable.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/system_properties.h>
#include <unistd.h>

#if !defined(__BIONIC__) || __ANDROID_API__ != 30
#error "Android Bionic API30 required"
#endif

struct property_result {
    unsigned int calls;
    int matches;
};

static void read_property(void *cookie, const char *name, const char *value,
                          uint32_t serial)
{
    struct property_result *result = cookie;
    (void)serial;
    ++result->calls;
    result->matches = strcmp(name, "debug.galwear.probe") == 0 &&
                      strcmp(value, "ready") == 0;
}

int main(int argc, char **argv)
{
    void *handle = dlopen("libc.so", RTLD_NOW | RTLD_LOCAL);
    if (!handle)
        return 1;
    void *symbol = dlsym(handle, "getpid");
    if (!symbol)
        return 2;
    pid_t (*runtime_getpid)(void) = (pid_t (*)(void))symbol;
    if (runtime_getpid() != getpid() || dlclose(handle))
        return 3;
    puts("r800-dynamic: bionic api=30 dlopen=PASS dlsym=PASS");
    /* Baseline: no property service is started by the dynamic supervisor.
     * Future property-service mode requires a real seeded Bionic area. */
    const prop_info *pi = __system_property_find("debug.galwear.probe");
    if (argc == 1) {
        if (pi != NULL)
            return 4;
        puts("r800-property: absent lookup=PASS service=not-started");
    } else if (argc == 2 && strcmp(argv[1], "--expect-property") == 0) {
        struct property_result result = {0, 0};
        if (!pi)
            return 5;
        __system_property_read_callback(pi, read_property, &result);
        if (result.calls != 1 || !result.matches)
            return 6;
        puts("r800-property: seeded read-callback=PASS");
    } else {
        return 7;
    }
    return 0;
}
