/* SPDX-License-Identifier: GPL-2.0-only
 * Separate dynamic Android ABI probe. Not a PID1 or a production executable.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <unistd.h>

#if !defined(__BIONIC__) || __ANDROID_API__ != 30
#error "Android Bionic API30 required"
#endif

int main(void)
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
    return 0;
}
