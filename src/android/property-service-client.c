/* SPDX-License-Identifier: GPL-2.0-only
 * Bionic public client API; original libinit property service required.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/system_properties.h>
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

int main(int argc, char **argv)
{
    const char *name = "debug.galwear.service";
    const char *version = "ro.property_service.version";
    uint32_t initial, changed, ignored;
    if (argc != 2 || strcmp(argv[1], "--virt-property-client") ||
        getpid() == 1 || getppid() != 1 ||
        check(version, "2", &ignored))
        return 1;
    if (__system_property_find(name) ||
        __system_property_set(name, "ready") ||
        check(name, "ready", &initial))
        return 2;
    puts("r800-property-client: socket-set=PASS read=ready");
    if (__system_property_set(name, "updated") ||
        check(name, "updated", &changed) || changed == initial)
        return 3;
    puts("r800-property-client: socket-update=PASS serial-changed=PASS");
    if (__system_property_set(version, "3") == 0 ||
        check(version, "2", &ignored))
        return 4;
    puts("r800-property-client: read-only-rejected=PASS");
    return 0;
}
