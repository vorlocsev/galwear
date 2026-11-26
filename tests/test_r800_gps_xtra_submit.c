/* Native behavioral fixture; ARM compilation uses the actual local ABI. */
#ifdef __arm__
typedef unsigned int size_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef long long int64_t;
typedef unsigned long pthread_t;
#include "gps_abi.h"
#else
#include <stddef.h>
#include <pthread.h>
/* Native equivalents, deliberately not an ARM ABI layout claim. */
typedef struct {
#if R800_XTRA_ABI == 2
    size_t size;
#endif
    void (*download_request_cb)(void);
    pthread_t (*create_thread_cb)(const char *, void (*)(void *), void *);
} GpsXtraCallbacks;
typedef struct {
    size_t size;
    int (*init)(GpsXtraCallbacks *);
    int (*inject_xtra_data)(char *, int);
} GpsXtraInterface;
typedef struct { const void *(*get_extension)(const char *); } GpsInterface;
#endif
#include "gps_xtra.h"
static int lookups, inits, injections, downloads, init_rc, inject_rc;
static char payload[] = {1, 0, 3, 4};
static void download(void) { ++downloads; }
static pthread_t thread(const char *n, void (*fn)(void *), void *arg)
{ (void)n; (void)fn; (void)arg; return 0; }
static int init(GpsXtraCallbacks *cb)
{
    ++inits;
#if R800_XTRA_ABI == 2
    if (cb->size != sizeof(*cb)) return -99;
#endif
    if (cb->create_thread_cb != thread || cb->download_request_cb != download) return -98;
    cb->download_request_cb();
    return init_rc;
}
static int inject(char *data, int size)
{
    ++injections;
    if (size != 4 || data[0] != 1 || data[1] != 0 || data[2] != 3 || data[3] != 4) return -97;
    return inject_rc;
}
static GpsXtraInterface ext = {sizeof(ext), init, inject};
static const void *lookup(const char *name)
{
    const char *want = "gps-xtra";
    ++lookups;
    while (*want && *want == *name) { ++want; ++name; }
    return *want || *name ? 0 : &ext;
}
#define CHECK(x) do { if (!(x)) return __LINE__; } while (0)
int main(void)
{
    GpsInterface gps = {.get_extension = lookup};
    GpsXtraCallbacks cb = {
#if R800_XTRA_ABI == 2
        .size = sizeof(cb),
#endif
        .download_request_cb = download, .create_thread_cb = thread};
    const GpsXtraInterface *cached = 0;
    int rc;
#define SUBMIT(data,n) gps_xtra_submit(&gps, &cached, &cb, data, n, &rc)
    if (R800_XTRA_ABI == 0) {
        CHECK(SUBMIT(payload,4) == XTRA_DISABLED && !lookups && !inits && !injections);
        return 0;
    }
    CHECK(SUBMIT(payload,0) == XTRA_INVALID_DATA && !lookups);
    CHECK(SUBMIT(payload,262145) == XTRA_INVALID_DATA && !lookups);
    ext.size = 0;
    CHECK(SUBMIT(payload,4) == XTRA_UNAVAILABLE && !inits && !cached);
    ext.size = sizeof(ext); ext.inject_xtra_data = 0;
    CHECK(SUBMIT(payload,4) == XTRA_UNAVAILABLE && !inits && !cached);
    ext.inject_xtra_data = inject;
    init_rc = -12;
    CHECK(SUBMIT(payload,4) == XTRA_INIT_FAILED && rc == -12 && !cached && !injections);
    init_rc = 0; inject_rc = -13;
    CHECK(SUBMIT(payload,4) == XTRA_INJECT_FAILED && rc == -13 && cached == &ext);
    inject_rc = 0;
    CHECK(SUBMIT(payload,4) == XTRA_OK && rc == 0 && inits == 2 && downloads == 2 && injections == 2);
    cached = 0; /* HAL cleanup/reinit invalidates cached extension. */
    CHECK(SUBMIT(payload,4) == XTRA_OK && inits == 3 && downloads == 3 && injections == 3);
    return 0;
}
