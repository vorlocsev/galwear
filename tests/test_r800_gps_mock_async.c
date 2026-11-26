#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdatomic.h>
#define R800_GPS_BRIDGE_HOST_TEST 1
#include "../src/tools/gps/gps_abi.h"
static GpsCallbacks callbacks;
#include "r800_mock_async.h"

static atomic_int fixes, nmeas;
static pthread_t owner;
static void fix(GpsLocation *l)
{
    assert(!pthread_equal(owner,pthread_self()));
    assert(l->latitude==52.25 && l->timestamp==123);
    atomic_fetch_add(&fixes,1);
}
static void nmea(GpsUtcTime t,const char *s,int n)
{
    assert(!pthread_equal(owner,pthread_self()));
    assert(t==123 && n==(int)strlen(s));
    atomic_fetch_add(&nmeas,1);
}
static void *trampoline(void *arg)
{
    (void)arg;
    async_worker(NULL);
    return NULL;
}
static pthread_t spawn(const char *name, void (*fn)(void *), void *arg)
{
    pthread_t th;
    assert(name && fn==async_worker && !arg);
    assert(!pthread_create(&th,NULL,trampoline,NULL));
    return th;
}
static pthread_t fail_spawn(const char *name, void (*fn)(void *), void *arg)
{
    (void)name; (void)fn; (void)arg;
    return 0;
}
int main(void)
{
    owner=pthread_self();
    callbacks=(GpsCallbacks){.size=sizeof(callbacks),.location_cb=fix,
        .nmea_cb=nmea,.create_thread_cb=spawn};
    assert(!async_begin());
    assert(async_begin()==-1);
    async_end();
    assert(!atomic_load(&fixes) && !atomic_load(&nmeas));
    assert(!async_begin());
    async_trigger();
    /* Join directly here to guarantee completion rather than racing cancel. */
    assert(!pthread_join(async_thread,NULL));
    async_live=0;
    assert(atomic_load(&fixes)==1 && atomic_load(&nmeas)==1);
    assert(!async_begin());
    async_end();
    assert(atomic_load(&fixes)==1 && atomic_load(&nmeas)==1);
    callbacks.create_thread_cb=fail_spawn;
    assert(async_begin()==-1 && !async_live);
    async_end();
    callbacks.create_thread_cb=NULL;
    assert(async_begin()==-1);
    puts("GPS_MOCK_ASYNC=PASS");
    return 0;
}
