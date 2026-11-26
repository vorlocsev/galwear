/* Host ABI gate regression: synthetic tables, no donor function calls. */
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>
#define R800_GPS_BRIDGE_HOST_TEST 1
#include "../src/tools/gps/gps_abi.h"
#include "../src/tools/gps/gps_interface_gate.h"

static int init(GpsCallbacks *p) { (void)p; return 0; }
static int action(void) { return 0; }
static void cleanup(void) {}
static int time_in(GpsUtcTime a, GpsUtcTime b, int c)
{ (void)a; (void)b; (void)c; return 0; }
static int loc(double a, double b, float c)
{ (void)a; (void)b; (void)c; return 0; }
static int pos(uint32_t a,uint32_t b,uint32_t c,uint32_t d,uint32_t e)
{ (void)a; (void)b; (void)c; (void)d; (void)e; return 0; }
static int xinit(GpsXtraCallbacks *p) { (void)p; return 0; }
static int xdata(char *p, int n) { (void)p; (void)n; return 0; }

int main(void)
{
    const GpsInterface good = {
        .size=sizeof(GpsInterface), .init=init, .start=action, .stop=action,
        .cleanup=cleanup, .inject_time=time_in, .inject_location=loc,
        .set_position_mode=pos
    };
    const GpsXtraInterface xgood = {
        .size=sizeof(GpsXtraInterface), .init=xinit, .inject_xtra_data=xdata
    };
    GpsInterface g = good;
    GpsXtraInterface x = xgood;
    assert(gps_interface_valid(&g));
    assert(gps_xtra_interface_valid(&x));
    assert(!gps_interface_valid(NULL));
    assert(!gps_xtra_interface_valid(NULL));
    g.size = sizeof(g)-1; assert(!gps_interface_valid(&g));
    g.size = sizeof(g)+1; assert(!gps_interface_valid(&g));
    x.size = sizeof(x)-1; assert(!gps_xtra_interface_valid(&x));
    x.size = sizeof(x)+1; assert(!gps_xtra_interface_valid(&x));
#define MISSING(field) do { g=good; g.field=NULL; assert(!gps_interface_valid(&g)); } while (0)
    MISSING(init); MISSING(start); MISSING(stop); MISSING(cleanup);
    MISSING(inject_time); MISSING(inject_location); MISSING(set_position_mode);
#undef MISSING
    x=xgood; x.init=NULL; assert(!gps_xtra_interface_valid(&x));
    x=xgood; x.inject_xtra_data=NULL; assert(!gps_xtra_interface_valid(&x));
    assert(!gps_interface_valid((const GpsInterface *)((char *)&g+1)));
    assert(!gps_xtra_interface_valid((const GpsXtraInterface *)((char *)&x+1)));

    /* A short size-only table ends immediately before an inaccessible page.
     * The gate must reject it without touching any following pointer. */
    long page = sysconf(_SC_PAGESIZE);
    assert(page > 0);
    char *area = mmap(NULL, (size_t)page*2, PROT_READ|PROT_WRITE,
                      MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    assert(area != MAP_FAILED);
    assert(mprotect(area+page, (size_t)page, PROT_NONE)==0);
    size_t *short_table = (size_t *)(area+page-sizeof(size_t));
    *short_table = sizeof(size_t);
    assert(!gps_interface_valid((const GpsInterface *)short_table));
    assert(!gps_xtra_interface_valid((const GpsXtraInterface *)short_table));
    assert(munmap(area, (size_t)page*2)==0);
    puts("GPS_INTERFACE_GATE=PASS");
    return 0;
}
