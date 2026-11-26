/* Native integration: HAL stays alive across termination and restart of GPS Bridge. */
#define R800_GPS_TEST_SOURCE_DEFAULT 1
#define main basic_lifecycle_main
#include "test_r800_gps_hal_lifecycle.c"
#undef main

static atomic_int status_events, locations, sentences;
static void restarted_status(GpsStatus *s)
{
    int i=atomic_load(&status_events);
    assert(s->status==(i%2?GPS_STATUS_SESSION_END:GPS_STATUS_SESSION_BEGIN));
    atomic_fetch_add(&status_events,1);
}
static void restarted_fix(GpsLocation *loc)
{
    assert(loc->flags==31 && loc->latitude==52.25 && loc->longitude==5.5);
    assert(loc->timestamp==123);
    atomic_fetch_add(&locations,1);
}
static void restarted_nmea(GpsUtcTime t,const char *s,int n)
{
    assert(t==123 && n==(int)strlen(s) && gps_nmea_checksum(s));
    atomic_fetch_add(&sentences,1);
}
static void wait_for_count(atomic_int *p,int n)
{
    for(int i=0;i<1000 && atomic_load(p)<n;++i) usleep(10000);
    assert(atomic_load(p)==n);
}
static void mark(const char *s)
{
    puts(s); fflush(stdout);
}
int main(int argc,char **argv)
{
    assert(argc==2 && (!strcmp(argv[1],"active") || !strcmp(argv[1],"idle")));
    int idle=!strcmp(argv[1],"idle");
    strcpy(test_path,"./gps.sock");
    GpsCallbacks c={.size=sizeof(c),.create_thread_cb=spawn,
                    .location_cb=restarted_fix,.status_cb=restarted_status,
                    .nmea_cb=restarted_nmea};
    assert(!iface.init(&c));
    assert(!iface.start());
    wait_for_count(&status_events,1);
    assert(!iface.inject_location(52,5,0.25f));
    wait_for_count(&locations,1);
    wait_for_count(&sentences,1);
    mark("FIRST_SESSION_READY");
    /* Parent terminates the original bridge only after this marker. */
    wait_for_count(&status_events,2);
    if(idle) assert(!iface.stop());
    mark("DISCONNECTED");
    if(idle) {
        /* The replacement must negotiate without starting an engine. */
        int rc=-ENOTCONN;
        for(int i=0;i<1000 && rc==-ENOTCONN;++i) {
            rc=iface.inject_time(123,0,50);
            if(rc==-ENOTCONN) usleep(10000);
        }
        assert(rc==0);
        assert(atomic_load(&status_events)==2);
        mark("IDLE_CONNECTION_READY");
        assert(getchar()=='\n'); /* Parent verifies no START in bridge log. */
        assert(!iface.start());
    }
    wait_for_count(&status_events,3);
    assert(!iface.inject_location(52,5,0.25f));
    wait_for_count(&locations,2);
    wait_for_count(&sentences,2);
    assert(!iface.stop());
    wait_for_count(&status_events,4);
    iface.cleanup();
    mark("GPS_HAL_BRIDGE_RESTART=PASS");
    return 0;
}
