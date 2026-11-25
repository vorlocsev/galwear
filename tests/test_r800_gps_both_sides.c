/* Actual Android HAL + actual bridge + synthetic Broadcom library. */
#define main basic_lifecycle_main
#include "test_r800_gps_hal_lifecycle.c"
#undef main
static atomic_int states, nmeas, received;
static void got_fix(GpsLocation *loc)
{
    assert(loc->flags==31 && loc->latitude==52.25 && loc->longitude==5.5);
    assert(loc->timestamp==123 && loc->speed==2 && loc->accuracy==3);
    atomic_fetch_add(&received,1);
}
static void got_status(GpsStatus *s)
{
    int i=atomic_load(&states);
    assert(s->status==(i%2?2:1));
    atomic_fetch_add(&states,1);
}
static void got_nmea(GpsUtcTime ts,const char *s,int n)
{
    assert(ts==123 && n==(int)strlen(s) && gps_nmea_checksum(s));
    atomic_fetch_add(&nmeas,1);
}
static void wait_for(atomic_int *p,int count)
{
    for(int i=0;i<500 && atomic_load(p)<count;++i) usleep(10000);
    assert(atomic_load(p)==count);
}
int main(void)
{
    strcpy(test_path,"./gps.sock");
    GpsCallbacks c={.size=sizeof(c),.create_thread_cb=spawn,
                    .location_cb=got_fix,.status_cb=got_status,.nmea_cb=got_nmea};
    assert(!iface.init(&c));
    assert(!iface.start());
    wait_for(&received,1);
    wait_for(&nmeas,1);
    wait_for(&states,1);
    assert(!iface.inject_time(123,0,50));
    assert(!iface.inject_location(52,5,0.25f));
    assert(!iface.stop());
    wait_for(&states,2);
    assert(!iface.start());
    wait_for(&received,2);
    wait_for(&nmeas,2);
    wait_for(&states,3);
    assert(!iface.stop());
    wait_for(&states,4);
    iface.cleanup();
    puts("GPS_BOTH_SIDES=PASS");
    return 0;
}
