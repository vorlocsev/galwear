/* Native synthetic Broadcom HAL. Never installed into a device image. */
#include <stdint.h>
#include <stddef.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#define R800_GPS_BRIDGE_HOST_TEST 1
#include "../src/tools/gps/gps_abi.h"
static GpsCallbacks callbacks;
static int inits, active;
static const char *mode(void) {
    const char *m=getenv("R800_MOCK_MODE");
    return m?m:"normal";
}
static int init(GpsCallbacks *c)
{
    ++inits;
    puts("MOCK_INIT"); fflush(stdout);
    if (inits>1 && !strcmp(mode(),"fail-reinit")) return -1;
    callbacks=*c;
    return 0;
}
static int start(void)
{
    puts("MOCK_START"); fflush(stdout);
    if (!strcmp(mode(),"fail-start")) return -1;
    if (active) return -1;
    active=1;
    GpsStatus status={sizeof(status),1};
    GpsLocation fix={.size=sizeof(fix),.flags=31,.latitude=52.25,.longitude=5.5,
                     .altitude=10,.speed=2,.bearing=90,.accuracy=3,.timestamp=123};
    callbacks.status_cb(&status);
    callbacks.location_cb(&fix);
    char line[]="$GPRMC,1*56\r\n";
    callbacks.nmea_cb(123,line,(int)strlen(line));
    return 0;
}
static void late_data(void)
{
    GpsLocation fix={.size=sizeof(fix),.flags=31,.latitude=52.25,.longitude=5.5,
                     .altitude=10,.speed=2,.bearing=90,.accuracy=3,.timestamp=60001};
    char line[]="$GPRMC,1*56\r\n";
    callbacks.location_cb(&fix);
    callbacks.nmea_cb(60001,line,(int)strlen(line));
    puts("MOCK_LATE_DATA"); fflush(stdout);
}
static int stop(void)
{
    puts("MOCK_STOP"); fflush(stdout);
    if (!strcmp(mode(),"fail-stop")) return -1;
    if (!active) return -1;
    if (!strcmp(mode(),"late-data")) late_data();
    active=0;
    GpsStatus status={sizeof(status),2};
    callbacks.status_cb(&status);
    return 0;
}
static void cleanup(void) {
    puts("MOCK_CLEANUP"); fflush(stdout); active=0;
}
static int time_in(GpsUtcTime t,GpsUtcTime ref,int unc)
{
    if (t<=0 || ref<0 || unc<0) return -1;
    if (!active && !strcmp(mode(),"late-data")) late_data();
    puts("MOCK_TIME"); fflush(stdout); return 0;
}
static int loc_in(double lat,double lon,float acc)
{
    if (lat!=52 || lon!=5 || acc!=0.25f) return -1;
    puts("MOCK_LOC"); fflush(stdout); return 0;
}
static int position(uint32_t m,uint32_t r,uint32_t i,uint32_t a,uint32_t t)
{
    puts("MOCK_CONFIG"); fflush(stdout);
    if (!strcmp(mode(),"fail-reinit") || (!strcmp(mode(),"retry-config") && inits==1)) return -1;
    return (m || r || i!=1000 || a || t)?-1:0;
}
static const GpsInterface iface={
    .size=sizeof(iface),.init=init,.start=start,.stop=stop,.cleanup=cleanup,
    .inject_time=time_in,.inject_location=loc_in,.set_position_mode=position
};
const GpsInterface *gps_get_hardware_interface(void) {return &iface;}
