#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "../src/hal/gps_wire.h"
int main(void) {
    struct gps_wire_fix f;
    struct gps_time_command t;
    struct gps_loc_command l;
    long long utc;
    const char *nmea;
    int status;
    assert(gps_parse_time("123 1 0",&t));
    assert(gps_parse_loc("0 0 0.25",&l));
    assert(gps_wire_parse_fix("31 52.2 5.1 10 0.2 359.9 3 123",&f));
    assert(f.flags==31 && f.utc==123 && f.lat>52 && f.lon>5);
    assert(!gps_wire_parse_fix("31 91 0 0 0 0 0 123",&f));
    assert(!gps_wire_parse_fix("31 0 181 0 0 0 0 123",&f));
    assert(!gps_wire_parse_fix("31 NaN 0 0 0 0 0 123",&f));
    assert(!gps_wire_parse_fix("31 0 0 0 -1 0 0 123",&f));
    assert(!gps_wire_parse_fix("31 0 0 0 0 360 0 123",&f));
    assert(!gps_wire_parse_fix("31 0 0 0 0 0 -1 123",&f));
    assert(!gps_wire_parse_fix("32 0 0 0 0 0 0 123",&f));
    assert(!gps_wire_parse_fix("1 0 0 0 0 0 0 0",&f));
    assert(!gps_wire_parse_fix("1 0 0 0 0 0 0 123 extra",&f));
    assert(!gps_wire_parse_fix("1 0 0 0 0 0 0 999999999999999999999",&f));
    assert(gps_wire_parse_status("4",&status) && status==4);
    assert(!gps_wire_parse_status("5",&status));
    assert(!gps_wire_parse_status("1 garbage",&status));
    assert(gps_wire_parse_nmea("123 $GPRMC,1",&utc,&nmea) && utc==123 && !strcmp(nmea,"$GPRMC,1"));
    assert(!gps_wire_parse_nmea("abc $GPRMC",&utc,&nmea));
    assert(!gps_wire_parse_nmea("123 $A\nSTATUS 4",&utc,&nmea));
    assert(!gps_wire_parse_nmea("123 junk",&utc,&nmea));
    puts("GPS_WIRE_ASSERTIONS=21 PASS");
    return 0;
}
