#include <assert.h>
#include <stdio.h>
#include "../src/tools/gps/gps_command.h"
int main(void) {
    struct gps_time_command t;
    struct gps_loc_command l;
    const char *badtime[] = {"", "0", "-1", "123 2", "123 2 3 4", "123 2 2147483648", "999999999999999999999999", "123x", "123 2 -1", "253402300800000"};
    const char *badloc[] = {"", "NaN 0 1", "0 Inf 1", "91 0 1", "0 -181 1", "0 0 0", "0 0 -1", "0 0 40000001", "0 0 1 extra", "1.2.3 0 1", "0 0", "0 0 1e3", ". 0 1"};
    unsigned count=0;
    assert(gps_parse_time("123", &t) && t.utc==123 && t.elapsed==0 && t.uncertainty==1000); ++count;
    assert(gps_parse_time("123 20 0", &t) && t.elapsed==20 && t.uncertainty==0); ++count;
    assert(gps_parse_time("253402300799999 0 2147483647", &t)); ++count;
    assert(gps_parse_loc("-90 180 1.5", &l) && l.lat==-90 && l.lon==180 && l.accuracy==1.5); ++count;
    assert(gps_parse_loc("0\t0 40000000", &l)); ++count;
    for (unsigned i=0;i<sizeof badtime/sizeof *badtime;i++) { assert(!gps_parse_time(badtime[i],&t)); ++count; }
    for (unsigned i=0;i<sizeof badloc/sizeof *badloc;i++) { assert(!gps_parse_loc(badloc[i],&l)); ++count; }
    printf("GPS_COMMAND_TESTS=%u PASS\n",count);
}
