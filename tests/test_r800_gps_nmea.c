#include <assert.h>
#include <stdio.h>
#include "../src/hal/gps_nmea.h"
static void sentence(char *out,const char *body)
{
    unsigned cs=0;
    for(const char *p=body;*p;++p) cs^=(unsigned char)*p;
    assert(snprintf(out,256,"$%s*%02X",body,cs)<256);
}
int main(void)
{
    char s[256];
    struct gps_nmea_gsv g;
    struct gps_nmea_gsa a;
    struct gps_time_command t;
    struct gps_loc_command l;
    assert(gps_parse_time("1",&t) && gps_parse_loc("0 0 1",&l));
    sentence(s,"GPGSV,1,1,02,01,45,123,35,33,10,200,20");
    assert(gps_nmea_checksum(s));
    assert(gps_nmea_parse_gsv(s,gps_nmea_talker(s+1),&g));
    assert(g.count==2 && g.sv[0].id==1 && g.sv[1].c==2 && g.sv[1].id==120);
    s[4]='X'; assert(!gps_nmea_checksum(s));
    sentence(s,"GLGSV,1,1,01,65,10,123,");
    assert(gps_nmea_parse_gsv(s,3,&g) && g.sv[0].id==1);
    sentence(s,"GBGSV,1,1,01,201,10,123,20,1");
    assert(gps_nmea_parse_gsv(s,5,&g) && g.sv[0].id==1);
    sentence(s,"GAGSV,1,1,01,12,10,123,20");
    assert(gps_nmea_parse_gsv(s,6,&g));
    sentence(s,"GPGSV,1,1,01,0,10,123,20");
    assert(!gps_nmea_parse_gsv(s,1,&g));
    sentence(s,"GPGSV,1,1,01,1,91,123,20");
    assert(!gps_nmea_parse_gsv(s,1,&g));
    sentence(s,"GPGSV,1,1,01,1,10,360,20");
    assert(!gps_nmea_parse_gsv(s,1,&g));
    sentence(s,"GPGSV,1,1,01,1,10,123");
    assert(!gps_nmea_parse_gsv(s,1,&g));
    sentence(s,"GPGSV,2,2,01,1,10,123,20");
    assert(!gps_nmea_parse_gsv(s,1,&g));
    sentence(s,"GNGSA,A,3,01,,,,,,,,,,,,1.0,1.0,1.0,3");
    assert(gps_nmea_parse_gsa(s,0,&a) && a.c==6 && a.count==1);
    sentence(s,"GNGSA,A,3,01,,,,,,,,,,,,1.0,1.0,1.0");
    assert(!gps_nmea_parse_gsa(s,0,&a));
    sentence(s,"GPGSA,A,1,01,,,,,,,,,,,,1.0,1.0,1.0");
    assert(gps_nmea_parse_gsa(s,1,&a) && a.count==0);
    assert(!gps_nmea_checksum("$GPRMC,1"));
    assert(!gps_nmea_checksum("$GPRMC,1*ZZ"));
    puts("GPS_NMEA_TEST=PASS");
    return 0;
}
