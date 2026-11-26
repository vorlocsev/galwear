#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <math.h>
#include "../src/tools/gps/gps_output.h"
static int seed(const char *s) {
    char b[96]; double lat,lon; long long utc;
    size_t n=strlen(s); assert(n<sizeof b); memcpy(b,s,n);
    return gps_parse_seed(b,(int)n,&lat,&lon,&utc);
}
int main(void) {
    struct gps_time_command t; struct gps_loc_command l;
    assert(gps_parse_time("1",&t) && gps_parse_loc("0 0 1",&l));
    assert(seed("-90 180 123\n"));
    assert(seed("0 0 123\r\n"));
    assert(!seed("NaN 1 123"));
    assert(!seed("91 1 123"));
    assert(!seed("0 -181 123"));
    assert(!seed("0 0 0"));
    assert(!seed("0 0 123 junk"));
    assert(!seed("0 0 123\nSTART"));
    assert(!gps_valid_seed(NAN,0,123));
    char z[]={'0',' ','0',' ','1',0,'2',0}; double x,y; long long u;
    assert(!gps_parse_seed(z,7,&x,&y,&u));
    assert(gps_nmea_length("$GPGGA\r\n",8)==6);
    assert(gps_nmea_length("!ABC",4)==4);
    assert(gps_nmea_length("$A\nSTART",8)==-1);
    assert(gps_nmea_length("$A\0B",4)==-1);
    assert(gps_nmea_length(NULL,5)==-1);
    assert(gps_nmea_length("$",0)==-1);
    char nmea[253]; memset(nmea,'A',sizeof nmea); nmea[0]='$';
    assert(gps_nmea_length(nmea,250)==250);
    assert(gps_nmea_length(nmea,251)==-1);
    unsigned int minutes=99, accuracy=99;
    assert(gps_seed_age(1,1,&minutes,&accuracy) && minutes==0 && accuracy==2000);
    assert(gps_seed_age(60001,1,&minutes,&accuracy) && minutes==1 && accuracy==2000);
    assert(gps_seed_age(86400000,1,&minutes,&accuracy) && minutes==1439 && accuracy==2000);
    assert(gps_seed_age(86400001,1,&minutes,&accuracy) && minutes==1440 && accuracy==25000);
    assert(gps_seed_age(2147483649LL,1,&minutes,&accuracy) && minutes==35791 && accuracy==25000);
    assert(gps_seed_age(2592000001LL,1,&minutes,&accuracy) && minutes==43200 && accuracy==25000);
    assert(!gps_seed_age(2592000002LL,1,&minutes,&accuracy));
    assert(!gps_seed_age(1,2,&minutes,&accuracy));
    assert(!gps_seed_age(1,0,&minutes,&accuracy));
    assert(!gps_seed_age(GPS_UTC_MAX+1,GPS_UTC_MAX,&minutes,&accuracy));
    puts("GPS_OUTPUT_TESTS=28 PASS");
    return 0;
}
