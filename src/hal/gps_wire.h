/* Android-side GPS bridge wire contract. Bounded decimal tokens. */
#ifndef R800_GPS_WIRE_H
#define R800_GPS_WIRE_H
#include "../tools/gps/gps_command.h"
struct gps_wire_fix {
    long long flags, utc;
    double lat, lon, alt, speed, bearing, accuracy;
};
static int gps_wire_parse_fix(const char *p, struct gps_wire_fix *out)
{
    struct gps_wire_fix f;
    double *fields[] = {&f.lat,&f.lon,&f.alt,&f.speed,&f.bearing,&f.accuracy};
    if (!gps_uint(&p,31,&f.flags)) return 0;
    for (unsigned i=0;i<6;i++) {
        p=gps_space(p);
        if (!gps_decimal(&p,fields[i])) return 0;
    }
    p=gps_space(p);
    if (!gps_uint(&p,GPS_UTC_MAX,&f.utc) || !f.utc || *gps_space(p)) return 0;
    if (!(f.flags & 1) || f.lat < -90 || f.lat > 90 || f.lon < -180 || f.lon > 180)
        return 0;
    if ((f.flags & 4) && f.speed < 0) return 0;
    if ((f.flags & 8) && (f.bearing < 0 || f.bearing >= 360)) return 0;
    if ((f.flags & 16) && f.accuracy < 0) return 0;
    *out=f;
    return 1;
}
static int gps_wire_parse_status(const char *p,int *out)
{
    long long s;
    if (!gps_uint(&p,4,&s) || *gps_space(p)) return 0;
    *out=(int)s;
    return 1;
}
static int gps_wire_parse_nmea(const char *p,long long *utc,const char **sentence)
{
    long long t;
    unsigned n=0;
    if (!gps_uint(&p,GPS_UTC_MAX,&t) || *p != ' ') return 0;
    ++p;
    if (*p != '$' && *p != '!') return 0;
    for (const unsigned char *s=(const unsigned char *)p; *s; ++s)
        if (++n>250 || *s<32 || *s>126) return 0;
    if (n<2) return 0;
    *utc=t; *sentence=p;
    return 1;
}
#endif
