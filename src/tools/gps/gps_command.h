/* Bounded decimal protocol parser shared with host tests. */
#ifndef R800_GPS_COMMAND_H
#define R800_GPS_COMMAND_H
#define GPS_UTC_MAX 253402300799999LL
struct gps_time_command { long long utc, elapsed; int uncertainty; };
struct gps_loc_command { double lat, lon, accuracy; };
static const char *gps_space(const char *p)
{
    while (*p == ' ' || *p == '\t') ++p;
    return p;
}
static int gps_uint(const char **p, long long max, long long *out)
{
    const char *s = *p;
    long long n = 0;
    if (*s < '0' || *s > '9') return 0;
    do {
        int d = *s++ - '0';
        if (d > max || n > (max - d) / 10) return 0;
        n = n * 10 + d;
    } while (*s >= '0' && *s <= '9');
    if (*s && *s != ' ' && *s != '\t') return 0;
    *p = s;
    *out = n;
    return 1;
}
static int gps_decimal(const char **p, double *out)
{
    const char *s = *p;
    double n = 0, scale = 1;
    int negative = 0, digits = 0, fraction = 0;
    if (*s == '-' || *s == '+') negative = *s++ == '-';
    while ((*s >= '0' && *s <= '9') || *s == '.') {
        if (*s == '.') {
            if (fraction) return 0;
            fraction = 1;
            ++s;
            continue;
        }
        if (++digits > 24) return 0;
        n = n * 10 + (*s++ - '0');
        if (fraction) scale *= 10;
    }
    if (!digits || (*s && *s != ' ' && *s != '\t')) return 0;
    *p = s;
    *out = (negative ? -n : n) / scale;
    return 1;
}
static int gps_parse_time(const char *p, struct gps_time_command *out)
{
    struct gps_time_command v = {0, 0, 1000};
    long long unc;
    p = gps_space(p);
    if (!gps_uint(&p, GPS_UTC_MAX, &v.utc) || !v.utc) return 0;
    p = gps_space(p);
    if (*p) {
        if (!gps_uint(&p, GPS_UTC_MAX, &v.elapsed)) return 0;
        p = gps_space(p);
        if (!gps_uint(&p, 2147483647LL, &unc)) return 0;
        v.uncertainty = (int)unc;
        if (*gps_space(p)) return 0;
    }
    *out = v;
    return 1;
}
static int gps_parse_loc(const char *p, struct gps_loc_command *out)
{
    struct gps_loc_command v;
    p = gps_space(p);
    if (!gps_decimal(&p, &v.lat)) return 0;
    p = gps_space(p);
    if (!gps_decimal(&p, &v.lon)) return 0;
    p = gps_space(p);
    if (!gps_decimal(&p, &v.accuracy) || *gps_space(p)) return 0;
    if (v.lat < -90 || v.lat > 90 || v.lon < -180 || v.lon > 180 ||
        v.accuracy <= 0 || v.accuracy > 40000000) return 0;
    *out = v;
    return 1;
}
#endif
