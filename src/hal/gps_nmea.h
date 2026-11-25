/* Strict NMEA satellite subset; no inferred ephemeris/almanac flags. */
#ifndef R800_GPS_NMEA_H
#define R800_GPS_NMEA_H
#include <string.h>
#include "../tools/gps/gps_command.h"

struct gps_nmea_sv { int c, id; float el, az, snr; };
struct gps_nmea_gsv { int total, part; unsigned count; struct gps_nmea_sv sv[4]; };
struct gps_nmea_gsa { int c; unsigned count; struct gps_nmea_sv sv[12]; };

static int gps_hex(unsigned char ch)
{
    if (ch >= '0' && ch <= '9') return ch-'0';
    if (ch >= 'A' && ch <= 'F') return ch-'A'+10;
    if (ch >= 'a' && ch <= 'f') return ch-'a'+10;
    return -1;
}
static int gps_nmea_checksum(const char *s)
{
    unsigned sum=0, n=0;
    if (!s || (*s!='$' && *s!='!')) return 0;
    for (++s; *s && *s!='*'; ++s) {
        if (++n>246 || (unsigned char)*s<32 || (unsigned char)*s>126) return 0;
        sum^=(unsigned char)*s;
    }
    if (!n || *s!='*' || !s[1] || !s[2] || s[3]) return 0;
    int hi=gps_hex(s[1]), lo=gps_hex(s[2]);
    return hi>=0 && lo>=0 && sum==(unsigned)(hi*16+lo);
}
static int gps_nmea_talker(const char *s)
{
    if (!strncmp(s,"GP",2)) return 1;
    if (!strncmp(s,"GL",2)) return 3;
    if (!strncmp(s,"QZ",2) || !strncmp(s,"GQ",2)) return 4;
    if (!strncmp(s,"BD",2) || !strncmp(s,"GB",2)) return 5;
    if (!strncmp(s,"GA",2)) return 6;
    return 0;
}
static int gps_nmea_id(int c,int prn,struct gps_nmea_sv *v)
{
    if (c==1 && prn>=33 && prn<=64) { c=2; prn+=87; }
    else if (c==3 && prn>=65 && prn<=96) prn-=64;
    else if (c==5 && prn>=201 && prn<=263) prn-=200;
    if (!((c==1 && prn>=1 && prn<=32) ||
          (c==2 && prn>=120 && prn<=151) ||
          (c==3 && prn>=1 && prn<=32) ||
          (c==4 && prn>=193 && prn<=200) ||
          (c==5 && prn>=1 && prn<=63) ||
          (c==6 && prn>=1 && prn<=36))) return 0;
    v->c=c; v->id=prn;
    return 1;
}
/* Empty fields are distinct from missing fields; never truncate tokens. */
static int gps_nmea_field(const char **p,char b[16])
{
    unsigned n=0;
    if (!*p) return 0;
    while (**p && **p!=',' && **p!='*') {
        if (n==15) return 0;
        b[n++]=*(*p)++;
    }
    b[n]=0;
    if (**p==',') ++*p;
    else *p=0;
    return 1;
}
static int gps_nmea_uint(const char *s,int max,int *v)
{
    long long n;
    if (!gps_uint(&s,max,&n) || *s) return 0;
    *v=(int)n;
    return 1;
}
static int gps_nmea_number(const char *s,int max,float *v)
{
    double n;
    if (!*s) { *v=0; return 1; }
    if (!gps_decimal(&s,&n) || *s || n<0 || n>max) return 0;
    *v=(float)n;
    return 1;
}
static int gps_nmea_parse_gsv(const char *s,int c,struct gps_nmea_gsv *out)
{
    struct gps_nmea_gsv m={0};
    char b[16];
    int count, prn;
    if (!gps_nmea_checksum(s) || !c || strlen(s)<7 || strncmp(s+3,"GSV,",4)) return 0;
    const char *p=s+7;
    if (!gps_nmea_field(&p,b) || !gps_nmea_uint(b,16,&m.total) || !m.total ||
        !gps_nmea_field(&p,b) || !gps_nmea_uint(b,m.total,&m.part) || !m.part ||
        !gps_nmea_field(&p,b) || !gps_nmea_uint(b,64,&count)) return 0;
    if (m.total!=(count ? (count+3)/4 : 1)) return 0;
    int remain=count-4*(m.part-1);
    unsigned expected=remain>4?4:remain>0?(unsigned)remain:0;
    for (unsigned i=0;i<expected;++i) {
        struct gps_nmea_sv *v=&m.sv[m.count];
        if (!gps_nmea_field(&p,b) || !gps_nmea_uint(b,263,&prn) ||
            !gps_nmea_id(c,prn,v) ||
            !gps_nmea_field(&p,b) || !gps_nmea_number(b,90,&v->el) ||
            !gps_nmea_field(&p,b) || !gps_nmea_number(b,359,&v->az) ||
            !gps_nmea_field(&p,b) || !gps_nmea_number(b,99,&v->snr)) return 0;
        ++m.count;
    }
    /* Optional NMEA 4.10 signal ID; reject other trailing data. */
    if (p && (!gps_nmea_field(&p,b) || (*b && !gps_nmea_uint(b,15,&prn)) || p)) return 0;
    *out=m; return 1;
}
static int gps_nmea_parse_gsa(const char *s,int c,struct gps_nmea_gsa *out)
{
    struct gps_nmea_gsa m={0};
    char b[16], ids[12][16];
    int fix, prn, system;
    float dop;
    if (!gps_nmea_checksum(s) || strlen(s)<7 || strncmp(s+3,"GSA,",4)) return 0;
    const char *p=s+7;
    if (!gps_nmea_field(&p,b) || (strcmp(b,"A") && strcmp(b,"M")) ||
        !gps_nmea_field(&p,b) || !gps_nmea_uint(b,3,&fix) || !fix) return 0;
    for (int i=0;i<12;++i)
        if (!gps_nmea_field(&p,ids[i])) return 0;
    for (int i=0;i<3;++i)
        if (!gps_nmea_field(&p,b) || !gps_nmea_number(b,999,&dop)) return 0;
    if (p) {
        if (!gps_nmea_field(&p,b) || !gps_nmea_uint(b,5,&system) || p) return 0;
        int mapped=system==1?1:system==2?3:system==3?6:system==4?5:system==5?4:0;
        if (!mapped || (c && c!=mapped)) return 0;
        c=mapped;
    }
    if (!c) return 0; /* GN without system ID is ambiguous */
    m.c=c;
    for (int i=0;i<12;++i) {
        if (!ids[i][0]) continue;
        if (!gps_nmea_uint(ids[i],263,&prn) || !gps_nmea_id(c,prn,&m.sv[m.count])) return 0;
        if (fix!=1) ++m.count;
    }
    *out=m; return 1;
}
#endif
