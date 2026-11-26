#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "../src/tools/gps/gps_protocol_v2.h"

static struct gps_v2_message msg(const char *line)
{
    struct gps_v2_message m;
    assert(gps_v2_parse(line,&m));
    return m;
}
static int receive(struct gps_v2_client *c,const char *line)
{
    struct gps_v2_message m=msg(line);
    return gps_v2_receive(c,&m);
}
int main(void)
{
    struct gps_v2_message m=msg("START 4294967295");
    assert(m.kind==GPS_V2_START && m.id==GPS_V2_MAX_ID);
    m=msg("STOP 1"); assert(m.kind==GPS_V2_STOP && m.id==1);
    m=msg("DATA 42 NMEA 123 $GPRMC,1*56");
    assert(m.id==42 && !strcmp(m.payload,"NMEA 123 $GPRMC,1*56"));
    const char *bad[]={"", "START", "START 0", "START 01", "START +1",
        "START -1", "START 4294967296", "STOP 1 ", "START  1", "START 1\t",
        "ACK 1 START", "DATA 1", "DATA 1 FIX ", "DATA 1 OTHER x",
        "DATA 0 FIX x", "DATA 1  FIX x", "START 1x"};
    for (unsigned i=0;i<sizeof(bad)/sizeof(bad[0]);++i)
        assert(!gps_v2_parse(bad[i],&m));
    struct gps_v2_client c={GPS_V2_IDLE,0};
    assert(!gps_v2_request(&c,0));
    assert(gps_v2_request(&c,1) && c.id==1);
    assert(!gps_v2_request(&c,1));
    assert(receive(&c,"DATA 1 FIX x")==0);
    assert(receive(&c,"ACK START 2")==-1);
    assert(receive(&c,"ACK STOP 1")==-1);
    assert(receive(&c,"ACK START 1")==1);
    assert(receive(&c,"DATA 1 FIX x")==2);
    assert(receive(&c,"ACK START 1")==-1);
    assert(receive(&c,"DATA 2 STATUS 1")==-1);
    assert(gps_v2_request(&c,0));
    assert(receive(&c,"DATA 1 STATUS 2")==0);
    assert(receive(&c,"ACK STOP 1")==1);
    assert(gps_v2_request(&c,1) && c.id==2);
    assert(receive(&c,"ACK START 2")==1);
    assert(receive(&c,"DATA 1 FIX old")==0);
    assert(receive(&c,"DATA 2 FIX new")==2);
    c.phase=GPS_V2_IDLE; c.id=GPS_V2_MAX_ID;
    assert(!gps_v2_request(&c,1));
    puts("GPS_PROTOCOL_V2=PASS");
    return 0;
}
