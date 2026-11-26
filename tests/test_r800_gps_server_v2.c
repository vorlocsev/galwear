#include <assert.h>
#include <stdio.h>
#include "../src/tools/gps/gps_server_v2.h"

static unsigned int id;
static enum gps_server_action plan(struct gps_v2_server *s,const char *line)
{
    return gps_server_plan(s,line,&id);
}
int main(void)
{
    struct gps_v2_server s={0};
    assert(plan(&s,"HELLO 3")==GPS_SERVER_REJECT && !s.mode);
    assert(plan(&s,"START 1")==GPS_SERVER_REJECT && !s.mode);
    assert(plan(&s,"HELLO 2")==GPS_SERVER_READY && s.mode==GPS_SERVER_V2);
    assert(plan(&s,"HELLO 2")==GPS_SERVER_REJECT);
    assert(plan(&s,"START")==GPS_SERVER_REJECT);
    assert(plan(&s,"START 2")==GPS_SERVER_REJECT);
    assert(plan(&s,"STOP 1")==GPS_SERVER_REJECT);
    assert(plan(&s,"START 1")==GPS_SERVER_START && id==1 && !s.active);
    gps_server_commit(&s,GPS_SERVER_START,id);
    assert(s.active && s.id==1);
    assert(plan(&s,"START 1")==GPS_SERVER_REJECT);
    assert(plan(&s,"START 2")==GPS_SERVER_REJECT);
    assert(plan(&s,"ACK START 1")==GPS_SERVER_REJECT);
    assert(plan(&s,"DATA 1 FIX x")==GPS_SERVER_REJECT);
    assert(plan(&s,"TIME 123")==GPS_SERVER_TIME);
    assert(plan(&s,"LOC 52 5 1")==GPS_SERVER_LOC);
    assert(plan(&s,"TIME ")==GPS_SERVER_REJECT);
    assert(plan(&s,"STOP 2")==GPS_SERVER_REJECT);
    assert(plan(&s,"STOP 1")==GPS_SERVER_STOP && id==1 && s.active);
    gps_server_commit(&s,GPS_SERVER_STOP,id);
    assert(!s.active && s.id==1);
    assert(plan(&s,"START 1")==GPS_SERVER_REJECT);
    assert(plan(&s,"START 2")==GPS_SERVER_START && id==2);
    gps_server_commit(&s,GPS_SERVER_START,id);
    assert(plan(&s,"STOP 2")==GPS_SERVER_STOP);
    gps_server_commit(&s,GPS_SERVER_STOP,id);
    s.id=GPS_V2_MAX_ID;
    assert(plan(&s,"START 1")==GPS_SERVER_REJECT);

    s=(struct gps_v2_server){0};
    assert(plan(&s,"START")==GPS_SERVER_START && s.mode==GPS_SERVER_V1);
    gps_server_commit(&s,GPS_SERVER_START,id);
    assert(plan(&s,"START")==GPS_SERVER_NOOP);
    assert(plan(&s,"HELLO 2")==GPS_SERVER_REJECT);
    assert(plan(&s,"STOP")==GPS_SERVER_STOP);
    gps_server_commit(&s,GPS_SERVER_STOP,id);
    assert(plan(&s,"STOP")==GPS_SERVER_NOOP);
    s=(struct gps_v2_server){0};
    assert(plan(&s,"TIME 123")==GPS_SERVER_TIME && s.mode==GPS_SERVER_V1);
    assert(plan(&s,"HELLO 2")==GPS_SERVER_REJECT);
    puts("GPS_SERVER_V2=PASS");
    return 0;
}
