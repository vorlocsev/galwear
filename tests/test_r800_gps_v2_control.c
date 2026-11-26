#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "../src/hal/gps_v2_control.h"

static const char *payload;
static int receive(struct gps_v2_control *c, const char *line, int wanted,
                   unsigned long epoch, long long now)
{
    return gps_v2_control_receive(c,line,wanted,epoch,now,&payload);
}
int main(void)
{
    struct gps_v2_control c;
    gps_v2_control_reset(&c,100);
    assert(gps_v2_control_plan(&c,1,1,101)==0);
    assert(receive(&c,"READY 1",1,1,102)==-1);
    assert(receive(&c,"READY 2",1,1,5100)==-1);
    assert(gps_v2_control_plan(&c,1,1,5100)==-1);
    assert(receive(&c,"READY 2",1,1,103)==1);
    assert(gps_v2_control_plan(&c,1,1,104)==1 && c.session.id==1);
    assert(receive(&c,"DATA 1 FIX x",1,1,105)==0);
    assert(receive(&c,"ACK START 1",1,1,106)==1);
    assert(receive(&c,"DATA 1 FIX x",1,1,107)==2 && !strcmp(payload,"FIX x"));
    assert(receive(&c,"DATA 1 FIX x",0,2,108)==0 && !payload);
    assert(receive(&c,"DATA 1 FIX x",1,3,109)==0);
    assert(gps_v2_control_plan(&c,1,3,110)==2);
    assert(receive(&c,"ACK STOP 1",1,3,111)==1);
    assert(gps_v2_control_plan(&c,1,3,112)==1 && c.session.id==2);
    assert(receive(&c,"ACK START 2",1,3,113)==1);
    assert(receive(&c,"DATA 1 FIX old",1,3,114)==0);
    assert(receive(&c,"DATA 2 FIX new",1,3,115)==2);
    assert(gps_v2_control_plan(&c,0,4,116)==2);
    assert(gps_v2_control_plan(&c,0,4,5116)==-1);
    gps_v2_control_reset(&c,6000);
    assert(receive(&c,"READY 2",0,4,6001)==1);
    assert(gps_v2_control_plan(&c,0,4,6002)==0 && c.session.id==0);
    assert(gps_v2_control_plan(&c,1,5,6003)==1 && c.session.id==1);
    assert(gps_v2_control_plan(&c,0,6,6004)==0);
    assert(receive(&c,"ACK START 1",0,6,6005)==1);
    assert(gps_v2_control_plan(&c,0,6,6006)==2);
    assert(receive(&c,"ACK STOP 1",0,6,6007)==1);
    puts("GPS_V2_CONTROL=PASS");
    return 0;
}
