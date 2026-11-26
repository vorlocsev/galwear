#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "../src/hal/gps_epoch_frame.h"

static int feed(struct gps_epoch_frame *f, unsigned long epoch, const char *s)
{
    int count=0;
    for (; *s; ++s) {
        int rc=gps_epoch_byte(f,epoch,(unsigned char)*s);
        assert(rc>=0);
        if (rc==1) { ++count; f->frame.used=0; }
    }
    return count;
}

int main(void)
{
    struct gps_epoch_frame f={0};
    gps_epoch_reset(&f,1);
    assert(feed(&f,1,"FIX 1")==0);
    assert(feed(&f,1," 52\n")==1);
    assert(!strcmp(f.frame.line,"FIX 1 52"));
    assert(feed(&f,1,"FIX 1")==0);
    assert(feed(&f,2," 53\n")==0);
    assert(feed(&f,2,"STATUS 1\n")==1);
    assert(!strcmp(f.frame.line,"STATUS 1"));
    assert(feed(&f,2,"FIX")==0);
    assert(feed(&f,3," 1")==0 && f.dropping);
    assert(feed(&f,4," 52\nSTATUS 2\n")==1);
    assert(!strcmp(f.frame.line,"STATUS 2"));
    assert(feed(&f,4,"FIX")==0);
    gps_epoch_reset(&f,4);
    assert(feed(&f,4,"STATUS 3\n")==1);
    assert(!strcmp(f.frame.line,"STATUS 3"));
    assert(feed(&f,4,"X")==0);
    assert(gps_epoch_byte(&f,5,0)==-1);
    gps_epoch_reset(&f,6);
    assert(gps_epoch_byte(&f,6,0)==-1);
    gps_epoch_reset(&f,7);
    assert(feed(&f,7,"X")==0);
    for (unsigned int i=1; i<GPS_FRAME_CAPACITY-2; ++i)
        assert(gps_epoch_byte(&f,8,'X')==0);
    assert(gps_epoch_byte(&f,8,'X')==-1);
    puts("GPS_EPOCH_FRAME=PASS");
    return 0;
}
