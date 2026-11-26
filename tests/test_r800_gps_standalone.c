#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "../src/tools/gps/gps_standalone.h"

static char trace[16];
static unsigned int used, interrupted;
static int config_error, start_error, stop_error;
static void mark(char c) { assert(used < sizeof(trace)-1); trace[used++]=c; trace[used]=0; }
static void aid(void) { mark('A'); }
static int configure(void) { mark('C'); return config_error; }
static int start(void) { mark('S'); return start_error; }
static unsigned int wait_run(unsigned int seconds) { mark('W'); assert(seconds==90); return interrupted; }
static int stop(void) { mark('T'); return stop_error; }
static void cleanup(void) { mark('X'); }
static const struct gps_standalone_ops ops = {aid,configure,start,wait_run,stop,cleanup};

static void scenario(int c,int s,int t,unsigned int i,enum gps_run_result expected,const char *order)
{
    used=0; trace[0]=0;
    config_error=c; start_error=s; stop_error=t; interrupted=i;
    assert(gps_standalone_run(&ops,90)==expected);
    assert(!strcmp(trace,order));
}

int main(void)
{
    unsigned int seconds=777;
    scenario(0,0,0,0,GPS_RUN_OK,"ACSWTX");
    scenario(1,0,0,0,GPS_RUN_CONFIG_FAILED,"ACX");
    scenario(0,1,0,0,GPS_RUN_START_FAILED,"ACS");
    scenario(0,0,1,0,GPS_RUN_STOP_FAILED,"ACSWT");
    scenario(0,0,0,1,GPS_RUN_INTERRUPTED,"ACSWTX");
    scenario(0,0,1,1,GPS_RUN_STOP_FAILED,"ACSWT");
    assert(gps_standalone_duration("1",&seconds) && seconds==1);
    assert(gps_standalone_duration("3600",&seconds) && seconds==3600);
    const char *invalid[]={NULL,"","0","-1","+1","3601","90x","90 "," 90","9999999999999999999"};
    for (unsigned int n=0;n<sizeof(invalid)/sizeof(invalid[0]);++n) {
        assert(!gps_standalone_duration(invalid[n],&seconds));
        assert(seconds==3600);
    }
    puts("GPS_STANDALONE_GATE=PASS");
    return 0;
}
