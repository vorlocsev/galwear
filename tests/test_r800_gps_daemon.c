#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "../src/tools/gps/gps_daemon.h"

static char trace[64];
static unsigned used, configs, fail_configs;
static int fail_start, fail_stop, fail_init;
static void mark(char c) { assert(used < sizeof(trace)-1); trace[used++]=c; trace[used]=0; }
static void aid(void) { mark('A'); }
static int configure(void) { mark('C'); return ++configs <= fail_configs; }
static int start(void) { mark('S'); return fail_start; }
static int stop(void) { mark('T'); return fail_stop; }
static void cleanup(void) { mark('X'); }
static int reinit(void) { mark('I'); return fail_init; }
static const struct gps_daemon_ops ops = {aid,configure,start,stop,cleanup,reinit};

static enum gps_daemon_state reset(void)
{
    used=configs=fail_configs=0; trace[0]=0;
    fail_start=fail_stop=fail_init=0;
    return GPS_DAEMON_READY;
}

int main(void)
{
    enum gps_daemon_state s=reset();
    assert(!gps_daemon_session(&s,&ops,0));
    assert(!gps_daemon_session(&s,&ops,1));
    assert(!gps_daemon_session(&s,&ops,1));
    assert(s==GPS_DAEMON_ACTIVE);
    assert(!gps_daemon_session(&s,&ops,0));
    assert(!gps_daemon_session(&s,&ops,1));
    assert(!gps_daemon_close(&s,&ops));
    assert(!gps_daemon_close(&s,&ops));
    assert(s==GPS_DAEMON_CLOSED && !strcmp(trace,"ACSTACSTX"));
    assert(gps_daemon_session(&s,&ops,1));

    s=reset(); fail_configs=1;
    assert(!gps_daemon_session(&s,&ops,1));
    assert(!gps_daemon_close(&s,&ops));
    assert(!strcmp(trace,"ACXIACSTX"));

    s=reset(); fail_configs=2;
    assert(gps_daemon_session(&s,&ops,1));
    assert(s==GPS_DAEMON_READY);
    assert(!gps_daemon_close(&s,&ops));
    assert(!strcmp(trace,"ACXIACX"));

    s=reset(); fail_configs=1; fail_init=1;
    assert(gps_daemon_session(&s,&ops,1));
    assert(s==GPS_DAEMON_BROKEN);
    assert(gps_daemon_close(&s,&ops));
    assert(!strcmp(trace,"ACXI"));

    s=reset(); fail_start=1;
    assert(gps_daemon_session(&s,&ops,1));
    assert(s==GPS_DAEMON_BROKEN);
    assert(gps_daemon_session(&s,&ops,1));
    assert(gps_daemon_close(&s,&ops));
    assert(!strcmp(trace,"ACS"));

    s=reset(); fail_stop=1;
    assert(!gps_daemon_session(&s,&ops,1));
    assert(gps_daemon_session(&s,&ops,0));
    assert(s==GPS_DAEMON_BROKEN);
    assert(gps_daemon_close(&s,&ops));
    assert(!strcmp(trace,"ACST"));

    s=reset(); fail_stop=1;
    assert(!gps_daemon_session(&s,&ops,1));
    assert(gps_daemon_close(&s,&ops));
    assert(!strcmp(trace,"ACST"));

    s=reset();
    assert(!gps_daemon_close(&s,&ops));
    assert(!strcmp(trace,"X"));
    puts("GPS_DAEMON_GATE=PASS");
    return 0;
}
