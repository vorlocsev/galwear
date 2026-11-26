/* Exercise the real Android HAL reader against a synthetic bridge peer.
 * Not a test of Broadcom, Tizen, or Android binary ABI. */
#define main basic_lifecycle_main
#include "test_r800_gps_hal_lifecycle.c"
#undef main

static atomic_int loc_count, nmea_count, sv_count, status_count;
static GpsLocation last_fix;
static GnssSvStatus last_sv;
static int last_status;

static void record_fix(GpsLocation *loc)
{
    last_fix = *loc;
    atomic_fetch_add(&loc_count,1);
}
static void record_nmea(GpsUtcTime ts,const char *s,int len)
{
    assert(ts==123 && len==(int)strlen(s) && gps_nmea_checksum(s));
    atomic_fetch_add(&nmea_count,1);
}
static void record_sv(void *data)
{
    last_sv=*(GnssSvStatus *)data;
    atomic_fetch_add(&sv_count,1);
}
static void record_status(GpsStatus *s)
{
    last_status=s->status;
    atomic_fetch_add(&status_count,1);
}
static void wait_count(atomic_int *counter,int expected)
{
    for(int i=0;i<500 && atomic_load(counter)<expected;++i)
        usleep(10000);
    assert(atomic_load(counter)==expected);
}
static void transmit(int fd,const char *s)
{
    size_t n=strlen(s);
    while(n) {
        ssize_t k=send(fd,s,n,MSG_NOSIGNAL);
        if(k<0 && errno==EINTR) continue;
        assert(k>0);
        s+=k; n-=(size_t)k;
    }
}
static void expect_line(int fd,const char *expected)
{
    for(size_t i=0;i<strlen(expected);++i) {
        char ch;
        await_readable(fd);
        assert(recv(fd,&ch,1,0)==1 && ch==expected[i]);
    }
}
static void nmea(int fd,const char *body)
{
    unsigned cs=0;
    char b[300];
    for(const char *p=body;*p;++p) cs^=(unsigned char)*p;
    int n=snprintf(b,sizeof(b),"NMEA 123 $%s*%02X\n",body,cs);
    assert(n>0 && n<(int)sizeof(b));
    transmit(fd,b);
}
static int connect_peer(int listener)
{
    await_readable(listener);
    int fd=accept(listener,NULL,NULL);
    assert(fd>=0);
    return fd;
}
int main(void)
{
    char dir[]="/tmp/r800-gps-wire.XXXXXX";
    struct sockaddr_un a={0};
    GpsCallbacks c={0};
    assert(mkdtemp(dir));
    assert(snprintf(test_path,sizeof(test_path),"%s/sock",dir)>0);
    int ls=socket(AF_UNIX,SOCK_STREAM,0);
    assert(ls>=0);
    a.sun_family=AF_UNIX;
    strcpy(a.sun_path,test_path);
    assert(!bind(ls,(struct sockaddr *)&a,sizeof(a)));
    assert(!listen(ls,2));
    c.size=sizeof(c);
    c.create_thread_cb=spawn;
    c.location_cb=record_fix;
    c.nmea_cb=record_nmea;
    c.gnss_sv_status_cb=record_sv;
    c.status_cb=record_status;
    assert(!iface.init(&c));
    assert(!iface.start());
    int fd=connect_peer(ls);
    expect_line(fd,"START\n");
    assert(atomic_load(&status_count)==0); /* no optimistic session notification */
    assert(!iface.inject_time(123,1,50));
    expect_line(fd,"TIME 123 1 50\n");
    assert(!iface.inject_location(52,5,0.25f));
    expect_line(fd,"LOC 52.00000000 5.00000000 0.250000\n");
    assert(iface.inject_location(91,5,1)==-EINVAL);
    assert(iface.inject_time(0,0,0)==-EINVAL);
    puts("GPS_PEER_COMMANDS=PASS");

    transmit(fd,"STATUS 1\nFIX 31 52.");
    transmit(fd,"25 5.5 10 2 90 3 123\nFIX 1 91 0 0 0 0 0 123\n");
    transmit(fd,"NMEA 123 $GPRMC,1*00\n");
    nmea(fd,"GPGSV,1,1,02,01,45,123,35,33,10,200,20");
    nmea(fd,"GPGSA,A,3,01,33,,,,,,,,,,,1.0,1.0,1.0");
    nmea(fd,"GPRMC,1");
    wait_count(&loc_count,1);
    wait_count(&sv_count,1);
    wait_count(&nmea_count,3);
    wait_count(&status_count,1);
    assert(last_status==1 && last_fix.latitude==52.25 && last_fix.longitude==5.5);
    assert(last_fix.speed==2 && last_fix.timestamp==123);
    assert(last_sv.num_svs==2);
    assert(last_sv.gnss_sv_list[0].svid==1 && last_sv.gnss_sv_list[0].flags==4);
    assert(last_sv.gnss_sv_list[1].constellation==2 && last_sv.gnss_sv_list[1].svid==120);
    assert(last_sv.gnss_sv_list[1].flags==4);
    puts("GPS_PEER_FRAGMENTED_FIX_AND_SATELLITES=PASS");

    nmea(fd,"GLGSV,2,1,05,65,10,100,20,66,20,120,30,67,30,140,40,68,40,160,50");
    nmea(fd,"GPRMC,1");
    wait_count(&sv_count,2);
    assert(last_sv.num_svs==0); /* missing part 2 */
    nmea(fd,"GPGSV,1,1,01,02,45,123,35");
    transmit(fd,"STATUS 3\n");
    wait_count(&status_count,2); /* FIFO barrier: pending GSV received */
    assert(!iface.stop());
    expect_line(fd,"STOP\n");
    transmit(fd,"FIX 1 50 5 0 0 0 0 123\nSTATUS 2\n");
    wait_count(&status_count,3);
    assert(last_status==2 && atomic_load(&loc_count)==1);
    assert(!iface.start());
    expect_line(fd,"START\n");
    nmea(fd,"GPRMC,1");
    wait_count(&sv_count,3);
    assert(last_sv.num_svs==0); /* no stale satellites across STOP/START */
    puts("GPS_PEER_STOP_AND_EPOCH_RESET=PASS");

    transmit(fd,"FIX 1 52");
    close(fd);
    fd=connect_peer(ls);
    expect_line(fd,"START\n");
    transmit(fd,"FIX 1 53 6 0 0 0 0 123\nSTATUS 3\n");
    wait_count(&status_count,4);
    wait_count(&loc_count,2);
    assert(last_fix.latitude==53 && last_fix.longitude==6);
    puts("GPS_PEER_RECONNECT=PASS");

    char bad[520];
    memset(bad,'X',sizeof(bad)-1); bad[sizeof(bad)-1]=0;
    transmit(fd,bad);
    await_readable(fd);
    char ch;
    ssize_t got=recv(fd,&ch,1,0);
    assert(got==0 || (got<0 && errno==ECONNRESET));
    close(fd);
    fd=connect_peer(ls);
    expect_line(fd,"START\n");
    const char nul[]={'F','I','X',' ',0,'\n'};
    assert(send(fd,nul,sizeof(nul),MSG_NOSIGNAL)==(ssize_t)sizeof(nul));
    await_readable(fd);
    got=recv(fd,&ch,1,0);
    assert(got==0 || (got<0 && errno==ECONNRESET));
    close(fd);
    fd=connect_peer(ls);
    expect_line(fd,"START\n");
    assert(atomic_load(&loc_count)==2);

    /* A complete GSV epoch on the old connection must not survive
     * reconnection, even when the wanted session is still active. */
    nmea(fd,"GPGSV,1,1,01,02,45,123,35");
    transmit(fd,"STATUS 3\n");
    wait_count(&status_count,5);
    close(fd);
    fd=connect_peer(ls);
    expect_line(fd,"START\n");
    nmea(fd,"GPRMC,1");
    wait_count(&sv_count,4);
    assert(last_sv.num_svs==0);

    /* STOP while connected clears the replay intent. A new idle
     * connection must accept TIME without a spurious START first. */
    assert(!iface.stop());
    expect_line(fd,"STOP\n");
    close(fd);
    fd=connect_peer(ls);
    int rc=-ENOTCONN;
    for (int i=0;i<500 && rc==-ENOTCONN;++i) {
        rc=iface.inject_time(123,1,50);
        if (rc==-ENOTCONN) usleep(10000);
    }
    assert(rc==0);
    expect_line(fd,"TIME 123 1 50\n");
    assert(!iface.start());
    expect_line(fd,"START\n");
    puts("GPS_PEER_ACTIVE_AND_IDLE_RECONNECT=PASS");

    iface.cleanup();
    await_readable(fd);
    assert(recv(fd,&ch,1,0)==0);
    assert(iface.inject_time(123,1,1)==-ENOTCONN);
    close(fd); close(ls); unlink(test_path); rmdir(dir);
    puts("GPS_PEER_MALFORMED_FRAME_AND_CLEANUP=PASS");
    puts("GPS_HAL_SYNTHETIC_PEER=PASS");
    return 0;
}
