/* Synthetic ARM32 HAL fixture. Never install on a watch or use with real GNSS. */
typedef unsigned int size_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef long long int64_t;
typedef unsigned long pthread_t;
#include "../src/tools/gps/gps_abi.h"

#ifndef MOCK_FAIL
#define MOCK_FAIL 0
#endif
#if MOCK_FAIL < 0 || MOCK_FAIL > 4
#error Invalid mock failure stage
#endif
#if R800_XTRA_ABI != 0
#error Mock exercises only the disabled XTRA contract
#endif

static GpsCallbacks *callbacks;
static unsigned state, time_seen;
static GpsLocation fix = {sizeof(GpsLocation), 31, 12.5, -34.25, 100.0,
                          1.5f, 90.0f, 5.0f, 1700000000000LL};
static GpsLocation invalid_fix = {0, 1, 0, 0, 0, 0, 0, 0, 1700000000000LL};
static GpsStatus started = {sizeof(GpsStatus), 1};
static GpsStatus stopped = {sizeof(GpsStatus), 2};
static GpsStatus invalid_status = {0, 99};
static const char nmea[] = "$GPGGA,MOCK*00\r\n";
static const char invalid_nmea[] = "$GPGGA,BAD\nFRAME";

static int mock_init(GpsCallbacks *cb)
{
    if (state || !cb || cb->size != sizeof(*cb) || !cb->location_cb ||
        !cb->status_cb || !cb->nmea_cb || !cb->set_capabilities_cb)
        return -90;
    if (MOCK_FAIL == 1) return -11;
    callbacks = cb;
    state = 1;
    cb->set_capabilities_cb(0x1234);
    return 0;
}
static int mock_time(GpsUtcTime utc, int64_t ref, int unc)
{
    if ((state != 1 && state != 3) || utc <= 0 || ref < 0 || unc < 0) return -91;
    time_seen = 1;
    return 0;
}
static int mock_location(double lat, double lon, float acc)
{
    return (state == 1 || state == 3) && lat >= -90 && lat <= 90 && lon >= -180 && lon <= 180 && acc > 0 ? 0 : -92;
}
static int mock_mode(uint32_t mode, uint32_t recurrence, uint32_t interval,
                     uint32_t accuracy, uint32_t time)
{
    if (state != 1 || !time_seen || mode || recurrence || interval != 1000 || accuracy || time)
        return -93;
    if (MOCK_FAIL == 2) return -12;
    state = 2;
    return 0;
}
static int mock_start(void)
{
    if (state != 2) return -94;
    if (MOCK_FAIL == 3) return -13;
    state = 3;
    callbacks->status_cb(&invalid_status);
    callbacks->location_cb(&invalid_fix);
    callbacks->nmea_cb(fix.timestamp, invalid_nmea, sizeof(invalid_nmea)-1);
    callbacks->status_cb(&started);
    callbacks->location_cb(&fix);
    callbacks->nmea_cb(fix.timestamp, nmea, sizeof(nmea)-1);
    return 0;
}
static int mock_stop(void)
{
    if (state != 3) return -95;
    if (MOCK_FAIL == 4) return -14;
    state = 1;
    time_seen = 0;
    callbacks->status_cb(&stopped);
    return 0;
}
static void mock_cleanup(void)
{
    if (callbacks) callbacks->set_capabilities_cb(0x4321);
    callbacks = 0;
    state = time_seen = 0;
}
static const void *mock_extension(const char *name)
{
    (void)name;
    /* Unexpected XTRA lookup must become visible in the transcript. */
    if (callbacks) callbacks->set_capabilities_cb(0xdead);
    return 0;
}
static const GpsInterface interface = {
    sizeof(GpsInterface), mock_init, mock_start, mock_stop, mock_cleanup,
    mock_time, mock_location, 0, mock_mode, mock_extension
};
__attribute__((visibility("default")))
const GpsInterface *gps_get_hardware_interface(void)
{
    return &interface;
}
