#ifndef R800_GPS_ABI_H
#define R800_GPS_ABI_H
/* Local legacy GPS ABI contract, not a verified proprietary donor ABI. */
/* ---- hardware/gps.h (AOSP), 32-bit ARM layout ---- */
typedef int64_t GpsUtcTime;
typedef struct {
	size_t size;
	uint16_t flags;
	double latitude;
	double longitude;
	double altitude;
	float speed;
	float bearing;
	float accuracy;
	GpsUtcTime timestamp;
} GpsLocation;
typedef struct {
	size_t size;
	uint16_t status;
} GpsStatus;
typedef struct {
	size_t size;
	void (*location_cb)(GpsLocation *);
	void (*status_cb)(GpsStatus *);
	void (*sv_status_cb)(void *);
	void (*nmea_cb)(GpsUtcTime, const char *, int);
	void (*set_capabilities_cb)(uint32_t);
	void (*acquire_wakelock_cb)(void);
	void (*release_wakelock_cb)(void);
	pthread_t (*create_thread_cb)(const char *, void (*)(void *), void *);
	void (*request_utc_time_cb)(void);
} GpsCallbacks;
typedef struct {
	size_t size;
	int (*init)(GpsCallbacks *);
	int (*start)(void);
	int (*stop)(void);
	void (*cleanup)(void);
	int (*inject_time)(GpsUtcTime, int64_t, int);
	int (*inject_location)(double, double, float);
	void (*delete_aiding_data)(uint16_t);
	int (*set_position_mode)(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);
	const void *(*get_extension)(const char *);
} GpsInterface;

/* "gps-xtra": Broadcom LTO (long-term orbits), the file Tizen's lbs plugin
 * downloads from gllto1.glpals.com into /opt/gnss/data/lto2.dat */
/* AOSP legacy callbacks have no size member. A sized vendor variant
 * must be explicitly selected after inspecting the exact donor library. */
#ifndef R800_XTRA_ABI
#define R800_XTRA_ABI 0
#endif
#if R800_XTRA_ABI < 0 || R800_XTRA_ABI > 2
#error Invalid R800_XTRA_ABI
#endif
typedef struct {
#if R800_XTRA_ABI == 2
	size_t size;
#endif
	void (*download_request_cb)(void);
	pthread_t (*create_thread_cb)(const char *, void (*)(void *), void *);
} GpsXtraCallbacks;
typedef struct {
	size_t size;
	int (*init)(GpsXtraCallbacks *);
	int (*inject_xtra_data)(char *, int);
} GpsXtraInterface;


#if !defined(__arm__) || !defined(__ARM_EABI__) || defined(__ARM_PCS_VFP)
#error R800 GPS requires ARM32 EABI base calling convention (soft/softfp)
#endif
#define GPS_SIZE(T,N) _Static_assert(sizeof(T)==(N), #T " size")
#define GPS_OFFSET(T,F,N) _Static_assert(__builtin_offsetof(T,F)==(N), #T "." #F " offset")
GPS_SIZE(void *,4);
GPS_SIZE(size_t,4);
GPS_SIZE(pthread_t,4);
GPS_SIZE(GpsUtcTime,8);
GPS_SIZE(GpsLocation,56);
GPS_OFFSET(GpsLocation,size,0);
GPS_OFFSET(GpsLocation,flags,4);
GPS_OFFSET(GpsLocation,latitude,8);
GPS_OFFSET(GpsLocation,longitude,16);
GPS_OFFSET(GpsLocation,altitude,24);
GPS_OFFSET(GpsLocation,speed,32);
GPS_OFFSET(GpsLocation,bearing,36);
GPS_OFFSET(GpsLocation,accuracy,40);
GPS_OFFSET(GpsLocation,timestamp,48);
GPS_SIZE(GpsStatus,8);
GPS_OFFSET(GpsStatus,status,4);
GPS_SIZE(GpsCallbacks,40);
GPS_OFFSET(GpsCallbacks,location_cb,4);
GPS_OFFSET(GpsCallbacks,status_cb,8);
GPS_OFFSET(GpsCallbacks,sv_status_cb,12);
GPS_OFFSET(GpsCallbacks,nmea_cb,16);
GPS_OFFSET(GpsCallbacks,set_capabilities_cb,20);
GPS_OFFSET(GpsCallbacks,acquire_wakelock_cb,24);
GPS_OFFSET(GpsCallbacks,release_wakelock_cb,28);
GPS_OFFSET(GpsCallbacks,create_thread_cb,32);
GPS_OFFSET(GpsCallbacks,request_utc_time_cb,36);
GPS_SIZE(GpsInterface,40);
GPS_OFFSET(GpsInterface,init,4);
GPS_OFFSET(GpsInterface,start,8);
GPS_OFFSET(GpsInterface,stop,12);
GPS_OFFSET(GpsInterface,cleanup,16);
GPS_OFFSET(GpsInterface,inject_time,20);
GPS_OFFSET(GpsInterface,inject_location,24);
GPS_OFFSET(GpsInterface,delete_aiding_data,28);
GPS_OFFSET(GpsInterface,set_position_mode,32);
GPS_OFFSET(GpsInterface,get_extension,36);
GPS_SIZE(GpsXtraInterface,12);
GPS_OFFSET(GpsXtraInterface,init,4);
GPS_OFFSET(GpsXtraInterface,inject_xtra_data,8);
#if R800_XTRA_ABI == 2
GPS_SIZE(GpsXtraCallbacks,12);
GPS_OFFSET(GpsXtraCallbacks,download_request_cb,4);
GPS_OFFSET(GpsXtraCallbacks,create_thread_cb,8);
#else
GPS_SIZE(GpsXtraCallbacks,8);
GPS_OFFSET(GpsXtraCallbacks,download_request_cb,0);
GPS_OFFSET(GpsXtraCallbacks,create_thread_cb,4);
#endif
#undef GPS_SIZE
#undef GPS_OFFSET
#endif
