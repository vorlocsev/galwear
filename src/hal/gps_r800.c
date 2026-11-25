/*
 * gps.r800.so: legacy GPS HAL module (hardware/gps.h) for the SM-R800 Wear OS port.
 *
 * The BCM47758 GNSS is driven from the Tizen chroot by tools/gps/gpsbridge (via
 * Tizen's lhd + Broadcom gpsd + libbrcm). gpsbridge listens on a unix socket on
 * the shared user partition; this module connects to it, sends START / STOP /
 * TIME, and turns the lines it gets back into GpsCallbacks:
 *
 *   FIX <flags> <lat> <lon> <alt> <speed> <bearing> <accuracy> <utc_ms>
 *   NMEA <utc_ms> <sentence>
 *   STATUS <n>
 *
 * Loaded by android.hardware.gnss@1.0-impl (hw_get_module("gps"),
 * ro.hardware=r800), which the vendor GNSS service registers as IGnss.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <time.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#ifndef R800_GPS_HOST_TEST
#include <android/log.h>
#include <hardware/hardware.h>
#endif
#include "gps_wire.h"
#include "../tools/gps/gps_frame.h"

#ifdef R800_GPS_HOST_TEST
#define LOGI(...) ((void)0)
#define LOGE(...) ((void)0)
#else
#define LOG_TAG "gps-r800"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#endif

#ifndef SOCK_PATH
#define SOCK_PATH "/oem/r800dev/gps.sock"
#endif

/* ---- hardware/gps.h (AOSP, stable ABI) ---- */
#define GPS_HARDWARE_MODULE_ID "gps"
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
	void (*set_system_info_cb)(const void *);
	void (*gnss_sv_status_cb)(void *);	/* GnssSvStatus* */
} GpsCallbacks;

/* hardware/gps.h GnssSvStatus (32-bit layout) */
#define GNSS_MAX_SVS 64
typedef struct {
	size_t size;
	int16_t svid;
	uint8_t constellation;	/* 1 GPS, 2 SBAS, 3 GLONASS, 4 QZSS, 5 BEIDOU, 6 GALILEO */
	float c_n0_dbhz;
	float elevation;
	float azimuth;
	uint8_t flags;		/* 1 ephemeris, 2 almanac, 4 used in fix */
} GnssSvInfo;
typedef struct {
	size_t size;
	int num_svs;
	GnssSvInfo gnss_sv_list[GNSS_MAX_SVS];
} GnssSvStatus;
/* legacy GpsSvStatus, for a framework wrapper that lacks gnss_sv_status_cb */
typedef struct {
	size_t size;
	int prn;
	float snr;
	float elevation;
	float azimuth;
} GpsSvInfo;
typedef struct {
	size_t size;
	int num_svs;
	GpsSvInfo sv_list[32];
	uint32_t ephemeris_mask;
	uint32_t almanac_mask;
	uint32_t used_in_fix_mask;
} GpsSvStatus;
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
 #ifndef R800_GPS_HOST_TEST
struct gps_device_t {
	struct hw_device_t common;
	const GpsInterface *(*get_gps_interface)(struct gps_device_t *);
};
#endif
#define GPS_CAPABILITY_SCHEDULING 0x01
#define GPS_STATUS_SESSION_BEGIN 1
#define GPS_STATUS_SESSION_END 2
#define GPS_STATUS_ENGINE_ON 3
#define GPS_STATUS_ENGINE_OFF 4

static GpsCallbacks callbacks_owned;
static GpsCallbacks *cb = &callbacks_owned;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static int sock = -1;
static int sock_failed; /* protected by lock; only reader closes published fd */
static int want_on;          /* framework asked for a session */
/* All lifecycle state below is protected by lock. The reader owns callback
 * delivery and the published fd. The framework may create detached threads. */
static int running, starting, reader_alive, reader_id_valid, cleaning;
static pthread_t reader_id;
static pthread_cond_t state_changed = PTHREAD_COND_INITIALIZER;

static int reader_running(void)
{
    int active;
    pthread_mutex_lock(&lock);
    active = running;
    pthread_mutex_unlock(&lock);
    return active;
}
static void retry_wait(int seconds)
{
    struct timespec deadline;
    if (clock_gettime(CLOCK_REALTIME, &deadline) != 0)
        return;
    deadline.tv_sec += seconds;
    pthread_mutex_lock(&lock);
    while (running) {
        if (pthread_cond_timedwait(&state_changed, &lock, &deadline) != 0)
            break;
    }
    pthread_mutex_unlock(&lock);
}

/* call with lock held */
static int send_line(const char *s)
{
    size_t n = strlen(s);
    if (!running || sock < 0 || sock_failed)
        return -ENOTCONN;
    if (send(sock, s, n, MSG_DONTWAIT | MSG_NOSIGNAL) != (ssize_t)n) {
        LOGE("bridge send failed or partial");
        sock_failed = 1;
        shutdown(sock, SHUT_RDWR);
        return -EIO;
    }
    return 0;
}

static void report_status(uint16_t st)
{
	GpsStatus s = { sizeof(s), st };
	if (cb && cb->status_cb)
		cb->status_cb(&s);
}

/*
 * Satellite status from the NMEA the bridge forwards: GSV gives the satellites in
 * view (PRN, elevation, azimuth, C/N0) per system, GSA the PRNs used in the fix.
 * One report per epoch, sent when the epoch's RMC arrives.
 */
static GnssSvStatus sv_cur;		/* being filled for this epoch */
static int used[8][100];		/* [constellation][svid] used in fix */

static int talker_constellation(const char *t)
{
	if (!strncmp(t, "GP", 2)) return 1;
	if (!strncmp(t, "GL", 2)) return 3;
	if (!strncmp(t, "QZ", 2)) return 4;
	if (!strncmp(t, "BD", 2) || !strncmp(t, "GB", 2)) return 5;
	if (!strncmp(t, "GA", 2)) return 6;
	return 0;
}

/* NMEA PRN -> (constellation, svid) as GnssSvInfo wants them */
static void map_prn(int c, int prn, int *oc, int *svid)
{
	*oc = c;
	*svid = prn;
	if (prn >= 65 && prn <= 96) {		/* GLONASS: slot + 64 */
		*oc = 3;
		*svid = prn - 64;
	} else if (prn >= 193 && prn <= 200) {	/* QZSS */
		*oc = 4;
	} else if (prn >= 33 && prn <= 64 && c == 1) {	/* SBAS: 120 + (prn - 33) */
		*oc = 2;
		*svid = prn + 87;
	} else if (prn >= 201 && prn <= 263) {	/* BeiDou, 200+ style */
		*oc = 5;
		*svid = prn - 200;
	}
}

static int field(const char **p, char *out, int n)
{
	int i = 0;
	if (!**p)
		return 0;
	while (**p && **p != ',' && **p != '*') {
		if (i < n - 1)
			out[i++] = **p;
		(*p)++;
	}
	out[i] = 0;
	if (**p == ',')
		(*p)++;
	else if (**p == '*')
		*p += strlen(*p);
	return 1;
}

static void parse_gsv(const char *s, int c)
{
	char f[16];
	const char *p = strchr(s, ',');
	int k;
	if (!p || !c)
		return;
	p++;
	field(&p, f, sizeof(f));	/* total messages */
	field(&p, f, sizeof(f));	/* message number */
	field(&p, f, sizeof(f));	/* satellites in view */
	for (k = 0; k < 4; k++) {
		char prn[8], el[8], az[8], snr[8];
		int oc, svid;
		if (!field(&p, prn, sizeof(prn)) || !prn[0])
			break;
		field(&p, el, sizeof(el));
		field(&p, az, sizeof(az));
		field(&p, snr, sizeof(snr));
		if (sv_cur.num_svs >= GNSS_MAX_SVS)
			return;
		map_prn(c, atoi(prn), &oc, &svid);
		GnssSvInfo *v = &sv_cur.gnss_sv_list[sv_cur.num_svs++];
		memset(v, 0, sizeof(*v));
		v->size = sizeof(*v);
		v->svid = (int16_t)svid;
		v->constellation = (uint8_t)oc;
		v->c_n0_dbhz = snr[0] ? (float)atof(snr) : 0.0f;
		v->elevation = el[0] ? (float)atof(el) : 0.0f;
		v->azimuth = az[0] ? (float)atof(az) : 0.0f;
	}
}

static void parse_gsa(const char *s, int c)
{
	char f[16];
	const char *p = strchr(s, ',');
	int k;
	if (!p)
		return;
	p++;
	field(&p, f, sizeof(f));	/* mode A/M */
	field(&p, f, sizeof(f));	/* fix type */
	for (k = 0; k < 12; k++) {
		int oc, svid;
		if (!field(&p, f, sizeof(f)))
			break;
		if (!f[0])
			continue;
		map_prn(c ? c : 1, atoi(f), &oc, &svid);
		if (oc > 0 && oc < 8 && svid > 0 && svid < 100)
			used[oc][svid] = 1;
	}
}

static void report_sv(void)
{
	int i;
	for (i = 0; i < sv_cur.num_svs; i++) {
		GnssSvInfo *v = &sv_cur.gnss_sv_list[i];
		if (v->constellation < 8 && v->svid > 0 && v->svid < 100 && used[v->constellation][v->svid])
			v->flags |= 4;
		if (v->elevation > 0 || v->azimuth > 0)
			v->flags |= 2;	/* position known: from almanac/LTO at least */
	}
	sv_cur.size = sizeof(sv_cur);
	if (cb && cb->size >= sizeof(GpsCallbacks) && cb->gnss_sv_status_cb) {
		cb->gnss_sv_status_cb(&sv_cur);
	} else if (cb && cb->sv_status_cb) {
		GpsSvStatus g;
		memset(&g, 0, sizeof(g));
		g.size = sizeof(g);
		for (i = 0; i < sv_cur.num_svs && g.num_svs < 32; i++) {
			GnssSvInfo *v = &sv_cur.gnss_sv_list[i];
			if (v->constellation != 1)
				continue;
			GpsSvInfo *o = &g.sv_list[g.num_svs++];
			o->size = sizeof(*o);
			o->prn = v->svid;
			o->snr = v->c_n0_dbhz;
			o->elevation = v->elevation;
			o->azimuth = v->azimuth;
			if (v->flags & 4 && v->svid <= 32)
				g.used_in_fix_mask |= 1u << (v->svid - 1);
		}
		cb->sv_status_cb(&g);
	}
	memset(&sv_cur, 0, sizeof(sv_cur));
	memset(used, 0, sizeof(used));
}

static void handle_nmea_sv(const char *s)
{
	if (s[0] != '$' || strlen(s) < 7)
		return;
	if (!strncmp(s + 3, "GSV", 3))
		parse_gsv(s, talker_constellation(s + 1));
	else if (!strncmp(s + 3, "GSA", 3))
		parse_gsa(s, talker_constellation(s + 1));
	else if (!strncmp(s + 3, "RMC", 3))
		report_sv();
}

static void handle_line(char *l)
{
    if (!strncmp(l, "FIX ", 4)) {
        struct gps_wire_fix f;
        GpsLocation loc;
        if (!gps_wire_parse_fix(l + 4, &f))
            return;
        memset(&loc, 0, sizeof(loc));
        loc.size = sizeof(loc);
        loc.flags = (uint16_t)f.flags;
        loc.latitude = f.lat;
        loc.longitude = f.lon;
        loc.altitude = f.alt;
        loc.speed = (float)f.speed;
        loc.bearing = (float)f.bearing;
        loc.accuracy = (float)f.accuracy;
        loc.timestamp = f.utc;
        if (cb && cb->location_cb)
            cb->location_cb(&loc);
    } else if (!strncmp(l, "NMEA ", 5)) {
        long long ts;
        const char *sentence;
        if (!gps_wire_parse_nmea(l + 5, &ts, &sentence))
            return;
        if (cb && cb->nmea_cb)
            cb->nmea_cb(ts, sentence, (int)strlen(sentence));
        if (reader_running())
            handle_nmea_sv(sentence);
    } else if (!strncmp(l, "STATUS ", 7)) {
        int st;
        if (gps_wire_parse_status(l + 7, &st))
            report_status((uint16_t)st);
    }
}

/* connects (retrying), re-sends the wanted state, then reads lines forever */
static void reader(void *arg)
{
	char buf[256];
	struct gps_frame frame = {{0}, 0};
	(void)arg;

	pthread_mutex_lock(&lock);
    reader_id = pthread_self();
    reader_id_valid = 1;
    pthread_mutex_unlock(&lock);
    if (reader_running() && cb->set_capabilities_cb)
        cb->set_capabilities_cb(GPS_CAPABILITY_SCHEDULING);

	while (reader_running()) {
		int fd;
		struct sockaddr_un a;

		pthread_mutex_lock(&lock);
		fd = sock;
		pthread_mutex_unlock(&lock);
		if (fd < 0) {
			fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
			memset(&a, 0, sizeof(a));
			a.sun_family = AF_UNIX;
			strncpy(a.sun_path, SOCK_PATH, sizeof(a.sun_path) - 1);
			if (fd < 0 || connect(fd, (struct sockaddr *)&a, sizeof(a)) < 0 ||
                fcntl(fd, F_SETFL, 0) < 0) {
				if (fd >= 0)
					close(fd);
				retry_wait(2);
				continue;
			}
			LOGI("connected to %s", SOCK_PATH);
			pthread_mutex_lock(&lock);
			if (!running) {
                pthread_mutex_unlock(&lock);
                close(fd);
                break;
            }
            sock = fd;
			sock_failed = 0;
			if (want_on)
				send_line("START\n");
			pthread_mutex_unlock(&lock);
			frame.used = 0;
			memset(&sv_cur, 0, sizeof(sv_cur));
			memset(used, 0, sizeof(used));
		}
		ssize_t n = read(fd, buf, sizeof(buf));
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			goto disconnected;
		for (ssize_t i = 0; i < n; ++i) {
			int state = gps_frame_byte(&frame, (unsigned char)buf[i]);
			if (state < 0)
				goto disconnected;
			if (state == 1) {
                int deliver;
                pthread_mutex_lock(&lock);
                deliver = running && (want_on || !strncmp(frame.line,"STATUS ",7));
                pthread_mutex_unlock(&lock);
                if (deliver)
                    handle_line(frame.line);
				frame.used = 0;
			}
		}
		continue;
disconnected:
		LOGE("bridge connection lost or malformed frame");
		pthread_mutex_lock(&lock);
		if (sock == fd) {
			sock = -1;
			sock_failed = 0;
		}
		close(fd);
		pthread_mutex_unlock(&lock);
		frame.used = 0;
		retry_wait(1);
	}
    pthread_mutex_lock(&lock);
    if (sock >= 0) {
        close(sock);
        sock = -1;
    }
    sock_failed = 0;
    want_on = 0;
    running = 0;
    reader_id_valid = 0;
    reader_alive = 0;
    memset(&callbacks_owned, 0, sizeof(callbacks_owned));
    pthread_cond_broadcast(&state_changed);
    pthread_mutex_unlock(&lock);
}

static int gps_init(GpsCallbacks *callbacks)
{
    const size_t legacy = offsetof(GpsCallbacks, set_system_info_cb);
    size_t size;
    pthread_t (*create)(const char *, void (*)(void *), void *);
    pthread_t th;

    if (!callbacks || callbacks->size < legacy)
        return -EINVAL;
    size = callbacks->size;
    if (!callbacks->create_thread_cb)
        return -EINVAL;
    pthread_mutex_lock(&lock);
    if (starting || reader_alive || running || cleaning) {
        pthread_mutex_unlock(&lock);
        return -EBUSY;
    }
    memset(&callbacks_owned, 0, sizeof(callbacks_owned));
    /* Copy complete known fields only; never retain the caller's pointer. */
    memcpy(&callbacks_owned, callbacks, legacy);
    callbacks_owned.size = legacy;
    if (size >= offsetof(GpsCallbacks, gnss_sv_status_cb)) {
        callbacks_owned.set_system_info_cb = callbacks->set_system_info_cb;
        callbacks_owned.size = offsetof(GpsCallbacks, gnss_sv_status_cb);
    }
    if (size >= sizeof(GpsCallbacks)) {
        callbacks_owned.gnss_sv_status_cb = callbacks->gnss_sv_status_cb;
        callbacks_owned.size = sizeof(GpsCallbacks);
    }
    create = callbacks_owned.create_thread_cb;
    want_on = 0;
    running = starting = reader_alive = 1;
    pthread_mutex_unlock(&lock);

    th = create("gps-r800-reader", reader, NULL);
    pthread_mutex_lock(&lock);
    starting = 0;
    if (!th) {
        running = reader_alive = 0;
        want_on = 0;
        memset(&callbacks_owned, 0, sizeof(callbacks_owned));
    }
    pthread_cond_broadcast(&state_changed);
    pthread_mutex_unlock(&lock);
    return th ? 0 : -EAGAIN;
}

static int gps_start(void)
{
    pthread_mutex_lock(&lock);
    if (!running) {
        pthread_mutex_unlock(&lock);
        return -ENODEV;
    }
    if (!want_on) {
        want_on = 1;
        send_line("START\n"); /* reader replays wanted state after reconnect */
    }
    pthread_mutex_unlock(&lock);
    return 0;
}

static int gps_stop(void)
{
    pthread_mutex_lock(&lock);
    if (want_on) {
        want_on = 0;
        send_line("STOP\n");
    }
    pthread_mutex_unlock(&lock);
    return 0;
}

static void gps_cleanup(void)
{
    pthread_mutex_lock(&lock);
    want_on = 0;
    running = 0;
    if (sock >= 0)
        shutdown(sock, SHUT_RDWR);
    pthread_cond_broadcast(&state_changed);
    /* A framework callback may request cleanup from the reader itself.
     * It cannot wait for its own return; the reader performs final cleanup. */
    if (reader_id_valid && pthread_equal(reader_id, pthread_self())) {
        pthread_mutex_unlock(&lock);
        return;
    }
    ++cleaning;
    while (starting || reader_alive)
        pthread_cond_wait(&state_changed, &lock);
    --cleaning;
    pthread_mutex_unlock(&lock);
}

static int gps_inject_time(GpsUtcTime t, int64_t ref, int unc)
{
	char l[96];
	struct gps_time_command parsed;
	int n = snprintf(l, sizeof(l), "%lld %lld %d", (long long)t, (long long)ref, unc);
	if (n <= 0 || n >= (int)sizeof(l) || !gps_parse_time(l, &parsed))
		return -EINVAL;
	n = snprintf(l, sizeof(l), "TIME %lld %lld %d\n", parsed.utc, parsed.elapsed, parsed.uncertainty);
	if (n <= 0 || n >= (int)sizeof(l))
		return -EINVAL;
	pthread_mutex_lock(&lock);
	int rc = send_line(l);
	pthread_mutex_unlock(&lock);
	return rc;
}

static int gps_inject_location(double lat, double lon, float acc)
{
	char l[96];
	struct gps_loc_command parsed;
	int n;
	if (!(lat >= -90 && lat <= 90 && lon >= -180 && lon <= 180 &&
	      acc > 0 && acc <= 40000000))
		return -EINVAL;
	n = snprintf(l, sizeof(l), "%.8f %.8f %.6f", lat, lon, (double)acc);
	if (n <= 0 || n >= (int)sizeof(l) || !gps_parse_loc(l, &parsed))
		return -EINVAL;
	n = snprintf(l, sizeof(l), "LOC %.8f %.8f %.6f\n", parsed.lat, parsed.lon, parsed.accuracy);
	if (n <= 0 || n >= (int)sizeof(l))
		return -EINVAL;
	pthread_mutex_lock(&lock);
	int rc = send_line(l);
	pthread_mutex_unlock(&lock);
	return rc;
}

static void gps_delete_aiding_data(uint16_t f) { (void)f; }

static int gps_set_position_mode(uint32_t mode, uint32_t rec, uint32_t interval,
				 uint32_t acc, uint32_t t)
{
	LOGI("set_position_mode mode %u recurrence %u interval %u", mode, rec, interval);
	(void)mode; (void)rec; (void)interval; (void)acc; (void)t;
	return 0;
}

static const void *gps_get_extension(const char *name)
{
	(void)name;
	return NULL;
}

static const GpsInterface iface __attribute__((used)) = {
	sizeof(GpsInterface), gps_init, gps_start, gps_stop, gps_cleanup, gps_inject_time,
	gps_inject_location, gps_delete_aiding_data, gps_set_position_mode, gps_get_extension,
};

#ifndef R800_GPS_HOST_TEST
static const GpsInterface *get_iface(struct gps_device_t *d)
{
	(void)d;
	return &iface;
}

static int dev_close(struct hw_device_t *d)
{
	gps_cleanup();
	free(d);
	return 0;
}

static int dev_open(const struct hw_module_t *m, const char *name, struct hw_device_t **out)
{
	struct gps_device_t *d = calloc(1, sizeof(*d));
	(void)name;
	if (!d)
		return -ENOMEM;
	d->common.tag = HARDWARE_DEVICE_TAG;
	d->common.version = 0;
	d->common.module = (struct hw_module_t *)m;
	d->common.close = dev_close;
	d->get_gps_interface = get_iface;
	*out = &d->common;
	LOGI("opened");
	return 0;
}

static struct hw_module_methods_t methods = { .open = dev_open };

__attribute__((visibility("default")))
struct hw_module_t HAL_MODULE_INFO_SYM = {
	.tag = HARDWARE_MODULE_TAG,
	.version_major = 1,
	.version_minor = 0,
	.id = GPS_HARDWARE_MODULE_ID,
	.name = "SM-R800 GPS (BCM47758 via gpsbridge)",
	.author = "r800-wearos",
	.methods = &methods,
};

#endif /* !R800_GPS_HOST_TEST */
