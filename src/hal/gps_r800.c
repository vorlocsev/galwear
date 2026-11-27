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
#include <math.h>
#include <limits.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stddef.h>
#include <poll.h>
#include <time.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <android/log.h>
#include <hardware/hardware.h>

#define LOG_TAG "gps-r800"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

#define SOCK_PATH "/oem/r800dev/gps.sock"

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
struct gps_device_t {
	struct hw_device_t common;
	const GpsInterface *(*get_gps_interface)(struct gps_device_t *);
};
#define GPS_CAPABILITY_SCHEDULING 0x01
#define GPS_STATUS_SESSION_BEGIN 1
#define GPS_STATUS_SESSION_END 2
#define GPS_STATUS_ENGINE_ON 3
#define GPS_STATUS_ENGINE_OFF 4

static GpsCallbacks *cb;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static int sock = -1;
static int want_on;          /* framework asked for a session */
static atomic_int running; /* requested reader state */
static pthread_t reader_thread;
static int reader_created, stopping;
static GpsCallbacks callbacks_copy;
static pthread_cond_t retry_cond = PTHREAD_COND_INITIALIZER;

/* call with lock held */
static int send_line(const char *s)
{
	if (sock < 0)
		return -ENOTCONN;
	size_t len = strlen(s), done = 0;
	while (done < len) {
		ssize_t n = send(sock, s + done, len - done, MSG_NOSIGNAL | MSG_DONTWAIT);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0) {
			LOGE("bridge send failed");
			/* Reader owns close(); shutdown wakes it without recycling fd. */
			shutdown(sock, SHUT_RDWR);
			return -EIO;
		}
		done += (size_t)n;
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
static int used[8][264];		/* [constellation][svid] used in fix */

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
	out[0] = 0;
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
		if (oc > 0 && oc < 8 && svid > 0 && svid < 264)
			used[oc][svid] = 1;
	}
}

static void report_sv(void)
{
	int i;
	for (i = 0; i < sv_cur.num_svs; i++) {
		GnssSvInfo *v = &sv_cur.gnss_sv_list[i];
		if (v->constellation < 8 && v->svid > 0 && v->svid < 264 && used[v->constellation][v->svid])
			v->flags |= 4;
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

/* Reject malformed/overflowing numbers before narrowing to HAL fields. */
static int number(const char **p, double *out)
{
	char *end;
	if (**p != ' ')
		return 0;
	const char *s = *p + 1;
	if (!*s || *s == ' ' || *s == '\t')
		return 0;
	errno = 0;
	double v = strtod(s, &end);
	if (end == s || errno == ERANGE || !isfinite(v) || (*end && *end != ' '))
		return 0;
	*out = v;
	*p = end;
	return 1;
}

static int utc_ms(const char *p, const char **endp, int64_t *out)
{
	char *end;
	if (*p < '0' || *p > '9')
		return 0;
	errno = 0;
	long long v = strtoll(p, &end, 10);
	if (errno == ERANGE || v <= 0 || (*end && *end != ' '))
		return 0;
	*endp = end;
	*out = v;
	return 1;
}

static int parse_fix(const char *p, GpsLocation *loc)
{
	double v[7];
	for (int i = 0; i < 7; i++)
		if (!number(&p, &v[i]))
			return 0;
	int64_t ts;
	const char *end;
	if (*p != ' ' || !utc_ms(p + 1, &end, &ts) || *end)
		return 0;
	if (v[0] < 1 || v[0] > 31 || (unsigned)v[0] != v[0] ||
	    !((unsigned)v[0] & 1) || v[1] < -90 || v[1] > 90 ||
	    v[2] < -180 || v[2] > 180 || v[3] < -20000 || v[3] > 100000 ||
	    v[4] < 0 || v[4] > 10000 || v[5] < 0 || v[5] >= 360 ||
	    v[6] < 0 || v[6] > 10000000)
		return 0;
	memset(loc, 0, sizeof(*loc));
	loc->size = sizeof(*loc);
	loc->flags = (uint16_t)v[0];
	loc->latitude = v[1]; loc->longitude = v[2]; loc->altitude = v[3];
	loc->speed = (float)v[4]; loc->bearing = (float)v[5]; loc->accuracy = (float)v[6];
	loc->timestamp = ts;
	return 1;
}

static int hex_digit(char c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	return -1;
}

static int valid_nmea(const char *s)
{
	if (*s++ != '$')
		return 0;
	unsigned sum = 0;
	while (*s && *s != '*') {
		if ((unsigned char)*s < 32 || (unsigned char)*s > 126)
			return 0;
		sum ^= (unsigned char)*s++;
	}
	if (*s != '*' || !s[1] || !s[2] || s[3])
		return 0;
	int a = hex_digit(s[1]), b = hex_digit(s[2]);
	return a >= 0 && b >= 0 && sum == (unsigned)(a * 16 + b);
}

static void handle_line(char *l)
{
	pthread_mutex_lock(&lock);
	int active = want_on;
	pthread_mutex_unlock(&lock);
	if (!active)
		return;
	if (!strncmp(l, "FIX ", 4)) {
		GpsLocation loc;
		if (parse_fix(l + 3, &loc) && cb && cb->location_cb)
			cb->location_cb(&loc);
	} else if (!strncmp(l, "NMEA ", 5)) {
		const char *s;
		int64_t ts;
		if (!utc_ms(l + 5, &s, &ts) || *s != ' ' || !valid_nmea(++s))
			return;
		if (cb && cb->nmea_cb)
			cb->nmea_cb(ts, s, strlen(s));
		handle_nmea_sv(s);
	} else if (!strncmp(l, "STATUS ", 7) && l[7] >= '1' && l[7] <= '4' && !l[8]) {
		report_status((uint16_t)(l[7] - '0'));
	}
}

/* Retry delay can be interrupted by cleanup; no blocking connect. */
static void retry_wait(int seconds)
{
	struct timespec until;
	if (clock_gettime(CLOCK_REALTIME, &until))
		return;
	until.tv_sec += seconds;
	pthread_mutex_lock(&lock);
	while (running) {
		int r = pthread_cond_timedwait(&retry_cond, &lock, &until);
		if (r)
			break;
	}
	pthread_mutex_unlock(&lock);
}

/* connects (retrying), re-sends the wanted state, then reads lines */
static void reader(void *arg)
{
	char buf[4096];
	size_t have = 0;
	int discard = 0;
	(void)arg;

	while (running) {
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
			if (fd < 0 || connect(fd, (struct sockaddr *)&a, sizeof(a)) < 0) {
				if (fd >= 0)
					close(fd);
				retry_wait(2);
				continue;
			}
			LOGI("connected to %s", SOCK_PATH);
			pthread_mutex_lock(&lock);
			if (!running) {
				close(fd);
				pthread_mutex_unlock(&lock);
				break;
			}
			sock = fd;
			if (want_on)
				send_line("START\n");
			pthread_mutex_unlock(&lock);
			have = 0;
			discard = 0;
			memset(&sv_cur, 0, sizeof(sv_cur));
			memset(used, 0, sizeof(used));
		}
		struct pollfd pfd = { .fd = fd, .events = POLLIN };
		int ready = poll(&pfd, 1, 250);
		if (!running)
			break;
		if (!ready || (ready < 0 && errno == EINTR))
			continue;
		char chunk[512];
		ssize_t n = ready < 0 ? -1 : read(fd, chunk, sizeof(chunk));
		if (n < 0 && (errno == EINTR || (ready > 0 && errno == EAGAIN &&
		    !(pfd.revents & (POLLHUP | POLLERR | POLLNVAL)))))
			continue;
		if (n <= 0) {
			LOGE("bridge connection lost");
			pthread_mutex_lock(&lock);
			if (sock == fd) {
				close(sock);
				sock = -1;
			}
			pthread_mutex_unlock(&lock);
			retry_wait(1);
			continue;
		}
		for (ssize_t i = 0; i < n && running; i++) {
			char ch = chunk[i];
			if (ch == '\n') {
				if (!discard) {
					buf[have] = 0;
					handle_line(buf);
				}
				have = 0;
				discard = 0;
			} else if (!discard) {
				if (!ch || have == sizeof(buf) - 1)
					discard = 1;
				else
					buf[have++] = ch;
			}
		}
	}
	pthread_mutex_lock(&lock);
	if (sock >= 0) {
		close(sock);
		sock = -1;
	}
	pthread_mutex_unlock(&lock);
}

/* The framework callback must return a joinable pthread_t (legacy HIDL
 * wrapper contract). Keep callback storage alive until reader is joined. */
static int gps_init(GpsCallbacks *callbacks)
{
	if (!callbacks || callbacks->size < offsetof(GpsCallbacks, request_utc_time_cb) ||
	    !callbacks->create_thread_cb)
		return -EINVAL;
	pthread_mutex_lock(&lock);
	if (reader_created || stopping) {
		pthread_mutex_unlock(&lock);
		return -EBUSY;
	}
	memset(&callbacks_copy, 0, sizeof(callbacks_copy));
	/* Copy complete pointer fields only, even for a legacy short struct. */
	size_t bytes = callbacks->size < sizeof(callbacks_copy) ? callbacks->size : sizeof(callbacks_copy);
	bytes = offsetof(GpsCallbacks, location_cb) +
		(bytes - offsetof(GpsCallbacks, location_cb)) / sizeof(void *) * sizeof(void *);
	memcpy(&callbacks_copy, callbacks, bytes);
	callbacks_copy.size = bytes;
	cb = &callbacks_copy;
	want_on = 0;
	running = 1;
	reader_thread = cb->create_thread_cb("gps-r800-reader", reader, NULL);
	if (!reader_thread) {
		running = 0;
		cb = NULL;
		memset(&callbacks_copy, 0, sizeof(callbacks_copy));
		pthread_mutex_unlock(&lock);
		return -EIO;
	}
	reader_created = 1;
	void (*caps)(uint32_t) = cb->set_capabilities_cb;
	pthread_mutex_unlock(&lock);
	if (caps)
		caps(GPS_CAPABILITY_SCHEDULING);
	return 0;
}

static void status_to(void (*callback)(GpsStatus *), uint16_t status)
{
	GpsStatus s = { sizeof(s), status };
	if (callback)
		callback(&s);
}

static int gps_start(void)
{
	pthread_mutex_lock(&lock);
	if (!running || stopping) {
		pthread_mutex_unlock(&lock);
		return -ENODEV;
	}
	int changed = !want_on;
	want_on = 1;
	if (changed)
		send_line("START\n");
	void (*status)(GpsStatus *) = cb->status_cb;
	pthread_mutex_unlock(&lock);
	if (changed)
		status_to(status, GPS_STATUS_SESSION_BEGIN);
	return 0;
}

static int gps_stop(void)
{
	pthread_mutex_lock(&lock);
	if (!running || stopping) {
		pthread_mutex_unlock(&lock);
		return -ENODEV;
	}
	int changed = want_on;
	want_on = 0;
	if (changed)
		send_line("STOP\n");
	void (*status)(GpsStatus *) = cb->status_cb;
	pthread_mutex_unlock(&lock);
	if (changed)
		status_to(status, GPS_STATUS_SESSION_END);
	return 0;
}

static int stop_reader(void)
{
	pthread_mutex_lock(&lock);
	if (!reader_created) {
		pthread_mutex_unlock(&lock);
		return 0;
	}
	if (stopping || pthread_equal(pthread_self(), reader_thread)) {
		pthread_mutex_unlock(&lock);
		return -EBUSY;
	}
	stopping = 1;
	int active = want_on;
	want_on = 0;
	if (active)
		send_line("STOP\n");
	running = 0;
	if (sock >= 0)
		shutdown(sock, SHUT_RDWR);
	pthread_cond_broadcast(&retry_cond);
	pthread_t thread = reader_thread;
	void (*status)(GpsStatus *) = cb->status_cb;
	pthread_mutex_unlock(&lock);
	int r = pthread_join(thread, NULL);
	pthread_mutex_lock(&lock);
	if (r) {
		/* Do not clear callbacks or allow unload without proof of exit. */
		LOGE("reader join failed: %d", r);
		pthread_mutex_unlock(&lock);
		return -r;
	}
	reader_created = stopping = 0;
	cb = NULL;
	memset(&callbacks_copy, 0, sizeof(callbacks_copy));
	pthread_mutex_unlock(&lock);
	if (active)
		status_to(status, GPS_STATUS_SESSION_END);
	return 0;
}

static void gps_cleanup(void)
{
	int r = stop_reader();
	if (r)
		LOGE("cleanup refused: %d", r);
}

static int gps_inject_time(GpsUtcTime t, int64_t ref, int unc)
{
	char l[96];
	if (t <= 0 || ref < 0 || unc < 0)
		return -EINVAL;
	/* ref = elapsedRealtime when t was valid; gpsbridge turns it into its clock */
	snprintf(l, sizeof(l), "TIME %lld %lld %d\n", (long long)t, (long long)ref, unc);
	pthread_mutex_lock(&lock);
	int r = running && !stopping ? send_line(l) : -ENODEV;
	pthread_mutex_unlock(&lock);
	return r;
}

static int gps_inject_location(double lat, double lon, float acc)
{
	char l[96];
	if (!isfinite(lat) || !isfinite(lon) || !isfinite(acc) ||
	    lat < -90 || lat > 90 || lon < -180 || lon > 180 || acc < 0 || acc > 10000000)
		return -EINVAL;
	snprintf(l, sizeof(l), "LOC %.6f %.6f %.0f\n", lat, lon, (double)acc);
	pthread_mutex_lock(&lock);
	int r = running && !stopping ? send_line(l) : -ENODEV;
	pthread_mutex_unlock(&lock);
	return r;
}

static void gps_delete_aiding_data(uint16_t f) { (void)f; }

static int gps_set_position_mode(uint32_t mode, uint32_t rec, uint32_t interval,
				 uint32_t acc, uint32_t t)
{
	LOGI("set_position_mode mode %u recurrence %u interval %u", mode, rec, interval);
	(void)acc; (void)t;
	return 0;
}

static const void *gps_get_extension(const char *name)
{
	(void)name;
	return NULL;
}

static const GpsInterface iface = {
	sizeof(GpsInterface), gps_init, gps_start, gps_stop, gps_cleanup, gps_inject_time,
	gps_inject_location, gps_delete_aiding_data, gps_set_position_mode, gps_get_extension,
};

static const GpsInterface *get_iface(struct gps_device_t *d)
{
	(void)d;
	return &iface;
}

static int dev_close(struct hw_device_t *d)
{
	if (!d)
		return -EINVAL;
	int r = stop_reader();
	if (r)
		return r;
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
