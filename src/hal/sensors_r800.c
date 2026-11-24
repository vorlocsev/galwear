/*
 * sensors.r800.so: legacy sensors HAL for the SM-R800 Wear OS port.
 *
 * The sensors sit behind the sensor-hub MCU in the Broadcom BCM47758 (Samsung SSP
 * over BBD). The kernel SSP driver exposes one input device per sensor and a
 * control node:
 *
 *   /sys/class/sensors/ssp_sensor/enable          bitmask of enabled SSP sensors
 *   /sys/class/sensors/ssp_sensor/<x>_poll_delay  sampling period in ns
 *
 * Every frame carries the values as EV_REL codes followed by a 64-bit boottime
 * timestamp split over four 16-bit codes. A REL event with value 0 is never
 * emitted, so missing codes in a frame mean 0 (the driver adds 1 to values that
 * can legitimately be 0: lux, heart rate).
 *
 * Loaded by android.hardware.sensors@1.0-impl (hw_get_module("sensors"),
 * ro.hardware=r800). Scales are from Tizen's /usr/etc/sensor.xml for the parts
 * on this board: LSM6DSL (accel 0.244 mg/LSB, gyro 70 mdps/LSB), LPS25H
 * (pressure raw/4096 hPa), TSL2584 (lux computed by the driver), PPS960 (HR).
 * Sensors: accelerometer, gyroscope (+ uncalibrated with the hub's bias), barometer,
 * light, heart rate; wrist tilt, ungaze (wrist down), off-body and step counter /
 * step detector from the hub's context algorithms.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/input.h>
#include <limits.h>
#include <math.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <android/log.h>
#include <hardware/hardware.h>

#define LOG_TAG "sensors-r800"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

/* ---- from AOSP hardware/libhardware/include/hardware/sensors.h (stable ABI) ---- */
#define SENSORS_HARDWARE_MODULE_ID "sensors"
#define SENSORS_HARDWARE_POLL "poll"
#define SENSORS_HEADER_VERSION 1
#define SENSORS_MODULE_API_VERSION_0_1 HARDWARE_MODULE_API_VERSION(0, 1)
#define SENSORS_DEVICE_API_VERSION_1_3 HARDWARE_DEVICE_API_VERSION_2(1, 3, SENSORS_HEADER_VERSION)

#define SENSOR_TYPE_META_DATA 0
#define SENSOR_TYPE_ACCELEROMETER 1
#define SENSOR_TYPE_GYROSCOPE 4
#define SENSOR_TYPE_LIGHT 5
#define SENSOR_TYPE_PRESSURE 6
#define SENSOR_TYPE_GYROSCOPE_UNCALIBRATED 16
#define SENSOR_TYPE_STEP_DETECTOR 18
#define SENSOR_TYPE_STEP_COUNTER 19
#define SENSOR_TYPE_HEART_RATE 21
#define SENSOR_TYPE_WRIST_TILT_GESTURE 26
#define SENSOR_TYPE_LOW_LATENCY_OFFBODY_DETECT 34
#define SENSOR_TYPE_DEVICE_PRIVATE_BASE 0x10000
/* Wear OS ClockworkAmbient looks this sensor up by string type and turns the
   screen off when values[0] > 0 ("ungaze": wrist turned away) */
#define SENSOR_TYPE_UNGAZE (SENSOR_TYPE_DEVICE_PRIVATE_BASE + 1)
#define SENSOR_STRING_TYPE_UNGAZE "com.google.sensor.ungaze_gesture"

#define SENSOR_STRING_TYPE_ACCELEROMETER "android.sensor.accelerometer"
#define SENSOR_STRING_TYPE_GYROSCOPE "android.sensor.gyroscope"
#define SENSOR_STRING_TYPE_LIGHT "android.sensor.light"
#define SENSOR_STRING_TYPE_PRESSURE "android.sensor.pressure"
#define SENSOR_STRING_TYPE_GYROSCOPE_UNCALIBRATED "android.sensor.gyroscope_uncalibrated"
#define SENSOR_STRING_TYPE_HEART_RATE "android.sensor.heart_rate"
#define SENSOR_STRING_TYPE_STEP_DETECTOR "android.sensor.step_detector"
#define SENSOR_STRING_TYPE_STEP_COUNTER "android.sensor.step_counter"
#define SENSOR_STRING_TYPE_WRIST_TILT_GESTURE "android.sensor.wrist_tilt_gesture"
#define SENSOR_STRING_TYPE_LOW_LATENCY_OFFBODY_DETECT "android.sensor.low_latency_offbody_detect"
#define SENSOR_PERMISSION_BODY_SENSORS "android.permission.BODY_SENSORS"
#define SENSOR_PERMISSION_ACTIVITY_RECOGNITION "android.permission.ACTIVITY_RECOGNITION"

#define SENSOR_FLAG_WAKE_UP 1
#define SENSOR_FLAG_CONTINUOUS_MODE 0
#define SENSOR_FLAG_ON_CHANGE_MODE 2
#define SENSOR_FLAG_SPECIAL_REPORTING_MODE 6

#define SENSOR_STATUS_NO_CONTACT -1
#define SENSOR_STATUS_UNRELIABLE 0
#define SENSOR_STATUS_ACCURACY_HIGH 3

#define META_DATA_FLUSH_COMPLETE 1
#define META_DATA_VERSION 0x103

#define GRAVITY_EARTH 9.80665f

typedef struct {
	union {
		float v[3];
		struct {
			float x, y, z;
		};
	};
	int8_t status;
	uint8_t reserved[3];
} sensors_vec_t;

typedef struct {
	int32_t what;
	int32_t sensor;
} meta_data_event_t;

typedef struct {
	float bpm;
	int8_t status;
} heart_rate_event_t;

typedef struct {
	float uncalib[3];
	float bias[3];
} uncalibrated_event_t;

typedef struct sensors_event_t {
	int32_t version;
	int32_t sensor;
	int32_t type;
	int32_t reserved0;
	int64_t timestamp;
	union {
		union {
			float data[16];
			sensors_vec_t acceleration;
			sensors_vec_t gyro;
			float light;
			float pressure;
			meta_data_event_t meta_data;
			heart_rate_event_t heart_rate;
			uncalibrated_event_t uncalibrated_gyro;
		};
		union {
			uint64_t data[8];
			uint64_t step_counter;
		} u64;
	};
	uint32_t flags;
	uint32_t reserved1[3];
} sensors_event_t;

struct sensor_t {
	const char *name;
	const char *vendor;
	int version;
	int handle;
	int type;
	float maxRange;
	float resolution;
	float power;
	int32_t minDelay;
	uint32_t fifoReservedEventCount;
	uint32_t fifoMaxEventCount;
	const char *stringType;
	const char *requiredPermission;
#ifdef __LP64__
	int64_t maxDelay;
	uint64_t flags;
#else
	int32_t maxDelay;
	uint32_t flags;
#endif
	void *reserved[2];
};

struct sensors_module_t {
	struct hw_module_t common;
	int (*get_sensors_list)(struct sensors_module_t *module, struct sensor_t const **list);
	int (*set_operation_mode)(unsigned int mode);
};

struct sensors_poll_device_t {
	struct hw_device_t common;
	int (*activate)(struct sensors_poll_device_t *dev, int sensor_handle, int enabled);
	int (*setDelay)(struct sensors_poll_device_t *dev, int sensor_handle, int64_t sampling_period_ns);
	int (*poll)(struct sensors_poll_device_t *dev, sensors_event_t *data, int count);
};

typedef struct sensors_poll_device_1 {
	union {
		struct sensors_poll_device_t v0;
		struct {
			struct hw_device_t common;
			int (*activate)(struct sensors_poll_device_t *dev, int sensor_handle, int enabled);
			int (*setDelay)(struct sensors_poll_device_t *dev, int sensor_handle, int64_t sampling_period_ns);
			int (*poll)(struct sensors_poll_device_t *dev, sensors_event_t *data, int count);
		};
	};
	int (*batch)(struct sensors_poll_device_1 *dev, int sensor_handle, int flags,
		     int64_t sampling_period_ns, int64_t max_report_latency_ns);
	int (*flush)(struct sensors_poll_device_1 *dev, int sensor_handle);
	int (*inject_sensor_data)(struct sensors_poll_device_1 *dev, const sensors_event_t *data);
	void (*reserved_procs[7])(void);
} sensors_poll_device_1_t;

_Static_assert(sizeof(sensors_event_t) == 104, "sensors_event_t ABI");
/* ------------------------------------------------------------------------------ */

#define SSP_SYSFS "/sys/class/sensors/ssp_sensor/"

/* handles; sensor_list[] is in the same order (index = handle - 1) */
enum { H_ACCEL = 1, H_GYRO, H_PRESSURE, H_LIGHT, H_HR, H_GYRO_UNCAL, H_COUNT };
/*
 * Context sensors: computed by the hub's own algorithms (Samsung libsensor-hal,
 * running inside Tizen's sensord in the /mnt/tz chroot). android-helper.sh runs
 * `sensorctl test wristup|wristdown|wear_on|pedo` there and writes one line per
 * event to the CTX_FIFO: "W <us>" for a wrist raise, "D <us>" for a wrist turned
 * down/away, "O <state>" for wear on (1) / off (2), "P <steps>" with the hub
 * pedometer's step total (counts from when that sensorctl started; it restarts
 * from 0 if sensorctl or sensord is restarted).
 */
enum { H_WRIST_TILT = H_COUNT, H_OFFBODY, H_UNGAZE, H_STEP_DETECTOR, H_STEP_COUNTER,
       H_STEP_COUNTER_WAKE, N_HANDLES };
#define CTX_FIFO "/dev/r800_context"

struct hub_sensor {
	int handle;
	const char *input_name;  /* input device name from the SSP driver */
	int ssp_bit;             /* bit in the enable mask */
	const char *delay_node;  /* *_poll_delay sysfs node */
	int ts_code;             /* first of the four timestamp REL codes */
	int fd;
	int enabled;
	int64_t period_ns;
	int32_t v[6];            /* REL values of the frame being collected */
	uint16_t ts[4];
	int dropped;            /* discard until next SYN_REPORT after overrun */
};

static struct hub_sensor hub[H_COUNT] = {
	[H_ACCEL] = { H_ACCEL, "accelerometer_sensor", 0, "accel_poll_delay", REL_Z + 1, .fd = -1 },
	[H_GYRO] = { H_GYRO, "gyro_sensor", 1, "gyro_poll_delay", REL_RZ + 1, .fd = -1 },
	[H_PRESSURE] = { H_PRESSURE, "pressure_sensor", 5, "pressure_poll_delay", REL_WHEEL + 1, .fd = -1 },
	[H_LIGHT] = { H_LIGHT, "light_sensor", 9, "light_poll_delay", REL_RX + 1, .fd = -1 },
	[H_HR] = { H_HR, "hrm_lib_sensor", 20, "hrm_lib_poll_delay", REL_Z + 1, .fd = -1 },
	[H_GYRO_UNCAL] = { H_GYRO_UNCAL, "uncal_gyro_sensor", 14, "uncal_gyro_poll_delay", REL_WHEEL + 1, .fd = -1 },
};

static const struct sensor_t sensor_list[] = {
	{ .name = "LSM6DSL Accelerometer", .vendor = "STMicroelectronics", .version = 1,
	  .handle = H_ACCEL, .type = SENSOR_TYPE_ACCELEROMETER,
	  .maxRange = 8.0f * GRAVITY_EARTH, .resolution = 0.000244f * GRAVITY_EARTH, .power = 0.25f,
	  .minDelay = 10000, .stringType = SENSOR_STRING_TYPE_ACCELEROMETER,
	  .maxDelay = 1000000, .flags = SENSOR_FLAG_CONTINUOUS_MODE },
	{ .name = "LSM6DSL Gyroscope", .vendor = "STMicroelectronics", .version = 1,
	  .handle = H_GYRO, .type = SENSOR_TYPE_GYROSCOPE,
	  .maxRange = 2000.0f * (float)M_PI / 180.0f, .resolution = 0.070f * (float)M_PI / 180.0f,
	  .power = 0.9f, .minDelay = 10000, .stringType = SENSOR_STRING_TYPE_GYROSCOPE,
	  .maxDelay = 1000000, .flags = SENSOR_FLAG_CONTINUOUS_MODE },
	{ .name = "LPS25H Barometer", .vendor = "STMicroelectronics", .version = 1,
	  .handle = H_PRESSURE, .type = SENSOR_TYPE_PRESSURE,
	  .maxRange = 1260.0f, .resolution = 1.0f / 4096.0f, .power = 0.03f,
	  .minDelay = 40000, .stringType = SENSOR_STRING_TYPE_PRESSURE,
	  .maxDelay = 1000000, .flags = SENSOR_FLAG_CONTINUOUS_MODE },
	{ .name = "TSL2584 Light", .vendor = "ams", .version = 1,
	  .handle = H_LIGHT, .type = SENSOR_TYPE_LIGHT,
	  .maxRange = 60000.0f, .resolution = 1.0f, .power = 0.1f,
	  .minDelay = 0, .stringType = SENSOR_STRING_TYPE_LIGHT,
	  .maxDelay = 1000000, .flags = SENSOR_FLAG_ON_CHANGE_MODE },
	{ .name = "PPS960 Heart Rate", .vendor = "TI", .version = 1,
	  .handle = H_HR, .type = SENSOR_TYPE_HEART_RATE,
	  .maxRange = 250.0f, .resolution = 1.0f, .power = 1.0f,
	  .minDelay = 0, .stringType = SENSOR_STRING_TYPE_HEART_RATE,
	  .requiredPermission = SENSOR_PERMISSION_BODY_SENSORS,
	  /* up to 30 min: sensorservice clamps slower requests to maxDelay, and a
	     slow request is what selects burst mode (see hr_update) */
	  .maxDelay = 1800000000, .flags = SENSOR_FLAG_ON_CHANGE_MODE },
	{ .name = "LSM6DSL Gyroscope Uncalibrated", .vendor = "STMicroelectronics", .version = 1,
	  .handle = H_GYRO_UNCAL, .type = SENSOR_TYPE_GYROSCOPE_UNCALIBRATED,
	  .maxRange = 2000.0f * (float)M_PI / 180.0f, .resolution = 0.070f * (float)M_PI / 180.0f,
	  .power = 0.9f, .minDelay = 10000, .stringType = SENSOR_STRING_TYPE_GYROSCOPE_UNCALIBRATED,
	  .maxDelay = 1000000, .flags = SENSOR_FLAG_CONTINUOUS_MODE },
	{ .name = "Samsung Wrist Up", .vendor = "Samsung", .version = 1,
	  .handle = H_WRIST_TILT, .type = SENSOR_TYPE_WRIST_TILT_GESTURE,
	  .maxRange = 1.0f, .resolution = 1.0f, .power = 0.05f,
	  .minDelay = 0, .stringType = SENSOR_STRING_TYPE_WRIST_TILT_GESTURE,
	  .maxDelay = 0, .flags = SENSOR_FLAG_SPECIAL_REPORTING_MODE | SENSOR_FLAG_WAKE_UP },
	{ .name = "Samsung Wear On/Off", .vendor = "Samsung", .version = 1,
	  .handle = H_OFFBODY, .type = SENSOR_TYPE_LOW_LATENCY_OFFBODY_DETECT,
	  .maxRange = 1.0f, .resolution = 1.0f, .power = 0.05f,
	  .minDelay = 0, .stringType = SENSOR_STRING_TYPE_LOW_LATENCY_OFFBODY_DETECT,
	  .maxDelay = 0, .flags = SENSOR_FLAG_ON_CHANGE_MODE | SENSOR_FLAG_WAKE_UP },
	{ .name = "Samsung Wrist Down", .vendor = "Samsung", .version = 1,
	  .handle = H_UNGAZE, .type = SENSOR_TYPE_UNGAZE,
	  .maxRange = 1.0f, .resolution = 1.0f, .power = 0.05f,
	  .minDelay = 0, .stringType = SENSOR_STRING_TYPE_UNGAZE,
	  .maxDelay = 0, .flags = SENSOR_FLAG_ON_CHANGE_MODE },
	{ .name = "Samsung Step Detector", .vendor = "Samsung", .version = 1,
	  .handle = H_STEP_DETECTOR, .type = SENSOR_TYPE_STEP_DETECTOR,
	  .maxRange = 1.0f, .resolution = 1.0f, .power = 0.05f,
	  .minDelay = 0, .stringType = SENSOR_STRING_TYPE_STEP_DETECTOR,
	  .requiredPermission = SENSOR_PERMISSION_ACTIVITY_RECOGNITION,
	  .maxDelay = 0, .flags = SENSOR_FLAG_SPECIAL_REPORTING_MODE },
	{ .name = "Samsung Step Counter", .vendor = "Samsung", .version = 1,
	  .handle = H_STEP_COUNTER, .type = SENSOR_TYPE_STEP_COUNTER,
	  .maxRange = 4294967295.0f, .resolution = 1.0f, .power = 0.05f,
	  .minDelay = 0, .stringType = SENSOR_STRING_TYPE_STEP_COUNTER,
	  .requiredPermission = SENSOR_PERMISSION_ACTIVITY_RECOGNITION,
	  .maxDelay = 0, .flags = SENSOR_FLAG_ON_CHANGE_MODE },
	/* same counter as a wake-up sensor: Wear Health Services only takes a
	   wake-up step counter (getDefaultSensor(19, true)) */
	{ .name = "Samsung Step Counter (wake-up)", .vendor = "Samsung", .version = 1,
	  .handle = H_STEP_COUNTER_WAKE, .type = SENSOR_TYPE_STEP_COUNTER,
	  .maxRange = 4294967295.0f, .resolution = 1.0f, .power = 0.05f,
	  .minDelay = 0, .stringType = SENSOR_STRING_TYPE_STEP_COUNTER,
	  .requiredPermission = SENSOR_PERMISSION_ACTIVITY_RECOGNITION,
	  .maxDelay = 0, .flags = SENSOR_FLAG_ON_CHANGE_MODE | SENSOR_FLAG_WAKE_UP },
};
#define N_SENSORS ((int)(sizeof(sensor_list) / sizeof(sensor_list[0])))

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static int wake_pipe[2] = { -1, -1 };
static pthread_cond_t poll_idle = PTHREAD_COND_INITIALIZER;
static sensors_poll_device_1_t *active_device;
static int closing, polling; /* protected by lock */
#define INPUT_RETRY_NS 5000000000LL
static int64_t input_retry_at;
static int input_restore_pending;

/* Caller holds lock. Reject stale devices and calls during close. */
static int device_ready(const void *dev)
{
	return active_device && (const void *)active_device == dev && !closing;
}
/* pending flush-complete events (by handle), delivered from poll() */
static int flush_pending[N_HANDLES];

/* context sensor state (lock) */
static int ctx_enabled[N_HANDLES];
static float offbody_state = 1.0f;   /* last known: 1 on body, 0 off */
static int offbody_known;           /* do not invent a wear state before first report */
static int offbody_report;           /* report the current state on next poll */
/* steps: the counter is monotonic since the HAL started; a smaller hub total
   means the pedometer restarted from 0, so its last total goes into the base */
static long long step_raw = -1;      /* last hub total, -1: none yet */
static uint64_t step_base, step_total;
static int step_report[N_HANDLES];   /* counter handles: report on next poll */
static int step_detect_pending;      /* step detector events still to deliver */
static int ctx_fd = -1, ctx_wfd = -1;
static char ctx_buf[256];
static int ctx_len, ctx_discard;
#define STEP_PENDING_MAX 64
#define CTX_READ_BUDGET 4096

/*
 * Heart rate in bursts. Fit's "Background heart rate" has Play Services record
 * one sample per 10 min (a 600 s sampling period). Run continuously, the PPG LED
 * would stay on all day; instead a request at least HR_BG_MIN_NS slow measures
 * for one burst per period: the hub's HR on until it has a settled reading
 * (HR_SETTLE_NS after the start, the first non-zero bpm after that), that one
 * reading reported, the LED off again. No burst while the watch is off the
 * wrist. A faster client (Fit's manual reading, a workout: 1 s) makes it
 * continuous; sensorservice passes the fastest request down.
 * State under lock; hub[H_HR].enabled is the hub's HR bit, hr_active Android's.
 */
#define HR_BG_MIN_NS (60LL * 1000000000)
#define HR_SETTLE_NS (10LL * 1000000000)
#define HR_BURST_NS (45LL * 1000000000)
#define HR_RETRY_NS (5LL * 1000000000)
#define HR_MAX_PERIOD_NS (1800LL * 1000000000)
/* The hub's HR algorithm reports once a second and gives nothing at all when
   asked for faster: Play Services' samples ask for "fastest" (0 -> 1 ms) */
#define HR_HUB_PERIOD_NS 1000000000LL
static int hr_active;          /* Android has the HR sensor enabled */
static int64_t hr_req_ns;      /* requested sampling period, unclamped */
static int hr_bg;              /* burst mode */
static int64_t hr_burst_start; /* 0: no burst running */
static int64_t hr_stop_retry; /* failed shutdown: retry instead of busy-loop */
static int64_t hr_next;        /* burst mode: next burst start */
static int hr_bursts, hr_skipped; /* stats for the log */

static int write_sysfs(const char *node, long long value)
{
	char path[128], buf[32];
	snprintf(path, sizeof(path), SSP_SYSFS "%s", node);
	int fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd < 0) {
		LOGE("open %s: %s", path, strerror(errno));
		return -errno;
	}
	int n = snprintf(buf, sizeof(buf), "%lld", value);
	ssize_t written = write(fd, buf, n);
	int r = written == n ? 0 : written < 0 ? -errno : -EIO;
	if (r)
		LOGE("write %s=%s: %s", path, buf, strerror(-r));
	close(fd);
	return r;
}

static int open_inputs(void)
{
	char path[32], name[64];
	int found = 0;
	for (int i = 0; i < 64; i++) {
		snprintf(path, sizeof(path), "/dev/input/event%d", i);
		int fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
		if (fd < 0)
			continue;
		memset(name, 0, sizeof(name));
		if (ioctl(fd, EVIOCGNAME(sizeof(name) - 1), name) < 0) {
			close(fd);
			continue;
		}
		int used = 0;
		for (int h = H_ACCEL; h < H_COUNT; h++) {
			if (hub[h].fd < 0 && !strcmp(name, hub[h].input_name)) {
				hub[h].fd = fd;
				hub[h].dropped = 1; /* wait for a complete new frame */
				used = 1;
				found++;
				LOGI("%s -> %s", hub[h].input_name, path);
				break;
			}
		}
		if (!used)
			close(fd);
	}
	return found;
}

/* caller holds lock */
/*
 * The enable mask is shared with Tizen's sensord (chroot), which turns on e.g.
 * HRM raw (bit 18) for Samsung's wear on/off detection. Only change our own bits:
 * writing just Android's sensors dropped bit 18 on every light-sensor toggle, the
 * hub then decided the watch was off the wrist and stopped wrist up/down.
 */
/* Strict decimal mask; never treat missing or malformed data as zero. */
static int parse_enable_mask(const char *buf, long long *mask)
{
	char *end;
	if (*buf < '0' || *buf > '9')
		return -EINVAL;
	errno = 0;
	long long value = strtoll(buf, &end, 10);
	if (errno == ERANGE || value < 0)
		return -ERANGE;
	if (*end == '\n')
		end++;
	if (*end)
		return -EINVAL;
	*mask = value;
	return 0;
}

static int read_enable_mask(long long *mask)
{
	char buf[32];
	int fd = open(SSP_SYSFS "enable", O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	ssize_t n;
	do {
		n = read(fd, buf, sizeof(buf) - 1);
	} while (n < 0 && errno == EINTR);
	int saved = errno;
	close(fd);
	if (n < 0)
		return -saved;
	if (n == 0 || n == sizeof(buf) - 1 || memchr(buf, '\0', n))
		return -EIO;
	buf[n] = 0;
	return parse_enable_mask(buf, mask);
}

static int apply_enable_mask(void)
{
	long long ours = 0, want = 0;
	for (int h = H_ACCEL; h < H_COUNT; h++) {
		ours |= 1LL << hub[h].ssp_bit;
		if (hub[h].enabled)
			want |= 1LL << hub[h].ssp_bit;
	}
	long long current;
	int r = read_enable_mask(&current);
	if (r) {
		LOGE("SSP enable mask read failed: %d; refusing write", r);
		return r;
	}
	long long mask = (current & ~ours) | want;
	return mask == current ? 0 : write_sysfs("enable", mask);
}

/* Only the poll owner or open/close under lock may change input FDs. */
static void input_lost(struct hub_sensor *s)
{
	if (s->fd >= 0)
		close(s->fd);
	s->fd = -1;
	memset(s->v, 0, sizeof(s->v));
	memset(s->ts, 0, sizeof(s->ts));
	s->dropped = 1;
	input_restore_pending = 1;
}

static int inputs_missing(void)
{
	for (int h = H_ACCEL; h < H_COUNT; h++)
		if (hub[h].fd < 0)
			return 1;
	return 0;
}

/* Caller holds lock. Restore configured sampling before enabling SSP.
 * On failure keep retrying at a fixed cadence; never replace an unread mask. */
static int recover_inputs(int64_t now)
{
	if (!inputs_missing() && !input_restore_pending)
		return -1;
	if (now >= input_retry_at) {
		input_retry_at = now + INPUT_RETRY_NS;
		if (inputs_missing() && open_inputs())
			input_restore_pending = 1;
		if (input_restore_pending) {
			int r = 0;
			for (int h = H_ACCEL; h < H_COUNT && !r; h++) {
				if (hub[h].enabled && hub[h].fd >= 0 && hub[h].period_ns > 0)
					r = write_sysfs(hub[h].delay_node, hub[h].period_ns);
			}
			if (!r)
				r = apply_enable_mask();
			if (!r)
				input_restore_pending = 0;
			else
				LOGE("SSP restore deferred: %d", r);
		}
	}
	if (!inputs_missing() && !input_restore_pending)
		return -1;
	int64_t left = input_retry_at - now;
	return left <= 0 ? 0 : (int)((left + 999999) / 1000000);
}

static int valid(int handle)
{
	return handle >= H_ACCEL && handle < N_HANDLES;
}

/* caller holds lock */
static int is_enabled(int handle)
{
	if (handle == H_HR)
		return hr_active; /* the hub's HR is off between bursts */
	return handle < H_COUNT ? hub[handle].enabled : ctx_enabled[handle];
}

/* Caller holds lock: prevent a write to a closed/recycled FD. */
static void wake_poll(void)
{
	char c = 'w';
	if (wake_pipe[1] >= 0) {
		ssize_t r;
		do { r = write(wake_pipe[1], &c, 1); } while (r < 0 && errno == EINTR);
	}
}

static int64_t now_ns(void);

/* caller holds lock: the hub's HR on or off (its poll delay at most 1 s) */
static int hr_hub(int on)
{
	if (hub[H_HR].enabled == on)
		return 0;
	int previous = hub[H_HR].enabled;
	int r = on ? write_sysfs(hub[H_HR].delay_node, HR_HUB_PERIOD_NS) : 0;
	if (r)
		return r;
	hub[H_HR].enabled = on;
	r = apply_enable_mask();
	if (r) {
		hub[H_HR].enabled = previous;
		LOGE("HR hub transition failed: %d", r);
	}
	return r;
}

/* keep the AP up for the length of a burst (needs group wakelock; best effort) */
static void hr_wakelock(int on)
{
	int fd = open(on ? "/sys/power/wake_lock" : "/sys/power/wake_unlock", O_WRONLY | O_CLOEXEC);
	if (fd >= 0) {
		(void)write(fd, "r800_hr", 7);
		close(fd);
	}
}

static int64_t hr_period(void)
{
	return hr_req_ns > HR_MAX_PERIOD_NS ? HR_MAX_PERIOD_NS : hr_req_ns;
}

/* caller holds lock: start a burst, or skip this one while off the wrist */
static void hr_burst_begin(int64_t now)
{
	if (!offbody_known || offbody_state < 0.5f) {
		hr_skipped++;
		hr_next = now + hr_period();
		return;
	}
	hr_wakelock(1);
	if (hr_hub(1)) {
		hr_wakelock(0);
		hr_next = now + HR_RETRY_NS;
		return;
	}
	hr_burst_start = now;
	hr_bursts++;
}

/* Stop failures retain the burst and wakelock for a bounded retry cadence. */
static int hr_burst_end(void)
{
	if (hr_hub(0)) {
		hr_stop_retry = now_ns() + HR_RETRY_NS;
		return -EIO;
	}
	hr_wakelock(0);
	hr_next = hr_burst_start + hr_period();
	hr_burst_start = hr_stop_retry = 0;
	return 0;
}

/* caller holds lock: apply hr_active / hr_req_ns */
static int hr_update(int64_t now)
{
	int bg = hr_active && hr_req_ns >= HR_BG_MIN_NS;
	int r;
	if (!bg) {
		r = hr_hub(!!hr_active);
		if (r)
			return r;
		if (hr_burst_start)
			hr_wakelock(0);
		hr_burst_start = hr_stop_retry = 0;
		hr_bg = 0;
	} else if (!hr_bg) {
		int was_on = hub[H_HR].enabled;
		r = hr_hub(0);
		if (r)
			return r;
		hr_bg = 1;
		if (was_on)
			hr_next = now + hr_period();
		else
			hr_burst_begin(now);
	}
	LOGI("hr: %s, period %lld s", !hr_active ? "off" : hr_bg ? "bursts" : "continuous",
	     (long long)(hr_req_ns / 1000000000));
	return 0;
}

static void hr_tick(int64_t now)
{
	if (!hr_bg)
		return;
	if (hr_stop_retry) {
		if (now >= hr_stop_retry)
			hr_burst_end();
		return;
	}
	if (hr_burst_start && now >= hr_burst_start + HR_BURST_NS) {
		LOGI("hr burst %d: timeout", hr_bursts);
		hr_burst_end();
	} else if (!hr_burst_start && now >= hr_next) {
		hr_burst_begin(now);
	}
}

static int hr_timeout_ms(int64_t now)
{
	if (!hr_bg)
		return -1;
	int64_t target = hr_stop_retry ? hr_stop_retry :
		hr_burst_start ? hr_burst_start + HR_BURST_NS : hr_next;
	int64_t t = target - now;
	return t <= 0 ? 0 : (int)(t / 1000000) + 1;
}

static int dev_activate(struct sensors_poll_device_t *dev, int handle, int enabled)
{
		if (!valid(handle))
		return -EINVAL;
	if (handle >= H_COUNT) {
		pthread_mutex_lock(&lock);
		if (!device_ready(dev)) {
			pthread_mutex_unlock(&lock);
			return -ENODEV;
		}
		ctx_enabled[handle] = !!enabled;
		/* on-change: deliver the current state right after activation */
		if (handle == H_OFFBODY)
			offbody_report = enabled && offbody_known;
		/* on-change: the current total right away (0 before any step) */
		if ((handle == H_STEP_COUNTER || handle == H_STEP_COUNTER_WAKE) && enabled)
			step_report[handle] = 1;
		if (handle == H_STEP_DETECTOR)
			step_detect_pending = 0;
		wake_poll();
		pthread_mutex_unlock(&lock);
		LOGI("activate %d = %d (context)", handle, enabled);
		return 0;
	}
	if (handle == H_HR) {
		pthread_mutex_lock(&lock);
		if (!device_ready(dev)) {
			pthread_mutex_unlock(&lock);
			return -ENODEV;
		}
		int previous = hr_active;
		hr_active = !!enabled;
		int r = hr_update(now_ns());
		if (r)
			hr_active = previous;
		wake_poll();
		pthread_mutex_unlock(&lock);
		LOGI("activate %d = %d (%d)", handle, enabled, r);
		return r;
	}
	pthread_mutex_lock(&lock);
		if (!device_ready(dev)) {
			pthread_mutex_unlock(&lock);
			return -ENODEV;
		}
	int previous = hub[handle].enabled;
	int r = 0;
	if (enabled && hub[handle].period_ns)
		r = write_sysfs(hub[handle].delay_node, hub[handle].period_ns);
	if (!r) {
		hub[handle].enabled = !!enabled;
		r = apply_enable_mask();
		if (r)
			hub[handle].enabled = previous;
	}
	pthread_mutex_unlock(&lock);
	LOGI("activate %d = %d (%d)", handle, enabled, r);
	return r;
}

static int dev_set_delay(struct sensors_poll_device_t *dev, int handle, int64_t ns)
{
		if (!valid(handle))
		return -EINVAL;
	if (handle >= H_COUNT) {
		pthread_mutex_lock(&lock);
		int ready = device_ready(dev);
		pthread_mutex_unlock(&lock);
		return ready ? 0 : -ENODEV; /* event driven */
	}
	const struct sensor_t *s = &sensor_list[handle - 1];
	int64_t req = ns;
	if (s->minDelay > 0 && ns < (int64_t)s->minDelay * 1000)
		ns = (int64_t)s->minDelay * 1000;
	if (ns > (int64_t)s->maxDelay * 1000)
		ns = (int64_t)s->maxDelay * 1000;
	if (ns <= 0)
		ns = 200000000; /* on-change sensors: 200 ms */
	if (handle == H_HR) {
		/* the hub's HR always runs at 1 s; slower requests mean bursts */
		pthread_mutex_lock(&lock);
		if (!device_ready(dev)) {
			pthread_mutex_unlock(&lock);
			return -ENODEV;
		}
		int64_t previous = hr_req_ns;
		hr_req_ns = req;
		hub[handle].period_ns = HR_HUB_PERIOD_NS;
		int r = hub[handle].enabled ? write_sysfs(hub[handle].delay_node, hub[handle].period_ns) : 0;
		if (!r && hr_active && previous != req)
			r = hr_update(now_ns());
		if (r)
			hr_req_ns = previous;
		wake_poll();
		pthread_mutex_unlock(&lock);
		return r;
	}
	pthread_mutex_lock(&lock);
		if (!device_ready(dev)) {
			pthread_mutex_unlock(&lock);
			return -ENODEV;
		}
	int r = hub[handle].enabled ? write_sysfs(hub[handle].delay_node, ns) : 0;
	if (!r)
		hub[handle].period_ns = ns;
	pthread_mutex_unlock(&lock);
	return r;
}

static int dev_batch(struct sensors_poll_device_1 *dev, int handle, int flags,
		     int64_t period_ns, int64_t latency_ns)
{
	(void)flags;
	(void)latency_ns; /* no FIFO batching: report immediately */
	return dev_set_delay(&dev->v0, handle, period_ns);
}

static int dev_flush(struct sensors_poll_device_1 *dev, int handle)
{
		if (!valid(handle))
		return -EINVAL;
	pthread_mutex_lock(&lock);
		if (!device_ready(dev)) {
			pthread_mutex_unlock(&lock);
			return -ENODEV;
		}
	int enabled = is_enabled(handle);
	if (enabled && flush_pending[handle] < INT_MAX) {
		flush_pending[handle]++;
		wake_poll();
		pthread_mutex_unlock(&lock);
		return 0;
	}
	pthread_mutex_unlock(&lock);
	return enabled ? -EOVERFLOW : -EINVAL;
}

static int dev_inject(struct sensors_poll_device_1 *dev, const sensors_event_t *data)
{
	(void)dev;
	(void)data;
	return -EINVAL;
}

/* turn a completed frame into an Android event; returns 1 if *ev was filled */
static int make_event(struct hub_sensor *s, sensors_event_t *ev)
{
	memset(ev, 0, sizeof(*ev));
	ev->version = sizeof(*ev);
	ev->sensor = s->handle;
	ev->type = sensor_list[s->handle - 1].type;
	ev->timestamp = (int64_t)(((uint64_t)s->ts[0] << 48) | ((uint64_t)s->ts[1] << 32) |
				  ((uint64_t)s->ts[2] << 16) | (uint64_t)s->ts[3]);
	if (!ev->timestamp) {
		struct timespec t;
		clock_gettime(CLOCK_BOOTTIME, &t);
		ev->timestamp = (int64_t)t.tv_sec * 1000000000LL + t.tv_nsec;
	}
	switch (s->handle) {
	case H_ACCEL: {
		const float k = 0.000244f * GRAVITY_EARTH;
		ev->acceleration.x = s->v[0] * k;
		ev->acceleration.y = s->v[1] * k;
		ev->acceleration.z = s->v[2] * k;
		ev->acceleration.status = SENSOR_STATUS_ACCURACY_HIGH;
		break;
	}
	case H_GYRO: {
		const float k = 0.070f * (float)M_PI / 180.0f;
		ev->gyro.x = s->v[0] * k;
		ev->gyro.y = s->v[1] * k;
		ev->gyro.z = s->v[2] * k;
		ev->gyro.status = SENSOR_STATUS_ACCURACY_HIGH;
		break;
	}
	case H_PRESSURE:
		if (s->v[0] <= 0)
			return 0;
		ev->pressure = s->v[0] / 4096.0f;
		break;
	case H_LIGHT:
		ev->light = s->v[0] > 0 ? (float)(s->v[0] - 1) : 0.0f;
		break;
	case H_HR: {
		int bpm = s->v[0] > 0 ? s->v[0] - 1 : 0;
		ev->heart_rate.bpm = (float)bpm;
		ev->heart_rate.status = bpm > 0 ? SENSOR_STATUS_ACCURACY_HIGH : SENSOR_STATUS_NO_CONTACT;
		break;
	}
	case H_GYRO_UNCAL: {
		/* raw rates in RX/RY/RZ, the hub's bias estimate in HWHEEL/DIAL/WHEEL */
		const float k = 0.070f * (float)M_PI / 180.0f;
		for (int i = 0; i < 3; i++) {
			ev->uncalibrated_gyro.uncalib[i] = s->v[i] * k;
			ev->uncalibrated_gyro.bias[i] = s->v[3 + i] * k;
		}
		break;
	}
	default:
		return 0;
	}
	return 1;
}

/* map a REL code to the value slot it fills for this sensor, or -1 */
static int value_slot(const struct hub_sensor *s, int code)
{
	switch (s->handle) {
	case H_ACCEL:
	case H_HR:
		return code >= REL_X && code <= REL_Z ? code - REL_X : -1;
	case H_GYRO:
		return code >= REL_RX && code <= REL_RZ ? code - REL_RX : -1;
	case H_PRESSURE:
		return code == REL_HWHEEL ? 0 : code == REL_WHEEL ? 1 : code == REL_DIAL ? 2 : -1;
	case H_LIGHT:
		return code == REL_RX ? 0 : -1;
	case H_GYRO_UNCAL:
		if (code >= REL_RX && code <= REL_RZ)
			return code - REL_RX;
		return code == REL_HWHEEL ? 3 : code == REL_DIAL ? 4 : code == REL_WHEEL ? 5 : -1;
	}
	return -1;
}

static int64_t now_ns(void)
{
	struct timespec t;
	clock_gettime(CLOCK_BOOTTIME, &t);
	return (int64_t)t.tv_sec * 1000000000LL + t.tv_nsec;
}

/* open the context FIFO (created by android-helper.sh); also hold a write end so
 * poll() never sees POLLHUP while the helper's writers restart */
static void ctx_open(void)
{
	if (ctx_fd >= 0)
		return;
	ctx_fd = open(CTX_FIFO, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
	if (ctx_fd < 0)
		return;
	ctx_wfd = open(CTX_FIFO, O_WRONLY | O_NONBLOCK | O_CLOEXEC);
	ctx_len = ctx_discard = 0;
	LOGI("context fifo open (%d/%d)", ctx_fd, ctx_wfd);
}

static void ctx_event(sensors_event_t *ev, int handle, float value)
{
	memset(ev, 0, sizeof(*ev));
	ev->version = sizeof(*ev);
	ev->sensor = handle;
	ev->type = sensor_list[handle - 1].type;
	ev->timestamp = now_ns();
	ev->data[0] = value;
}

/* (lock held) */
static void step_event(sensors_event_t *ev, int handle)
{
	ctx_event(ev, handle, 0.0f);
	ev->u64.step_counter = step_total;
}

/* (lock held) queued step counter / detector events */
static void step_drain(sensors_event_t *data, int count, int *n_out)
{
	for (int h = H_STEP_COUNTER; h <= H_STEP_COUNTER_WAKE; h++) {
		if (!ctx_enabled[h])
			step_report[h] = 0;
		else if (step_report[h] && *n_out < count) {
			step_event(&data[(*n_out)++], h);
			step_report[h] = 0;
		}
	}
	while (step_detect_pending > 0 && *n_out < count) {
		if (ctx_enabled[H_STEP_DETECTOR])
			ctx_event(&data[(*n_out)++], H_STEP_DETECTOR, 1.0f);
		step_detect_pending--;
	}
}

/* Exact protocol: W/D timestamp, O wear state, P nonnegative step total. */
static int parse_context_line(const char *line, long long *value)
{
	if (!line[0] || line[1] != ' ' ||
	    (line[0] != 'W' && line[0] != 'D' && line[0] != 'O' && line[0] != 'P'))
		return -EINVAL;
	int r = parse_enable_mask(line + 2, value);
	if (r)
		return r;
	if (line[0] == 'O' && *value != 1 && *value != 2)
		return -EINVAL;
	return line[0];
}

static uint64_t step_add(uint64_t a, uint64_t b)
{
	return b > UINT64_MAX - a ? UINT64_MAX : a + b;
}

/* caller holds lock */
static void ctx_line(const char *line, sensors_event_t *data, int count, int *n_out)
{
	long long raw;
	int kind = parse_context_line(line, &raw);
	if (kind == 'W' && ctx_enabled[H_WRIST_TILT])
		ctx_event(&data[(*n_out)++], H_WRIST_TILT, 1.0f);
	else if (kind == 'D' && ctx_enabled[H_UNGAZE])
		ctx_event(&data[(*n_out)++], H_UNGAZE, 1.0f);
	else if (kind == 'O') {
		float st = raw == 1 ? 1.0f : 0.0f;
		int changed = !offbody_known || st != offbody_state || offbody_report;
		offbody_known = 1;
		offbody_state = st;
		offbody_report = 0;
		if (st < 0.5f && hr_bg && hr_burst_start && !hr_stop_retry)
			hr_burst_end();
		if (changed && ctx_enabled[H_OFFBODY])
			ctx_event(&data[(*n_out)++], H_OFFBODY, st);
	} else if (kind == 'P') {
		int first = step_raw < 0;
		long long d = first ? 0 : raw >= step_raw ? raw - step_raw : raw;
		if (!first && raw < step_raw)
			step_base = step_add(step_base, (uint64_t)step_raw);
		step_raw = raw;
		step_total = step_add(step_base, (uint64_t)raw);
		if (d > 0 || first)
			for (int h = H_STEP_COUNTER; h <= H_STEP_COUNTER_WAKE; h++)
				step_report[h] = ctx_enabled[h];
		if (ctx_enabled[H_STEP_DETECTOR]) {
			int room = STEP_PENDING_MAX - step_detect_pending;
			step_detect_pending += d > room ? room : (int)d;
		}
		step_drain(data, count, n_out);
	}
}

/* Read bounded bytes without consuming later complete records once the
 * caller's output array fills. Context events are low-rate. Discard an
 * entire overlong/NUL-containing record, not only its first fragment. */
static void ctx_read(sensors_event_t *data, int count, int *n_out)
{
	for (int budget = CTX_READ_BUDGET; budget > 0 && *n_out < count; budget--) {
		char ch;
		ssize_t r = read(ctx_fd, &ch, 1);
		if (r < 0 && errno == EINTR)
			continue;
		if (r != 1)
			break;
		if (ch == '\n') {
			if (!ctx_discard) {
				ctx_buf[ctx_len] = 0;
				pthread_mutex_lock(&lock);
				ctx_line(ctx_buf, data, count, n_out);
				pthread_mutex_unlock(&lock);
			}
			ctx_len = ctx_discard = 0;
		} else if (!ctx_discard) {
			if (!ch || ctx_len >= (int)sizeof(ctx_buf) - 1)
				ctx_discard = 1;
			else
				ctx_buf[ctx_len++] = ch;
		}
	}
}

/* Each SSP frame contains relative values; missing codes mean zero.
 * After SYN_DROPPED the incomplete frame is not recoverable. */
static int discard_overrun(struct hub_sensor *s, const struct input_event *ev)
{
	if (ev->type == EV_SYN && ev->code == SYN_DROPPED) {
		memset(s->v, 0, sizeof(s->v));
		memset(s->ts, 0, sizeof(s->ts));
		s->dropped = 1;
		return 1;
	}
	if (!s->dropped)
		return 0;
	if (ev->type == EV_SYN && ev->code == SYN_REPORT)
		s->dropped = 0;
	return 1;
}

static int poll_events(sensors_event_t *data, int count)
{
	if (!data || count <= 0)
		return -EINVAL;
	struct pollfd pfd[H_COUNT + 2];
	int idx[H_COUNT + 2];
	int n_out = 0;

	for (;;) {
		/* flush-complete events first */
		pthread_mutex_lock(&lock);
		if (closing) {
			pthread_mutex_unlock(&lock);
			return -ENODEV;
		}
		int recover_tmo = recover_inputs(now_ns());
		if (offbody_report && ctx_enabled[H_OFFBODY] && n_out < count) {
			ctx_event(&data[n_out++], H_OFFBODY, offbody_state);
			offbody_report = 0;
		}
		step_drain(data, count, &n_out);
		for (int h = H_ACCEL; h < N_HANDLES && n_out < count; h++) {
			while (flush_pending[h] > 0 && n_out < count) {
				sensors_event_t *ev = &data[n_out++];
				memset(ev, 0, sizeof(*ev));
				ev->version = META_DATA_VERSION;
				ev->type = SENSOR_TYPE_META_DATA;
				ev->meta_data.what = META_DATA_FLUSH_COMPLETE;
				ev->meta_data.sensor = h;
				flush_pending[h]--;
			}
		}
		pthread_mutex_unlock(&lock);
		if (n_out)
			return n_out;

		int n = 0;
		pfd[n].fd = wake_pipe[0];
		pfd[n].events = POLLIN;
		idx[n++] = 0;
		for (int h = H_ACCEL; h < H_COUNT; h++) {
			if (hub[h].fd < 0)
				continue;
			pfd[n].fd = hub[h].fd;
			pfd[n].events = POLLIN;
			idx[n++] = h;
		}
		ctx_open();
		if (ctx_fd >= 0) {
			pfd[n].fd = ctx_fd;
			pfd[n].events = POLLIN;
			idx[n++] = H_WRIST_TILT; /* marker: context fifo */
		}
		/* until the helper has made the FIFO, look for it every 5 s */
		int tmo = ctx_fd >= 0 ? -1 : 5000;
		pthread_mutex_lock(&lock);
		int ht = hr_timeout_ms(now_ns());
		pthread_mutex_unlock(&lock);
		if (recover_tmo >= 0 && (tmo < 0 || recover_tmo < tmo))
			tmo = recover_tmo;
		if (ht >= 0 && (tmo < 0 || ht < tmo))
			tmo = ht;
		int pr = poll(pfd, n, tmo);
		int poll_errno = errno;
		pthread_mutex_lock(&lock);
		if (closing) {
			pthread_mutex_unlock(&lock);
			return -ENODEV;
		}
		hr_tick(now_ns());
		pthread_mutex_unlock(&lock);
		if (pr < 0) {
			if (poll_errno == EINTR)
				continue;
			return -poll_errno;
		}
		if (pfd[0].revents & (POLLERR | POLLHUP | POLLNVAL))
			return -EIO;
		if (pfd[0].revents & POLLIN) {
			char buf[16];
			(void)read(wake_pipe[0], buf, sizeof(buf));
		}
		for (int i = 1; i < n && n_out < count; i++) {
			if (pfd[i].revents & (POLLERR | POLLHUP | POLLNVAL)) {
				if (idx[i] == H_WRIST_TILT) {
					if (ctx_fd >= 0) close(ctx_fd);
					if (ctx_wfd >= 0) close(ctx_wfd);
					ctx_fd = ctx_wfd = -1;
					ctx_len = ctx_discard = 0;
					pthread_mutex_lock(&lock);
					offbody_known = offbody_report = 0;
					pthread_mutex_unlock(&lock);
				} else {
					input_lost(&hub[idx[i]]);
				}
				continue;
			}
			if (!(pfd[i].revents & POLLIN))
				continue;
			if (idx[i] == H_WRIST_TILT) {
				ctx_read(data, count, &n_out);
				continue;
			}
			struct hub_sensor *s = &hub[idx[i]];
			/* Read one record at a time so reaching caller capacity
			 * never discards unread records from a larger read. */
			struct input_event ie[1];
			ssize_t r = -1;
			int budget = 256;
			while (n_out < count && budget-- > 0 && (r = read(s->fd, ie, sizeof(ie))) > 0) {
				if (r != sizeof(ie)) {
					input_lost(s);
					break;
				}
				for (int j = 0; j < 1; j++) {
					if (discard_overrun(s, &ie[j]))
						continue;
					if (ie[j].type == EV_REL) {
						int c = ie[j].code;
						if (c >= s->ts_code && c < s->ts_code + 4)
							s->ts[c - s->ts_code] = (uint16_t)ie[j].value;
						else {
							int slot = value_slot(s, c);
							if (slot >= 0)
								s->v[slot] = ie[j].value;
						}
					} else if (ie[j].type == EV_SYN && ie[j].code == SYN_REPORT) {
						int on;
						pthread_mutex_lock(&lock);
						on = s->enabled;
						/* burst mode: only the first settled reading (v = bpm + 1),
						   which also ends the burst */
						if (s->handle == H_HR && hr_bg) {
							int64_t t = now_ns();
							on = hr_burst_start && !hr_stop_retry && s->v[0] > 1 &&
							     t - hr_burst_start >= HR_SETTLE_NS;
							if (on) {
								LOGI("hr burst %d: %d bpm after %lld s (%d skipped off-wrist)",
								     hr_bursts, s->v[0] - 1,
								     (long long)((t - hr_burst_start) / 1000000000),
								     hr_skipped);
								hr_burst_end();
							}
						}
						pthread_mutex_unlock(&lock);
						if (on && make_event(s, &data[n_out]))
							n_out++;
						memset(s->v, 0, sizeof(s->v));
						memset(s->ts, 0, sizeof(s->ts));
					}
				}
			}
			if (s->fd >= 0 && budget >= 0 && n_out < count && (r == 0 ||
			    (r < 0 && errno != EAGAIN && errno != EINTR)))
				input_lost(s);
		}
		if (n_out)
			return n_out;
	}
}

static int dev_poll(struct sensors_poll_device_t *dev, sensors_event_t *data, int count)
{
	pthread_mutex_lock(&lock);
	if (!device_ready(dev) || polling) {
		int r = device_ready(dev) ? -EBUSY : -ENODEV;
		pthread_mutex_unlock(&lock);
		return r;
	}
	polling = 1;
	pthread_mutex_unlock(&lock);
	int r = poll_events(data, count);
	pthread_mutex_lock(&lock);
	polling = 0;
	pthread_cond_broadcast(&poll_idle);
	pthread_mutex_unlock(&lock);
	return r;
}

/* Close only after the poll owner has exited. Caller holds lock. */
static void close_fd(int *fd)
{
	if (*fd >= 0)
		close(*fd);
	*fd = -1;
}

static int dev_close(struct hw_device_t *dev)
{
	pthread_mutex_lock(&lock);
	if (!device_ready(dev)) {
		pthread_mutex_unlock(&lock);
		return -ENODEV;
	}
	closing = 1;
	wake_poll();
	while (polling)
		pthread_cond_wait(&poll_idle, &lock);

	int previous[H_COUNT];
	for (int h = H_ACCEL; h < H_COUNT; h++) {
		previous[h] = hub[h].enabled;
		hub[h].enabled = 0;
	}
	int r = apply_enable_mask();
	if (r) {
		/* Do not pretend a failed SSP disable succeeded. Retain the
		 * device and descriptors so close can be retried. */
		for (int h = H_ACCEL; h < H_COUNT; h++)
			hub[h].enabled = previous[h];
		closing = 0;
		pthread_mutex_unlock(&lock);
		return r;
	}
	if (hr_burst_start)
		hr_wakelock(0);
	hr_active = hr_bg = hr_bursts = hr_skipped = 0;
	hr_req_ns = hr_burst_start = hr_stop_retry = hr_next = 0;
	for (int h = H_ACCEL; h < H_COUNT; h++) {
		close_fd(&hub[h].fd);
		hub[h].period_ns = 0;
		hub[h].dropped = 0;
		memset(hub[h].v, 0, sizeof(hub[h].v));
		memset(hub[h].ts, 0, sizeof(hub[h].ts));
	}
	close_fd(&ctx_fd);
	close_fd(&ctx_wfd);
	close_fd(&wake_pipe[0]);
	close_fd(&wake_pipe[1]);
	ctx_len = ctx_discard = 0;
	input_retry_at = 0;
	input_restore_pending = 0;
	offbody_known = offbody_report = 0;
	offbody_state = 1.0f;
	step_detect_pending = 0;
	memset(ctx_enabled, 0, sizeof(ctx_enabled));
	memset(step_report, 0, sizeof(step_report));
	memset(flush_pending, 0, sizeof(flush_pending));
	/* Preserve process-lifetime monotonic step accounting on reopen. */
	active_device = NULL;
	closing = 0;
	pthread_mutex_unlock(&lock);
	free(dev);
	return 0;
}

static int open_sensors(const struct hw_module_t *module, const char *id, struct hw_device_t **device)
{
	if (!device || !id || strcmp(id, SENSORS_HARDWARE_POLL))
		return -EINVAL;
	sensors_poll_device_1_t *dev = calloc(1, sizeof(*dev));
	if (!dev)
		return -ENOMEM;
	pthread_mutex_lock(&lock);
	if (active_device || closing) {
		pthread_mutex_unlock(&lock);
		free(dev);
		return -EBUSY;
	}
	if (wake_pipe[0] < 0) {
		if (pipe2(wake_pipe, O_NONBLOCK | O_CLOEXEC) < 0) {
			pthread_mutex_unlock(&lock);
			free(dev);
			return -errno;
		}
		open_inputs();
		for (int h = H_ACCEL; h < H_COUNT; h++)
			hub[h].enabled = 0;
		int r = apply_enable_mask();
		if (r) {
			for (int h = H_ACCEL; h < H_COUNT; h++) {
				if (hub[h].fd >= 0)
					close(hub[h].fd);
				hub[h].fd = -1;
			}
			close(wake_pipe[0]);
			close(wake_pipe[1]);
			wake_pipe[0] = wake_pipe[1] = -1;
			pthread_mutex_unlock(&lock);
			free(dev);
			return r;
		}
	}
	input_retry_at = 0;
	input_restore_pending = 0;
	active_device = dev;
	pthread_mutex_unlock(&lock);

	dev->common.tag = HARDWARE_DEVICE_TAG;
	dev->common.version = SENSORS_DEVICE_API_VERSION_1_3;
	dev->common.module = (struct hw_module_t *)module;
	dev->common.close = dev_close;
	dev->activate = dev_activate;
	dev->setDelay = dev_set_delay;
	dev->poll = dev_poll;
	dev->batch = dev_batch;
	dev->flush = dev_flush;
	dev->inject_sensor_data = dev_inject;
	*device = &dev->common;
	LOGI("opened, %d sensors", N_SENSORS);
	return 0;
}

static int get_sensors_list(struct sensors_module_t *module, struct sensor_t const **list)
{
	(void)module;
	*list = sensor_list;
	return N_SENSORS;
}

static int set_operation_mode(unsigned int mode)
{
	return mode == 0 ? 0 : -EINVAL;
}

static struct hw_module_methods_t sensors_methods = {
	.open = open_sensors,
};

__attribute__((visibility("default")))
struct sensors_module_t HAL_MODULE_INFO_SYM = {
	.common = {
		.tag = HARDWARE_MODULE_TAG,
		.module_api_version = SENSORS_MODULE_API_VERSION_0_1,
		.hal_api_version = HARDWARE_HAL_API_VERSION,
		.id = SENSORS_HARDWARE_MODULE_ID,
		.name = "SM-R800 SSP sensor hub",
		.author = "r800-wearos",
		.methods = &sensors_methods,
	},
	.get_sensors_list = get_sensors_list,
	.set_operation_mode = set_operation_mode,
};
