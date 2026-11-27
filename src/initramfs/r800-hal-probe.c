/* ARM32 Bionic diagnostic only. Lifecycle mode requires hardware-free guest. */
#include <dlfcn.h>
#include <errno.h>
#include <stdint.h>
#include <linux/input.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <hardware/audio.h>
#include <hardware/hwcomposer.h>
#include <hardware/hardware.h>
#include <stdio.h>
#include <string.h>

#if !defined(__BIONIC__) || !defined(__arm__) || __ANDROID_API__ != 28
#error "ARM32 Bionic API28 required"
#endif
_Static_assert(sizeof(hw_module_t) == 128, "Unexpected HAL module ABI");

static int missing(const char *path)
{
    return access(path, F_OK) == -1 && errno == ENOENT;
}

static int fd_count(void)
{
    int count = 0;
    for (int fd = 0; fd < 256; ++fd) {
        if (fcntl(fd, F_GETFD) != -1)
            ++count;
        else if (errno != EBADF)
            return -1;
    }
    return count;
}

static int lifecycle(const hw_module_t *module, const char *id)
{
    const char *name = NULL;
    int expected = 0;
    if (!strcmp(id, "audio")) name = AUDIO_HARDWARE_INTERFACE;
    else if (!strcmp(id, "gps")) name = "gps";
    else if (!strcmp(id, "lights")) name = "backlight";
    else if (!strcmp(id, "hwcomposer")) {
        name = HWC_HARDWARE_COMPOSER;
        expected = -ENOENT;
    } else if (!strcmp(id, "sensors")) {
        name = "poll";
        expected = -ENOENT;
    } else return 6;

    if (!missing("/dev/graphics/fb0") || !missing("/dev/fb0") ||
        !missing("/sys/class/sensors/ssp_sensor/enable") ||
        !missing("/dev/snd") || !missing("/dev/input")) {
        fprintf(stderr, "Hardware-free guest required\n");
        return 7;
    }
    int baseline = -1;
    /* Warm up logging before measuring descriptor count; no hardware I/O
     * methods, sensor polling, GPS init, PCM stream or brightness calls. */
    for (int i = 0; i < 17; ++i) {
        hw_device_t *device = NULL;
        int rc = module->methods->open(module, name, &device);
        if (rc != expected || (expected && device)) {
            fprintf(stderr, "open mismatch %s attempt=%d got=%d expected=%d\n",
                    id, i, rc, expected);
            return 8;
        }
        if (!expected) {
            if (!device || device->tag != HARDWARE_DEVICE_TAG ||
                device->module != module || !device->close)
                return 9;
            if (!strcmp(id, "audio")) {
                struct audio_hw_device *audio = (struct audio_hw_device *)device;
                bool mute = false;
                if (device->version != AUDIO_DEVICE_API_VERSION_2_0 ||
                    !audio->set_mic_mute || !audio->get_mic_mute ||
                    audio->set_mic_mute(audio, true) ||
                    audio->get_mic_mute(audio, &mute) || !mute ||
                    audio->set_mic_mute(audio, false) ||
                    audio->get_mic_mute(audio, &mute) || mute)
                    return 10;
            }
            if (device->close(device))
                return 11;
        }
        int now = fd_count();
        if (now < 0 || (i && now != baseline)) {
            fprintf(stderr, "descriptor count changed %s baseline=%d now=%d\n",
                    id, baseline, now);
            return 12;
        }
        baseline = now;
    }
    printf("HAL_LIFECYCLE_PASS %s repeats=16 open_rc=%d fd_window=256\n", id, expected);
    return 0;
}

/* Stable legacy lights ABI, mirrored by lights_r800.c. */
struct probe_light_state {
    unsigned int color;
    int flashMode, flashOnMS, flashOffMS, brightnessMode;
};
struct probe_light_device {
    hw_device_t common;
    int (*set_light)(struct probe_light_device *, const struct probe_light_state *);
};
#define FIXTURE "/sys/class/backlight/exynos_panel"
#define BRIGHTNESS FIXTURE "/brightness"
#define BACKUP FIXTURE "/brightness.saved"

static int fixture_read(const char *path, const char *expected)
{
    char buf[32];
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return 0;
    ssize_t n = read(fd, buf, sizeof(buf));
    int rc = close(fd);
    return !rc && n == (ssize_t)strlen(expected) && !memcmp(buf, expected, (size_t)n);
}

static int fixture_write(const char *path, const char *value)
{
    int fd = open(path, O_WRONLY | O_TRUNC | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return 0;
    ssize_t n = write(fd, value, strlen(value));
    int rc = close(fd);
    return !rc && n == (ssize_t)strlen(value);
}

static int fixture_reset(const char *value)
{
    return fixture_write(BRIGHTNESS, value);
}

static int lights_fixture(const hw_module_t *module)
{
    struct statfs fs;
    struct stat st;
    if (statfs(FIXTURE, &fs) || (unsigned long)fs.f_type == 0x62656572UL ||
        !fixture_read(FIXTURE "/.galwear-fixture", "GALWEAR_LIGHTS_FIXTURE_V1\n") ||
        lstat(BRIGHTNESS, &st) || !S_ISREG(st.st_mode) || !missing(BACKUP))
        return 20;
    hw_device_t *base = NULL;
    if (module->methods->open(module, "backlight", &base) ||
        !base || base->tag != HARDWARE_DEVICE_TAG || base->module != module || !base->close)
        return 21;
    struct probe_light_device *dev = (struct probe_light_device *)base;
    if (!dev->set_light) return 22;
    const struct { unsigned int color; const char *value; } cases[] = {
        {0xffffffffu, "255\n"}, {0x00ff0000u, "76\n"},
        {0x0000ff00u, "149\n"}, {0x000000ffu, "28\n"},
        {0x00808080u, "128\n"}, {0xff000000u, "0\n"}
    };
    struct probe_light_state state = {0};
    for (size_t i = 0; i < sizeof(cases)/sizeof(cases[0]); ++i) {
        state.color = cases[i].color;
        if (!fixture_reset("") || dev->set_light(dev, &state) ||
            !fixture_read(BRIGHTNESS, cases[i].value))
            return 23;
    }
    state.color = 0x00000000u;
    if (!fixture_reset("sentinel\n") || dev->set_light(dev, &state) ||
        !fixture_read(BRIGHTNESS, "sentinel\n"))
        return 24;
    state.color = 0x00ffffffu;
    if (rename(BRIGHTNESS, BACKUP)) return 25;
    int rc = dev->set_light(dev, &state);
    if (rename(BACKUP, BRIGHTNESS) || rc != -ENOENT ||
        !fixture_reset("") || dev->set_light(dev, &state) ||
        !fixture_read(BRIGHTNESS, "255\n"))
        return 26;
    if (base->close(base)) return 27;
    puts("HAL_LIGHTS_FIXTURE_PASS rgb_cases=6 cache_skip=1 missing_retry=1");
    return 0;
}

/* Legacy sensors ABI, matching the implementation's ARM32 layout. */
struct sensors_event_t {
    int32_t version, sensor, type, reserved0;
    int64_t timestamp;
    union { float values[16]; uint64_t step[8]; int32_t meta[16]; };
    uint32_t flags, reserved1[3];
};
_Static_assert(sizeof(struct sensors_event_t) == 104, "sensor event ABI");
struct sensors_poll_device_t {
    hw_device_t common;
    int (*activate)(struct sensors_poll_device_t *, int, int);
    int (*setDelay)(struct sensors_poll_device_t *, int, int64_t);
    int (*poll)(struct sensors_poll_device_t *, struct sensors_event_t *, int);
};
struct probe_sensors_v1 {
    struct sensors_poll_device_t v0;
    int (*batch)(struct probe_sensors_v1 *, int, int, int64_t, int64_t);
    int (*flush)(struct probe_sensors_v1 *, int);
};
#define SSP_FIXTURE "/sys/class/sensors/ssp_sensor"
#define SSP_ENABLE SSP_FIXTURE "/enable"
#define SSP_DELAY SSP_FIXTURE "/accel_poll_delay"
#define SSP_SAVED SSP_FIXTURE "/enable.saved"

static int regular_fixture(const char *path)
{
    struct stat st;
    return !lstat(path, &st) && S_ISREG(st.st_mode);
}

static int sensors_fixture(const hw_module_t *module)
{
    struct statfs fs;
    if (statfs(SSP_FIXTURE, &fs) || (unsigned long)fs.f_type == 0x62656572UL ||
        !fixture_read(SSP_FIXTURE "/.galwear-fixture", "GALWEAR_SSP_FIXTURE_V1\n") ||
        !regular_fixture(SSP_ENABLE) || !regular_fixture(SSP_DELAY) ||
        !missing(SSP_SAVED) || !missing("/dev/input") ||
        !fixture_read(SSP_ENABLE, "262144") || !fixture_read(SSP_DELAY, "00000000"))
        return 30;

    /* All masks and periods used here have fixed decimal width: ordinary
     * files do not implement sysfs store/truncate semantics. */
    hw_device_t *base = NULL;
    if (module->methods->open(module, "poll", &base) ||
        !base || base->tag != HARDWARE_DEVICE_TAG || base->module != module ||
        base->version != HARDWARE_DEVICE_API_VERSION_2(1, 3, 1) || !base->close)
        return 31;
    struct sensors_poll_device_t *dev = (struct sensors_poll_device_t *)base;
    if (!dev->activate || !dev->setDelay) return 32;
    hw_device_t *duplicate = NULL;
    if (module->methods->open(module, "poll", &duplicate) != -EBUSY || duplicate)
        return 33;
    /* Accelerometer minDelay 10 ms; cached while disabled, written on enable. */
    if (dev->setDelay(dev, 1, 1) || !fixture_read(SSP_DELAY, "00000000") ||
        dev->activate(dev, 1, 1) || !fixture_read(SSP_DELAY, "10000000") ||
        !fixture_read(SSP_ENABLE, "262145") ||
        dev->setDelay(dev, 1, 20000000) || !fixture_read(SSP_DELAY, "20000000"))
        return 34;
    if (dev->activate(dev, 2, 1) || !fixture_read(SSP_ENABLE, "262147") ||
        dev->activate(dev, 1, 0) || !fixture_read(SSP_ENABLE, "262146") ||
        dev->activate(dev, 0, 1) != -EINVAL)
        return 35;
    if (!fixture_write(SSP_ENABLE, "broken") ||
        dev->activate(dev, 1, 1) != -EINVAL || !fixture_read(SSP_ENABLE, "broken") ||
        !fixture_write(SSP_ENABLE, "262146") ||
        dev->activate(dev, 2, 0) || !fixture_read(SSP_ENABLE, "262144"))
        return 36;
    /* Failed enable rolls back internal state; retry and close must preserve
     * the external bit. Failed close retains the device for a retry. */
    if (dev->activate(dev, 1, 1) || !fixture_read(SSP_ENABLE, "262145") ||
        rename(SSP_ENABLE, SSP_SAVED))
        return 37;
    int rc = base->close(base);
    if (rename(SSP_SAVED, SSP_ENABLE) || rc != -ENOENT ||
        !fixture_read(SSP_ENABLE, "262145") ||
        base->close(base) || !fixture_read(SSP_ENABLE, "262144"))
        return 38;

    int baseline = fd_count();
    if (baseline < 0) return 39;
    for (int i = 0; i < 16; ++i) {
        base = NULL;
        if (module->methods->open(module, "poll", &base) || !base ||
            base->close(base) || !fixture_read(SSP_ENABLE, "262144") ||
            fd_count() != baseline)
            return 40;
    }
    puts("HAL_SENSORS_FIXTURE_PASS external_bit=18 delay_clamp=1 rollback=1 close_retry=1 repeats=16");
    return 0;
}

#define CONTEXT_FIFO "/dev/r800_context"

static int context_send(int fd, const void *data, size_t len)
{
    return write(fd, data, len) == (ssize_t)len;
}

static int context_event(struct sensors_poll_device_t *dev, int handle, int type,
                         float value, uint64_t steps)
{
    struct {
        struct sensors_event_t ev;
        uint64_t guard;
    } out;
    memset(&out, 0, sizeof(out));
    out.guard = UINT64_C(0xabcdef1276543210);
    int n = dev->poll(dev, &out.ev, 1);
    if (n != 1 || out.guard != UINT64_C(0xabcdef1276543210) ||
        out.ev.version != 104 || out.ev.sensor != handle ||
        out.ev.type != type || out.ev.timestamp <= 0 ||
        (type == 19 ? out.ev.step[0] != steps : out.ev.values[0] != value)) {
        fprintf(stderr, "context event mismatch n=%d handle=%d type=%d expected=%d/%d\n",
                n, out.ev.sensor, out.ev.type, handle, type);
        return 0;
    }
    return 1;
}

static int sensors_context(const hw_module_t *module)
{
    struct statfs fs;
    struct stat st;
    if (statfs(SSP_FIXTURE, &fs) || (unsigned long)fs.f_type == 0x62656572UL ||
        !fixture_read(SSP_FIXTURE "/.galwear-fixture", "GALWEAR_SSP_FIXTURE_V1\n") ||
        !regular_fixture(SSP_ENABLE) || !fixture_read(SSP_ENABLE, "262144") ||
        !missing("/dev/input") || lstat(CONTEXT_FIFO, &st) || !S_ISFIFO(st.st_mode))
        return 50;
    int fd = open(CONTEXT_FIFO, O_RDWR | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return 51;
    hw_device_t *base = NULL;
    if (module->methods->open(module, "poll", &base) || !base ||
        base->tag != HARDWARE_DEVICE_TAG || base->module != module ||
        base->version != HARDWARE_DEVICE_API_VERSION_2(1, 3, 1) || !base->close)
        return 52;
    struct probe_sensors_v1 *v1 = (struct probe_sensors_v1 *)base;
    struct sensors_poll_device_t *dev = &v1->v0;
    if (!dev->activate || !dev->poll || !v1->flush) return 53;
    for (int h = 7; h <= 12; ++h)
        if (dev->activate(dev, h, 1)) return 54;
    /* Initial reports for both step counters, before any FIFO data. */
    if (!context_event(dev, 11, 19, 0, 0) || !context_event(dev, 12, 19, 0, 0))
        return 55;
    static const char first[] = "W 100\nD 101\nO 1\nO 1\nO 2\nP 5\nP 7\nP 1\n";
    if (!context_send(fd, first, sizeof(first)-1) ||
        !context_event(dev, 7, 26, 1, 0) ||
        !context_event(dev, 9, 65537, 1, 0) ||
        !context_event(dev, 8, 34, 1, 0) ||
        !context_event(dev, 8, 34, 0, 0) ||
        !context_event(dev, 11, 19, 0, 5) ||
        !context_event(dev, 12, 19, 0, 5) ||
        !context_event(dev, 11, 19, 0, 7) ||
        !context_event(dev, 12, 19, 0, 7) ||
        !context_event(dev, 10, 18, 1, 0) ||
        !context_event(dev, 10, 18, 1, 0) ||
        !context_event(dev, 11, 19, 0, 8) ||
        !context_event(dev, 12, 19, 0, 8) ||
        !context_event(dev, 10, 18, 1, 0))
        return 56;
    /* Malformed, NUL-containing and overlong lines must be discarded in full. */
    static const char invalid[] = "O 9\nP -1\nW 1\0D 2\n";
    char overlong[300];
    memset(overlong, '9', sizeof(overlong));
    overlong[0] = 'W'; overlong[1] = ' ';
    overlong[sizeof(overlong)-1] = '\n';
    if (dev->activate(dev, 7, 0) ||
        !context_send(fd, invalid, sizeof(invalid)-1) ||
        !context_send(fd, overlong, sizeof(overlong)) ||
        !context_send(fd, "W 200\nD 201\n", sizeof("W 200\nD 201\n")-1) ||
        !context_event(dev, 9, 65537, 1, 0))
        return 57;
    struct sensors_event_t ev;
    memset(&ev, 0, sizeof(ev));
    if (v1->flush(v1, 7) != -EINVAL || v1->flush(v1, 11) ||
        dev->poll(dev, &ev, 1) != 1 || ev.version != 0x103 ||
        ev.type != 0 || ev.meta[0] != 1 || ev.meta[1] != 11)
        return 58;
    if (base->close(base)) return 59;
    base = NULL;
    if (module->methods->open(module, "poll", &base) || !base) return 60;
    dev = (struct sensors_poll_device_t *)base;
    if (dev->activate(dev, 11, 1) || !context_event(dev, 11, 19, 0, 8) ||
        base->close(base) || close(fd) || !fixture_read(SSP_ENABLE, "262144"))
        return 61;
    puts("HAL_SENSORS_CONTEXT_PASS single_slot=1 gestures=3 offbody=2 step_events=12 malformed=3 flush=1 reopen=1");
    return 0;
}

/* Real poll() over synthetic evdev FIFO records. The separately compiled
 * test adapter implements EVIOCGNAME only for these FIFO inodes. */
static int send_input(int fd, unsigned short type, unsigned short code, int value)
{
    struct input_event ev = {0};
    ev.type = type; ev.code = code; ev.value = value;
    return context_send(fd, &ev, sizeof(ev));
}

static int frame(int fd, int ts_code, const unsigned short *codes,
                 const int *values, size_t count)
{
    for (size_t i = 0; i < count; ++i)
        if (!send_input(fd, EV_REL, codes[i], values[i])) return 0;
    if (!send_input(fd, EV_REL, ts_code + 2, 1) ||
        !send_input(fd, EV_REL, ts_code + 3, 0x2345)) return 0;
    return send_input(fd, EV_SYN, SYN_REPORT, 0);
}

static int input_event_matches(struct sensors_poll_device_t *dev, int handle,
                               int type, const float *values, size_t n, int status)
{
    struct { struct sensors_event_t ev; uint64_t guard; } out;
    memset(&out, 0, sizeof(out));
    out.guard = UINT64_C(0xabcdef1276543210);
    int rc = dev->poll(dev, &out.ev, 1);
    if (rc != 1 || out.guard != UINT64_C(0xabcdef1276543210) ||
        out.ev.version != 104 || out.ev.sensor != handle ||
        out.ev.type != type || out.ev.timestamp != INT64_C(0x12345)) {
        fprintf(stderr, "evdev mismatch handle=%d type=%d rc=%d timestamp=%lld\n",
                out.ev.sensor, out.ev.type, rc, (long long)out.ev.timestamp);
        return 0;
    }
    for (size_t i = 0; i < n; ++i) {
        float delta = out.ev.values[i] - values[i];
        if (!(delta >= -0.0001f && delta <= 0.0001f)) return 0;
    }
    if (status != -128) {
        const int8_t *raw = (const int8_t *)out.ev.values;
        if (raw[type == 21 ? 4 : 12] != status) return 0;
    }
    return 1;
}

static int sensors_evdev(const hw_module_t *module)
{
    struct statfs fs;
    if (statfs(SSP_FIXTURE, &fs) || (unsigned long)fs.f_type == 0x62656572UL ||
        !fixture_read(SSP_FIXTURE "/.galwear-fixture", "GALWEAR_EVDEV_FIXTURE_V1\n") ||
        !fixture_read("/dev/input/.galwear-fixture", "GALWEAR_EVDEV_FIXTURE_V1\n") ||
        !regular_fixture(SSP_ENABLE) || !fixture_read(SSP_ENABLE, "1073741824"))
        return 70;
    int fds[6];
    for (int i = 0; i < 6; ++i) {
        char path[64];
        struct stat st;
        snprintf(path, sizeof(path), "/dev/input/event%d", i);
        if (lstat(path, &st) || !S_ISFIFO(st.st_mode)) return 71;
        fds[i] = open(path, O_RDWR | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);
        if (fds[i] < 0) return 72;
    }
    hw_device_t *base = NULL;
    if (module->methods->open(module, "poll", &base) || !base ||
        base->tag != HARDWARE_DEVICE_TAG || base->module != module ||
        base->version != HARDWARE_DEVICE_API_VERSION_2(1, 3, 1) || !base->close)
        return 73;
    struct sensors_poll_device_t *dev = (struct sensors_poll_device_t *)base;
    if (!dev->activate || !dev->poll) return 74;
    for (int h = 1; h <= 6; ++h)
        if (dev->activate(dev, h, 1)) return 75;
    /* Newly opened devices discard the first incomplete frame. */
    for (int i = 0; i < 6; ++i)
        if (!send_input(fds[i], EV_REL, REL_X, 999) ||
            !send_input(fds[i], EV_SYN, SYN_REPORT, 0)) return 76;
    const unsigned short accel[] = {REL_X, REL_Z};
    const int av[] = {1000, -1000};
    const float ae[] = {2.3928226f, 0.0f, -2.3928226f};
    if (!frame(fds[0], REL_Z+1, accel, av, 2) ||
        !input_event_matches(dev, 1, 1, ae, 3, 3)) return 77;
    const unsigned short gyro[] = {REL_RX, REL_RY, REL_RZ};
    const int gv[] = {1000, -500, 100};
    const float ge[] = {1.2217305f, -0.6108652f, 0.1221731f};
    if (!frame(fds[1], REL_RZ+1, gyro, gv, 3) ||
        !input_event_matches(dev, 2, 4, ge, 3, 3)) return 78;
    const unsigned short pressure[] = {REL_HWHEEL};
    const int pv[] = {0}, pv2[] = {4096000};
    const float pe[] = {1000.0f};
    if (!frame(fds[2], REL_WHEEL+1, pressure, pv, 1) ||
        !frame(fds[2], REL_WHEEL+1, pressure, pv2, 1) ||
        !input_event_matches(dev, 3, 6, pe, 1, -128)) return 79;
    const unsigned short lux[] = {REL_RX};
    const int lv[] = {124};
    const float le[] = {123.0f};
    if (!frame(fds[3], REL_RX+1, lux, lv, 1) ||
        !input_event_matches(dev, 4, 5, le, 1, -128)) return 80;
    const unsigned short hr[] = {REL_X};
    const int hv[] = {73}, hz[] = {1};
    const float he[] = {72.0f}, hzero[] = {0.0f};
    if (!frame(fds[4], REL_Z+1, hr, hv, 1) ||
        !frame(fds[4], REL_Z+1, hr, hz, 1) ||
        !input_event_matches(dev, 5, 21, he, 1, 3) ||
        !input_event_matches(dev, 5, 21, hzero, 1, -1)) return 81;
    const unsigned short uncal[] = {REL_RX, REL_RY, REL_RZ, REL_HWHEEL, REL_DIAL, REL_WHEEL};
    const int uv[] = {1000, -500, 100, 10, -20, 30};
    const float ue[] = {1.2217305f, -0.6108652f, 0.1221731f, 0.0122173f, -0.0244346f, 0.0366519f};
    if (!frame(fds[5], REL_WHEEL+1, uncal, uv, 6) ||
        !input_event_matches(dev, 6, 16, ue, 6, -128)) return 82;
    /* SYN_DROPPED invalidates partial frame and the following sync. */
    const unsigned short ax[] = {REL_X};
    const int good[] = {100}, bad[] = {9999};
    const float recovered[] = {0.23928226f, 0.0f, 0.0f};
    if (!send_input(fds[0], EV_REL, REL_Y, 999) ||
        !send_input(fds[0], EV_SYN, SYN_DROPPED, 0) ||
        !frame(fds[0], REL_Z+1, ax, bad, 1) ||
        !frame(fds[0], REL_Z+1, ax, good, 1) ||
        !input_event_matches(dev, 1, 1, recovered, 3, 3)) return 83;
    if (base->close(base) || !fixture_read(SSP_ENABLE, "1073741824")) return 84;
    for (int i = 0; i < 6; ++i)
        if (close(fds[i])) return 85;
    puts("HAL_SENSORS_EVDEV_PASS handles=6 events=8 pressure_reject=1 syn_dropped=1");
    return 0;
}

#include "r800-gps-fixture.h"
#include "r800-audio-fixture.h"
#include "r800-audio-pcm-fixture.h"

int main(int argc, char **argv)
{
    if (argc != 3 && (argc != 4 ||
        (strcmp(argv[3], "--lifecycle") && strcmp(argv[3], "--lights-fixture") &&
         strcmp(argv[3], "--sensors-fixture") && strcmp(argv[3], "--sensors-context") &&
         strcmp(argv[3], "--sensors-evdev") && strcmp(argv[3], "--gps-fixture") && strcmp(argv[3], "--audio-fixture") && strcmp(argv[3], "--audio-pcm-fixture")))) return 2;
    if (argc == 4 && !strcmp(argv[3], "--lights-fixture") && strcmp(argv[2], "lights")) return 2;
    if (argc == 4 && (!strcmp(argv[3], "--sensors-fixture") ||
        !strcmp(argv[3], "--sensors-context") || !strcmp(argv[3], "--sensors-evdev")) &&
        strcmp(argv[2], "sensors")) return 2;
    if (argc == 4 && !strcmp(argv[3], "--gps-fixture") && strcmp(argv[2], "gps")) return 2;
    if (argc == 4 && (!strcmp(argv[3], "--audio-fixture") || !strcmp(argv[3], "--audio-pcm-fixture")) && strcmp(argv[2], "audio")) return 2;
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle) {
        fprintf(stderr, "dlopen failed: %s\n", dlerror());
        return 3;
    }
    dlerror();
    const hw_module_t *module = dlsym(handle, HAL_MODULE_INFO_SYM_AS_STR);
    const char *error = dlerror();
    if (error || !module || module->tag != HARDWARE_MODULE_TAG ||
        !module->id || strcmp(module->id, argv[2]) ||
        (module->hal_api_version != 0 && module->hal_api_version != HARDWARE_HAL_API_VERSION) ||
        !module->module_api_version || !module->methods || !module->methods->open ||
        !module->name || !module->author) {
        fprintf(stderr, "HMI metadata mismatch\n");
        dlclose(handle);
        return 4;
    }
    printf("HAL_HMI_PASS %s module_api=%u hal_api=%u\n", argv[2],
           (unsigned)module->module_api_version, (unsigned)module->hal_api_version);
    int rc = 0;
    if (argc == 4 && !strcmp(argv[3], "--gps-fixture")) {
        rc = gps_fixture(module);
        /* On failure, the reader may still be alive. Never unload it. */
        if (rc) {
            fflush(stdout);
            fflush(stderr);
            _exit(rc);
        }
        return dlclose(handle) ? 5 : 0;
    }
    if (argc == 4)
        rc = !strcmp(argv[3], "--audio-pcm-fixture") ? audio_pcm_fixture(module) :
             !strcmp(argv[3], "--audio-fixture") ? audio_fixture(module) :
             !strcmp(argv[3], "--lights-fixture") ? lights_fixture(module) :
             !strcmp(argv[3], "--sensors-fixture") ? sensors_fixture(module) :
             !strcmp(argv[3], "--sensors-context") ? sensors_context(module) :
             !strcmp(argv[3], "--sensors-evdev") ? sensors_evdev(module) : lifecycle(module, argv[2]);
    int close_rc = dlclose(handle);
    return rc ? rc : close_rc ? 5 : 0;
}
