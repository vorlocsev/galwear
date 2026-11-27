/* ARM32 Bionic diagnostic only. Lifecycle mode requires hardware-free guest. */
#include <dlfcn.h>
#include <errno.h>
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

/* Legacy sensors poll-device prefix; only activate/setDelay are called. */
struct sensors_event_t;
struct sensors_poll_device_t {
    hw_device_t common;
    int (*activate)(struct sensors_poll_device_t *, int, int);
    int (*setDelay)(struct sensors_poll_device_t *, int, int64_t);
    int (*poll)(struct sensors_poll_device_t *, struct sensors_event_t *, int);
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

int main(int argc, char **argv)
{
    if (argc != 3 && (argc != 4 ||
        (strcmp(argv[3], "--lifecycle") && strcmp(argv[3], "--lights-fixture") &&
         strcmp(argv[3], "--sensors-fixture")))) return 2;
    if (argc == 4 && !strcmp(argv[3], "--lights-fixture") && strcmp(argv[2], "lights")) return 2;
    if (argc == 4 && !strcmp(argv[3], "--sensors-fixture") && strcmp(argv[2], "sensors")) return 2;
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
    if (argc == 4)
        rc = !strcmp(argv[3], "--lights-fixture") ? lights_fixture(module) :
             !strcmp(argv[3], "--sensors-fixture") ? sensors_fixture(module) : lifecycle(module, argv[2]);
    int close_rc = dlclose(handle);
    return rc ? rc : close_rc ? 5 : 0;
}
