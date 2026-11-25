/*
 * audio.primary.r800.so: legacy primary audio HAL for the SM-R800 Wear OS port.
 *
 * The sound card is Exynos9110-Sound (card 0): the ABOX DSP mixes RDMA PCM
 * streams and feeds the cod9005x codec over UAIF0; the codec drives the speaker.
 * One output, the speaker, on card 0 / device 0 (RDMA0) at 48 kHz, stereo,
 * 16 bit. One input, the digital mic (DMIC1 on the codec), on card 0 / device 9
 * (WDMA1: codec -> UAIF0 -> NSRC0 -> SIFM0 -> WDMA1) at 48 kHz; the codec puts
 * the one mic on both channels, so mono is the left channel. Each route
 * (tools/audio/README.md) is set when its PCM is opened, and the speaker amp /
 * DMIC are switched off again when the stream goes to standby.
 *
 * Loaded by android.hardware.audio@2.0-impl (hw_get_module_by_class("audio",
 * "primary"), ro.hardware.audio.primary=r800). Device API 2.0: the framework
 * does routing and patches in software. tinyalsa 2.0.0 is linked in statically.
 *
 * The ABOX firmware only boots ~16 s after power-on, after this HAL starts, so
 * nothing touches the card until the first write; if the PCM cannot be opened
 * yet, writes sleep for the buffer's duration and the open is retried later
 * (reads return silence the same way).
 *
 * tinyalsa must carry tools/audio/tinyalsa-2.0.0-sync-ptr.patch: unpatched,
 * every pcm_readi/pcm_writei in a 32-bit process rewinds the kernel's appl_ptr.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <math.h>
#include <pthread.h>
#include <stdint.h>
#include <limits.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <android/log.h>
#include <sys/system_properties.h>
#include <hardware/audio.h>
#include <hardware/hardware.h>
#include <tinyalsa/asoundlib.h>

#define LOG_TAG "audio-r800"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

#define CARD 0
#define SPK_DEVICE 0           /* RDMA0 */
#define OUT_RATE 48000
#define OUT_CHANNELS 2
#define OUT_PERIOD 960         /* 20 ms */
#define OUT_PERIODS 4
#define FRAME_BYTES (OUT_CHANNELS * 2)
#define RETRY_NS 1000000000LL  /* wait this long between failed PCM opens */

#define MIC_DEVICE 9           /* WDMA1 */
#define IN_RATE 48000
#define IN_HW_CHANNELS 2
#define IN_PERIOD 960          /* 20 ms */
#define IN_PERIODS 8

struct mix_setting {
    const char *name;
    const char *str;           /* enum value, or NULL to set the integer */
    int val;
};

/* RDMA0 -> SPUS IN0 -> SIFS0 -> UAIF0 -> cod9005x speaker */
static const struct mix_setting spk_on[] = {
    { "ABOX SPUS IN0", "RDMA", 0 },
    { "ABOX SPUS OUT0", "SIFS0", 0 },
    { "ABOX UAIF0 SPK", "SIFS0", 0 },
    { "Codec Enable", NULL, 1 },
    { "SPK SPK On", NULL, 1 },
    { "DAC Soft Mute", NULL, 0 },
};
static const struct mix_setting spk_off[] = {
    { "SPK SPK On", NULL, 0 },
};

/* cod9005x DMIC1 -> UAIF0 -> NSRC0 -> SIFM0 -> WDMA1 (Tizen's media-mic path,
 * plus the codec's DAPM switch "DMIC1 On" that powers its capture path) */
static const struct mix_setting mic_on[] = {
    { "ABOX UAIF0 width", NULL, 16 },
    { "ABOX UAIF0 channel", NULL, 2 },
    { "ABOX UAIF0 rate", NULL, 48000 },
    { "ABOX SPUM ASRC1", "On", 0 },
    { "ABOX RECP PIFS0", NULL, 1 },
    { "ABOX SIFM0", "WDMA", 0 },
    { "ABOX NSRC0", "UAIF0", 0 },
    { "Codec Enable", NULL, 1 },
    { "DMIC Bias", NULL, 1 },
    { "DMIC1 Switch", NULL, 1 },
    { "DMIC1 DMIC1 On", NULL, 1 },
    { "ADC Digital Mute", NULL, 0 },
};
/* The mic sits behind a small port and is very quiet: with Tizen's settings
 * (ADC gain 180, DMIC volume 1) loud speech close to the watch peaks around
 * -50 dBFS. Defaults here add ~35 dB; tunable without a rebuild through
 * vendor.audio.r800.adc_gain (0-234, ~0.5 dB steps) and
 * vendor.audio.r800.dmic_vol (1-7; 0 = no data). */
#define DEFAULT_ADC_GAIN 234
#define DEFAULT_DMIC_VOL 3

static int prop_int(const char *name, int def, int lo, int hi)
{
    char v[PROP_VALUE_MAX];
    if (__system_property_get(name, v) <= 0)
        return def;
    int x = atoi(v);
    return x < lo ? lo : x > hi ? hi : x;
}

static const struct mix_setting mic_off[] = {
    { "DMIC1 DMIC1 On", NULL, 0 },
    { "DMIC1 Switch", NULL, 0 },
};

struct r800_audio_device {
    struct audio_hw_device dev;   /* first: the framework casts back to this */
    pthread_mutex_t lock;
    _Atomic bool mic_mute;
    audio_mode_t mode;
    struct r800_stream_out *out;
    struct r800_stream_in *in;
    /* Bluetooth hands-free call audio (see the HFP section) */
    _Atomic bool hfp_active;     /* the bridge owns the speaker, mic and UAIF1 */
    volatile bool hfp_run;
    int hfp_rate;                 /* SCO rate: 8000 (CVSD) or 16000 (mSBC) */
    volatile int hfp_volume;      /* 0..15 from the HFP client */
    volatile int64_t hfp_dl_loud_ns; /* last time the phone's audio was loud */
    pthread_t hfp_dl, hfp_ul;
    struct pcm *hfp_pcm[4];
};

struct r800_stream_out {
    struct audio_stream_out stream;
    struct r800_audio_device *adev;
    pthread_mutex_t lock;
    struct pcm *pcm;
    bool standby;
    uint64_t written;             /* frames written since the stream was opened */
    int64_t next_open_ns;         /* do not retry pcm_open before this */
    audio_devices_t devices;
};

struct r800_stream_in {
    struct audio_stream_in stream;
    struct r800_audio_device *adev;
    pthread_mutex_t lock;
    struct pcm *pcm;
    bool standby;
    unsigned int channels;        /* to the framework: 1 or 2 */
    audio_channel_mask_t channel_mask;
    uint64_t frames_read;
    uint64_t start_frames;        /* frames_read at the last start */
    int peak;
    int64_t next_open_ns;
    audio_devices_t devices;
    int16_t hwbuf[IN_PERIOD * IN_HW_CHANNELS];
};

static int64_t now_ns(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000000000LL + t.tv_nsec;
}

static int apply_mixer(const struct mix_setting *s, size_t n)
{
    int status = 0;
    struct mixer *m = mixer_open(CARD);
    if (!m) {
        LOGE("mixer_open(%d) failed", CARD);
        return -EIO;
    }
    for (size_t i = 0; i < n; i++) {
        struct mixer_ctl *c = mixer_get_ctl_by_name(m, s[i].name);
        int r;
        if (!c) {
            LOGE("no mixer control '%s'", s[i].name);
            status = -EIO;
            continue;
        }
        if (s[i].str)
            r = mixer_ctl_set_enum_by_string(c, s[i].str);
        else {
            r = 0;
            for (unsigned k = 0; k < mixer_ctl_get_num_values(c) && !r; k++)
                r = mixer_ctl_set_value(c, k, s[i].val);
        }
        if (r) {
            LOGE("set '%s' failed: %d", s[i].name, r);
            status = -EIO;
        }
    }
    mixer_close(m);
    return status;
}

/* ---- output stream ---- */

static uint32_t out_get_sample_rate(const struct audio_stream *s) { (void)s; return OUT_RATE; }
static int out_set_sample_rate(struct audio_stream *s, uint32_t r) { (void)s; return r == OUT_RATE ? 0 : -ENOSYS; }
static size_t out_get_buffer_size(const struct audio_stream *s) { (void)s; return OUT_PERIOD * FRAME_BYTES; }
static audio_channel_mask_t out_get_channels(const struct audio_stream *s) { (void)s; return AUDIO_CHANNEL_OUT_STEREO; }
static audio_format_t out_get_format(const struct audio_stream *s) { (void)s; return AUDIO_FORMAT_PCM_16_BIT; }
static int out_set_format(struct audio_stream *s, audio_format_t f) { (void)s; return f == AUDIO_FORMAT_PCM_16_BIT ? 0 : -ENOSYS; }
static int out_dump(const struct audio_stream *s, int fd) { (void)s; (void)fd; return 0; }
static int out_add_audio_effect(const struct audio_stream *s, effect_handle_t e) { (void)s; (void)e; return 0; }
static int out_remove_audio_effect(const struct audio_stream *s, effect_handle_t e) { (void)s; (void)e; return 0; }
static uint32_t out_get_latency(const struct audio_stream_out *s) { (void)s; return OUT_PERIOD * OUT_PERIODS * 1000 / OUT_RATE; }
static int out_set_volume(struct audio_stream_out *s, float l, float r) { (void)s; (void)l; (void)r; return -ENOSYS; }
static int out_get_next_write_timestamp(const struct audio_stream_out *s, int64_t *t) { (void)s; (void)t; return -ENOSYS; }

static audio_devices_t out_get_device(const struct audio_stream *s)
{
    return ((const struct r800_stream_out *)s)->devices;
}

/* call with out->lock held */
static void do_standby(struct r800_stream_out *out)
{
    if (out->standby)
        return;
    if (out->pcm) {
        pcm_close(out->pcm);
        out->pcm = NULL;
    }
    if (!out->adev->hfp_active)   /* a call keeps the speaker on */
        apply_mixer(spk_off, sizeof(spk_off) / sizeof(spk_off[0]));
    out->standby = true;
}

static int out_standby(struct audio_stream *s)
{
    struct r800_stream_out *out = (struct r800_stream_out *)s;
    pthread_mutex_lock(&out->lock);
    do_standby(out);
    pthread_mutex_unlock(&out->lock);
    return 0;
}

static int out_set_parameters(struct audio_stream *s, const char *kv)
{
    (void)s;
    LOGI("out set_parameters '%s'", kv);
    return 0;
}

static char *out_get_parameters(const struct audio_stream *s, const char *keys)
{
    (void)s;
    (void)keys;
    return strdup("");
}

/* call with out->lock held; returns 0 when the PCM is running */
static int start_output(struct r800_stream_out *out)
{
    struct pcm_config cfg;
    int64_t t = now_ns();

    if (t < out->next_open_ns)
        return -EAGAIN;
    if (out->adev->hfp_active)
        return -EBUSY;
    memset(&cfg, 0, sizeof(cfg));
    cfg.channels = OUT_CHANNELS;
    cfg.rate = OUT_RATE;
    cfg.format = PCM_FORMAT_S16_LE;
    cfg.period_size = OUT_PERIOD;
    cfg.period_count = OUT_PERIODS;
    cfg.start_threshold = OUT_PERIOD;   /* start as soon as one period is queued */
    cfg.stop_threshold = OUT_PERIOD * OUT_PERIODS;

    if (apply_mixer(spk_on, sizeof(spk_on) / sizeof(spk_on[0])))
        goto fail;
    out->pcm = pcm_open(CARD, SPK_DEVICE, PCM_OUT | PCM_MONOTONIC, &cfg);
    if (!out->pcm || !pcm_is_ready(out->pcm)) {
        LOGE("pcm_open(%d,%d): %s (DSP firmware not booted yet?)", CARD, SPK_DEVICE,
             out->pcm ? pcm_get_error(out->pcm) : "no handle");
        goto fail;
    }
    out->standby = false;
    out->next_open_ns = 0;
    LOGI("speaker started");
    return 0;

fail:
    if (out->pcm)
        pcm_close(out->pcm);
    out->pcm = NULL;
    if (apply_mixer(spk_off, sizeof(spk_off) / sizeof(spk_off[0])))
        LOGW("speaker route rollback failed");
    out->standby = true;
    out->next_open_ns = now_ns() + RETRY_NS;
    return -EIO;
}

static ssize_t out_write(struct audio_stream_out *s, const void *buf, size_t bytes)
{
    struct r800_stream_out *out = (struct r800_stream_out *)s;
    size_t frames = bytes / FRAME_BYTES;
    int r = 0;
    if (bytes % FRAME_BYTES || frames > INT_MAX)
        return -EINVAL;
    if (!frames)
        return 0;

    pthread_mutex_lock(&out->lock);
    if (out->adev->hfp_active && out->pcm)
        do_standby(out);
    if (out->standby && !out->pcm)
        r = start_output(out);
    size_t done = 0;
    while (!r && done < frames) {
        size_t n = frames - done;
        if (n > OUT_PERIOD)
            n = OUT_PERIOD;
        int count = pcm_writei(out->pcm, (const char *)buf + done * FRAME_BYTES, n);
        if (count <= 0 || (size_t)count > n) {
            LOGE("pcm_writei made no valid progress: %d", count);
            do_standby(out);
            out->next_open_ns = now_ns() + RETRY_NS;
            r = -EIO;
            break;
        }
        done += (size_t)count;
    }
    out->written += done;
    pthread_mutex_unlock(&out->lock);

    /* no PCM: consume the data at the real rate so the mixer thread doesn't spin */
    if (r < 0)
        usleep((frames - done) * 1000000LL / OUT_RATE);
    return bytes;
}

static int out_get_render_position(const struct audio_stream_out *s, uint32_t *dsp_frames)
{
    (void)s;
    (void)dsp_frames;
    return -ENOSYS;
}

static int out_get_presentation_position(const struct audio_stream_out *s,
                                         uint64_t *frames, struct timespec *ts)
{
    struct r800_stream_out *out = (struct r800_stream_out *)s;
    int ret = -ENODATA;

    pthread_mutex_lock(&out->lock);
    if (out->pcm) {
        unsigned int avail;
        if (!pcm_get_htimestamp(out->pcm, &avail, ts)) {
            unsigned int capacity = pcm_get_buffer_size(out->pcm);
            uint64_t queued = avail <= capacity ? capacity - avail : UINT64_MAX;
            if (queued <= out->written) {
                *frames = out->written - queued;
                ret = 0;
            }
        }
    }
    pthread_mutex_unlock(&out->lock);
    return ret;
}

/* ---- input stream ---- */

static uint32_t in_get_sample_rate(const struct audio_stream *s) { (void)s; return IN_RATE; }
static int in_set_sample_rate(struct audio_stream *s, uint32_t r) { (void)s; return r == IN_RATE ? 0 : -ENOSYS; }
static audio_format_t in_get_format(const struct audio_stream *s) { (void)s; return AUDIO_FORMAT_PCM_16_BIT; }
static int in_set_format(struct audio_stream *s, audio_format_t f) { (void)s; return f == AUDIO_FORMAT_PCM_16_BIT ? 0 : -ENOSYS; }
static int in_dump(const struct audio_stream *s, int fd) { (void)s; (void)fd; return 0; }
static int in_add_audio_effect(const struct audio_stream *s, effect_handle_t e) { (void)s; (void)e; return 0; }
static int in_remove_audio_effect(const struct audio_stream *s, effect_handle_t e) { (void)s; (void)e; return 0; }
static int in_set_gain(struct audio_stream_in *s, float g) { (void)s; (void)g; return 0; }
static uint32_t in_get_input_frames_lost(struct audio_stream_in *s) { (void)s; return 0; }

static size_t in_get_buffer_size(const struct audio_stream *s)
{
    const struct r800_stream_in *in = (const struct r800_stream_in *)s;
    return IN_PERIOD * in->channels * 2;
}

static audio_channel_mask_t in_get_channels(const struct audio_stream *s)
{
    return ((const struct r800_stream_in *)s)->channel_mask;
}

static audio_devices_t in_get_device(const struct audio_stream *s)
{
    return ((const struct r800_stream_in *)s)->devices;
}

static int in_set_parameters(struct audio_stream *s, const char *kv)
{
    (void)s;
    LOGI("in set_parameters '%s'", kv);
    return 0;
}

static char *in_get_parameters(const struct audio_stream *s, const char *keys)
{
    (void)s;
    (void)keys;
    return strdup("");
}

/* call with in->lock held */
static void in_do_standby(struct r800_stream_in *in)
{
    if (in->standby)
        return;
    if (in->pcm) {
        pcm_close(in->pcm);
        in->pcm = NULL;
    }
    if (!in->adev->hfp_active)    /* a call keeps the mic on */
        apply_mixer(mic_off, sizeof(mic_off) / sizeof(mic_off[0]));
    in->standby = true;
}

static int in_standby(struct audio_stream *s)
{
    struct r800_stream_in *in = (struct r800_stream_in *)s;
    pthread_mutex_lock(&in->lock);
    in_do_standby(in);
    pthread_mutex_unlock(&in->lock);
    return 0;
}

/* call with in->lock held; returns 0 when the PCM is running */
static int start_input(struct r800_stream_in *in)
{
    struct pcm_config cfg;
    int64_t t = now_ns();

    if (t < in->next_open_ns)
        return -EAGAIN;
    if (in->adev->hfp_active)     /* WDMA1 belongs to the call: silence */
        return -EBUSY;
    memset(&cfg, 0, sizeof(cfg));
    cfg.channels = IN_HW_CHANNELS;
    cfg.rate = IN_RATE;
    cfg.format = PCM_FORMAT_S16_LE;
    cfg.period_size = IN_PERIOD;
    cfg.period_count = IN_PERIODS;

    int gain = prop_int("vendor.audio.r800.adc_gain", DEFAULT_ADC_GAIN, 0, 234);
    char vol[2] = { (char)('0' + prop_int("vendor.audio.r800.dmic_vol", DEFAULT_DMIC_VOL, 1, 7)), 0 };
    const struct mix_setting mic_gain[] = {
        { "ADC Left Gain", NULL, gain },
        { "ADC Right Gain", NULL, gain },
        { "DMIC1 Volume", vol, 0 },
    };
    if (apply_mixer(mic_on, sizeof(mic_on) / sizeof(mic_on[0])) ||
        apply_mixer(mic_gain, sizeof(mic_gain) / sizeof(mic_gain[0])))
        goto fail;
    in->pcm = pcm_open(CARD, MIC_DEVICE, PCM_IN | PCM_MONOTONIC, &cfg);
    if (!in->pcm || !pcm_is_ready(in->pcm)) {
        LOGE("pcm_open(%d,%d) in: %s", CARD, MIC_DEVICE,
             in->pcm ? pcm_get_error(in->pcm) : "no handle");
        goto fail;
    }
    in->standby = false;
    in->next_open_ns = 0;
    LOGI("mic started (%u ch, mic mute %d, adc gain %d, dmic vol %s)", in->channels,
         in->adev->mic_mute, gain, vol);
    in->start_frames = in->frames_read;
    in->peak = 0;
    return 0;

fail:
    if (in->pcm)
        pcm_close(in->pcm);
    in->pcm = NULL;
    if (apply_mixer(mic_off, sizeof(mic_off) / sizeof(mic_off[0])))
        LOGW("mic route rollback failed");
    in->standby = true;
    in->next_open_ns = now_ns() + RETRY_NS;
    return -EIO;
}

static ssize_t in_read(struct audio_stream_in *s, void *buf, size_t bytes)
{
    struct r800_stream_in *in = (struct r800_stream_in *)s;
    size_t frames = bytes / (in->channels * 2);
    int16_t *dst = buf;
    size_t done = 0;
    int r = 0;
    bool mute;
    if (bytes % (in->channels * 2) || frames > INT_MAX)
        return -EINVAL;
    if (!frames)
        return 0;

    pthread_mutex_lock(&in->lock);
    if (in->adev->hfp_active && in->pcm)
        in_do_standby(in);        /* hand WDMA1 to the call bridge */
    if (in->standby && !in->pcm)
        r = start_input(in);
    while (!r && done < frames) {
        size_t n = frames - done;
        if (n > IN_PERIOD)
            n = IN_PERIOD;
        if (in->channels == IN_HW_CHANNELS) {
            r = pcm_readi(in->pcm, dst + done * IN_HW_CHANNELS, n);
        } else {
            r = pcm_readi(in->pcm, in->hwbuf, n);
            for (int i = 0; r > 0 && (size_t)r <= n && i < r; i++)
                dst[done + i] = in->hwbuf[i * IN_HW_CHANNELS];   /* left = DMIC1 */
        }
        if (r <= 0 || (size_t)r > n) {
            LOGE("pcm_readi made no valid progress: %d", r);
            r = -EIO;
            in_do_standby(in);
            in->next_open_ns = now_ns() + RETRY_NS;
            break;
        }
        done += r;
        r = 0;
    }
    /* report the level of the first second after each start (debugging aid) */
    if (in->frames_read - in->start_frames < IN_RATE) {
        for (size_t i = 0; i < done * in->channels; i++) {
            int v = dst[i] < 0 ? -dst[i] : dst[i];
            if (v > in->peak)
                in->peak = v;
        }
        if (in->frames_read + frames - in->start_frames >= IN_RATE)
            LOGI("mic first second: peak %d", in->peak);
    }
    in->frames_read += frames;
    mute = in->adev->mic_mute;
    pthread_mutex_unlock(&in->lock);

    if (done < frames)
        memset(dst + done * in->channels, 0, (frames - done) * in->channels * 2);
    if (mute)
        memset(buf, 0, bytes);
    /* no PCM: deliver silence at the real rate so the record thread doesn't spin */
    if (r < 0)
        usleep((frames - done) * 1000000LL / IN_RATE);
    return bytes;
}

static int in_get_capture_position(const struct audio_stream_in *s, int64_t *frames,
                                   int64_t *time)
{
    struct r800_stream_in *in = (struct r800_stream_in *)s;
    int ret = -ENOSYS;

    pthread_mutex_lock(&in->lock);
    if (in->pcm) {
        unsigned int avail;
        struct timespec ts;
        if (!pcm_get_htimestamp(in->pcm, &avail, &ts)) {
            *frames = in->frames_read + avail;
            *time = ts.tv_sec * 1000000000LL + ts.tv_nsec;
            ret = 0;
        }
    }
    pthread_mutex_unlock(&in->lock);
    return ret;
}

/* ---- Bluetooth hands-free call audio (HFP client) ----
 *
 * Calls go through the phone; the watch is its hands-free unit. When the SCO
 * link comes up, Android's HFP client (com.android.bluetooth
 * HeadsetClientStateMachine) sets "hfp_set_sampling_rate=8000|16000",
 * "hfp_enable=true" and "hfp_volume=0..15"; "hfp_enable=false" when it drops.
 *
 * The BCM43012's I2S lines go to ABOX UAIF1 (DSP is clock master, 16 bit
 * stereo frames at the SCO rate; the BT chip is the I2S slave). The call audio
 * itself never passes through the AP: like Tizen's libtizen-audio
 * (_voice_bt_pcm_open, "Companion Call case"), the HAL puts the DSP in call
 * mode (Audio Mode IN_CALL, Sound Type BTVOICE, the speech-enhancement mode of
 * mixer_paths.xml "abox-se-mode-*"), applies Tizen's "hfp-speaker" and
 * "hfp-main-mic-wb-sco-*" routes, and opens and *starts* four PCMs without ever
 * reading or writing them: RDMA6 (pcm 6), WDMA0 (8), WDMA2 (10), RDMA4 (4).
 * Those are the DSP's call/realtime DMAs; in call mode its firmware moves the
 * audio itself (phone -> UAIF1 -> speaker, mic -> echo cancel -> UAIF1), so
 * reading them from the AP only ever times out.
 * Speaker gain vendor.audio.r800.call_dac (DAC Gain, Tizen: 164).
 */
#define MEDIA_DAC_GAIN 130  /* the codec's value outside calls */

static const struct {
    int dev;
    unsigned int flags;
} hfp_streams[] = {
    { 6, PCM_OUT },   /* RDMA6 -> SIFS2 -> UAIF1: to the phone */
    { 8, PCM_IN },    /* WDMA0 */
    { 10, PCM_IN },   /* WDMA2 <- NSRC1 <- UAIF1: from the phone */
    { 4, PCM_OUT },   /* RDMA4 -> SIFS0 -> UAIF0: speaker */
};
#define HFP_N_STREAMS (sizeof(hfp_streams) / sizeof(hfp_streams[0]))
static void hfp_stop(struct r800_audio_device *adev);

/* call with adev->lock held */
static int hfp_start(struct r800_audio_device *adev)
{
    if (adev->hfp_active)
        return 0;
    bool wb = adev->hfp_rate == 16000;
    int rate = wb ? 16000 : 8000;
    int dac = prop_int("vendor.audio.r800.call_dac", 164, 0, 234);
    int gain = prop_int("vendor.audio.r800.call_adc_gain", 180, 0, 234);
    const struct mix_setting route[] = {
        { "ABOX Audio Mode", "IN_CALL", 0 },
        { "ABOX Sound Type", "BTVOICE", 0 },
        /* Tizen's boot defaults for the record path (WDMA0): RSRC0 = SIFS0,
           RECP -> PIFS0, rate floor 8 kHz; without them WDMA0 won't prepare */
        { "ABOX RSRC0", "SIFS0", 0 },
        { "ABOX RECP PIFS0", NULL, 1 },
        { "ABOX Sampling Rate Recp Min", NULL, 8000 },
        /* hfp-speaker */
        { "ABOX SPUS IN4", "RDMA", 0 },
        { "ABOX SPUS OUT4", "SIFS0", 0 },
        { "ABOX UAIF0 SPK", "SIFS0", 0 },
        { "ABOX NSRC2", "SIFS0", 0 },
        { "ABOX SIFM2", "WDMA", 0 },
        { "ABOX SPUS IN6", "RDMA", 0 },
        { "ABOX SPUS OUT6", "SIFS2", 0 },
        { "ABOX SIFS2", "SPUS OUT6", 0 },
        { "ABOX UAIF1 SPK", "SIFS2", 0 },
        { "Codec Enable", NULL, 1 },
        { "SPK SPK On", NULL, 1 },
        { "DAC Soft Mute", NULL, 0 },
        { "DAC Gain", NULL, dac },
        /* hfp-main-mic: media-mic + UAIF1 -> NSRC1 -> WDMA2 */
        { "ABOX UAIF0 width", NULL, 16 },
        { "ABOX UAIF0 channel", NULL, 2 },
        { "ABOX UAIF0 rate", NULL, 48000 },
        { "ABOX NSRC0", "UAIF0", 0 },
        { "ABOX SIFM0", "WDMA", 0 },
        { "DMIC Bias", NULL, 1 },
        { "DMIC1 Switch", NULL, 1 },
        { "DMIC1 DMIC1 On", NULL, 1 },
        { "ADC Digital Mute", NULL, 0 },
        { "ADC Left Gain", NULL, gain },
        { "ADC Right Gain", NULL, gain },
        { "ABOX NSRC1", "UAIF1", 0 },
        { "ABOX SIFM1", "WDMA", 0 },
        /* set-bt-sco-rate-* */
        { "ABOX UAIF1 width", NULL, 16 },
        { "ABOX UAIF1 channel", NULL, 2 },
        { "ABOX UAIF1 rate", NULL, rate },
        /* abox-se-mode-wb-8k / -16k */
        { "ABOX Speech Update Flag", NULL, 1 },
        { "ABOX PCM ext VPCMIN ON", NULL, 2 },
        { "ABOX PCM ext VPCMOUT ON", NULL, 2 },
        { "ABOX PCM ext APCALL BUFFTYPE", NULL, 1 },
        { "ABOX OEM AP Call BW", NULL, 0x101 },
        { "ABOX OEM AP Call type", NULL, wb ? 3 : 2 },
        { "ABOX OEM SV Mode", NULL, 1 },
        { "ABOX Speech Param", NULL, wb ? 3 : 2 },
        /* m_asrc2_inmux1_*_to_48k, s_asrc6_out2_48k_to_* */
        { "ABOX Sampling Rate Inmux1 Min", NULL, rate },
        { "ABOX SPUM ASRC2", "On", 0 },
        { "ABOX Sampling Rate Out2 Min", NULL, rate },
        { "ABOX SPUS ASRC6", "On", 0 },
    };
    struct pcm_config cfg;

    /* Device lock is held: take stream locks in a fixed order. The media
     * paths never acquire the device lock while holding a stream lock. */
    if (adev->out)
        pthread_mutex_lock(&adev->out->lock);
    if (adev->in)
        pthread_mutex_lock(&adev->in->lock);
    if (adev->out)
        do_standby(adev->out);
    if (adev->in)
        in_do_standby(adev->in);
    adev->hfp_active = true;   /* reserve routing until start or rollback */
    if (apply_mixer(route, sizeof(route) / sizeof(route[0])))
        goto fail;

    /* Tizen's pcm_config_bt_companion_call_*: 48 kHz stereo, 960 x 4,
       started right away and never stopped on underrun */
    memset(&cfg, 0, sizeof(cfg));
    cfg.channels = 2;
    cfg.rate = 48000;
    cfg.format = PCM_FORMAT_S16_LE;
    cfg.period_size = 960;
    cfg.period_count = 4;
    cfg.start_threshold = 960;
    cfg.stop_threshold = 0xffffffff;
    for (size_t i = 0; i < HFP_N_STREAMS; i++) {
        struct pcm *p = pcm_open(CARD, hfp_streams[i].dev, hfp_streams[i].flags, &cfg);
        if (!p || !pcm_is_ready(p)) {
            LOGE("hfp: pcm_open(%d): %s", hfp_streams[i].dev,
                 p ? pcm_get_error(p) : "no handle");
            if (p)
                pcm_close(p);
            goto fail;
        }
        if (pcm_prepare(p) < 0 || pcm_start(p) < 0) {
            LOGE("hfp: pcm_start(%d): %s", hfp_streams[i].dev, pcm_get_error(p));
            pcm_close(p);
            goto fail;
        }
        adev->hfp_pcm[i] = p;
    }
    if (adev->in)
        pthread_mutex_unlock(&adev->in->lock);
    if (adev->out)
        pthread_mutex_unlock(&adev->out->lock);
    LOGI("hfp: call audio on (DSP call mode), SCO %d Hz, volume %d, DAC %d", rate,
         adev->hfp_volume, dac);
    return 0;

fail:
    /* No partial HFP session may retain the route or PCM handles. */
    if (adev->in)
        pthread_mutex_unlock(&adev->in->lock);
    if (adev->out)
        pthread_mutex_unlock(&adev->out->lock);
    hfp_stop(adev);
    return -EIO;
}

/* call with adev->lock held */
static void hfp_stop(struct r800_audio_device *adev)
{
    if (!adev->hfp_active)
        return;
    if (adev->out)
        pthread_mutex_lock(&adev->out->lock);
    if (adev->in)
        pthread_mutex_lock(&adev->in->lock);
    for (int i = HFP_N_STREAMS - 1; i >= 0; i--) {
        if (adev->hfp_pcm[i]) {
            pcm_stop(adev->hfp_pcm[i]);
            pcm_close(adev->hfp_pcm[i]);
            adev->hfp_pcm[i] = NULL;
        }
    }
    const struct mix_setting route_off[] = {
        { "ABOX Speech Update Flag", NULL, 0 },
        { "ABOX PCM ext VPCMIN ON", NULL, 0 },
        { "ABOX PCM ext VPCMOUT ON", NULL, 0 },
        { "ABOX PCM ext APCALL BUFFTYPE", NULL, 0 },
        { "ABOX OEM SV Mode", NULL, 0 },
        { "ABOX Audio Mode", "NORMAL", 0 },
        { "ABOX Sound Type", "VOICE", 0 },
        { "ABOX UAIF1 SPK", "RESERVED", 0 },
        { "ABOX NSRC1", "RESERVED", 0 },
        { "ABOX NSRC2", "RESERVED", 0 },
        { "ABOX Sampling Rate Inmux1 Min", NULL, 48000 },
        { "ABOX Sampling Rate Out2 Min", NULL, 48000 },
        { "DAC Gain", NULL, MEDIA_DAC_GAIN },
    };
    apply_mixer(route_off, sizeof(route_off) / sizeof(route_off[0]));
    adev->hfp_active = false;
    if (!adev->out || adev->out->standby)
        apply_mixer(spk_off, sizeof(spk_off) / sizeof(spk_off[0]));
    if (!adev->in || adev->in->standby)
        apply_mixer(mic_off, sizeof(mic_off) / sizeof(mic_off[0]));
    if (adev->in)
        pthread_mutex_unlock(&adev->in->lock);
    if (adev->out)
        pthread_mutex_unlock(&adev->out->lock);
    LOGI("hfp: call audio off");
}

/* value of "key=" in a "k=v;k=v" list, or NULL */
static const char *kv_get(const char *kv, const char *key, char *val, size_t len)
{
    size_t kl = strlen(key);
    for (const char *p = kv; p && *p; ) {
        if (!strncmp(p, key, kl) && p[kl] == '=') {
            const char *v = p + kl + 1, *e = strchr(v, ';');
            size_t n = e ? (size_t)(e - v) : strlen(v);
            if (!len || n >= len)
                return NULL;
            memcpy(val, v, n);
            val[n] = 0;
            return val;
        }
        p = strchr(p, ';');
        if (p)
            p++;
    }
    return NULL;
}

/* ---- device ---- */

static int adev_open_output_stream(struct audio_hw_device *dev, audio_io_handle_t handle,
                                   audio_devices_t devices, audio_output_flags_t flags,
                                   struct audio_config *config,
                                   struct audio_stream_out **stream_out, const char *address)
{
    struct r800_audio_device *adev = (struct r800_audio_device *)dev;
    struct r800_stream_out *out;
    (void)handle;
    (void)address;

    LOGI("open_output_stream devices 0x%x flags 0x%x rate %u ch 0x%x fmt 0x%x", devices,
         flags, config->sample_rate, config->channel_mask, config->format);
    *stream_out = NULL;
    if (config->sample_rate != OUT_RATE || config->channel_mask != AUDIO_CHANNEL_OUT_STEREO ||
        config->format != AUDIO_FORMAT_PCM_16_BIT) {
        /* tell the framework what we support; it retries with these */
        config->sample_rate = OUT_RATE;
        config->channel_mask = AUDIO_CHANNEL_OUT_STEREO;
        config->format = AUDIO_FORMAT_PCM_16_BIT;
        return -EINVAL;
    }
    pthread_mutex_lock(&adev->lock);
    if (adev->out) {
        pthread_mutex_unlock(&adev->lock);
        LOGE("only one output stream");
        return -ENOSYS;
    }
    out = calloc(1, sizeof(*out));
    if (!out) {
        pthread_mutex_unlock(&adev->lock);
        return -ENOMEM;
    }
    out->stream.common.get_sample_rate = out_get_sample_rate;
    out->stream.common.set_sample_rate = out_set_sample_rate;
    out->stream.common.get_buffer_size = out_get_buffer_size;
    out->stream.common.get_channels = out_get_channels;
    out->stream.common.get_format = out_get_format;
    out->stream.common.set_format = out_set_format;
    out->stream.common.standby = out_standby;
    out->stream.common.dump = out_dump;
    out->stream.common.get_device = out_get_device;
    out->stream.common.set_parameters = out_set_parameters;
    out->stream.common.get_parameters = out_get_parameters;
    out->stream.common.add_audio_effect = out_add_audio_effect;
    out->stream.common.remove_audio_effect = out_remove_audio_effect;
    out->stream.get_latency = out_get_latency;
    out->stream.set_volume = out_set_volume;
    out->stream.write = out_write;
    out->stream.get_render_position = out_get_render_position;
    out->stream.get_next_write_timestamp = out_get_next_write_timestamp;
    out->stream.get_presentation_position = out_get_presentation_position;
    pthread_mutex_init(&out->lock, NULL);
    out->adev = adev;
    out->standby = true;
    out->devices = devices;
    adev->out = out;
    pthread_mutex_unlock(&adev->lock);
    *stream_out = &out->stream;
    return 0;
}

static void adev_close_output_stream(struct audio_hw_device *dev, struct audio_stream_out *s)
{
    struct r800_audio_device *adev = (struct r800_audio_device *)dev;
    struct r800_stream_out *out = (struct r800_stream_out *)s;

    out_standby(&s->common);
    pthread_mutex_lock(&adev->lock);
    if (adev->out == out)
        adev->out = NULL;
    pthread_mutex_unlock(&adev->lock);
    pthread_mutex_destroy(&out->lock);
    free(out);
}

static int adev_open_input_stream(struct audio_hw_device *dev, audio_io_handle_t handle,
                                  audio_devices_t devices, struct audio_config *config,
                                  struct audio_stream_in **stream_in, audio_input_flags_t flags,
                                  const char *address, audio_source_t source)
{
    struct r800_audio_device *adev = (struct r800_audio_device *)dev;
    struct r800_stream_in *in;
    (void)handle;
    (void)address;

    LOGI("open_input_stream devices 0x%x flags 0x%x source %d rate %u ch 0x%x fmt 0x%x",
         devices, flags, source, config->sample_rate, config->channel_mask, config->format);
    *stream_in = NULL;
    if (config->sample_rate != IN_RATE || config->format != AUDIO_FORMAT_PCM_16_BIT ||
        (config->channel_mask != AUDIO_CHANNEL_IN_MONO &&
         config->channel_mask != AUDIO_CHANNEL_IN_STEREO)) {
        /* tell the framework what we support; it retries with these */
        config->sample_rate = IN_RATE;
        config->format = AUDIO_FORMAT_PCM_16_BIT;
        if (config->channel_mask != AUDIO_CHANNEL_IN_STEREO)
            config->channel_mask = AUDIO_CHANNEL_IN_MONO;
        return -EINVAL;
    }
    pthread_mutex_lock(&adev->lock);
    if (adev->in) {
        pthread_mutex_unlock(&adev->lock);
        LOGE("only one input stream");
        return -ENOSYS;
    }
    in = calloc(1, sizeof(*in));
    if (!in) {
        pthread_mutex_unlock(&adev->lock);
        return -ENOMEM;
    }
    in->stream.common.get_sample_rate = in_get_sample_rate;
    in->stream.common.set_sample_rate = in_set_sample_rate;
    in->stream.common.get_buffer_size = in_get_buffer_size;
    in->stream.common.get_channels = in_get_channels;
    in->stream.common.get_format = in_get_format;
    in->stream.common.set_format = in_set_format;
    in->stream.common.standby = in_standby;
    in->stream.common.dump = in_dump;
    in->stream.common.get_device = in_get_device;
    in->stream.common.set_parameters = in_set_parameters;
    in->stream.common.get_parameters = in_get_parameters;
    in->stream.common.add_audio_effect = in_add_audio_effect;
    in->stream.common.remove_audio_effect = in_remove_audio_effect;
    in->stream.set_gain = in_set_gain;
    in->stream.read = in_read;
    in->stream.get_input_frames_lost = in_get_input_frames_lost;
    in->stream.get_capture_position = in_get_capture_position;
    pthread_mutex_init(&in->lock, NULL);
    in->adev = adev;
    in->standby = true;
    in->channel_mask = config->channel_mask;
    in->channels = config->channel_mask == AUDIO_CHANNEL_IN_STEREO ? 2 : 1;
    in->devices = devices;
    adev->in = in;
    pthread_mutex_unlock(&adev->lock);
    *stream_in = &in->stream;
    return 0;
}

static void adev_close_input_stream(struct audio_hw_device *dev, struct audio_stream_in *s)
{
    struct r800_audio_device *adev = (struct r800_audio_device *)dev;
    struct r800_stream_in *in = (struct r800_stream_in *)s;

    in_standby(&s->common);
    pthread_mutex_lock(&adev->lock);
    if (adev->in == in)
        adev->in = NULL;
    pthread_mutex_unlock(&adev->lock);
    pthread_mutex_destroy(&in->lock);
    free(in);
}

static int adev_set_parameters(struct audio_hw_device *dev, const char *kv)
{
    struct r800_audio_device *adev = (struct r800_audio_device *)dev;
    char v[16];
    int ret = 0;

    LOGI("set_parameters '%s'", kv);
    pthread_mutex_lock(&adev->lock);
    if (kv_get(kv, "hfp_set_sampling_rate", v, sizeof(v))) {
        int rate = !strcmp(v, "8000") ? 8000 : !strcmp(v, "16000") ? 16000 : 0;
        if (!rate) {
            ret = -EINVAL;
            goto done;
        }
        if (rate != adev->hfp_rate) {
            adev->hfp_rate = rate;
            if (adev->hfp_active) {   /* codec renegotiated mid-call */
                hfp_stop(adev);
                ret = hfp_start(adev);
                if (ret)
                    goto done;
            }
        }
    }
    if (kv_get(kv, "hfp_volume", v, sizeof(v)))
        adev->hfp_volume = atoi(v);
    if (kv_get(kv, "hfp_enable", v, sizeof(v))) {
        if (!strcmp(v, "true"))
            ret = hfp_start(adev);
        else if (!strcmp(v, "false"))
            hfp_stop(adev);
        else
            ret = -EINVAL;
    }
done:
    pthread_mutex_unlock(&adev->lock);
    return ret;
}

static char *adev_get_parameters(const struct audio_hw_device *dev, const char *keys)
{
    (void)dev;
    (void)keys;
    return strdup("");
}

static int adev_init_check(const struct audio_hw_device *dev) { (void)dev; return 0; }
static int adev_set_voice_volume(struct audio_hw_device *dev, float v) { (void)dev; (void)v; return 0; }
static int adev_set_master_volume(struct audio_hw_device *dev, float v) { (void)dev; (void)v; return -ENOSYS; }
static int adev_get_master_volume(struct audio_hw_device *dev, float *v) { (void)dev; (void)v; return -ENOSYS; }
static int adev_dump(const audio_hw_device_t *dev, int fd) { (void)dev; (void)fd; return 0; }

static int adev_set_mode(struct audio_hw_device *dev, audio_mode_t mode)
{
    ((struct r800_audio_device *)dev)->mode = mode;
    return 0;
}

static int adev_set_mic_mute(struct audio_hw_device *dev, bool state)
{
    ((struct r800_audio_device *)dev)->mic_mute = state;
    return 0;
}

static int adev_get_mic_mute(const struct audio_hw_device *dev, bool *state)
{
    *state = ((const struct r800_audio_device *)dev)->mic_mute;
    return 0;
}

static size_t adev_get_input_buffer_size(const struct audio_hw_device *dev,
                                         const struct audio_config *config)
{
    (void)dev;
    if (config->sample_rate != IN_RATE || config->format != AUDIO_FORMAT_PCM_16_BIT)
        return 0;
    return IN_PERIOD * audio_channel_count_from_in_mask(config->channel_mask) * 2;
}

static int adev_close(hw_device_t *device)
{
    struct r800_audio_device *adev = (struct r800_audio_device *)device;
    pthread_mutex_lock(&adev->lock);
    hfp_stop(adev);
    pthread_mutex_unlock(&adev->lock);
    pthread_mutex_destroy(&adev->lock);
    free(adev);
    return 0;
}

static int adev_open(const hw_module_t *module, const char *name, hw_device_t **device)
{
    struct r800_audio_device *adev;

    if (strcmp(name, AUDIO_HARDWARE_INTERFACE))
        return -EINVAL;
    adev = calloc(1, sizeof(*adev));
    if (!adev)
        return -ENOMEM;
    pthread_mutex_init(&adev->lock, NULL);
    atomic_init(&adev->mic_mute, false);
    atomic_init(&adev->hfp_active, false);
    adev->hfp_rate = 8000;
    adev->hfp_volume = 11;
    adev->dev.common.tag = HARDWARE_DEVICE_TAG;
    adev->dev.common.version = AUDIO_DEVICE_API_VERSION_2_0;
    adev->dev.common.module = (struct hw_module_t *)module;
    adev->dev.common.close = adev_close;
    adev->dev.init_check = adev_init_check;
    adev->dev.set_voice_volume = adev_set_voice_volume;
    adev->dev.set_master_volume = adev_set_master_volume;
    adev->dev.get_master_volume = adev_get_master_volume;
    adev->dev.set_mode = adev_set_mode;
    adev->dev.set_mic_mute = adev_set_mic_mute;
    adev->dev.get_mic_mute = adev_get_mic_mute;
    adev->dev.set_parameters = adev_set_parameters;
    adev->dev.get_parameters = adev_get_parameters;
    adev->dev.get_input_buffer_size = adev_get_input_buffer_size;
    adev->dev.open_output_stream = adev_open_output_stream;
    adev->dev.close_output_stream = adev_close_output_stream;
    adev->dev.open_input_stream = adev_open_input_stream;
    adev->dev.close_input_stream = adev_close_input_stream;
    adev->dev.dump = adev_dump;
    *device = &adev->dev.common;
    LOGI("opened");
    return 0;
}

static struct hw_module_methods_t hal_module_methods = {
    .open = adev_open,
};

__attribute__((visibility("default")))
struct audio_module HAL_MODULE_INFO_SYM = {
    .common = {
        .tag = HARDWARE_MODULE_TAG,
        .module_api_version = AUDIO_MODULE_API_VERSION_0_1,
        .hal_api_version = HARDWARE_HAL_API_VERSION,
        .id = AUDIO_HARDWARE_MODULE_ID,
        .name = "SM-R800 audio HAL",
        .author = "r800-wearos",
        .methods = &hal_module_methods,
    },
};
