/* Test-only Audio HAL: real binary, deliberately absent ALSA hardware. */
static int audio_fixture(const hw_module_t *module)
{
    if (!missing("/dev/snd") || !missing("/sys/class/sound"))
        return 110;
    hw_device_t *base = NULL;
    if (module->methods->open(module, AUDIO_HARDWARE_INTERFACE, &base) ||
        !base || base->tag != HARDWARE_DEVICE_TAG || base->module != module ||
        base->version != AUDIO_DEVICE_API_VERSION_2_0 || !base->close)
        return 111;
    struct audio_hw_device *dev = (struct audio_hw_device *)base;
    if (!dev->init_check || dev->init_check(dev) || !dev->open_output_stream ||
        !dev->open_input_stream || !dev->close_output_stream ||
        !dev->close_input_stream || !dev->get_input_buffer_size ||
        !dev->set_mic_mute || !dev->get_mic_mute || !dev->set_parameters)
        return 112;
    int baseline = fd_count();
    if (baseline < 0) return 113;
    for (int i = 0; i < 8; ++i) {
        struct audio_config oc = { .sample_rate = 44100, .channel_mask = AUDIO_CHANNEL_OUT_MONO,
                                   .format = AUDIO_FORMAT_PCM_16_BIT };
        struct audio_stream_out *out = NULL;
        if (dev->open_output_stream(dev, 1, AUDIO_DEVICE_OUT_SPEAKER, 0, &oc, &out, "") != -EINVAL ||
            out || oc.sample_rate != 48000 || oc.channel_mask != AUDIO_CHANNEL_OUT_STEREO ||
            oc.format != AUDIO_FORMAT_PCM_16_BIT ||
            dev->open_output_stream(dev, 1, AUDIO_DEVICE_OUT_SPEAKER, 0, &oc, &out, "") || !out)
            return 114;
        struct audio_stream_out *duplicate = NULL;
        if (dev->open_output_stream(dev, 2, AUDIO_DEVICE_OUT_SPEAKER, 0, &oc, &duplicate, "") != -ENOSYS ||
            duplicate || out->common.get_sample_rate(&out->common) != 48000 ||
            out->common.get_channels(&out->common) != AUDIO_CHANNEL_OUT_STEREO ||
            out->common.get_format(&out->common) != AUDIO_FORMAT_PCM_16_BIT ||
            out->common.get_buffer_size(&out->common) != 3840 ||
            out->get_latency(out) != 80)
            return 115;
        struct audio_config ic = { .sample_rate = 16000, .channel_mask = AUDIO_CHANNEL_IN_MONO,
                                   .format = AUDIO_FORMAT_PCM_16_BIT };
        struct audio_stream_in *in = NULL;
        if (dev->open_input_stream(dev, 3, AUDIO_DEVICE_IN_BUILTIN_MIC, &ic, &in, 0, "", AUDIO_SOURCE_MIC) != -EINVAL ||
            in || ic.sample_rate != 48000 || ic.channel_mask != AUDIO_CHANNEL_IN_MONO ||
            ic.format != AUDIO_FORMAT_PCM_16_BIT)
            return 116;
        ic.channel_mask = i % 2 ? AUDIO_CHANNEL_IN_STEREO : AUDIO_CHANNEL_IN_MONO;
        size_t expected = i % 2 ? 3840 : 1920;
        if (dev->get_input_buffer_size(dev, &ic) != expected ||
            dev->open_input_stream(dev, 3, AUDIO_DEVICE_IN_BUILTIN_MIC, &ic, &in, 0, "", AUDIO_SOURCE_MIC) || !in ||
            in->common.get_sample_rate(&in->common) != 48000 ||
            in->common.get_channels(&in->common) != ic.channel_mask ||
            in->common.get_buffer_size(&in->common) != expected)
            return 117;
        struct audio_stream_in *dup_in = NULL;
        if (dev->open_input_stream(dev, 4, AUDIO_DEVICE_IN_BUILTIN_MIC, &ic, &dup_in, 0, "", AUDIO_SOURCE_MIC) != -ENOSYS ||
            dup_in || base->close(base) != -EBUSY)
            return 118;
        int16_t playback[96] = {0};
        struct { int16_t pcm[96]; uint32_t guard; } capture;
        memset(&capture, 0x55, sizeof(capture));
        capture.guard = UINT32_C(0x1234abcd);
        bool muted = false;
        if (out->write(out, playback, 1) != -EINVAL ||
            in->read(in, capture.pcm, 1) != -EINVAL ||
            out->write(out, playback, 0) != 0 ||
            in->read(in, capture.pcm, 0) != 0 ||
            dev->set_mic_mute(dev, i % 2 != 0) ||
            dev->get_mic_mute(dev, &muted) || muted != (i % 2 != 0))
            return 119;
        /* No /dev/snd: mixer_open fails; HAL consumes playback and
         * provides silence rather than reporting fabricated PCM progress. */
        for (int repeat = 0; repeat < 2; ++repeat) {
            memset(capture.pcm, 0x55, sizeof(capture.pcm));
            if (out->write(out, playback, sizeof(playback)) != (ssize_t)sizeof(playback) ||
                in->read(in, capture.pcm, sizeof(capture.pcm)) != (ssize_t)sizeof(capture.pcm) ||
                capture.guard != UINT32_C(0x1234abcd)) return 120;
            for (size_t k = 0; k < sizeof(capture.pcm)/sizeof(capture.pcm[0]); ++k)
                if (capture.pcm[k]) return 121;
        }
        uint64_t presented = 0;
        struct timespec ts = {0};
        int64_t frames = 0, time = 0;
        if (out->get_presentation_position(out, &presented, &ts) != -ENODATA ||
            in->get_capture_position(in, &frames, &time) != -ENOSYS ||
            out->common.standby(&out->common) || in->common.standby(&in->common))
            return 122;
        dev->close_output_stream(dev, out);
        dev->close_input_stream(dev, in);
        if (fd_count() != baseline) return 123;
    }
    if (dev->set_parameters(dev, "hfp_set_sampling_rate=44100") != -EINVAL ||
        dev->set_parameters(dev, "hfp_enable=invalid") != -EINVAL ||
        dev->set_parameters(dev, "hfp_set_sampling_rate=8000") ||
        dev->set_parameters(dev, "hfp_set_sampling_rate=16000") ||
        dev->set_parameters(dev, "hfp_enable=true") >= 0 ||
        dev->set_parameters(dev, "hfp_enable=false") ||
        base->close(base))
        return 124;
    puts("HAL_AUDIO_FIXTURE_PASS cycles=8 mono=4 stereo=4 silent_reads=16 missing_pcm=1 busy_close=8");
    return 0;
}
