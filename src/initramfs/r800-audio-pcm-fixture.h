/* Test-only successful PCM operations, production HAL unchanged. */
static int audio_hfp_fixture(const hw_module_t *module,
                             unsigned int (*get)(unsigned int),
                             void (*fail)(unsigned int))
{
    hw_device_t *base=NULL;
    if (module->methods->open(module,AUDIO_HARDWARE_INTERFACE,&base) || !base)
        return 151;
    struct audio_hw_device *dev=(struct audio_hw_device *)base;
    struct audio_config oc={.sample_rate=48000,.channel_mask=AUDIO_CHANNEL_OUT_STEREO,
                            .format=AUDIO_FORMAT_PCM_16_BIT};
    struct audio_config ic={.sample_rate=48000,.channel_mask=AUDIO_CHANNEL_IN_MONO,
                            .format=AUDIO_FORMAT_PCM_16_BIT};
    struct audio_stream_out *out=NULL;
    struct audio_stream_in *in=NULL;
    if (dev->open_output_stream(dev,1,AUDIO_DEVICE_OUT_SPEAKER,0,&oc,&out,"") || !out ||
        dev->open_input_stream(dev,2,AUDIO_DEVICE_IN_BUILTIN_MIC,&ic,&in,0,"",AUDIO_SOURCE_MIC) || !in)
        return 152;
    int16_t playback[2000],capture[1000];
    for (int i=0;i<1000;++i) { playback[2*i]=i+1; playback[2*i+1]=-(i+1); }
    if (out->write(out,playback,sizeof(playback))!=(ssize_t)sizeof(playback) ||
        in->read(in,capture,sizeof(capture))!=(ssize_t)sizeof(capture) ||
        get(0)!=6 || get(1)!=4 || get(5)!=3000 || get(6)!=5000 || get(4))
        return 153;
    if (dev->set_parameters(dev,"hfp_set_sampling_rate=8000;hfp_enable=true") ||
        get(8)!=15 || get(14)!=15 || !get(9) || get(10)!=8000 ||
        get(11)!=4 || get(12)!=0 || get(0)!=10 || get(1)!=6 || get(4))
        return 154;
    if (dev->set_parameters(dev,"hfp_enable=true") || get(0)!=10)
        return 155;
    unsigned int writes=get(2),reads=get(3);
    memset(capture,0x55,sizeof(capture));
    if (out->write(out,playback,sizeof(playback))!=(ssize_t)sizeof(playback) ||
        in->read(in,capture,sizeof(capture))!=(ssize_t)sizeof(capture) ||
        get(2)!=writes || get(3)!=reads || get(0)!=10)
        return 156;
    for (int i=0;i<1000;++i) if (capture[i]) return 157;
    if (dev->set_parameters(dev,"hfp_set_sampling_rate=16000") ||
        get(8)!=15 || get(14)!=15 || !get(9) || get(10)!=16000 ||
        get(11)!=8 || get(12)!=4 || get(0)!=14 || get(1)!=10 || get(4))
        return 158;
    if (dev->set_parameters(dev,"hfp_enable=false") ||
        get(8) || get(14) || get(9) || get(12)!=8 || get(0)!=14 || get(1)!=14 ||
        dev->set_parameters(dev,"hfp_enable=false") || get(1)!=14 || get(4))
        return 159;
    if (out->write(out,playback,sizeof(playback))!=(ssize_t)sizeof(playback) ||
        in->read(in,capture,sizeof(capture))!=(ssize_t)sizeof(capture) ||
        get(0)!=16 || get(5)!=4000 || get(6)!=6000 || get(4))
        return 160;
    for (int i=0;i<1000;++i) if (capture[i]!=i+1) return 161;
    /* Fail third HFP start, leaving two started and one unstarted handle.
     * Verify all three are closed, active channels stopped in reverse order,
     * and the mixer is restored before media starts again. */
    fail(3);
    if (dev->set_parameters(dev,"hfp_enable=true")!=-EIO ||
        get(8) || get(14) || get(9) || get(0)!=19 || get(1)!=19 ||
        get(11)!=10 || get(12)!=10 || get(13)!=11 || get(4))
        return 162;
    if (out->write(out,playback,sizeof(playback))!=(ssize_t)sizeof(playback) ||
        in->read(in,capture,sizeof(capture))!=(ssize_t)sizeof(capture) ||
        get(0)!=21 || get(5)!=5000 || get(6)!=7000 || get(4))
        return 163;
    for (int i=0;i<1000;++i) if (capture[i]!=i+1) return 164;
    dev->close_output_stream(dev,out);
    dev->close_input_stream(dev,in);
    if (base->close(base) || get(0)!=21 || get(1)!=21 || get(8) || get(14) ||
        get(9) || get(4)) return 165;
    puts("HAL_AUDIO_HFP_PASS sco=8000,16000 starts=10 stops=10 rollback=1 media_resume=2");
    return 0;
}
static int audio_pcm_fixture(const hw_module_t *module)
{
    if (!missing("/dev/snd") || !missing("/sys/class/sound")) return 130;
    unsigned int (*get)(unsigned int)=dlsym(RTLD_DEFAULT,"r800_pcm_fixture_get");
    void (*fail)(unsigned int)=dlsym(RTLD_DEFAULT,"r800_pcm_fixture_fail");
    if (!get || !fail || get(0) || get(4)) return 131;
    hw_device_t *base=NULL;
    if (module->methods->open(module,AUDIO_HARDWARE_INTERFACE,&base) || !base ||
        base->tag!=HARDWARE_DEVICE_TAG || base->module!=module || !base->close)
        return 132;
    struct audio_hw_device *dev=(struct audio_hw_device *)base;
    struct audio_config oc={.sample_rate=48000,.channel_mask=AUDIO_CHANNEL_OUT_STEREO,
                            .format=AUDIO_FORMAT_PCM_16_BIT};
    struct audio_stream_out *out=NULL;
    if (dev->open_output_stream(dev,1,AUDIO_DEVICE_OUT_SPEAKER,0,&oc,&out,"") || !out)
        return 133;
    int16_t playback[2000];
    for (int i=0;i<1000;++i) { playback[2*i]=i+1; playback[2*i+1]=-(i+1); }
    if (out->write(out,playback,sizeof(playback))!=(ssize_t)sizeof(playback) ||
        get(5)!=1000 || get(2)<=2 || get(4)) return 134;
    uint64_t presented=0;
    struct timespec ts={0};
    if (out->get_presentation_position(out,&presented,&ts) ||
        presented!=984 || ts.tv_sec!=123 || ts.tv_nsec!=456) return 135;
    unsigned int old=get(0);
    fail(1);
    if (out->write(out,playback,sizeof(playback))!=(ssize_t)sizeof(playback) ||
        get(1)!=1 || get(5)!=1000 ||
        out->write(out,playback,sizeof(playback))!=(ssize_t)sizeof(playback) || get(0)!=old)
        return 136;
    usleep(1100000);
    if (out->write(out,playback,sizeof(playback))!=(ssize_t)sizeof(playback) ||
        get(5)!=2000 || get(0)!=old+1 || get(4)) return 137;
    dev->close_output_stream(dev,out);
    for (int stereo=0;stereo<2;++stereo) {
        struct audio_config ic={.sample_rate=48000,.channel_mask=stereo?AUDIO_CHANNEL_IN_STEREO:AUDIO_CHANNEL_IN_MONO,
                                .format=AUDIO_FORMAT_PCM_16_BIT};
        struct audio_stream_in *in=NULL;
        if (dev->open_input_stream(dev,2,AUDIO_DEVICE_IN_BUILTIN_MIC,&ic,&in,0,"",AUDIO_SOURCE_MIC) || !in)
            return 138;
        struct { int16_t samples[2000]; uint32_t guard; } buf;
        size_t bytes=1000u*(stereo?4u:2u);
        memset(&buf,0x55,sizeof(buf)); buf.guard=UINT32_C(0xabcd1234);
        if (in->read(in,buf.samples,bytes)!=(ssize_t)bytes || buf.guard!=UINT32_C(0xabcd1234))
            return 139;
        for (int i=0;i<1000;++i) {
            if (stereo) {
                if (buf.samples[2*i]!=i+1 || buf.samples[2*i+1]!=-(i+1)) return 140;
            } else if (buf.samples[i]!=i+1) return 141;
        }
        if (!stereo && buf.samples[1000]!=0x5555) return 142;
        int64_t frames=0,time=0;
        if (in->get_capture_position(in,&frames,&time) || frames!=1016 || time!=123000000456LL)
            return 143;
        if (dev->set_mic_mute(dev,true) || in->read(in,buf.samples,bytes)!=(ssize_t)bytes ||
            dev->set_mic_mute(dev,false)) return 144;
        for (size_t k=0;k<bytes/2;++k) if (buf.samples[k]) return 145;
        if (buf.guard!=UINT32_C(0xabcd1234)) return 146;
        fail(2);
        memset(buf.samples,0x55,bytes);
        if (in->read(in,buf.samples,bytes)!=(ssize_t)bytes) return 147;
        for (size_t k=0;k<bytes/2;++k) if (buf.samples[k]) return 148;
        old=get(0);
        if (in->read(in,buf.samples,bytes)!=(ssize_t)bytes || get(0)!=old) return 149;
        dev->close_input_stream(dev,in);
    }
    if (base->close(base) || get(0)!=4 || get(1)!=4 || get(4) ||
        get(5)!=2000 || get(6)!=4000 || get(3)<=8 || !get(7)) return 150;
    puts("HAL_AUDIO_PCM_PASS out_frames=2000 in_frames=4000 mono=1 stereo=1 mute=2 retry=1 opens=4 closes=4");
    return audio_hfp_fixture(module,get,fail);
}
