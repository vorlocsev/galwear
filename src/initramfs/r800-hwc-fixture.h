/* Test-only HWC open, power transitions, present guards and timer VSync. */
#include <stdlib.h>
#include <hardware/gralloc.h>
static atomic_int hwc_ticks,hwc_bad;
static atomic_llong hwc_last;
static void hwc_fixture_vsync(const hwc_procs_t *procs,int disp,int64_t ts)
{
    (void)procs;
    int64_t prev=atomic_exchange(&hwc_last,ts);
    if (disp!=0 || ts<=0 || ts<=prev) atomic_store(&hwc_bad,1);
    atomic_fetch_add(&hwc_ticks,1);
}
static int hwc_wait_ticks(int target)
{
    for (int i=0;i<200;++i) {
        if (atomic_load(&hwc_bad)) return 0;
        if (atomic_load(&hwc_ticks)>=target) return 1;
        usleep(10000);
    }
    return 0;
}
/* Exercise the real prepare/set entry points with no usable target.
 * Pipes are synthetic pollable inputs, not kernel sync_file fences. The
 * caller checks unchanged framebuffer bytes before and after this test. */
static int hwc_present_guard(hwc_composer_device_1_t *dev)
{
    int before=fd_count();
    if (before<0 || !dev->prepare || !dev->set) return 0;
    hwc_display_contents_1_t *c=calloc(1,sizeof(*c)+sizeof(hwc_layer_1_t));
    if (!c) return 0;
    c->numHwLayers=1;
    hwc_display_contents_1_t *displays[]={c};
    hwc_layer_1_t *layer=&c->hwLayers[0];
    int p[2];
    if (pipe(p)) { free(c); return 0; }
    layer->compositionType=HWC_FRAMEBUFFER; /* missing final target */
    layer->acquireFenceFd=p[0];
    layer->releaseFenceFd=124;
    c->retireFenceFd=123;
    if (dev->prepare(dev,1,displays)!=-EINVAL ||
        dev->set(dev,1,displays)!=-EINVAL ||
        layer->acquireFenceFd!=p[0] || layer->releaseFenceFd!=124 ||
        c->retireFenceFd!=123 || fcntl(p[0],F_GETFD)<0) return 0;
    /* A readable pipe is accepted, but a NULL target cannot be presented. */
    layer->compositionType=HWC_FRAMEBUFFER_TARGET;
    layer->releaseFenceFd=c->retireFenceFd=-1;
    if (write(p[1],"x",1)!=1 || dev->prepare(dev,1,displays) ||
        dev->set(dev,1,displays) || layer->acquireFenceFd!=-1 ||
        layer->releaseFenceFd!=-1 || c->retireFenceFd!=-1 ||
        fcntl(p[0],F_GETFD)!=-1 || errno!=EBADF) return 0;
    if (close(p[1]) || pipe(p)) return 0;
    /* A hung-up pipe must be consumed without presenting. */
    layer->acquireFenceFd=p[0];
    if (close(p[1]) || dev->prepare(dev,1,displays) ||
        dev->set(dev,1,displays) || layer->acquireFenceFd!=-1 ||
        layer->releaseFenceFd!=-1 || c->retireFenceFd!=-1 ||
        fcntl(p[0],F_GETFD)!=-1 || errno!=EBADF) return 0;
    free(c);
    return fd_count()==before;
}

/* Compare every visible pixel; format 0 = zero, 1 = raw, 2 = R/B swapped. */
static int hwc_fb_matches(int first,int second)
{
    int fd=open("/dev/graphics/fb0",O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
    if (fd<0) return 0;
    unsigned char row[360*4];
    int ok=1;
    for (int half=0;ok && half<2;++half) {
        int fmt=half?second:first;
        for (int y=0;ok && y<360;++y) {
            if (pread(fd,row,sizeof(row),(off_t)(half*360+y)*sizeof(row))!=(ssize_t)sizeof(row)) { ok=0; break; }
            for (int x=0;x<360;++x) {
                unsigned char r=(unsigned char)x,g=(unsigned char)y,b=(unsigned char)(x+y);
                unsigned char want[4]={0,0,0,0};
                if (fmt) {
                    want[0]=fmt==1?r:b; want[1]=g; want[2]=fmt==1?b:r; want[3]=255;
                }
                if (memcmp(row+x*4,want,4)) { ok=0; break; }
            }
        }
    }
    return close(fd)==0 && ok;
}
static int hwc_cpu_present(hwc_composer_device_1_t *dev,int cycle)
{
    int before=fd_count();
    int fd=open("/dev/graphics/pixels",O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
    struct stat s;
    if (before<0 || fd<0 || fstat(fd,&s) || !S_ISREG(s.st_mode) || s.st_size!=368*360*4) return 0;
    native_handle_t *buf=calloc(1,sizeof(*buf)+5*sizeof(int));
    hwc_display_contents_1_t *c=calloc(1,sizeof(*c)+sizeof(hwc_layer_1_t));
    if (!buf || !c) return 0;
    buf->version=sizeof(*buf); buf->numFds=1; buf->numInts=4;
    buf->data[0]=fd; buf->data[2]=360; buf->data[3]=360; buf->data[4]=368;
    c->numHwLayers=1;
    hwc_display_contents_1_t *displays[]={c};
    hwc_layer_1_t *l=&c->hwLayers[0];
    l->compositionType=HWC_FRAMEBUFFER_TARGET;
    l->handle=buf;
    l->acquireFenceFd=l->releaseFenceFd=c->retireFenceFd=-1;
    for (int i=0;i<2;++i) {
        buf->data[1]=i?HAL_PIXEL_FORMAT_BGRA_8888:HAL_PIXEL_FORMAT_RGBA_8888;
        if (dev->prepare(dev,1,displays) || dev->set(dev,1,displays) ||
            l->acquireFenceFd!=-1 || l->releaseFenceFd!=-1 || c->retireFenceFd!=-1 ||
            fcntl(fd,F_GETFD)<0 || !hwc_fb_matches(i||cycle?1:0,2)) return 0;
    }
    free(c); free(buf);
    return close(fd)==0 && fd_count()==before;
}

static int hwc_fixture(const hw_module_t *module)
{
    struct stat st;
    if (!fixture_read("/sys/devices/platform/148e0000.dsim/.galwear-fixture","GALWEAR_DSIM_FIXTURE_V1\n") ||
        !regular_fixture("/sys/devices/platform/148e0000.dsim/cmd_rw") ||
        !fixture_read("/dev/graphics/.galwear-fixture","GALWEAR_HWC_FIXTURE_V1\n") ||
        lstat("/dev/graphics/fb0",&st) || !S_ISREG(st.st_mode) ||
        st.st_size!=360*720*4 || !missing("/dev/fb0") ||
        !missing("/sys/devices/platform/148b0000.decon_f/vsync"))
        return 170;
    unsigned int (*get)(unsigned int)=dlsym(RTLD_DEFAULT,"r800_hwc_fixture_get");
    void (*mode)(unsigned int)=dlsym(RTLD_DEFAULT,"r800_hwc_fixture_mode");
    if (!get || !mode || get(0)) return 171;
    /* liblog may open a process-lifetime descriptor on its first write.
     * Warm it independently of HWC so framebuffer leaks cannot become part
     * of the baseline. The HAL is already loaded; use its liblog dependency. */
    void *loglib=dlopen("liblog.so",RTLD_NOW | RTLD_NOLOAD);
    if (!loglib) { fprintf(stderr,"HWC log warmup: liblog not loaded\n"); return 171; }
    int (*log_write)(int,const char *,const char *)=dlsym(loglib,"__android_log_write");
    if (!log_write) { dlclose(loglib); return 171; }
    int cold=fd_count();
    int log_rc=log_write(6,"galwear-hwc-fixture","warm up log transport before FD baseline");
    dlclose(loglib);
    int baseline=fd_count();
    fprintf(stderr,"HWC log warmup: rc=%d fd=%d/%d\n",log_rc,cold,baseline);
    if (cold<0 || baseline<cold || baseline>cold+1) return 171;
    /* The framebuffer must never be open before the first HWC attempt. */
    for (int fd=0;fd<256;++fd) {
        struct stat opened;
        if (!fstat(fd,&opened) && opened.st_dev==st.st_dev && opened.st_ino==st.st_ino)
            return 171;
    }
    hw_device_t *base=NULL;
    mode(1);
    int rc=module->methods->open(module,HWC_HARDWARE_COMPOSER,&base);
    int after=fd_count();
    fprintf(stderr,"HWC negative geometry: rc=%d expected=%d base=%p fd=%d/%d fixed=%u variable=%u bad=%u\n",
            rc,-EINVAL,(void *)base,baseline,after,get(1),get(2),get(0));
    int fb_leaks=0;
    for (int fd=0;fd<256;++fd) {
        struct stat opened;
        if (!fstat(fd,&opened) && opened.st_dev==st.st_dev && opened.st_ino==st.st_ino)
            ++fb_leaks;
    }
    if (rc!=-EINVAL || base || after!=baseline || get(1)!=1 || get(2)!=1 || get(0) || fb_leaks) {
        fprintf(stderr,"HWC negative geometry: framebuffer_fd_leaks=%d\n",fb_leaks);
        for (int fd=0;fd<256;++fd) {
            if (fcntl(fd,F_GETFD)==-1) continue;
            char path[48],target[256];
            snprintf(path,sizeof(path),"/proc/self/fd/%d",fd);
            ssize_t n=readlink(path,target,sizeof(target)-1);
            if (n>=0) { target[n]='\0'; fprintf(stderr,"HWC open fd %d: %s\n",fd,target); }
        }
        return 172;
    }
    mode(0);
    static const hwc_procs_t procs={.vsync=hwc_fixture_vsync};
    for (int cycle=0;cycle<4;++cycle) {
        rc=module->methods->open(module,HWC_HARDWARE_COMPOSER,&base);
        if (rc || !base || base->tag!=HARDWARE_DEVICE_TAG || base->module!=module ||
            base->version!=HWC_DEVICE_API_VERSION_1_4 || !base->close) {
            fprintf(stderr,"HWC open failed cycle=%d rc=%d base=%p fixed=%u variable=%u bad=%u\n",
                    cycle,rc,(void *)base,get(1),get(2),get(0));
            return 173;
        }
        hwc_composer_device_1_t *dev=(hwc_composer_device_1_t *)base;
        if (!dev->query || !dev->getDisplayConfigs || !dev->getDisplayAttributes ||
            !dev->setPowerMode || !dev->registerProcs || !dev->eventControl ||
            !dev->getActiveConfig || !dev->setActiveConfig) return 174;
        uint32_t config=99;
        size_t count=1;
        const uint32_t attrs[]={HWC_DISPLAY_WIDTH,HWC_DISPLAY_HEIGHT,HWC_DISPLAY_VSYNC_PERIOD,
                                 HWC_DISPLAY_DPI_X,HWC_DISPLAY_DPI_Y,HWC_DISPLAY_NO_ATTRIBUTE};
        int32_t vals[5]={0};
        int q=0;
        if (dev->getDisplayConfigs(dev,0,&config,&count) || config || count!=1 ||
            dev->getDisplayAttributes(dev,0,0,attrs,vals) ||
            vals[0]!=360 || vals[1]!=360 || vals[2]!=16666667 ||
            vals[3]!=277090 || vals[4]!=277090 ||
            dev->query(dev,HWC_VSYNC_PERIOD,&q) || q!=16666667 ||
            dev->getActiveConfig(dev,0)!=0 || dev->setActiveConfig(dev,0,1)!=-EINVAL ||
            dev->eventControl(dev,1,HWC_EVENT_VSYNC,1)!=-EINVAL)
            return 175;
        if (dev->setPowerMode(dev,0,HWC_POWER_MODE_OFF) ||
            dev->setPowerMode(dev,0,HWC_POWER_MODE_NORMAL) ||
            dev->setPowerMode(dev,0,HWC_POWER_MODE_DOZE) ||
            dev->setPowerMode(dev,0,HWC_POWER_MODE_DOZE_SUSPEND) ||
            dev->setPowerMode(dev,0,HWC_POWER_MODE_NORMAL))
            return 176;
        mode(2);
        if (dev->setPowerMode(dev,0,HWC_POWER_MODE_DOZE)!=-EIO ||
            dev->setPowerMode(dev,0,HWC_POWER_MODE_NORMAL) ||
            !fixture_read("/sys/devices/platform/148e0000.dsim/cmd_rw","2")) return 177;
        if (!hwc_fb_matches(cycle?1:0,cycle?2:0) || !hwc_present_guard(dev) ||
            !hwc_fb_matches(cycle?1:0,cycle?2:0)) {
            fprintf(stderr,"HWC present guard failed cycle=%d\n",cycle);
            return 182;
        }
        if (!hwc_cpu_present(dev,cycle) || get(8)!=(unsigned int)(2*(cycle+1))) {
            fprintf(stderr,"HWC CPU present failed cycle=%d pans=%u\n",cycle,get(8));
            return 183;
        }
        dev->registerProcs(dev,&procs);
        int prior=atomic_load(&hwc_ticks);
        if (dev->eventControl(dev,0,HWC_EVENT_VSYNC,1) ||
            !hwc_wait_ticks(prior+3) ||
            dev->eventControl(dev,0,HWC_EVENT_VSYNC,0)) return 178;
        /* Unregister drains any in-flight callback before returning. */
        dev->registerProcs(dev,NULL);
        int stopped=atomic_load(&hwc_ticks);
        usleep(70000);
        if (atomic_load(&hwc_ticks)!=stopped || atomic_load(&hwc_bad)) return 179;
        if (base->close(base) || fd_count()!=baseline) return 180;
        base=NULL;
    }
    if (get(0) || get(1)!=5 || get(2)!=5 || get(3)!=4 ||
        get(5)!=12 || get(6)!=4 || get(7)!=4 || atomic_load(&hwc_ticks)<12)
        return 181;
    puts("HAL_HWC_PRESENT_GUARD_PASS cycles=4 invalid_list=4 ready_null_target=4 hungup=4");
    puts("HAL_HWC_CPU_PRESENT_PASS frames=8 rgba=4 bgra=4 stride=368 pan=8");
    puts("HAL_HWC_FIXTURE_PASS geometry=360x360 cycles=4 invalid_bpp=1 power_recovery=4 timer_vsync=4");
    return 0;
}
