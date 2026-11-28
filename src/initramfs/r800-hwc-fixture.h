/* Test-only HWC open, power transitions, present guards and timer VSync. */
#include <stdlib.h>
#include <hardware/gralloc.h>
#include <EGL/egl.h>
#include <EGL/eglext.h>
#include <GLES2/gl2.h>
#include <poll.h>
#include <sys/eventfd.h>
#include "r800-window-queue-fixture.h"
#include "r800-native-handle-import-fixture.h"
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
/* Generate a pollable acquire FD through the separate EGL test provider.
 * The buffer itself is still the deterministic read-only Gralloc fixture. */
static int hwc_egl_acquire(void)
{
    int before=fd_count();
    void *lib=dlopen("/system/lib/libGLES_galwear_native.so",RTLD_NOW|RTLD_LOCAL);
    if (!lib || before<0) return -1;
#define EGL_RESOLVE(name) __typeof__(&name) p_##name=(__typeof__(&name))dlsym(lib,#name); if(!p_##name)return -1
    EGL_RESOLVE(eglGetDisplay);
    EGL_RESOLVE(eglInitialize);
    EGL_RESOLVE(eglBindAPI);
    EGL_RESOLVE(eglChooseConfig);
    EGL_RESOLVE(eglCreateContext);
    EGL_RESOLVE(eglCreatePbufferSurface);
    EGL_RESOLVE(eglMakeCurrent);
    EGL_RESOLVE(eglGetProcAddress);
    EGL_RESOLVE(eglDestroySurface);
    EGL_RESOLVE(eglDestroyContext);
    EGL_RESOLVE(eglTerminate);
    EGL_RESOLVE(glFlush);
    EGL_RESOLVE(glGetError);
#undef EGL_RESOLVE
    PFNEGLCREATESYNCKHRPROC create=(PFNEGLCREATESYNCKHRPROC)p_eglGetProcAddress("eglCreateSyncKHR");
    PFNEGLDESTROYSYNCKHRPROC destroy=(PFNEGLDESTROYSYNCKHRPROC)p_eglGetProcAddress("eglDestroySyncKHR");
    PFNEGLCLIENTWAITSYNCKHRPROC wait=(PFNEGLCLIENTWAITSYNCKHRPROC)p_eglGetProcAddress("eglClientWaitSyncKHR");
    PFNEGLDUPNATIVEFENCEFDANDROIDPROC export_fd=(PFNEGLDUPNATIVEFENCEFDANDROIDPROC)p_eglGetProcAddress("eglDupNativeFenceFDANDROID");
    if (!create || !destroy || !wait || !export_fd) return -1;
    EGLDisplay d=p_eglGetDisplay(EGL_DEFAULT_DISPLAY);
    EGLConfig config=0; EGLint count=0;
    if (d==EGL_NO_DISPLAY || !p_eglInitialize(d,NULL,NULL) ||
        !p_eglBindAPI(EGL_OPENGL_ES_API) ||
        !p_eglChooseConfig(d,NULL,&config,1,&count) || count!=1 || !config) return -1;
    const EGLint ca[]={EGL_CONTEXT_CLIENT_VERSION,2,EGL_NONE};
    const EGLint pa[]={EGL_WIDTH,8,EGL_HEIGHT,8,EGL_NONE};
    EGLContext c=p_eglCreateContext(d,config,EGL_NO_CONTEXT,ca);
    EGLSurface surface=p_eglCreatePbufferSurface(d,config,pa);
    if (c==EGL_NO_CONTEXT || surface==EGL_NO_SURFACE || !p_eglMakeCurrent(d,surface,surface,c)) return -1;
    EGLSyncKHR sync=create(d,EGL_SYNC_NATIVE_FENCE_ANDROID,NULL);
    if (sync==EGL_NO_SYNC_KHR || wait(d,sync,0,0)!=EGL_TIMEOUT_EXPIRED_KHR) return -1;
    p_glFlush();
    if (p_glGetError()!=GL_NO_ERROR || wait(d,sync,0,0)!=EGL_CONDITION_SATISFIED_KHR) return -1;
    int fd=export_fd(d,sync);
    if (fd<0 || fcntl(fd,F_GETFD)!=FD_CLOEXEC || !destroy(d,sync) ||
        !p_eglMakeCurrent(d,EGL_NO_SURFACE,EGL_NO_SURFACE,EGL_NO_CONTEXT) ||
        !p_eglDestroySurface(d,surface) || !p_eglDestroyContext(d,c) ||
        !p_eglTerminate(d) || dlclose(lib)) return -1;
    struct pollfd ready={.fd=fd,.events=POLLIN};
    if (poll(&ready,1,0)!=1 || ready.revents!=POLLIN || fd_count()!=before+1) return -1;
    return fd;
}
static int hwc_cpu_present(hwc_composer_device_1_t *dev,int cycle)
{
    int before=fd_count();
    struct window_queue queue={.slots={{.fence=-1},{.fence=-1}}};
    for(int i=0;i<2;++i){
        int fd=open("/dev/graphics/pixels",O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
        struct stat s;
        if(before<0||fd<0||fstat(fd,&s)||!S_ISREG(s.st_mode)||s.st_size!=368*360*4)return 0;
        const size_t bytes=sizeof(native_handle_t)+5*sizeof(int);
        native_handle_t *raw=calloc(1,bytes),*buf=NULL;
        if(!raw){close(fd);return 0;}
        raw->version=sizeof(*raw);raw->numFds=1;raw->numInts=4;
        raw->data[0]=fd;raw->data[1]=i?HAL_PIXEL_FORMAT_BGRA_8888:HAL_PIXEL_FORMAT_RGBA_8888;
        raw->data[2]=360;raw->data[3]=360;raw->data[4]=368;
        int rc=import_model(raw,bytes,&buf);
        int valid=!rc&&buf&&buf!=raw&&buf->data[0]!=fd&&
            fcntl(buf->data[0],F_GETFD)==FD_CLOEXEC&&
            !memcmp(raw->data+1,buf->data+1,4*sizeof(int));
        int closed=close(fd);
        free(raw);
        if(!valid||closed||fcntl(fd,F_GETFD)!=-1||errno!=EBADF){
            if(buf)free_model(&buf);
            return 0;
        }
        if(fd_count()!=before+i+1){free_model(&buf);return 0;}
        queue.slots[i].handle=buf;
    }
    hwc_display_contents_1_t *c=calloc(1,sizeof(*c)+sizeof(hwc_layer_1_t));
    if(!c)return 0;
    c->numHwLayers=1;
    hwc_display_contents_1_t *displays[]={c};
    hwc_layer_1_t *l=&c->hwLayers[0];
    l->compositionType=HWC_FRAMEBUFFER_TARGET;
    l->acquireFenceFd=l->releaseFenceFd=c->retireFenceFd=-1;
    buffer_handle_t handle=NULL;
    int acquire=-1;
    if(window_acquire(&queue,&handle,&acquire)!=-EAGAIN||
       window_dequeue(&queue)!=0||window_dequeue(&queue)!=1||
       window_dequeue(&queue)!=-EAGAIN)return 0;
    /* Cancel a producer-owned slot; the cancellation takes its fence. */
    int cancelled=hwc_egl_acquire();
    if(cancelled<0||window_cancel(&queue,0,cancelled)||
       fcntl(cancelled,F_GETFD)!=-1||errno!=EBADF||
       window_dequeue(&queue)!=0)return 0;
    if(window_queue_buffer(&queue,0,-1))return 0;
    int fence=hwc_egl_acquire();
    if(fence<0||window_queue_buffer(&queue,1,fence))return 0;
    /* Duplicate queue and cancel of an already queued slot must not consume
     * the unrelated caller-owned FD or the pending queue fence. */
    int rejected=fcntl(fence,F_DUPFD_CLOEXEC,0);
    if(rejected<0||window_queue_buffer(&queue,1,rejected)!=-EINVAL||
       window_cancel(&queue,1,rejected)!=-EINVAL||fcntl(rejected,F_GETFD)<0||
       close(rejected)||fcntl(fence,F_GETFD)<0||window_dequeue(&queue)!=-EAGAIN)return 0;
    for(int i=0;i<2;++i){
        int slot=window_acquire(&queue,&handle,&acquire);
        if(slot!=i||handle!=queue.slots[i].handle||
           acquire!=(i?fence:-1)||window_dequeue(&queue)!=(i?0:-EAGAIN))return 0;
        if(i&&window_cancel(&queue,0,-1))return 0;
        l->handle=handle;l->acquireFenceFd=acquire;
        if(dev->prepare(dev,1,displays)||dev->set(dev,1,displays)||
           l->acquireFenceFd!=-1||l->releaseFenceFd!=-1||c->retireFenceFd!=-1||
           fcntl(handle->data[0],F_GETFD)<0||!hwc_fb_matches(i||cycle?1:0,2))return 0;
        if(i&&(fcntl(acquire,F_GETFD)!=-1||errno!=EBADF))return 0;
        if(window_release_cpu(&queue,slot,l->releaseFenceFd)||
           window_release_cpu(&queue,slot,-1)!=-EINVAL)return 0;
    }
    if(window_acquire(&queue,&handle,&acquire)!=-EAGAIN||queue.count||
       queue.slots[0].state!=WINDOW_FREE||queue.slots[1].state!=WINDOW_FREE)return 0;
    free(c);
    for(int i=0;i<2;++i){
        int imported_fd=queue.slots[i].handle->data[0];
        if(free_model(&queue.slots[i].handle)||queue.slots[i].handle||
           fcntl(imported_fd,F_GETFD)!=-1||errno!=EBADF)return 0;
    }
    return fd_count()==before;
}

/* Independent delayed-release control. Both descriptors share eventfd
 * state, but only the queue owns the transferred descriptor. */
static int hwc_window_release_async(void)
{
    int baseline=fd_count();
    for(int i=0;i<4;++i){
        struct window_queue q={.slots={{.state=WINDOW_ACQUIRED,.fence=-1},
                                       {.state=WINDOW_DEQUEUED,.fence=-1}}};
        int producer=eventfd(0,EFD_CLOEXEC|EFD_NONBLOCK);
        if(producer<0)return 0;
        int release=fcntl(producer,F_DUPFD_CLOEXEC,0);
        if(release<0||window_release_async(&q,0,release)||
           window_reap_release(&q,0)!=-EAGAIN||window_dequeue(&q)!=-EAGAIN||
           q.slots[0].fence!=release||fcntl(release,F_GETFD)<0)return 0;
        int rejected=fcntl(producer,F_DUPFD_CLOEXEC,0);
        if(rejected<0||window_release_async(&q,0,rejected)!=-EINVAL||
           fcntl(rejected,F_GETFD)<0||close(rejected))return 0;
        if(eventfd_write(producer,1)||window_reap_release(&q,0)||
           fcntl(release,F_GETFD)!=-1||errno!=EBADF||
           fcntl(producer,F_GETFD)<0||close(producer)||
           window_dequeue(&q)!=0||window_cancel(&q,0,-1))return 0;
        /* Error completion quarantines the slot, never grants reuse. */
        q.slots[0].state=WINDOW_ACQUIRED;
        const size_t bytes=sizeof(native_handle_t)+sizeof(int);
        native_handle_t *raw=calloc(1,bytes);
        if(!raw)return 0;
        int pixel=open("/dev/graphics/pixels",O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
        if(pixel<0){free(raw);return 0;}
        raw->version=sizeof(*raw);raw->numFds=1;raw->numInts=0;raw->data[0]=pixel;
        int imported=import_model(raw,bytes,&q.slots[0].handle);
        int closed=close(pixel);
        free(raw);
        if(imported||closed||!q.slots[0].handle)return 0;
        int owned=q.slots[0].handle->data[0];
        int pipefd[2];
        if(pipe(pipefd)||close(pipefd[1])||window_release_async(&q,0,pipefd[0])||
           window_reap_release(&q,0)!=-EIO||
           q.slots[0].state!=WINDOW_QUARANTINED||window_dequeue(&q)!=-EAGAIN||
           fcntl(pipefd[0],F_GETFD)!=-1||errno!=EBADF||
           fcntl(owned,F_GETFD)!=FD_CLOEXEC||
           window_cancel(&q,1,-1)||window_dequeue(&q)!=1||
           window_cancel(&q,1,-1)||q.slots[0].state!=WINDOW_QUARANTINED||
           fd_count()!=baseline+1)return 0;
        /* Fixture teardown only: no device is accessing this synthetic file.
         * A failed real release fence would not establish hardware quiescence. */
        if(free_model(&q.slots[0].handle)||q.slots[0].handle||
           fcntl(owned,F_GETFD)!=-1||errno!=EBADF||fd_count()!=baseline)return 0;
    }
    return 1;
}
/* Consume a genuine output FD from the HWC code (mock DECON provider).
 * Duplicate for the existing counter assertion before the queue reaps it. */
static int hwc_queue_overlay_release(int fd,int signal_fd,native_handle_t *handle)
{
    if(!handle||fcntl(handle->data[0],F_GETFD)!=FD_CLOEXEC)return 0;
    struct window_queue q={.slots={{.handle=handle,.state=WINDOW_ACQUIRED,.fence=-1},
                                   {.state=WINDOW_DEQUEUED,.fence=-1}}};
    if(window_release_async(&q,0,fd)||window_dequeue(&q)!=-EAGAIN||
       q.slots[0].handle!=handle||fcntl(handle->data[0],F_GETFD)!=FD_CLOEXEC||
       window_reap_release(&q,0)!=-EAGAIN||q.slots[0].state!=WINDOW_RELEASE_PENDING||
       q.slots[0].fence!=fd||fcntl(fd,F_GETFD)<0||window_dequeue(&q)!=-EAGAIN||
       eventfd_write(signal_fd,21)||window_reap_release(&q,0)||
       fcntl(fd,F_GETFD)!=-1||errno!=EBADF||
       q.slots[0].handle!=handle||fcntl(handle->data[0],F_GETFD)!=FD_CLOEXEC||
       window_dequeue(&q)!=0||window_cancel(&q,0,-1))return 0;
    return 1;
}

/* Synthetic DECON accepts one client-target window. Eventfds stand in for
 * kernel-owned release/retire descriptors, not actual sync_file fences. */
static int hwc_zero_copy(const hw_module_t *module,unsigned int (*get)(unsigned int),
                         void (*mode)(unsigned int))
{
    int before=fd_count();
    hw_device_t *base=NULL;
    mode(3);
    if (before<0 || module->methods->open(module,HWC_HARDWARE_COMPOSER,&base) || !base) return 0;
    hwc_composer_device_1_t *dev=(hwc_composer_device_1_t *)base;
    int source=open("/dev/graphics/pixels",O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
    const size_t bytes=sizeof(native_handle_t)+5*sizeof(int);
    native_handle_t *raw=calloc(1,bytes),*buf=NULL;
    hwc_display_contents_1_t *c=calloc(1,sizeof(*c)+sizeof(hwc_layer_1_t));
    if(source<0||!raw||!c){
        if(source>=0)close(source);
        free(raw);free(c);base->close(base);return 0;
    }
    raw->version=sizeof(*raw);raw->numFds=1;raw->numInts=4;
    raw->data[0]=source;raw->data[1]=HAL_PIXEL_FORMAT_RGBA_8888;
    raw->data[2]=360;raw->data[3]=360;raw->data[4]=368;
    int imported=import_model(raw,bytes,&buf);
    int valid=!imported&&buf&&buf!=raw&&buf->data[0]!=source&&
        fcntl(buf->data[0],F_GETFD)==FD_CLOEXEC&&
        !memcmp(raw->data+1,buf->data+1,4*sizeof(int));
    int closed=close(source);
    free(raw);
    if(!valid||closed||fcntl(source,F_GETFD)!=-1||errno!=EBADF){
        if(buf)free_model(&buf);
        free(c);base->close(base);return 0;
    }
    int fd=buf->data[0];
    c->numHwLayers=1;
    hwc_display_contents_1_t *displays[]={c};
    hwc_layer_1_t *l=&c->hwLayers[0];
    l->compositionType=HWC_FRAMEBUFFER_TARGET; l->handle=buf;
    l->releaseFenceFd=c->retireFenceFd=-1;
    int pair[2];
    if (pipe(pair) || write(pair[1],"x",1)!=1) return 0;
    l->acquireFenceFd=pair[0];
    if (dev->prepare(dev,1,displays) || dev->set(dev,1,displays) ||
        l->acquireFenceFd!=-1 || l->releaseFenceFd!=-1 ||
        get(9)!=1 || get(10)!=1 || get(8)!=8 ||
        c->retireFenceFd<0 || c->retireFenceFd!=(int)get(12) ||
        c->retireFenceFd==(int)get(11) || fcntl(pair[0],F_GETFD)!=-1 || errno!=EBADF ||
        fcntl((int)get(11),F_GETFD)!=-1 || errno!=EBADF ||
        fcntl(fd,F_GETFD)!=FD_CLOEXEC || !hwc_fb_matches(1,2)) return 0;
    uint64_t value=0;
    if (read(c->retireFenceFd,&value,sizeof(value))!=(ssize_t)sizeof(value) ||
        value!=13 || close(c->retireFenceFd) || close(pair[1])) return 0;
    c->retireFenceFd=-1;
    /* ENOTTY disables zero-copy; a hung-up acquire must not trigger CPU read. */
    mode(4);
    if (pipe(pair) || close(pair[1])) return 0;
    l->acquireFenceFd=pair[0];
    if (dev->prepare(dev,1,displays) || dev->set(dev,1,displays) ||
        l->acquireFenceFd!=-1 || l->releaseFenceFd!=-1 || c->retireFenceFd!=-1 ||
        fcntl(pair[0],F_GETFD)!=-1 || errno!=EBADF ||
        get(9)!=2 || get(10)!=1 || get(8)!=8 ||
        fcntl(fd,F_GETFD)!=FD_CLOEXEC || !hwc_fb_matches(1,2)) return 0;
    /* A subsequent ready RGBA target must use CPU copy, never retry WIN_CONFIG. */
    if (pipe(pair) || write(pair[1],"x",1)!=1) return 0;
    l->acquireFenceFd=pair[0];
    if (dev->prepare(dev,1,displays) || dev->set(dev,1,displays) ||
        l->acquireFenceFd!=-1 || l->releaseFenceFd!=-1 || c->retireFenceFd!=-1 ||
        fcntl(pair[0],F_GETFD)!=-1 || errno!=EBADF ||
        get(9)!=2 || get(10)!=1 || get(8)!=9 || get(0) ||
        !hwc_fb_matches(1,2) || close(pair[1]) ||
        fcntl(fd,F_GETFD)!=FD_CLOEXEC) return 0;
    free(c);
    if(free_model(&buf)||buf||fcntl(fd,F_GETFD)!=-1||errno!=EBADF)return 0;
    mode(0);
    return base->close(base)==0 && fd_count()==before;
}

/* All layers use separate read-only FDs to the private synthetic pixel file.
 * No actual compositing, DMA or sync_file signaling is claimed. */
static int hwc_overlay(const hw_module_t *module,unsigned int (*get)(unsigned int),
                       void (*mode)(unsigned int))
{
    int before=fd_count();
    hw_device_t *base=NULL;
    mode(5);
    if (before<0 || module->methods->open(module,HWC_HARDWARE_COMPOSER,&base) || !base) return 0;
    hwc_composer_device_1_t *dev=(hwc_composer_device_1_t *)base;
    native_handle_t *buf[3]={0};
    const int formats[]={HAL_PIXEL_FORMAT_RGBA_8888,HAL_PIXEL_FORMAT_RGBX_8888,HAL_PIXEL_FORMAT_BGRA_8888};
    const int blends[]={HWC_BLENDING_NONE,HWC_BLENDING_PREMULT,HWC_BLENDING_COVERAGE};
    for (int i=0;i<3;++i) {
        const size_t bytes=sizeof(native_handle_t)+5*sizeof(int);
        native_handle_t *raw=calloc(1,bytes);
        if(!raw)return 0;
        int fd=open("/dev/graphics/pixels",O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
        if(fd<0){free(raw);return 0;}
        raw->version=sizeof(*raw);raw->numFds=1;raw->numInts=4;
        raw->data[0]=fd;raw->data[1]=formats[i];
        raw->data[2]=360;raw->data[3]=360;raw->data[4]=368;
        int rc=import_model(raw,bytes,&buf[i]);
        int valid=!rc&&buf[i]&&buf[i]!=raw&&buf[i]->data[0]!=fd&&
            fcntl(buf[i]->data[0],F_GETFD)==FD_CLOEXEC&&
            !memcmp(raw->data+1,buf[i]->data+1,4*sizeof(int));
        int closed=close(fd);
        free(raw);
        if(!valid||closed||fcntl(fd,F_GETFD)!=-1||errno!=EBADF){
            if(buf[i])free_model(&buf[i]);
            return 0;
        }
    }
    hwc_display_contents_1_t *c=calloc(1,sizeof(*c)+4*sizeof(hwc_layer_1_t));
    if (!c) return 0;
    hwc_display_contents_1_t *displays[]={c};
    /* Prime the format gate through a successful real client-target set. */
    c->numHwLayers=1;
    hwc_layer_1_t *l=&c->hwLayers[0];
    l->compositionType=HWC_FRAMEBUFFER_TARGET; l->handle=buf[0];
    int prime[2];
    if (pipe(prime) || write(prime[1],"x",1)!=1) return 0;
    l->acquireFenceFd=prime[0]; l->releaseFenceFd=c->retireFenceFd=-1;
    if (dev->prepare(dev,1,displays) || dev->set(dev,1,displays) ||
        l->acquireFenceFd!=-1 || l->releaseFenceFd!=-1 || c->retireFenceFd<0 ||
        get(9)!=3 || get(10)!=2 || close(c->retireFenceFd) || close(prime[1])) return 0;
    /* 2-layer then 3-layer success, followed by five EIO failures. */
    for (int round=0;round<7;++round) {
        int n=round==1?3:2;
        mode(round==0?9:round==1?5:6);
        c->numHwLayers=n+1;
        c->retireFenceFd=-1;
        int pairs[4][2];
        for (int i=0;i<=n;++i) {
            l=&c->hwLayers[i]; memset(l,0,sizeof(*l));
            l->compositionType=i==n?HWC_FRAMEBUFFER_TARGET:HWC_FRAMEBUFFER;
            l->handle=i==n?NULL:buf[i];
            l->sourceCropf=(hwc_frect_t){0,0,360,360};
            l->displayFrame=(hwc_rect_t){0,0,360,360};
            l->planeAlpha=i==n?255:255-i*40;
            l->blending=i==n?HWC_BLENDING_NONE:blends[i];
            if (pipe(pairs[i]) || write(pairs[i][1],"x",1)!=1) return 0;
            l->acquireFenceFd=pairs[i][0]; l->releaseFenceFd=-1;
        }
        if (round==0) {
            c->hwLayers[0].transform=HWC_TRANSFORM_ROT_90;
            if (dev->prepare(dev,1,displays)) return 0;
            for (int i=0;i<n;++i) if (c->hwLayers[i].compositionType!=HWC_FRAMEBUFFER) return 0;
            c->hwLayers[0].transform=0;
        }
        if (dev->prepare(dev,1,displays)) return 0;
        for (int i=0;i<n;++i) if (c->hwLayers[i].compositionType!=HWC_OVERLAY) return 0;
        if (dev->set(dev,1,displays)) return 0;
        for (int i=0;i<=n;++i) {
            l=&c->hwLayers[i];
            if (l->acquireFenceFd!=-1 || fcntl(pairs[i][0],F_GETFD)!=-1 || errno!=EBADF ||
                close(pairs[i][1])) return 0;
            if (round<2 && i<n) {
                uint64_t v=0;
                if (l->releaseFenceFd<0 || l->releaseFenceFd==c->retireFenceFd) return 0;
                int observe=l->releaseFenceFd;
                if(round==0&&i==0){
                    observe=fcntl(l->releaseFenceFd,F_DUPFD_CLOEXEC,0);
                    if(observe<0||!hwc_queue_overlay_release(l->releaseFenceFd,observe,buf[i]))return 0;
                }
                if(read(observe,&v,sizeof(v))!=(ssize_t)sizeof(v) ||
                   v!=(uint64_t)(21+i) || close(observe))return 0;
            } else if (l->releaseFenceFd!=-1) return 0;
        }
        if (round<2) {
            uint64_t v=0;
            if (c->retireFenceFd<0 ||
                read(c->retireFenceFd,&v,sizeof(v))!=(ssize_t)sizeof(v) ||
                v!=31 || close(c->retireFenceFd)) return 0;
        } else if (c->retireFenceFd!=-1) return 0;
        if (get(13)!=(unsigned int)(round+1) || get(14)!=(unsigned int)(round<2?round+1:2) ||
            get(8)!=9 || get(0) || !hwc_fb_matches(1,2)) return 0;
    }
    /* The sixth attempt is not an overlay: prepare must select GPU composition. */
    mode(5);
    c->retireFenceFd=-1;
    for (size_t i=0;i<c->numHwLayers;++i) {
        c->hwLayers[i].acquireFenceFd=c->hwLayers[i].releaseFenceFd=-1;
    }
    if (dev->prepare(dev,1,displays) || c->hwLayers[0].compositionType!=HWC_FRAMEBUFFER ||
        c->hwLayers[1].compositionType!=HWC_FRAMEBUFFER || get(13)!=7) return 0;
    /* Restart HWC after the failure latch; format verification must be
     * earned again, and overlay selection must recover. */
    if (base->close(base)) return 0;
    base=NULL;
    if (module->methods->open(module,HWC_HARDWARE_COMPOSER,&base) || !base) return 0;
    dev=(hwc_composer_device_1_t *)base;
    if (dev->prepare(dev,1,displays) || c->hwLayers[0].compositionType!=HWC_FRAMEBUFFER ||
        c->hwLayers[1].compositionType!=HWC_FRAMEBUFFER) return 0;
    c->numHwLayers=1;
    l=&c->hwLayers[0]; memset(l,0,sizeof(*l));
    l->compositionType=HWC_FRAMEBUFFER_TARGET; l->handle=buf[0];
    if (pipe(prime) || write(prime[1],"x",1)!=1) return 0;
    l->acquireFenceFd=prime[0]; l->releaseFenceFd=c->retireFenceFd=-1;
    if (dev->prepare(dev,1,displays) || dev->set(dev,1,displays) ||
        l->acquireFenceFd!=-1 || l->releaseFenceFd!=-1 || c->retireFenceFd<0 ||
        get(9)!=4 || get(10)!=3 || close(c->retireFenceFd) || close(prime[1])) return 0;
    int steady=fd_count();
    if (steady<0) return 0;
    for (int round=0;round<2;++round) {
        mode(7+round);
        c->numHwLayers=3; c->retireFenceFd=-1;
        int pairs[3][2];
        for (int i=0;i<3;++i) {
            l=&c->hwLayers[i]; memset(l,0,sizeof(*l));
            l->compositionType=i==2?HWC_FRAMEBUFFER_TARGET:HWC_FRAMEBUFFER;
            l->handle=i==2?NULL:buf[i];
            l->sourceCropf=(hwc_frect_t){0,0,360,360};
            l->displayFrame=(hwc_rect_t){0,0,360,360};
            l->planeAlpha=i==2?255:255-i*40;
            l->blending=i==2?HWC_BLENDING_NONE:blends[i];
            if (pipe(pairs[i]) || write(pairs[i][1],"x",1)!=1) return 0;
            l->acquireFenceFd=pairs[i][0]; l->releaseFenceFd=-1;
        }
        if (dev->prepare(dev,1,displays) || c->hwLayers[0].compositionType!=HWC_OVERLAY ||
            c->hwLayers[1].compositionType!=HWC_OVERLAY || dev->set(dev,1,displays)) return 0;
        for (int i=0;i<3;++i) {
            if (c->hwLayers[i].acquireFenceFd!=-1 || close(pairs[i][1])) return 0;
        }
        if (c->hwLayers[2].releaseFenceFd!=-1) return 0;
        if (!round) {
            int dup=c->hwLayers[0].releaseFenceFd, rel=c->hwLayers[1].releaseFenceFd;
            int retire=c->retireFenceFd;
            uint64_t v=0;
            /* The dup may reuse a just-closed acquire FD. Prove identity
             * through shared eventfd state, not by comparing old numbers. */
            if (dup<0 || rel<0 || retire<0 || dup==retire || dup==rel || rel==retire ||
                fcntl(dup,F_GETFD)!=FD_CLOEXEC ||
                read(dup,&v,sizeof(v))!=(ssize_t)sizeof(v) || v!=31 ||
                read(retire,&v,sizeof(v))!=-1 || errno!=EAGAIN ||
                read(rel,&v,sizeof(v))!=(ssize_t)sizeof(v) || v!=22 ||
                close(dup) || close(rel) || close(retire)) return 0;
        } else if (c->hwLayers[0].releaseFenceFd!=-1 ||
                   c->hwLayers[1].releaseFenceFd!=-1 || c->retireFenceFd!=-1) return 0;
        if (fd_count()!=steady || get(13)!=(unsigned int)(8+round) ||
            get(14)!=(unsigned int)(3+round) || get(8)!=9 || get(0) ||
            !hwc_fb_matches(1,2)) return 0;
    }
    mode(5);
    if (dev->prepare(dev,1,displays) || c->hwLayers[0].compositionType!=HWC_FRAMEBUFFER ||
        c->hwLayers[1].compositionType!=HWC_FRAMEBUFFER || get(13)!=9) return 0;
    free(c);
    for (int i=0;i<3;++i) {
        int imported_fd=buf[i]->data[0];
        if(free_model(&buf[i])||buf[i]||
           fcntl(imported_fd,F_GETFD)!=-1||errno!=EBADF)return 0;
    }
    mode(0);
    return base->close(base)==0 && fd_count()==before;
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
    if (!hwc_zero_copy(module,get,mode)) {
        fprintf(stderr,"HWC zero-copy failed: calls=%u success=%u pans=%u bad=%u\n",
                get(9),get(10),get(8),get(0));
        return 184;
    }
    if (!hwc_overlay(module,get,mode)) {
        fprintf(stderr,"HWC overlay failed: calls=%u success=%u client=%u pans=%u bad=%u\n",
                get(13),get(14),get(9),get(8),get(0));
        return 185;
    }
    if (!hwc_window_release_async()) return 186;
    puts("HAL_HWC_WINDOW_RELEASE_FIXTURE_PASS cycles=4 delayed=4 signaled=4 rejected=4 quarantined=4 overlay_handoff=1 fd_stable=1");
    puts("HAL_HWC_OVERLAY_RECOVERY_PASS reopen=1 format_gate=1 release_dup=1 no_fences_disable=1");
    puts("HAL_HWC_IMPORTED_OVERLAY_FIXTURE_PASS imports=3 source_closed=3 freed=3 overlay_release_handoff=1 fd_stable=1");
    puts("HAL_HWC_DELAYED_OVERLAY_RELEASE_FIXTURE_PASS unsignaled=1 blocked_reuse=1 signaled=1 reclaimed=1");
    puts("HAL_HWC_IMPORTED_QUARANTINE_FIXTURE_PASS cycles=4 retained=4 blocked_reuse=4 teardown=4 fd_stable=1");
    puts("HAL_HWC_OVERLAY_PASS windows=2,3 releases=5 retire=2 eio=5 disabled=1 transform_reject=1");
    puts("HAL_HWC_ZERO_COPY_PASS win_config=2 accepted=1 enotty=1 fallback=1 retire=1 release_closed=1");
    puts("HAL_HWC_IMPORTED_ZERO_COPY_FIXTURE_PASS imports=1 source_closed=1 accepted=1 enotty=1 fallback=1 freed=1 fd_stable=1");
    puts("HAL_HWC_PRESENT_GUARD_PASS cycles=4 invalid_list=4 ready_null_target=4 hungup=4");
    puts("HAL_HWC_CPU_PRESENT_PASS frames=8 rgba=4 bgra=4 stride=368 pan=8");
    puts("HAL_HWC_IMPORTED_HANDLE_FIXTURE_PASS frames=8 imports=8 source_closed=8 freed=8 cloexec=8 fd_stable=1");
    puts("HAL_HWC_EGL_ACQUIRE_FIXTURE_PASS frames=4 exported=4 consumed=4 provider_unloaded=4 pixel_match=4");
    puts("HAL_HWC_WINDOW_QUEUE_FIXTURE_PASS cycles=4 slots=2 fifo_frames=8 cancel=4 rejected_transfer=8 backpressure=4 fd_stable=1");
    puts("HAL_HWC_FIXTURE_PASS geometry=360x360 cycles=4 invalid_bpp=1 power_recovery=4 timer_vsync=4");
    return 0;
}
