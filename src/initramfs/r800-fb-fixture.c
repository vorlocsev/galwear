/* Test-only framebuffer adapter. Only the private regular file is accepted. */
#include <errno.h>
#include <linux/fb.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/system_properties.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/eventfd.h>
#include "../hal/r800_decon_abi.h"

#define FB_PATH "/dev/graphics/fb0"
#define VSYNC_CMD _IOW('F',206,uint32_t)
#define POWER_CMD _IOW('F',223,uint32_t)
static atomic_uint bad, invalid_geometry, fail_power, fixed, variable, wake, blanks, power, vsync_on, vsync_off, pans;
static atomic_uint zero_copy, fail_win, win_calls, win_success;
static atomic_int last_release=-1,last_retire=-1;
static atomic_uint overlays, fail_overlay, overlay_calls, overlay_success, missing_fences, delayed_release;
unsigned int r800_hwc_fixture_get(unsigned int k)
{
    switch(k) {
    case 0: return bad;
    case 1: return fixed;
    case 2: return variable;
    case 3: return wake;
    case 4: return blanks;
    case 5: return power;
    case 6: return vsync_on;
    case 7: return vsync_off;
    case 8: return pans;
    case 9: return win_calls;
    case 10: return win_success;
    case 11: return (unsigned int)last_release;
    case 12: return (unsigned int)last_retire;
    case 13: return overlay_calls;
    case 14: return overlay_success;
    default: return UINT32_MAX;
    }
}
void r800_hwc_fixture_mode(unsigned int mode)
{
    invalid_geometry=mode==1;
    fail_power=mode==2;
    zero_copy=mode>=3 && mode<=9;
    fail_win=mode==4;
    overlays=mode>=5 && mode<=9;
    fail_overlay=mode==6;
    missing_fences=mode==7?1:mode==8?2:0;
    delayed_release=mode==9;
}
int __system_property_get(const char *name,char *value)
{
    const char *v="";
    if (!strcmp(name,"debug.r800.layer_stride")) v="96";
    else if (!strcmp(name,"debug.r800.realblank")) v="1";
    else if (!strcmp(name,"debug.r800.zerocopy")) v=zero_copy?"1":"0";
    else if (!strcmp(name,"vendor.hwc.r800.overlay")) v=overlays?"1":"0";
    strcpy(value,v);
    return (int)strlen(v);
}
int __system_property_set(const char *name,const char *value)
{
    if (!strcmp(name,"debug.r800.hwc_woke") && !strcmp(value,"1")) return 0;
    ++bad;
    return -1;
}
static int overlay_config(struct r800_win_config_data *d)
{
    const int formats[]={2,6,3};
    const struct r800_frame src={0,0,360,360,368,360},dst={0,0,360,360,360,360};
    struct stat expected;
    if (!overlays || d->retire_fence!=-1 || d->fd_odma!=-1 ||
        lstat("/dev/graphics/pixels",&expected) || !S_ISREG(expected.st_mode)) goto invalid;
    int n=d->config[2].state==R800_WIN_STATE_BUFFER?3:2;
    for (int i=0;i<=R800_MAX_DECON_WIN;++i) {
        struct r800_win_config *w=&d->config[i];
        if (w->fd_idma[1]!=-1 || w->fd_idma[2]!=-1 || w->rel_fence!=-1) goto invalid;
        if (i>=n) {
            if (w->state!=R800_WIN_STATE_DISABLED || w->fd_idma[0]!=-1 || w->acq_fence!=-1) goto invalid;
            continue;
        }
        struct stat actual;
        if (w->state!=R800_WIN_STATE_BUFFER || w->channel!=(unsigned int)i ||
            w->format!=formats[i] || w->plane_alpha!=255-i*40 || w->blending!=i ||
            w->protection || w->compression || w->acq_fence<0 ||
            fcntl(w->acq_fence,F_GETFD)<0 ||
            fstat(w->fd_idma[0],&actual) || !S_ISREG(actual.st_mode) ||
            actual.st_dev!=expected.st_dev || actual.st_ino!=expected.st_ino ||
            actual.st_size!=368*360*4 || memcmp(&w->src,&src,sizeof(src)) ||
            memcmp(&w->dst,&dst,sizeof(dst))) goto invalid;
        for (int j=0;j<i;++j)
            if (w->acq_fence==d->config[j].acq_fence ||
                w->fd_idma[0]==d->config[j].fd_idma[0]) goto invalid;
    }
    ++overlay_calls;
    if (fail_overlay) { errno=EIO; return -1; }
    int rel[3]={-1,-1,-1};
    int retire=-1;
    if (missing_fences==2) { ++overlay_success; return 0; }
    for (int i=0;i<n;++i) {
        if (missing_fences==1 && i==0) continue;
        rel[i]=eventfd(delayed_release&&i==0?0:21+i,EFD_CLOEXEC|EFD_NONBLOCK);
        if (rel[i]<0) goto cleanup;
    }
    retire=eventfd(31,EFD_CLOEXEC|EFD_NONBLOCK);
    if (retire<0) goto cleanup;
    for (int i=0;i<n;++i) d->config[i].rel_fence=rel[i];
    d->retire_fence=retire;
    ++overlay_success;
    return 0;
cleanup:
    for (int i=0;i<n;++i) if (rel[i]>=0) close(rel[i]);
    if (retire>=0) close(retire);
invalid:
    ++bad; errno=EINVAL; return -1;
}
int ioctl(int fd,int request,...)
{
    struct stat st={0},expected={0};
    int fd_rc=fstat(fd,&st);
    int path_rc=lstat(FB_PATH,&expected);
    if (fd_rc || path_rc || !S_ISREG(st.st_mode) ||
        !S_ISREG(expected.st_mode) || st.st_ino!=expected.st_ino ||
        st.st_dev!=expected.st_dev || st.st_size!=360*720*4) {
        fprintf(stderr,"HWC fixture ioctl rejected: request=%#x fd=%d stat=%d/%d mode=%o/%o ino=%" PRIu64 "/%" PRIu64 " dev=%" PRIu64 "/%" PRIu64 " size=%" PRId64 "\n",
                (unsigned int)request,fd,fd_rc,path_rc,(unsigned int)st.st_mode,
                (unsigned int)expected.st_mode,(uint64_t)st.st_ino,(uint64_t)expected.st_ino,
                (uint64_t)st.st_dev,(uint64_t)expected.st_dev,(int64_t)st.st_size);
        errno=ENOTTY;
        return -1;
    }
    va_list ap;
    va_start(ap,request);
    if ((unsigned int)request==FBIOBLANK) {
        int v=va_arg(ap,int);
        va_end(ap);
        if (v==FB_BLANK_POWERDOWN || v==FB_BLANK_UNBLANK) { ++blanks; return 0; }
        ++bad; errno=EINVAL; return -1;
    }
    void *arg=va_arg(ap,void *);
    va_end(ap);
    if (!arg) { ++bad; errno=EINVAL; return -1; }
    switch ((unsigned int)request) {
    case FBIOGET_FSCREENINFO: {
        struct fb_fix_screeninfo *f=arg;
        memset(f,0,sizeof(*f)); f->line_length=1440; f->smem_len=360*720*4;
        ++fixed; return 0;
    }
    case FBIOGET_VSCREENINFO: {
        struct fb_var_screeninfo *v=arg;
        memset(v,0,sizeof(*v));
        v->xres=v->xres_virtual=360; v->yres=360; v->yres_virtual=720;
        v->width=v->height=33; v->bits_per_pixel=invalid_geometry?16:32;
        v->red.offset=16; v->red.length=8; v->green.offset=8; v->green.length=8;
        v->blue.length=8; v->transp.offset=24; v->transp.length=8;
        ++variable; return 0;
    }
    case FBIOPUT_VSCREENINFO: {
        const struct fb_var_screeninfo *v=arg;
        if (v->xres!=360 || v->yres!=360 || v->bits_per_pixel!=32) break;
        ++wake; return 0;
    }
    case R800_S3CFB_WIN_CONFIG: {
        struct r800_win_config_data *d=arg;
        if (d->config[1].state==R800_WIN_STATE_BUFFER) return overlay_config(d);
        struct r800_win_config *c=&d->config[0];
        struct stat pixel, expected_pixel;
        const struct r800_frame src={0,0,360,360,368,360},dst={0,0,360,360,360,360};
        if (!zero_copy || d->retire_fence!=-1 || d->fd_odma!=-1 ||
            c->state!=R800_WIN_STATE_BUFFER || c->fd_idma[1]!=-1 || c->fd_idma[2]!=-1 ||
            c->rel_fence!=-1 || c->acq_fence<0 || fcntl(c->acq_fence,F_GETFD)<0 ||
            c->plane_alpha!=255 || c->blending!=R800_BLENDING_NONE || c->channel ||
            c->format!=R800_FMT_RGBA_8888 || c->protection || c->compression ||
            memcmp(&c->src,&src,sizeof(src)) || memcmp(&c->dst,&dst,sizeof(dst)) ||
            fstat(c->fd_idma[0],&pixel) || lstat("/dev/graphics/pixels",&expected_pixel) ||
            !S_ISREG(pixel.st_mode) || !S_ISREG(expected_pixel.st_mode) ||
            pixel.st_dev!=expected_pixel.st_dev || pixel.st_ino!=expected_pixel.st_ino ||
            pixel.st_size!=368*360*4) break;
        for (int i=1;i<=R800_MAX_DECON_WIN;++i) {
            const struct r800_win_config *w=&d->config[i];
            if (w->state!=R800_WIN_STATE_DISABLED || w->fd_idma[0]!=-1 ||
                w->fd_idma[1]!=-1 || w->fd_idma[2]!=-1 || w->acq_fence!=-1 || w->rel_fence!=-1) {
                ++bad; errno=EINVAL; return -1;
            }
        }
        ++win_calls;
        if (atomic_exchange(&fail_win,0)) { errno=ENOTTY; return -1; }
        int rel=eventfd(7,EFD_CLOEXEC|EFD_NONBLOCK);
        if (rel<0) break;
        int retire=eventfd(13,EFD_CLOEXEC|EFD_NONBLOCK);
        if (retire<0) { close(rel); break; }
        last_release=rel; last_retire=retire;
        c->rel_fence=rel; d->retire_fence=retire;
        ++win_success;
        return 0;
    }
    case FBIOPAN_DISPLAY: {
        const struct fb_var_screeninfo *v=arg;
        unsigned int want=(atomic_load(&pans)%2==0)?360:0;
        if (v->xoffset || v->yoffset!=want || v->xres!=360 || v->yres!=360 ||
            v->bits_per_pixel!=32) break;
        ++pans; return 0;
    }
    case VSYNC_CMD: {
        uint32_t v=*(uint32_t *)arg;
        if (v==1) ++vsync_on;
        else if (!v) ++vsync_off;
        else break;
        return 0;
    }
    case POWER_CMD:
        if (*(uint32_t *)arg!=1) break;
        ++power;
        if (atomic_exchange(&fail_power,0)) { errno=EIO; return -1; }
        return 0;
    default: break;
    }
    fprintf(stderr,"HWC fixture unexpected request=%#x\n",(unsigned int)request);
    ++bad; errno=EINVAL; return -1;
}
