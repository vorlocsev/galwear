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

#define FB_PATH "/dev/graphics/fb0"
#define VSYNC_CMD _IOW('F',206,uint32_t)
#define POWER_CMD _IOW('F',223,uint32_t)
static atomic_uint bad, invalid_geometry, fail_power, fixed, variable, wake, blanks, power, vsync_on, vsync_off, pans;
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
    default: return UINT32_MAX;
    }
}
void r800_hwc_fixture_mode(unsigned int mode)
{
    invalid_geometry=mode==1;
    fail_power=mode==2;
}
int __system_property_get(const char *name,char *value)
{
    const char *v="";
    if (!strcmp(name,"debug.r800.layer_stride")) v="96";
    else if (!strcmp(name,"debug.r800.realblank")) v="1";
    else if (!strcmp(name,"debug.r800.zerocopy")) v="0";
    strcpy(value,v);
    return (int)strlen(v);
}
int __system_property_set(const char *name,const char *value)
{
    if (!strcmp(name,"debug.r800.hwc_woke") && !strcmp(value,"1")) return 0;
    ++bad;
    return -1;
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
