/* Test-only libhardware substitute; never included in firmware. */
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <hardware/gralloc.h>

#define PIXELS "/dev/graphics/pixels"
#define SIZE (368*360*4)
static void *mapped;
static buffer_handle_t active;
static int lock_buffer(const gralloc_module_t *m, buffer_handle_t h, int usage,
                       int l,int t,int w,int height,void **out)
{
    (void)m;
    struct stat s,p;
    if (!out || !h || mapped || h->version!=sizeof(native_handle_t) ||
        h->numFds!=1 || h->numInts!=4 || l || t || w!=360 || height!=360 ||
        usage!=GRALLOC_USAGE_SW_READ_OFTEN || h->data[2]!=360 ||
        h->data[3]!=360 || h->data[4]!=368 ||
        (h->data[1]!=HAL_PIXEL_FORMAT_RGBA_8888 && h->data[1]!=HAL_PIXEL_FORMAT_BGRA_8888) ||
        fstat(h->data[0],&s) || lstat(PIXELS,&p) || !S_ISREG(s.st_mode) ||
        !S_ISREG(p.st_mode) || s.st_dev!=p.st_dev || s.st_ino!=p.st_ino ||
        s.st_size!=SIZE || (fcntl(h->data[0],F_GETFL)&O_ACCMODE)!=O_RDONLY)
        return -EINVAL;
    void *v=mmap(NULL,SIZE,PROT_READ,MAP_SHARED,h->data[0],0);
    if (v==MAP_FAILED) return -errno;
    mapped=v; active=h; *out=v;
    return 0;
}
static int unlock_buffer(const gralloc_module_t *m,buffer_handle_t h)
{
    (void)m;
    if (!mapped || active!=h) return -EINVAL;
    if (munmap(mapped,SIZE)) return -errno;
    mapped=NULL; active=NULL;
    return 0;
}
static const gralloc_module_t fixture={
    .common={.tag=HARDWARE_MODULE_TAG,.id=GRALLOC_HARDWARE_MODULE_ID,
             .name="GalWear synthetic gralloc",.author="GalWear test"},
    .lock=lock_buffer,.unlock=unlock_buffer
};
int hw_get_module(const char *id,const struct hw_module_t **module)
{
    if (!id || !module || strcmp(id,GRALLOC_HARDWARE_MODULE_ID)) return -EINVAL;
    *module=&fixture.common;
    return 0;
}
