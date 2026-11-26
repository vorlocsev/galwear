/* Linux ARM EABI fstat64 UAPI, independent of glibc struct stat layout. */
#ifndef R800_GPS_CACHE_ARM_STAT_H
#define R800_GPS_CACHE_ARM_STAT_H
#if !defined(__arm__) || !defined(__ARM_EABI__) || defined(__ARMEB__)
#error Expected little-endian ARM EABI
#endif
struct gps_arm_stat64 {
    unsigned long long dev;
    unsigned char pad0[4];
    unsigned long old_ino;
    unsigned mode, links;
    unsigned long uid, gid;
    unsigned long long rdev;
    unsigned char pad3[4];
    long long size;
    unsigned long blksize;
    unsigned long long blocks;
    unsigned long atime, atime_ns, mtime, mtime_ns, ctime, ctime_ns;
    unsigned long long ino;
};
_Static_assert(sizeof(struct gps_arm_stat64) == 104, "ARM stat64 size");
_Static_assert(__builtin_offsetof(struct gps_arm_stat64, mode) == 16, "ARM mode");
_Static_assert(__builtin_offsetof(struct gps_arm_stat64, links) == 20, "ARM links");
_Static_assert(__builtin_offsetof(struct gps_arm_stat64, size) == 48, "ARM size");
_Static_assert(__builtin_offsetof(struct gps_arm_stat64, mtime) == 80, "ARM mtime");
_Static_assert(__builtin_offsetof(struct gps_arm_stat64, ctime) == 88, "ARM ctime");
/* __NR_fstat64 = __NR_SYSCALL_BASE + 197; EABI base is zero. */
static int gps_cache_stat(int fd, struct gps_cache_meta *out)
{
    struct gps_arm_stat64 st;
    if (syscall(197L, fd, &st) != 0)
        return -1;
    *out = (struct gps_cache_meta){st.mode, st.links, st.size,
                                   st.mtime, st.mtime_ns, st.ctime, st.ctime_ns};
    return 0;
}
#endif
