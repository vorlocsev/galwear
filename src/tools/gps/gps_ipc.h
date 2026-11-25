/* Linux statx UAPI; no dependency on a glibc stat structure layout. */
#ifndef R800_GPS_IPC_H
#define R800_GPS_IPC_H
#ifdef R800_GPS_BRIDGE_HOST_TEST
#include <errno.h>
#include <sys/file.h>
#include <sys/syscall.h>
#define IPC_STATX SYS_statx
#define IPC_ERRNO errno
#else
long syscall(long, ...);
int flock(int, int);
int openat(int, const char *, int, ...);
int unlinkat(int, const char *, int);
int connect(int, const void *, unsigned int);
int *__errno_location(void);
#define IPC_STATX 397 /* ARM EABI */
#define IPC_ERRNO (*__errno_location())
#define O_DIRECTORY 040000
#define O_CLOEXEC 02000000
#define O_WRONLY 1
#define O_CREAT 0100
#define O_EXCL 0200
#define LOCK_EX 2
#define LOCK_NB 4
#define ENOENT 2
#define ECONNREFUSED 111
#endif
#define IPC_SOCKET "gps.sock"
#define IPC_MARKER "gps.sock.owner"
#define IPC_REQUIRED 0x3dfu /* type, mode, nlink, uid, gid, ctime, ino, size */
struct ipc_time { long long sec; unsigned int nsec; int reserved; };
struct ipc_stat {
    unsigned int mask, blksize;
    unsigned long long attributes;
    unsigned int nlink, uid, gid;
    unsigned short mode, spare;
    unsigned long long ino, size, blocks, attributes_mask;
    struct ipc_time atime, btime, ctime, mtime;
    unsigned int rdev_major, rdev_minor, dev_major, dev_minor;
    unsigned char tail[112];
};
_Static_assert(sizeof(struct ipc_stat)==256,"statx size");
_Static_assert(__builtin_offsetof(struct ipc_stat,ctime)==96,"statx ctime");
_Static_assert(__builtin_offsetof(struct ipc_stat,dev_major)==136,"statx dev");
struct ipc_owner {
    unsigned long long magic, ino;
    long long sec;
    unsigned int nsec, major, minor, reserved;
};
#define IPC_MAGIC 0x5238303047505331ULL
static int ipc_stat_at(int fd,const char *name,struct ipc_stat *st)
{
    int flags=0x100; /* AT_SYMLINK_NOFOLLOW */
    if (!*name) flags|=0x1000; /* AT_EMPTY_PATH */
    if (syscall(IPC_STATX,fd,name,flags,0x7ff,st)<0)
        return IPC_ERRNO==ENOENT ? 0 : -1;
    return (st->mask & IPC_REQUIRED)==IPC_REQUIRED ? 1 : -1;
}
static int ipc_same(const struct ipc_stat *a,const struct ipc_stat *b)
{
    return a->ino==b->ino && a->dev_major==b->dev_major && a->dev_minor==b->dev_minor &&
           a->ctime.sec==b->ctime.sec && a->ctime.nsec==b->ctime.nsec;
}
static int ipc_owned(const struct ipc_stat *st,unsigned int type,unsigned int perms)
{
    return (st->mode&0170000)==type && (st->mode&07777)==perms &&
           st->uid==getuid() && st->nlink==1;
}
static int gps_ipc_lock(const char *dir)
{
    struct ipc_stat st;
    int fd=open(dir,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if (fd<0) return -1;
    if (ipc_stat_at(fd,"",&st)!=1 || (st.mode&0170000)!=0040000 ||
        st.uid!=getuid() || (st.mode&0022) || flock(fd,LOCK_EX|LOCK_NB)!=0) {
        close(fd); return -1;
    }
    return fd;
}
static int gps_ipc_record(int dirfd)
{
    struct ipc_stat st;
    struct ipc_owner owner;
    int fd,ok;
    if (ipc_stat_at(dirfd,IPC_SOCKET,&st)!=1 || !ipc_owned(&st,0140000,0660)) return -1;
    owner=(struct ipc_owner){IPC_MAGIC,st.ino,st.ctime.sec,st.ctime.nsec,
                              st.dev_major,st.dev_minor,0};
    fd=openat(dirfd,IPC_MARKER,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    if (fd<0) return -1;
    ok=write(fd,&owner,sizeof(owner))==(long)sizeof(owner) && fsync(fd)==0;
    if (close(fd)!=0) ok=0;
    return ok && fsync(dirfd)==0 ? 0 : -1;
}
static int gps_ipc_recover(int dirfd,const char *path)
{
    struct ipc_stat st,marker,check;
    struct ipc_owner owner;
    struct { unsigned short family; char path[108]; } addr={0};
    int a=ipc_stat_at(dirfd,IPC_SOCKET,&st), b=ipc_stat_at(dirfd,IPC_MARKER,&marker);
    int fd,rc,err;
    unsigned int i;
    if (a==0 && b==0) return 0;
    if (a!=1 || b!=1 || !ipc_owned(&st,0140000,0660) ||
        !ipc_owned(&marker,0100000,0600) || marker.size!=sizeof(owner)) return -1;
    fd=openat(dirfd,IPC_MARKER,O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC);
    if (fd<0) return -1;
    rc=ipc_stat_at(fd,"",&check)==1 && ipc_same(&marker,&check) &&
       read(fd,&owner,sizeof(owner))==(long)sizeof(owner);
    close(fd);
    if (!rc || owner.magic!=IPC_MAGIC || owner.reserved || owner.ino!=st.ino ||
        owner.sec!=st.ctime.sec || owner.nsec!=st.ctime.nsec ||
        owner.major!=st.dev_major || owner.minor!=st.dev_minor) return -1;
    addr.family=AF_UNIX;
    for(i=0;i<sizeof(addr.path)-1 && path[i];++i) addr.path[i]=path[i];
    if (path[i]) return -1;
    fd=socket(AF_UNIX,SOCK_STREAM|O_NONBLOCK|O_CLOEXEC,0);
    if (fd<0) return -1;
    rc=connect(fd,(const void *)&addr,sizeof(addr)); err=IPC_ERRNO;
    close(fd);
    if (rc==0 || err!=ECONNREFUSED) return -1;
    if (ipc_stat_at(dirfd,IPC_SOCKET,&check)!=1 || !ipc_same(&st,&check) ||
        ipc_stat_at(dirfd,IPC_MARKER,&check)!=1 || !ipc_same(&marker,&check)) return -1;
    if (unlinkat(dirfd,IPC_SOCKET,0)!=0 || unlinkat(dirfd,IPC_MARKER,0)!=0) return -1;
    return fsync(dirfd)==0 ? 0 : -1;
}
#endif
