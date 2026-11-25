/* SM-R800 bring-up /init: freestanding, raw aarch64 syscalls, logs to /dev/kmsg. */
typedef unsigned long u64; typedef long s64;
#define AT_FDCWD -100
static s64 sc(s64 n, s64 a, s64 b, s64 c, s64 d, s64 e) {
  register s64 x8 asm("x8") = n, x0 asm("x0") = a, x1 asm("x1") = b, x2 asm("x2") = c, x3 asm("x3") = d, x4 asm("x4") = e;
  asm volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4) : "memory");
  return x0;
}
static s64 sc6(s64 n, s64 a, s64 b, s64 c, s64 d, s64 e, s64 f) {
  register s64 x8 asm("x8") = n, x0 asm("x0") = a, x1 asm("x1") = b, x2 asm("x2") = c, x3 asm("x3") = d, x4 asm("x4") = e, x5 asm("x5") = f;
  asm volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5) : "memory");
  return x0;
}
#define openat(p,f) sc(56,AT_FDCWD,(s64)(p),(f),0,0)
#define close(fd) sc(57,(fd),0,0,0,0)
#define read(fd,b,n) sc(63,(fd),(s64)(b),(n),0,0)
#define write(fd,b,n) sc(64,(fd),(s64)(b),(n),0,0)
#define mkdir(p) sc(34,AT_FDCWD,(s64)(p),0755,0,0)
#define mount(s,t,ty) sc(40,(s64)(s),(s64)(t),(s64)(ty),0,0)
static int kfd = -1;
static u64 slen(const char *s) { u64 n = 0; while (s[n]) n++; return n; }
static void klog(const char *s) {
  char b[512]; u64 n = 0; const char *p = "<0>r800-init: ";
  while (*p) b[n++] = *p++;
  while (*s && n < sizeof(b) - 2) b[n++] = *s++;
  b[n++] = '\n';
  if (kfd >= 0) write(kfd, b, n); else write(1, b, n);
}
static void num(char *o, s64 v) { char t[24]; int i = 0; if (v < 0) { *o++ = '-'; v = -v; }
  do { t[i++] = '0' + v % 10; v /= 10; } while (v); while (i) *o++ = t[--i]; *o = 0; }
static void kv(const char *k, s64 v) { char b[128]; u64 n = 0; while (*k) b[n++] = *k++; num(b + n, v); klog(b); }
static void dumpfile(const char *path, int maxlines) {
  static char buf[8192]; char line[400];
  s64 fd = openat(path, 0); if (fd < 0) { kv("open failed ", fd); klog(path); return; }
  s64 n = read(fd, buf, sizeof(buf) - 1); close(fd); if (n < 0) n = 0; buf[n] = 0;
  { char h[128] = "--- "; u64 i = 4; const char *p = path; while (*p) h[i++] = *p++; h[i] = 0; klog(h); }
  int lines = 0; u64 j = 0;
  for (s64 i = 0; i <= n && lines < maxlines; i++) {
    if (i == n || buf[i] == '\n') { line[j] = 0; if (j) { klog(line); lines++; } j = 0; }
    else if (j < sizeof(line) - 1) line[j++] = buf[i];
  }
}
void _start(void) {
  mkdir("/dev"); mkdir("/proc"); mkdir("/sys");
  s64 r1 = mount("devtmpfs", "/dev", "devtmpfs");
  kfd = openat("/dev/kmsg", 1);
  klog("=== hello from userspace, pid 1 is alive ===");
  kv("devtmpfs mount: ", r1);
  kv("proc mount: ", mount("proc", "/proc", "proc"));
  kv("sysfs mount: ", mount("sysfs", "/sys", "sysfs"));
  { s64 fd = openat("/proc/sys/kernel/printk_devkmsg", 1); kv("printk_devkmsg on: ", fd >= 0 ? write(fd, "on\n", 3) : fd); if (fd >= 0) close(fd); }
  for (int i = 0; i < 50; i++) {  /* wait up to 5 s for the eMMC */
    static char pb[4096]; s64 fd = openat("/proc/partitions", 0), n = fd >= 0 ? read(fd, pb, sizeof(pb) - 1) : 0;
    if (fd >= 0) close(fd); if (n < 0) n = 0; pb[n] = 0;
    int found = 0; for (s64 j = 0; j + 7 < n; j++) if (pb[j]=='m'&&pb[j+1]=='m'&&pb[j+2]=='c'&&pb[j+3]=='b'&&pb[j+4]=='l'&&pb[j+5]=='k'&&pb[j+6]=='0') { found = 1; break; }
    if (found) { kv("mmcblk0 present after ms: ", i * 100); break; }
    struct { s64 s, ns; } t = { 0, 100000000 }; sc(101, (s64)&t, 0, 0, 0, 0);
  }
  dumpfile("/proc/version", 3);
  dumpfile("/proc/cmdline", 3);
  dumpfile("/proc/partitions", 40);
  dumpfile("/proc/meminfo", 4);
  dumpfile("/proc/cpuinfo", 12);
  /* ---- framebuffer test ---- */
  s64 fb = -1;
  for (int i = 0; i < 100 && fb < 0; i++) {   /* wait up to 10 s for /dev/fb0 */
    fb = openat("/dev/fb0", 2);
    if (fb < 0) { struct { s64 s, ns; } t = { 0, 100000000 }; sc(101, (s64)&t, 0, 0, 0, 0); }
  }
  kv("open /dev/fb0: ", fb);
  dumpfile("/proc/fb", 4);
  unsigned char var[160], fix[80]; unsigned int *pix = 0;
  unsigned int xres = 0, yres = 0, bpp = 0, line = 0, smem = 0;
  if (fb >= 0) {
    s64 vr = sc(29, fb, 0x4600, (s64)var, 0, 0);
    s64 fr = sc(29, fb, 0x4602, (s64)fix, 0, 0);
    kv("FBIOGET_VSCREENINFO: ", vr);
    kv("FBIOGET_FSCREENINFO: ", fr);
    if (vr == 0 && fr == 0) {
    xres = *(unsigned int *)(var + 0); yres = *(unsigned int *)(var + 4);
    bpp = *(unsigned int *)(var + 24);
    smem = *(unsigned int *)(fix + 24); line = *(unsigned int *)(fix + 48);
    kv("xres ", xres); kv("yres ", yres); kv("bpp ", bpp); kv("line_length ", line); kv("smem_len ", smem);
    kv("red.offset ", *(unsigned int *)(var + 32)); kv("green.offset ", *(unsigned int *)(var + 44));
    kv("blue.offset ", *(unsigned int *)(var + 56));
    { char id[17]; for (int k = 0; k < 16; k++) id[k] = fix[k]; id[16] = 0; klog(id); }
    kv("FBIOBLANK unblank: ", sc(29, fb, 0x4611, 0, 0, 0));
    /* A failed ioctl or unsupported geometry must not prevent handover. */
    if (bpp == 32 && xres == 360 && yres == 360 &&
        line >= (u64)xres * 4 && (line % 4) == 0 &&
        (u64)(yres - 1) * line + (u64)xres * 4 <= smem &&
        smem <= 64U * 1024U * 1024U) {
      s64 m = sc6(222, 0, smem, 3, 1, fb, 0);
      kv("mmap: ", (m < 0 && m > -4096) ? m : 1);
      if (m > 0) pix = (unsigned int *)m;
    } else {
      klog("framebuffer geometry unsupported; skipping splash");
    }
    } else {
      klog("framebuffer metadata unavailable; skipping splash");
    }
  }
  unsigned int cols[3] = { 0xffff0000, 0xff00ff00, 0xff0000ff };
  /* ---- hand over to /data/r800dev/start.sh ---- */
  mkdir("/data");
  /*
   * Normal rw mount WITH journal replay. It used to be ro,noload (later remounted
   * rw by start.sh), which left Tizen's journal unreplayed: Tizen's next mount then
   * replayed stale metadata over everything Android had written to p17 (run 112:
   * helper updates and the STAY flag silently rolled back).
   */
  s64 data_mount = sc(40, (s64)"/dev/mmcblk0p17", (s64)"/data", (s64)"ext4", 0, 0);
  kv("mount p17 rw: ", data_mount);
  /*
   * Boot splash: /data/r800dev/splash.raw (xres*yres XRGB, made from param's
   * logo.jpg, the "Galaxy Watch" S-Boot shows), so the screen stays on the logo
   * until Android's boot animation. Black when missing. (It used to be R/G/B bars,
   * the display-path test frame; those now only mean "hand-over failed".)
   */
  if (pix && bpp == 32 && line && yres) {
    for (unsigned int y = 0; y < yres; y++) {
      unsigned int *row = (unsigned int *)((char *)pix + (u64)y * line);
      for (unsigned int x = 0; x < xres; x++) row[x] = 0xff000000;
    }
    s64 sf = data_mount == 0 ? openat("/data/r800dev/splash.raw", 0) : -1;
    if (sf >= 0) {
      for (unsigned int y = 0; y < yres; y++)
        if (read(sf, (char *)pix + (u64)y * line, xres * 4) != (s64)(xres * 4)) break;
      close(sf);
    }
    kv("splash: ", sf);
    sc(29, fb, 0x4606, (s64)var, 0, 0);
  }
  if (data_mount == 0) {
    char *argv[] = { "sh", "/data/r800dev/start.sh", 0 };
    char *envp[] = { "PATH=/bin:/sbin:/data/r800dev/bin", "HOME=/", "TERM=vt100", 0 };
    kv("execve start.sh: ", sc(221, (s64)"/data/r800dev/bin/busybox", (s64)argv, (s64)envp, 0, 0));
  }
  klog("hand-over failed, staying in the test loop");
  for (int i = 0;; i++) {
    struct { s64 s, ns; } ts = { 5, 0 };
    if (pix && bpp == 32 && line && yres) {
      for (unsigned int y = 0; y < yres; y++) {
        unsigned int *row = (unsigned int *)((char *)pix + (u64)y * line);
        unsigned int c = cols[(y * 3 / yres + i) % 3];
        for (unsigned int x = 0; x < xres; x++) row[x] = (x < 8 || y < 8 || x >= xres - 8 || y >= yres - 8) ? 0xffffffff : c;
      }
      kv("pan: ", sc(29, fb, 0x4606, (s64)var, 0, 0));
    }
    dumpfile("/proc/uptime", 1);
    sc(101, (s64)&ts, 0, 0, 0, 0);
  }
}
