/* Synthetic ARM32 glibc probe. No GNSS, no hardware or user data. */
typedef unsigned int size_t;
typedef unsigned long pthread_t;
extern int puts(const char *);
extern int fflush(void *);
extern const char *gnu_get_libc_version(void);
extern int strcmp(const char *,const char *);
extern int pthread_create(pthread_t *,const void *,void *(*)(void *),void *);
extern int pthread_join(pthread_t,void **);
extern void *dlopen(const char *,int);
extern void *dlsym(void *,const char *);
extern int dlclose(void *);
extern int __libc_start_main(int (*)(int,char **,char **),int,char **,
                             void (*)(void),void (*)(void),void *);
static __thread volatile int tls = 17;
static int mark(const char *line)
{
    return puts(line) < 0 || fflush(0) != 0;
}
static void *worker(void *arg)
{
    int *result = arg;
    if (tls != 17) return 0;
    tls = 42;
    *result = tls == 42;
    return 0;
}
__attribute__((used)) static int main_probe(int argc,char **argv,char **envp)
{
    pthread_t thread;
    int result = 0;
    void *handle;
    int (*fn)(int);
    (void)argc; (void)argv; (void)envp;
    if (strcmp(gnu_get_libc_version(),"2.24") != 0) return 10;
    if (mark("GLIBC_2_24=PASS")) return 16;
    if (tls != 17) return 11;
    tls = 91;
    if (tls != 91) return 11;
    if (mark("MAIN_TLS=PASS")) return 16;
    if (pthread_create(&thread,0,worker,&result)) return 12;
    if (pthread_join(thread,0) || !result || tls != 91) return 13;
    if (mark("PTHREAD_TLS=PASS")) return 16;
    handle = dlopen("/probe_plugin.so",2);
    if (!handle) return 14;
    if (mark("DLOPEN=PASS")) return 16;
    fn = (int (*)(int))dlsym(handle,"probe_add");
    if (!fn || fn(21) != 42) return 15;
    if (mark("DLSYM=PASS")) return 16;
    if (dlclose(handle)) return 17;
    if (mark("DLCLOSE=PASS") || mark("DLOPEN_DLSYM=PASS") ||
        mark("R800_GLIBC_QEMU_PROBE=PASS")) return 16;
    return 0;
}
__attribute__((used,naked,noreturn)) void _start(void)
{
    __asm__ volatile(
        "mov fp, #0\n"
        "mov lr, #0\n"
        "pop {r1}\n"
        "mov r2, sp\n"
        "push {r2}\n"
        "push {r0}\n"
        "mov ip, #0\n"
        "push {ip}\n"
        "mov r3, #0\n"
        "ldr r0, =main_probe\n"
        "bl __libc_start_main\n"
        "udf #0\n");
}
