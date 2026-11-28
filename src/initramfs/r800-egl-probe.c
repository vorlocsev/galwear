/* ARM32 Bionic dlsym smoke; never calls EGL/GLES or opens a GPU device. */
#include <assert.h>
#include <dlfcn.h>
#include <dirent.h>
#include <stdio.h>
#include <string.h>
static const char *egl[]={"eglGetDisplay","eglInitialize","eglChooseConfig","eglCreateContext",
 "eglDestroyContext","eglMakeCurrent","eglGetProcAddress","eglSwapBuffers","eglTerminate",0};
static const char *gles[]={"glGetString","glGetError","glClear","glDrawArrays","glCreateShader",
 "glShaderSource","glCompileShader","glCreateProgram","glLinkProgram","glUseProgram",0};
static int fds(void) {
    DIR *d=opendir("/proc/self/fd");assert(d);
    int n=0;struct dirent *e;
    while((e=readdir(d)))if(strcmp(e->d_name,".")&&strcmp(e->d_name,".."))++n;
    assert(closedir(d)==0);return n;
}
static void *load(const char *name) {
    void *h=dlopen(name,RTLD_NOW|RTLD_LOCAL);
    if(!h)fprintf(stderr,"load %s: %s\n",name,dlerror());
    assert(h);return h;
}
static void require(void *h,const char **names) {
    for(;*names;++names) {
        dlerror();void *p=dlsym(h,*names);const char *error=dlerror();
        if(!p||error)fprintf(stderr,"symbol %s: %s\n",*names,error?error:"null");
        assert(p&&!error);
    }
}
static void absent(void *h,const char *name) {
    dlerror();assert(!dlsym(h,name));assert(dlerror());
}
static void exercise(void) {
    void *e=load("libEGL_galwear_fixture.so");
    void *g=load("libGLESv2_galwear_fixture.so");
    require(e,egl);require(g,gles);absent(e,"glUseProgram");absent(g,"eglInitialize");
    assert(dlclose(g)==0);assert(dlclose(e)==0);
    void *c=load("libGLES_galwear_fixture.so");
    require(c,egl);require(c,gles);assert(dlclose(c)==0);
    void *bad=load("libGLESv2_galwear_incomplete.so");
    absent(bad,"glUseProgram");assert(dlclose(bad)==0);
    dlerror();assert(!dlopen("libGLES_galwear_private.so",RTLD_NOW|RTLD_LOCAL));assert(dlerror());
    dlerror();assert(!dlopen("/vendor/lib/egl/libGLES_galwear_private.so",RTLD_NOW|RTLD_LOCAL));assert(dlerror());
    g=load("libGLESv2_galwear_fixture.so");require(g,gles);assert(dlclose(g)==0);
}
int main(void) {
    exercise(); /* warm up lazy runtime resources before fd baseline */
    int before=fds();
    for(int i=0;i<4;++i){exercise();assert(fds()==before);}
    puts("EGL_LINK_FIXTURE_PASS cycles=4 split=1 combined=1 missing=1 private_denials=2 recovery=1 fd_stable=1");
    return 0;
}
