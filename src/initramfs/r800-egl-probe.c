/* ARM32 Bionic dlsym and synthetic EGL lifecycle only; no GPU device. */
#include <EGL/egl.h>
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
static void *resolve(void *h,const char *name) {
    dlerror();
    void *p=dlsym(h,name);
    assert(p&&!dlerror());
    return p;
}
#define RESOLVE(name) __typeof__(&name) p_##name=(__typeof__(&name))resolve(h,#name)
#define EXPECT_ERROR(e) do {assert(p_eglGetError()==(e));assert(p_eglGetError()==EGL_SUCCESS);}while(0)
static void lifecycle(void *h) {
    RESOLVE(eglGetDisplay);RESOLVE(eglInitialize);RESOLVE(eglGetError);
    RESOLVE(eglBindAPI);RESOLVE(eglChooseConfig);RESOLVE(eglCreateContext);
    RESOLVE(eglCreatePbufferSurface);RESOLVE(eglMakeCurrent);RESOLVE(eglSwapBuffers);
    RESOLVE(eglDestroySurface);RESOLVE(eglDestroyContext);RESOLVE(eglTerminate);
    const EGLint cfgattrs[]={EGL_NONE};
    const EGLint ctxattrs[]={EGL_CONTEXT_CLIENT_VERSION,2,EGL_NONE};
    const EGLint pbattrs[]={EGL_WIDTH,8,EGL_HEIGHT,8,EGL_NONE};
    EGLDisplay d=p_eglGetDisplay(EGL_DEFAULT_DISPLAY);
    assert(d!=EGL_NO_DISPLAY);
    EGLint major=0,minor=0,count=0;
    EGLConfig config=0;
    assert(!p_eglInitialize(EGL_NO_DISPLAY,0,0));EXPECT_ERROR(EGL_BAD_DISPLAY);
    assert(!p_eglChooseConfig(d,cfgattrs,&config,1,&count));EXPECT_ERROR(EGL_NOT_INITIALIZED);
    assert(p_eglInitialize(d,&major,&minor)&&major==1&&minor==4);
    assert(p_eglBindAPI(EGL_OPENGL_ES_API));
    assert(p_eglChooseConfig(d,cfgattrs,&config,1,&count)&&count==1&&config);
    assert(p_eglCreateContext(d,(EGLConfig)0,EGL_NO_CONTEXT,ctxattrs)==EGL_NO_CONTEXT);
    EXPECT_ERROR(EGL_BAD_CONFIG);
    EGLContext c=p_eglCreateContext(d,config,EGL_NO_CONTEXT,ctxattrs);
    assert(c!=EGL_NO_CONTEXT);
    assert(p_eglCreatePbufferSurface(d,(EGLConfig)0,pbattrs)==EGL_NO_SURFACE);
    EXPECT_ERROR(EGL_BAD_CONFIG);
    /* Roll back a partially prepared context, then create a fresh one. */
    assert(p_eglDestroyContext(d,c));
    c=p_eglCreateContext(d,config,EGL_NO_CONTEXT,ctxattrs);
    assert(c!=EGL_NO_CONTEXT);
    EGLSurface s=p_eglCreatePbufferSurface(d,config,pbattrs);
    assert(s!=EGL_NO_SURFACE);
    assert(!p_eglMakeCurrent(d,s,s,EGL_NO_CONTEXT));EXPECT_ERROR(EGL_BAD_CONTEXT);
    assert(p_eglMakeCurrent(d,s,s,c));
    assert(!p_eglSwapBuffers(d,EGL_NO_SURFACE));EXPECT_ERROR(EGL_BAD_SURFACE);
    for(int i=0;i<3;++i)assert(p_eglSwapBuffers(d,s));
    assert(p_eglMakeCurrent(d,EGL_NO_SURFACE,EGL_NO_SURFACE,EGL_NO_CONTEXT));
    assert(p_eglDestroySurface(d,s));
    assert(p_eglDestroyContext(d,c));
    assert(p_eglTerminate(d));
    assert(!p_eglChooseConfig(d,cfgattrs,&config,1,&count));EXPECT_ERROR(EGL_NOT_INITIALIZED);
}
static void lifecycle_cycles(void) {
    void *h=load("libEGL_galwear_lifecycle.so");
    for(int i=0;i<4;++i)lifecycle(h);
    assert(dlclose(h)==0);
    h=load("libEGL_galwear_lifecycle.so");lifecycle(h);assert(dlclose(h)==0);
}
int main(void) {
    exercise(); /* warm up lazy runtime resources before fd baseline */
    int before=fds();
    for(int i=0;i<4;++i){exercise();assert(fds()==before);}
    lifecycle_cycles();
    assert(fds()==before);
    puts("EGL_LINK_FIXTURE_PASS cycles=4 split=1 combined=1 missing=1 private_denials=2 recovery=1 fd_stable=1");
    puts("EGL_LIFECYCLE_FIXTURE_PASS cycles=5 swaps=15 errors=35 partial_rollback=5 reload=1 fd_stable=1");
    return 0;
}
