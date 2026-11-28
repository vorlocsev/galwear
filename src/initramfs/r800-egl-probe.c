/* ARM32 Bionic dlsym and synthetic EGL lifecycle only; no GPU device. */
#include <EGL/egl.h>
#include <EGL/eglext.h>
#include <GLES2/gl2.h>
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
static void gles_context(void *h,int stage) {
    RESOLVE(glGetString);RESOLVE(glGetError);RESOLVE(glCreateShader);
    RESOLVE(glShaderSource);RESOLVE(glCompileShader);RESOLVE(glGetShaderiv);
    RESOLVE(glCreateProgram);RESOLVE(glLinkProgram);RESOLVE(glGetProgramiv);
    RESOLVE(glUseProgram);RESOLVE(glClear);RESOLVE(glDrawArrays);
    int (*count)(void)=(int (*)(void))resolve(h,"galwear_fixture_draw_count");
    if(stage!=1) {
        assert(p_glGetString(GL_VERSION)==0);
        assert(p_glGetError()==GL_INVALID_OPERATION);
        assert(p_glGetError()==GL_NO_ERROR);
        assert(count()==(stage==2?3:0));
        return;
    }
    assert(strcmp((const char *)p_glGetString(GL_VERSION),"OpenGL ES 2.0 GalWear synthetic")==0);
    assert(count()==0);
    assert(p_glGetError()==GL_NO_ERROR);
    p_glDrawArrays(GL_TRIANGLES,0,3);
    assert(p_glGetError()==GL_INVALID_OPERATION);
    GLuint shader=p_glCreateShader(GL_VERTEX_SHADER);
    assert(shader);
    const GLchar *bad="invalid",*good="void main(){gl_Position=vec4(0.0);}";
    GLint ok=-1;
    p_glShaderSource(shader,1,&bad,0);p_glCompileShader(shader);
    p_glGetShaderiv(shader,GL_COMPILE_STATUS,&ok);assert(ok==0);
    GLuint program=p_glCreateProgram();assert(program);
    p_glLinkProgram(program);p_glGetProgramiv(program,GL_LINK_STATUS,&ok);assert(ok==0);
    p_glUseProgram(program);assert(p_glGetError()==GL_INVALID_OPERATION);
    p_glShaderSource(shader,1,&good,0);p_glCompileShader(shader);
    p_glGetShaderiv(shader,GL_COMPILE_STATUS,&ok);assert(ok==1);
    p_glLinkProgram(program);p_glGetProgramiv(program,GL_LINK_STATUS,&ok);assert(ok==1);
    p_glUseProgram(program);p_glClear(GL_COLOR_BUFFER_BIT);
    for(int i=0;i<3;++i)p_glDrawArrays(GL_TRIANGLES,0,3);
    assert(p_glGetError()==GL_NO_ERROR && count()==3);
    p_glUseProgram(0);
}
struct fence_api {
    PFNEGLCREATESYNCKHRPROC create;
    PFNEGLDESTROYSYNCKHRPROC destroy;
    PFNEGLCLIENTWAITSYNCKHRPROC wait;
    PFNEGLGETSYNCATTRIBKHRPROC get;
};
static struct fence_api extension_api(void *h,EGLDisplay d,int supported) {
    RESOLVE(eglQueryString);RESOLVE(eglGetProcAddress);
    const char *extensions=p_eglQueryString(d,EGL_EXTENSIONS);
    assert(extensions);
    assert(strcmp(extensions,supported?"EGL_KHR_fence_sync":"")==0);
    assert(!p_eglGetProcAddress("eglDupNativeFenceFDANDROID"));
    assert(!p_eglGetProcAddress("eglGalWearUnknown"));
    absent(h,"eglCreateSyncKHR");absent(h,"eglDestroySyncKHR");
    absent(h,"eglClientWaitSyncKHR");absent(h,"eglGetSyncAttribKHR");
    struct fence_api api={
        (PFNEGLCREATESYNCKHRPROC)p_eglGetProcAddress("eglCreateSyncKHR"),
        (PFNEGLDESTROYSYNCKHRPROC)p_eglGetProcAddress("eglDestroySyncKHR"),
        (PFNEGLCLIENTWAITSYNCKHRPROC)p_eglGetProcAddress("eglClientWaitSyncKHR"),
        (PFNEGLGETSYNCATTRIBKHRPROC)p_eglGetProcAddress("eglGetSyncAttribKHR")
    };
    if(supported)assert(api.create&&api.destroy&&api.wait&&api.get);
    else assert(!api.create&&!api.destroy&&!api.wait&&!api.get);
    return api;
}
static void lifecycle(void *h,int with_gles) {
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
    struct fence_api ext=extension_api(h,d,with_gles);
    EGLSyncKHR sync=EGL_NO_SYNC_KHR;
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
    if(with_gles){
        gles_context(h,0);
        assert(ext.create(d,EGL_SYNC_FENCE_KHR,0)==EGL_NO_SYNC_KHR);EXPECT_ERROR(EGL_BAD_MATCH);
    }
    assert(p_eglMakeCurrent(d,s,s,c));
    if(with_gles){
        gles_context(h,1);
        EGLint status=0;
        sync=ext.create(d,EGL_SYNC_FENCE_KHR,0);assert(sync!=EGL_NO_SYNC_KHR);
        assert(ext.get(d,sync,EGL_SYNC_STATUS_KHR,&status)&&status==EGL_UNSIGNALED_KHR);
        assert(ext.wait(d,sync,0,0)==EGL_TIMEOUT_EXPIRED_KHR);
    }
    assert(!p_eglSwapBuffers(d,EGL_NO_SURFACE));EXPECT_ERROR(EGL_BAD_SURFACE);
    for(int i=0;i<3;++i)assert(p_eglSwapBuffers(d,s));
    if(with_gles){
        EGLint status=0;
        assert(ext.get(d,sync,EGL_SYNC_STATUS_KHR,&status)&&status==EGL_SIGNALED_KHR);
        assert(ext.wait(d,sync,0,0)==EGL_CONDITION_SATISFIED_KHR);
        assert(ext.destroy(d,sync));
        assert(!ext.get(d,sync,EGL_SYNC_STATUS_KHR,&status));EXPECT_ERROR(EGL_BAD_PARAMETER);
    }
    assert(p_eglMakeCurrent(d,EGL_NO_SURFACE,EGL_NO_SURFACE,EGL_NO_CONTEXT));
    if(with_gles)gles_context(h,2);
    assert(p_eglDestroySurface(d,s));
    assert(p_eglDestroyContext(d,c));
    assert(p_eglTerminate(d));
    if(with_gles)gles_context(h,3);
    assert(!p_eglChooseConfig(d,cfgattrs,&config,1,&count));EXPECT_ERROR(EGL_NOT_INITIALIZED);
}
static void lifecycle_cycles(void) {
    void *h=load("libEGL_galwear_lifecycle.so");
    for(int i=0;i<4;++i)lifecycle(h,0);
    assert(dlclose(h)==0);
    h=load("libEGL_galwear_lifecycle.so");lifecycle(h,0);assert(dlclose(h)==0);
}
int main(void) {
    exercise(); /* warm up lazy runtime resources before fd baseline */
    int before=fds();
    for(int i=0;i<4;++i){exercise();assert(fds()==before);}
    lifecycle_cycles();
    void *combined=load("libGLES_galwear_context.so");
    for(int i=0;i<4;++i)lifecycle(combined,1);
    assert(dlclose(combined)==0);
    assert(fds()==before);
    puts("EGL_LINK_FIXTURE_PASS cycles=4 split=1 combined=1 missing=1 private_denials=2 recovery=1 fd_stable=1");
    puts("EGL_LIFECYCLE_FIXTURE_PASS cycles=5 swaps=15 errors=35 partial_rollback=5 reload=1 fd_stable=1");
    puts("EGL_GLES_CONTEXT_FIXTURE_PASS cycles=4 draw_model=12 compile_recovery=4 link_recovery=4 context_reset=4 fd_stable=1");
    puts("EGL_EXTENSION_FIXTURE_PASS supported=4 absent=5 proc_only=4 timeout=4 signaled=4 destroy=4 native_fence_absent=9");
    return 0;
}
