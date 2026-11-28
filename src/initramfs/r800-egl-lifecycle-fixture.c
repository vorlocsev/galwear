/* Test-only, single-threaded EGL lifecycle model; no graphics implementation. */
#include <EGL/egl.h>
static char display_token,config_token,context_token,surface_token;
#define DISPLAY ((EGLDisplay)&display_token)
#define CONFIG ((EGLConfig)&config_token)
#define CONTEXT ((EGLContext)&context_token)
#define SURFACE ((EGLSurface)&surface_token)
static EGLint error=EGL_SUCCESS;
static int initialized,context,surface,current,bound;
static EGLBoolean fail(EGLint e) {error=e;return EGL_FALSE;}
static EGLBoolean ready(EGLDisplay d) {
    if(d!=DISPLAY)return fail(EGL_BAD_DISPLAY);
    if(!initialized)return fail(EGL_NOT_INITIALIZED);
    return EGL_TRUE;
}
EGLint eglGetError(void) {EGLint e=error;error=EGL_SUCCESS;return e;}
EGLDisplay eglGetDisplay(EGLNativeDisplayType d) {
    if(d==EGL_DEFAULT_DISPLAY)return DISPLAY;
    fail(EGL_BAD_PARAMETER);return EGL_NO_DISPLAY;
}
EGLBoolean eglInitialize(EGLDisplay d,EGLint *major,EGLint *minor) {
    if(d!=DISPLAY)return fail(EGL_BAD_DISPLAY);
    initialized=1;
    if(major)*major=1;
    if(minor)*minor=4;
    return EGL_TRUE;
}
EGLBoolean eglBindAPI(EGLenum api) {
    if(api!=EGL_OPENGL_ES_API)return fail(EGL_BAD_PARAMETER);
    bound=1;return EGL_TRUE;
}
EGLBoolean eglChooseConfig(EGLDisplay d,const EGLint *attrs,EGLConfig *configs,EGLint size,EGLint *count) {
    if(!ready(d))return EGL_FALSE;
    if(!count||size<0)return fail(EGL_BAD_PARAMETER);
    if(attrs&&attrs[0]!=EGL_NONE)return fail(EGL_BAD_ATTRIBUTE);
    *count=1;
    if(configs&&size>0)configs[0]=CONFIG;
    return EGL_TRUE;
}
EGLContext eglCreateContext(EGLDisplay d,EGLConfig c,EGLContext share,const EGLint *attrs) {
    if(!ready(d))return EGL_NO_CONTEXT;
    if(c!=CONFIG){fail(EGL_BAD_CONFIG);return EGL_NO_CONTEXT;}
    if(share!=EGL_NO_CONTEXT){fail(EGL_BAD_CONTEXT);return EGL_NO_CONTEXT;}
    if(!bound||context){fail(EGL_BAD_ALLOC);return EGL_NO_CONTEXT;}
    if(!attrs||attrs[0]!=EGL_CONTEXT_CLIENT_VERSION||attrs[1]!=2||attrs[2]!=EGL_NONE){
        fail(EGL_BAD_ATTRIBUTE);return EGL_NO_CONTEXT;
    }
    context=1;return CONTEXT;
}
EGLSurface eglCreatePbufferSurface(EGLDisplay d,EGLConfig c,const EGLint *attrs) {
    if(!ready(d))return EGL_NO_SURFACE;
    if(c!=CONFIG){fail(EGL_BAD_CONFIG);return EGL_NO_SURFACE;}
    if(surface){fail(EGL_BAD_ALLOC);return EGL_NO_SURFACE;}
    if(!attrs||attrs[0]!=EGL_WIDTH||attrs[1]!=8||attrs[2]!=EGL_HEIGHT||
        attrs[3]!=8||attrs[4]!=EGL_NONE){fail(EGL_BAD_ATTRIBUTE);return EGL_NO_SURFACE;}
    surface=1;return SURFACE;
}
EGLBoolean eglMakeCurrent(EGLDisplay d,EGLSurface draw,EGLSurface read,EGLContext c) {
    if(!ready(d))return EGL_FALSE;
    if(c==EGL_NO_CONTEXT&&draw==EGL_NO_SURFACE&&read==EGL_NO_SURFACE){
        current=0;return EGL_TRUE;
    }
    if(!context||c!=CONTEXT)return fail(EGL_BAD_CONTEXT);
    if(!surface||draw!=SURFACE||read!=SURFACE)return fail(EGL_BAD_SURFACE);
    current=1;return EGL_TRUE;
}
EGLBoolean eglSwapBuffers(EGLDisplay d,EGLSurface s) {
    if(!ready(d))return EGL_FALSE;
    if(!surface||s!=SURFACE)return fail(EGL_BAD_SURFACE);
    /* Model successful completion only for this test's bound surface. */
    if(!current)return fail(EGL_BAD_MATCH);
    return EGL_TRUE;
}
EGLBoolean eglDestroySurface(EGLDisplay d,EGLSurface s) {
    if(!ready(d))return EGL_FALSE;
    if(!surface||s!=SURFACE)return fail(EGL_BAD_SURFACE);
    /* Probe always unbinds first; deferred deletion is not modeled. */
    if(current)return fail(EGL_BAD_ACCESS);
    surface=0;return EGL_TRUE;
}
EGLBoolean eglDestroyContext(EGLDisplay d,EGLContext c) {
    if(!ready(d))return EGL_FALSE;
    if(!context||c!=CONTEXT)return fail(EGL_BAD_CONTEXT);
    if(current)return fail(EGL_BAD_ACCESS);
    context=0;return EGL_TRUE;
}
EGLBoolean eglTerminate(EGLDisplay d) {
    if(!ready(d))return EGL_FALSE;
    initialized=context=surface=current=bound=0;
    return EGL_TRUE;
}
__eglMustCastToProperFunctionPointerType eglGetProcAddress(const char *p) {(void)p;return 0;}
