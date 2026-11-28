/* Test-only, single-threaded EGL lifecycle model; no graphics implementation. */
#include <EGL/egl.h>
#include <EGL/eglext.h>
static char display_token,config_token,context_token,surface_token;
#define DISPLAY ((EGLDisplay)&display_token)
#define CONFIG ((EGLConfig)&config_token)
#define CONTEXT ((EGLContext)&context_token)
#define SURFACE ((EGLSurface)&surface_token)
static EGLint error=EGL_SUCCESS;
static int initialized,context,surface,current,bound;
#ifdef FIXTURE_CONTEXT_GLES
#include <GLES2/gl2.h>
#include <string.h>
static GLenum gl_error;
static char sync_token;
static int sync_live,sync_signaled;
#define SYNC ((EGLSyncKHR)&sync_token)
static int shader,source_ok,compiled,program,linked,active,draws;
static void reset_gl(void) {
    gl_error=GL_NO_ERROR;
    shader=source_ok=compiled=program=linked=active=draws=0;
}
static int gl_ready(void) {
    if(current)return 1;
    gl_error=GL_INVALID_OPERATION;return 0;
}
#else
static void reset_gl(void) {}
#endif
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
    reset_gl();context=1;return CONTEXT;
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
#ifdef FIXTURE_CONTEXT_GLES
    if(sync_live)sync_signaled=1;
#endif
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
    context=0;reset_gl();return EGL_TRUE;
}
EGLBoolean eglTerminate(EGLDisplay d) {
    if(!ready(d))return EGL_FALSE;
    initialized=context=surface=current=bound=0;reset_gl();
#ifdef FIXTURE_CONTEXT_GLES
    sync_live=sync_signaled=0;
#endif
    return EGL_TRUE;
}
const char *eglQueryString(EGLDisplay d,EGLint name) {
    if(!ready(d))return 0;
    if(name!=EGL_EXTENSIONS){fail(EGL_BAD_PARAMETER);return 0;}
#ifdef FIXTURE_CONTEXT_GLES
    return "EGL_KHR_fence_sync";
#else
    return "";
#endif
}
#ifdef FIXTURE_CONTEXT_GLES
/* Single-object, zero-timeout fence model. No real sync_file, waits or GPU. */
static EGLSyncKHR create_sync(EGLDisplay d,EGLenum type,const EGLint *attrs) {
    if(!ready(d))return EGL_NO_SYNC_KHR;
    if(type!=EGL_SYNC_FENCE_KHR){fail(EGL_BAD_ATTRIBUTE);return EGL_NO_SYNC_KHR;}
    if(attrs&&attrs[0]!=EGL_NONE){fail(EGL_BAD_ATTRIBUTE);return EGL_NO_SYNC_KHR;}
    if(!current){fail(EGL_BAD_MATCH);return EGL_NO_SYNC_KHR;}
    if(sync_live){fail(EGL_BAD_ALLOC);return EGL_NO_SYNC_KHR;}
    sync_live=1;sync_signaled=0;return SYNC;
}
static EGLBoolean valid_sync(EGLDisplay d,EGLSyncKHR sync) {
    if(!ready(d))return EGL_FALSE;
    if(!sync_live||sync!=SYNC)return fail(EGL_BAD_PARAMETER);
    return EGL_TRUE;
}
static EGLBoolean destroy_sync(EGLDisplay d,EGLSyncKHR sync) {
    if(!valid_sync(d,sync))return EGL_FALSE;
    sync_live=sync_signaled=0;return EGL_TRUE;
}
static EGLint wait_sync(EGLDisplay d,EGLSyncKHR sync,EGLint flags,EGLTimeKHR timeout) {
    if(!valid_sync(d,sync))return EGL_FALSE;
    if(flags||timeout!=0){fail(EGL_BAD_PARAMETER);return EGL_FALSE;}
    return sync_signaled?EGL_CONDITION_SATISFIED_KHR:EGL_TIMEOUT_EXPIRED_KHR;
}
static EGLBoolean get_sync(EGLDisplay d,EGLSyncKHR sync,EGLint attribute,EGLint *value) {
    if(!valid_sync(d,sync))return EGL_FALSE;
    if(!value)return fail(EGL_BAD_PARAMETER);
    if(attribute!=EGL_SYNC_STATUS_KHR)return fail(EGL_BAD_ATTRIBUTE);
    *value=sync_signaled?EGL_SIGNALED_KHR:EGL_UNSIGNALED_KHR;return EGL_TRUE;
}
#endif
__eglMustCastToProperFunctionPointerType eglGetProcAddress(const char *p) {
#ifdef FIXTURE_CONTEXT_GLES
    if(!p)return 0;
    if(strcmp(p,"eglCreateSyncKHR")==0)return (__eglMustCastToProperFunctionPointerType)create_sync;
    if(strcmp(p,"eglDestroySyncKHR")==0)return (__eglMustCastToProperFunctionPointerType)destroy_sync;
    if(strcmp(p,"eglClientWaitSyncKHR")==0)return (__eglMustCastToProperFunctionPointerType)wait_sync;
    if(strcmp(p,"eglGetSyncAttribKHR")==0)return (__eglMustCastToProperFunctionPointerType)get_sync;
#else
    (void)p;
#endif
    return 0;
}

#ifdef FIXTURE_CONTEXT_GLES
/* Deliberately limited state model. No shader compilation or rasterization. */
const GLubyte *glGetString(GLenum name) {
    if(!gl_ready())return 0;
    if(name==GL_VERSION)return (const GLubyte *)"OpenGL ES 2.0 GalWear synthetic";
    gl_error=GL_INVALID_ENUM;return 0;
}
GLenum glGetError(void) {GLenum e=gl_error;gl_error=GL_NO_ERROR;return e;}
GLuint glCreateShader(GLenum type) {
    if(!gl_ready())return 0;
    if(type!=GL_VERTEX_SHADER){gl_error=GL_INVALID_ENUM;return 0;}
    shader=1;source_ok=compiled=0;return 1;
}
void glShaderSource(GLuint id,GLsizei count,const GLchar *const *strings,const GLint *lengths) {
    if(!gl_ready())return;
    if(id!=1||!shader||count!=1||!strings||!strings[0]||lengths){
        gl_error=GL_INVALID_VALUE;return;
    }
    /* Only recognize the explicit test token; do not parse GLSL. */
    source_ok=strcmp(strings[0],"void main(){gl_Position=vec4(0.0);}") == 0;
    compiled=0;
}
void glCompileShader(GLuint id) {
    if(!gl_ready())return;
    if(id!=1||!shader){gl_error=GL_INVALID_VALUE;return;}
    compiled=source_ok;
}
void glGetShaderiv(GLuint id,GLenum pname,GLint *value) {
    if(!gl_ready())return;
    if(id!=1||!shader||!value||pname!=GL_COMPILE_STATUS){gl_error=GL_INVALID_VALUE;return;}
    *value=compiled;
}
GLuint glCreateProgram(void) {
    if(!gl_ready())return 0;
    program=1;linked=active=0;return 2;
}
/* Test-only model associates the sole shader with the sole program.
 * It does not implement the GLES shader attachment/linking contract. */
void glLinkProgram(GLuint id) {
    if(!gl_ready())return;
    if(id!=2||!program){gl_error=GL_INVALID_VALUE;return;}
    linked=compiled;
}
void glGetProgramiv(GLuint id,GLenum pname,GLint *value) {
    if(!gl_ready())return;
    if(id!=2||!program||!value||pname!=GL_LINK_STATUS){gl_error=GL_INVALID_VALUE;return;}
    *value=linked;
}
void glUseProgram(GLuint id) {
    if(!gl_ready())return;
    if(id==0){active=0;return;}
    if(id!=2||!program||!linked){gl_error=GL_INVALID_OPERATION;return;}
    active=1;
}
void glClear(GLbitfield mask) {
    if(!gl_ready())return;
    if(mask!=GL_COLOR_BUFFER_BIT)gl_error=GL_INVALID_VALUE;
}
void glDrawArrays(GLenum mode,GLint first,GLsizei count) {
    if(!gl_ready())return;
    if(mode!=GL_TRIANGLES){gl_error=GL_INVALID_ENUM;return;}
    if(first<0||count<0){gl_error=GL_INVALID_VALUE;return;}
    if(!active){gl_error=GL_INVALID_OPERATION;return;}
    ++draws;
}
int galwear_fixture_draw_count(void) {return draws;}
#endif
