/* Synthetic symbol provider only. Never install as a real EGL driver. */
#include <EGL/egl.h>
#include <GLES2/gl2.h>
#ifdef FIXTURE_EGL
EGLDisplay eglGetDisplay(EGLNativeDisplayType d) {(void)d;return EGL_NO_DISPLAY;}
EGLBoolean eglInitialize(EGLDisplay d,EGLint *a,EGLint *b) {(void)d;(void)a;(void)b;return EGL_FALSE;}
EGLBoolean eglChooseConfig(EGLDisplay d,const EGLint *a,EGLConfig *c,EGLint n,EGLint *o) {(void)d;(void)a;(void)c;(void)n;(void)o;return EGL_FALSE;}
EGLContext eglCreateContext(EGLDisplay d,EGLConfig c,EGLContext s,const EGLint *a) {(void)d;(void)c;(void)s;(void)a;return EGL_NO_CONTEXT;}
EGLBoolean eglDestroyContext(EGLDisplay d,EGLContext c) {(void)d;(void)c;return EGL_FALSE;}
EGLBoolean eglMakeCurrent(EGLDisplay d,EGLSurface a,EGLSurface b,EGLContext c) {(void)d;(void)a;(void)b;(void)c;return EGL_FALSE;}
__eglMustCastToProperFunctionPointerType eglGetProcAddress(const char *p) {(void)p;return 0;}
EGLBoolean eglSwapBuffers(EGLDisplay d,EGLSurface s) {(void)d;(void)s;return EGL_FALSE;}
EGLBoolean eglTerminate(EGLDisplay d) {(void)d;return EGL_FALSE;}
#endif
#ifdef FIXTURE_GLES
const GLubyte *glGetString(GLenum n) {(void)n;return 0;}
GLenum glGetError(void) {return GL_INVALID_OPERATION;}
void glClear(GLbitfield m) {(void)m;}
void glDrawArrays(GLenum m,GLint f,GLsizei n) {(void)m;(void)f;(void)n;}
GLuint glCreateShader(GLenum t) {(void)t;return 0;}
void glShaderSource(GLuint s,GLsizei n,const GLchar *const *v,const GLint *l) {(void)s;(void)n;(void)v;(void)l;}
void glCompileShader(GLuint s) {(void)s;}
GLuint glCreateProgram(void) {return 0;}
void glLinkProgram(GLuint p) {(void)p;}
#ifndef FIXTURE_INCOMPLETE
void glUseProgram(GLuint p) {(void)p;}
#endif
#endif
