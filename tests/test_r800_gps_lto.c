#include <assert.h>
#include <string.h>
#include <stdio.h>
#include "../src/tools/gps/gps_lto.h"
struct source { const char *data; unsigned size, pos, chunk; int fail_at; };
static long pull(void *ctx, char *buf, unsigned n)
{
    struct source *s = ctx;
    if (s->fail_at >= 0 && s->pos >= (unsigned)s->fail_at) return -1;
    if (n > s->size - s->pos) n = s->size - s->pos;
    if (n > s->chunk) n = s->chunk;
    memcpy(buf, s->data + s->pos, n);
    s->pos += n;
    return n;
}
static long broken(void *ctx, char *buf, unsigned n)
{
    (void)ctx; (void)buf; return (long)n + 1;
}
int main(void)
{
    char b[4];
    struct source s = {"abcdx", 3, 0, 1, -1};
    assert(gps_read_lto(pull,&s,b,sizeof b)==3 && !memcmp(b,"abc",3));
    s=(struct source){"abcdx",4,0,2,-1};
    assert(gps_read_lto(pull,&s,b,sizeof b)==4);
    s=(struct source){"abcdx",5,0,2,-1};
    assert(gps_read_lto(pull,&s,b,sizeof b)==-1);
    s=(struct source){"abcdx",4,0,2,2};
    assert(gps_read_lto(pull,&s,b,sizeof b)==-1);
    s=(struct source){"abcdx",4,0,2,4};
    assert(gps_read_lto(pull,&s,b,sizeof b)==-1);
    s=(struct source){"",0,0,1,-1};
    assert(gps_read_lto(pull,&s,b,sizeof b)==0);
    assert(gps_read_lto(broken,0,b,sizeof b)==-1);
    assert(gps_read_lto(pull,&s,b,0)==-1);
    puts("GPS_LTO_TESTS=8 PASS");
    return 0;
}
