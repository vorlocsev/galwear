/* Test-only tinyalsa interposition. Never accesses host sound devices. */
#include <tinyalsa/asoundlib.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>

struct pcm { unsigned int input, frames, capacity, hfp, prepared, started; };
struct mixer { int live; };
struct mixer_ctl { const char *name; };
static struct mixer m;
static struct mixer_ctl ctl;
static unsigned int opens, closes, writes, reads, mixer_calls, bad, fail_next;
static unsigned int out_frames, in_frames;
static unsigned int hfp_live, hfp_started, call_mode, sco_rate, starts, stops, prepares;
unsigned int r800_pcm_fixture_get(unsigned int key)
{
    switch (key) {
    case 0: return opens;
    case 1: return closes;
    case 2: return writes;
    case 3: return reads;
    case 4: return bad;
    case 5: return out_frames;
    case 6: return in_frames;
    case 7: return mixer_calls;
    case 8: return hfp_live;
    case 9: return call_mode;
    case 10: return sco_rate;
    case 11: return starts;
    case 12: return stops;
    case 13: return prepares;
    case 14: return hfp_started;
    default: return 0xffffffffu;
    }
}
void r800_pcm_fixture_fail(unsigned int mode) { fail_next = mode; }
struct mixer *mixer_open(unsigned int card)
{
    if (card || m.live) { ++bad; return NULL; }
    m.live=1; ++mixer_calls; return &m;
}
void mixer_close(struct mixer *p)
{
    if (p!=&m || !m.live) ++bad;
    m.live=0;
}
struct mixer_ctl *mixer_get_ctl_by_name(struct mixer *p,const char *name)
{
    if (p!=&m || !m.live || !name || !*name) { ++bad; return NULL; }
    ctl.name=name;
    return &ctl;
}
unsigned int mixer_ctl_get_num_values(const struct mixer_ctl *p)
{
    if (p!=&ctl) ++bad;
    return 2;
}
int mixer_ctl_set_value(struct mixer_ctl *p,unsigned int id,int value)
{
    if (p!=&ctl || id>=2 || !m.live) { ++bad; return -EINVAL; }
    if (!strcmp(p->name,"ABOX UAIF1 rate")) {
        if (value!=8000 && value!=16000) ++bad;
        sco_rate=(unsigned int)value;
    }
    return 0;
}
int mixer_ctl_set_enum_by_string(struct mixer_ctl *p,const char *s)
{
    if (p!=&ctl || !m.live || !s || !*s) { ++bad; return -EINVAL; }
    if (!strcmp(p->name,"ABOX Audio Mode")) {
        if (!strcmp(s,"IN_CALL")) call_mode=1;
        else if (!strcmp(s,"NORMAL")) {
            if (hfp_live || hfp_started) ++bad;
            call_mode=0;
        } else ++bad;
    }
    return 0;
}
struct pcm *pcm_open(unsigned int card,unsigned int device,unsigned int flags,
                     const struct pcm_config *cfg)
{
    unsigned int input=!!(flags & PCM_IN);
    unsigned int hfp=0;
    if (device==6 && !input) hfp=1;
    else if (device==8 && input) hfp=2;
    else if (device==10 && input) hfp=3;
    else if (device==4 && !input) hfp=4;
    if (card || !cfg || cfg->channels!=2 || cfg->rate!=48000 ||
        cfg->format!=PCM_FORMAT_S16_LE || cfg->period_size!=960) {
        ++bad; return NULL;
    }
    if (hfp) {
        if (!call_mode || (sco_rate!=8000 && sco_rate!=16000) ||
            flags!=(unsigned int)(input?PCM_IN:PCM_OUT) ||
            cfg->period_count!=4 || cfg->start_threshold!=960 ||
            cfg->stop_threshold!=0xffffffffu ||
            hfp_live!=((1u<<(hfp-1))-1u) || hfp_started!=hfp_live) {
            ++bad; return NULL;
        }
    } else if (call_mode || hfp_live || device!=(input?9u:0u) ||
        flags!=(unsigned int)((input?PCM_IN:PCM_OUT)|PCM_MONOTONIC) ||
        cfg->period_count!=(input?8u:4u)) {
        ++bad; return NULL;
    }
    struct pcm *p=calloc(1,sizeof(*p));
    if (p) {
        p->input=input; p->capacity=cfg->period_size*cfg->period_count;
        p->hfp=hfp; ++opens;
        if (hfp) hfp_live|=1u<<(hfp-1);
    }
    return p;
}
int pcm_close(struct pcm *p)
{
    if (!p) { ++bad; return -EINVAL; }
    if (p->hfp) {
        if (p->started || !(hfp_live & (1u<<(p->hfp-1)))) ++bad;
        hfp_live &= ~(1u<<(p->hfp-1));
    }
    ++closes; free(p); return 0;
}
int pcm_prepare(struct pcm *p)
{
    if (!p || !p->hfp || p->prepared || p->started) { ++bad; return -EINVAL; }
    p->prepared=1; ++prepares; return 0;
}
int pcm_start(struct pcm *p)
{
    if (!p || !p->hfp || !p->prepared || p->started) { ++bad; return -EINVAL; }
    if (fail_next==3 && p->hfp==3) { fail_next=0; return -EIO; }
    p->started=1; hfp_started|=1u<<(p->hfp-1); ++starts; return 0;
}
int pcm_stop(struct pcm *p)
{
    if (!p || !p->hfp || !p->started ||
        hfp_started!=((1u<<p->hfp)-1u)) { ++bad; return -EINVAL; }
    p->started=0; hfp_started &= ~(1u<<(p->hfp-1)); ++stops; return 0;
}
int pcm_is_ready(const struct pcm *p) { return p!=NULL; }
const char *pcm_get_error(const struct pcm *p) { (void)p; return "synthetic PCM"; }
unsigned int pcm_get_buffer_size(const struct pcm *p) { return p->capacity; }
int pcm_get_htimestamp(struct pcm *p,unsigned int *avail,struct timespec *ts)
{
    if (!p || !avail || !ts) { ++bad; return -EINVAL; }
    *avail=p->input?16:p->capacity-16;
    ts->tv_sec=123; ts->tv_nsec=456; return 0;
}
int pcm_writei(struct pcm *p,const void *data,unsigned int n)
{
    if (!p || p->hfp || call_mode || p->input || !data || !n || n>960) { ++bad; return -EINVAL; }
    ++writes;
    if (fail_next==1) { fail_next=0; return 0; }
    if (n>127) n=127;
    const int16_t *s=data;
    for (unsigned int i=0;i<n;++i) {
        int16_t v=(int16_t)((out_frames+i)%1000+1);
        if (s[2*i]!=v || s[2*i+1]!=-v) ++bad;
    }
    out_frames+=n; p->frames+=n; return (int)n;
}
int pcm_readi(struct pcm *p,void *data,unsigned int n)
{
    if (!p || p->hfp || call_mode || !p->input || !data || !n || n>960) { ++bad; return -EINVAL; }
    ++reads;
    if (fail_next==2) { fail_next=0; return -EIO; }
    if (n>113) n=113;
    int16_t *s=data;
    for (unsigned int i=0;i<n;++i) {
        int16_t v=(int16_t)((in_frames+i)%1000+1);
        s[2*i]=v; s[2*i+1]=-v;
    }
    in_frames+=n; p->frames+=n; return (int)n;
}
