#ifndef R800_MOCK_ASYNC_H
#define R800_MOCK_ASYNC_H

/* One worker per mock session. All state is guarded by async_lock. */
static pthread_mutex_t async_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t async_changed = PTHREAD_COND_INITIALIZER;
static pthread_t async_thread;
static int async_live, async_triggered, async_cancelled;

static void async_worker(void *arg)
{
    (void)arg;
    pthread_mutex_lock(&async_lock);
    while (!async_triggered && !async_cancelled)
        pthread_cond_wait(&async_changed, &async_lock);
    int deliver = !async_cancelled;
    pthread_mutex_unlock(&async_lock);
    if (deliver) {
        GpsLocation fix={.size=sizeof(fix),.flags=31,.latitude=52.25,.longitude=5.5,
                         .altitude=10,.speed=2,.bearing=90,.accuracy=3,.timestamp=123};
        char line[]="$GPRMC,1*56\r\n";
        callbacks.location_cb(&fix);
        callbacks.nmea_cb(123,line,(int)strlen(line));
        puts("MOCK_ASYNC_DATA"); fflush(stdout);
    }
}

/* Only the mock owner invokes these helpers. Worker never joins itself. */
static int async_begin(void)
{
    if (async_live || !callbacks.create_thread_cb) return -1;
    pthread_mutex_lock(&async_lock);
    async_triggered = async_cancelled = 0;
    pthread_mutex_unlock(&async_lock);
    async_thread = callbacks.create_thread_cb("mock-gnss", async_worker, NULL);
    if (!async_thread) return -1;
    async_live = 1;
    return 0;
}
static void async_trigger(void)
{
    pthread_mutex_lock(&async_lock);
    async_triggered = 1;
    pthread_cond_signal(&async_changed);
    pthread_mutex_unlock(&async_lock);
}
static void async_end(void)
{
    if (!async_live) return;
    pthread_mutex_lock(&async_lock);
    async_cancelled = 1;
    pthread_cond_signal(&async_changed);
    pthread_mutex_unlock(&async_lock);
    if (pthread_join(async_thread, NULL)) abort();
    async_live = 0;
}
#endif
