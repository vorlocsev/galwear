/* Test-only two-slot producer/consumer state model. Not ANativeWindow ABI
 * or Android BufferQueue. CPU HWC path completes synchronously (no release FD).
 * On rejected queue/cancel calls caller retains ownership of the supplied FD. */
enum window_slot_state {WINDOW_FREE,WINDOW_DEQUEUED,WINDOW_QUEUED,WINDOW_ACQUIRED};
struct window_slot {
    native_handle_t *handle;
    enum window_slot_state state;
    int fence;
};
struct window_queue {
    struct window_slot slots[2];
    int fifo[2],count;
};
static int window_dequeue(struct window_queue *q)
{
    for(int i=0;i<2;++i)if(q->slots[i].state==WINDOW_FREE){
        q->slots[i].state=WINDOW_DEQUEUED;return i;
    }
    return -EAGAIN;
}
static int window_queue_buffer(struct window_queue *q,int id,int fd)
{
    if(id<0||id>=2||q->slots[id].state!=WINDOW_DEQUEUED||q->count>=2||
       fd < -1 || (fd>=0&&fcntl(fd,F_GETFD)<0))return -EINVAL;
    q->slots[id].fence=fd;
    q->slots[id].state=WINDOW_QUEUED;
    q->fifo[q->count++]=id;
    return 0;
}
static int window_cancel(struct window_queue *q,int id,int fd)
{
    if(id<0||id>=2||q->slots[id].state!=WINDOW_DEQUEUED||
       fd < -1 || (fd>=0&&fcntl(fd,F_GETFD)<0))return -EINVAL;
    if(fd>=0&&close(fd))return -errno;
    q->slots[id].state=WINDOW_FREE;
    return 0;
}
static int window_acquire(struct window_queue *q,buffer_handle_t *handle,int *fd)
{
    if(!q->count)return -EAGAIN;
    int id=q->fifo[0];
    if(q->slots[id].state!=WINDOW_QUEUED)return -EINVAL;
    q->fifo[0]=q->fifo[1];--q->count;
    q->slots[id].state=WINDOW_ACQUIRED;
    *handle=q->slots[id].handle;
    *fd=q->slots[id].fence;
    q->slots[id].fence=-1;
    return id;
}
static int window_release_cpu(struct window_queue *q,int id,int release_fd)
{
    if(id<0||id>=2||q->slots[id].state!=WINDOW_ACQUIRED||release_fd!=-1)return -EINVAL;
    q->slots[id].state=WINDOW_FREE;
    return 0;
}
