#include <pjlib.h>

#define THIS_FILE "main.c"

#define DELAY_MS_Q 10
#define DELAY_MS 20
#define DEFAULT_THREAD_CNT 1
#define TIMER_ID_RUN 1
#define TIMER_ID_STOPED -1

struct global_info
{
    pj_ioqueue_t *ioq;
    pj_timer_heap_t *ht;

    int thread_cnt;
    pj_thread_t **threads;
    pj_bool_t quit;
} global;

static int work_proc(void *arg)
{
    PJ_UNUSED_ARG(arg);

    while (!global.quit)
    {
        pj_time_val max_timeout = {0, DELAY_MS_Q};
        pj_time_val timeout = {0, 0};
        pj_timer_heap_poll(global.ht, &timeout);
        if (PJ_TIME_VAL_GT(timeout, max_timeout))
            timeout = max_timeout;
        pj_ioqueue_poll(global.ioq, &timeout);
    }

    return 0;
}

static void timer_cb(pj_timer_heap_t *timer_heap, struct pj_timer_entry *entry)
{
    static pj_uint64_t cnt = 0;
    pj_time_val delay = {0, DELAY_MS};
    cnt++;
    if (cnt % 50 == 0)
        PJ_LOG(4, (THIS_FILE, "cnt:%d", cnt));
    pj_timer_heap_schedule(timer_heap, entry, &delay);
}

static int timer_cb2(pj_timer_heap_t *timer_heap, struct pj_timer_entry *entry)
{
    static pj_uint64_t cnt = 0;
    cnt++;
    if (cnt % 50 == 0)
        PJ_LOG(4, (THIS_FILE, "%s() cnt:%d", __FUNCTION__, cnt));
    if (cnt == 1000)
    {
        /* stop */
        entry->id = TIMER_ID_STOPED;
        return 0;
    }
    return DELAY_MS;
}

int main(int argc, char **argv)
{
    pj_status_t status;
    pj_caching_pool cp;
    pj_pool_factory *pf;
    pj_pool_t *pool;
    pj_ioqueue_t *ioq;
    pj_timer_heap_t *ht;
    pj_lock_t *lock;
    pj_timer_entry timer;
    pj_time_val delay = {0, DELAY_MS};
    int thread_cnt = DEFAULT_THREAD_CNT;
    int i;

    pj_init();

    if (argc == 2)
    {
        thread_cnt = atoi(argv[1]);
        thread_cnt = PJ_MAX(1, thread_cnt);
    }
    PJ_LOG(4, (THIS_FILE, "thread count: %d\n", thread_cnt));

    pj_caching_pool_init(&cp, NULL, 0);
    pf = &cp.factory;
    pool = pj_pool_create(pf, "app", 500, 500, NULL);

    status = pj_ioqueue_create(pool, 10, &ioq);
    PJ_ASSERT_RETURN(status == PJ_SUCCESS, status);

    status = pj_timer_heap_create(pool, 64, &ht);
    PJ_ASSERT_RETURN(status == PJ_SUCCESS, status);

    pj_lock_create_recursive_mutex(pool, NULL, &lock);
    pj_timer_heap_set_lock(ht, lock, PJ_TRUE);

    pj_bzero(&global, sizeof(global));
    global.ioq = ioq;
    global.ht = ht;
    global.thread_cnt = thread_cnt;

    global.threads = (pj_thread_t **)pj_pool_calloc(pool, thread_cnt, sizeof(pj_thread_t *));

    for (i = 0; i < thread_cnt; i++)
    {
        pj_thread_create(pool, "work%p", work_proc, &global, 0, 0, &global.threads[i]);
    }

    pj_timer_entry_init(&timer, TIMER_ID_RUN, &global, timer_cb);
    pj_timer_entry_init2(&timer, TIMER_ID_RUN, &global, timer_cb2);
    pj_timer_heap_schedule(ht, &timer, &delay);

    PJ_LOG(4, (THIS_FILE, "input 'q' to quit"));
    while (1)
    {
        char input[8];
        fgets(input, sizeof(input), stdin);

        if (input[0] == 'q')
            break;
    }
    global.quit = PJ_TRUE;

    PJ_LOG(2, (THIS_FILE, "exit ..."));

    for (i = 0; i < thread_cnt; i++)
    {
        pj_thread_join(global.threads[i]);
        pj_thread_destroy(global.threads[i]);
    }
    pj_ioqueue_destroy(ioq);
    pj_timer_heap_destroy(ht);
    pj_pool_release(pool);
    pj_caching_pool_destroy(&cp);

    pj_shutdown();

    return 0;
}
