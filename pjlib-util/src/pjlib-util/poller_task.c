#include <pjlib-util/poller_task.h>

#define THIS_FILE "poller_task.c"

typedef struct poller_task_t
{
    pj_pool_t *pool;
    void *user_data;
    pj_task_t *task;
    pj_ioqueue_t *ioq;
    pj_timer_heap_t *ht;
    pj_task_msg_t mq;
    pj_lock_t *lock;
} poller_task_t;

static pj_bool_t on_signal_msg(pj_task_t *task, pj_task_msg_t *msg);
static pj_bool_t on_task_run(pj_task_t *task);

int pj_poller_task_create(pj_pool_factory *pf, const char *name, int maxfd, void *user_data, pj_task_t **pptask)
{
    pj_status_t status;
    pj_pool_t *pool;
    poller_task_t *ptask;
    pj_task_vtable_t *vt;

    PJ_ASSERT_RETURN(pf && pptask, PJ_EINVAL);
    if (!name || !name[0])
        name = "poller-task";
    pool = pj_pool_create(pf, "poller-task%p", (maxfd + 1) * 600, 1000, NULL);
    ptask = PJ_POOL_ZALLOC_T(pool, poller_task_t);
    ptask->pool = pool;
    ptask->user_data = user_data;
    pj_list_init(&ptask->mq);

    if (!strcmp(pj_ioqueue_name(), "select") && maxfd > PJ_IOQUEUE_MAX_HANDLES)
        maxfd = PJ_IOQUEUE_MAX_HANDLES;
    status = pj_ioqueue_create(pool, maxfd, &ptask->ioq);
    if (status != PJ_SUCCESS)
    {
        PJ_PERROR(1, (THIS_FILE, status, "create ioqueue error"));
        goto on_error;
    }

    status = pj_timer_heap_create(pool, 256, &ptask->ht);
    if (status != PJ_SUCCESS)
    {
        PJ_PERROR(1, (THIS_FILE, status, "create timer heap error"));
        goto on_error;
    }

    status = pj_lock_create_recursive_mutex(pool, "media-task-lock%p", &ptask->lock);
    if (status != PJ_SUCCESS)
    {
        PJ_PERROR(1, (THIS_FILE, status, "create lock error"));
        goto on_error;
    }

    ptask->task = pj_task_create(name, pool, NULL, ptask);
    if (status != PJ_SUCCESS)
    {
        PJ_LOG(1, (THIS_FILE, "create task error"));
        status = PJ_ENOMEM;
        goto on_error;
    }
    vt = pj_task_vtable_get(ptask->task);
    vt->signal_msg = on_signal_msg;
    vt->run = on_task_run;

    if (!pj_task_start(ptask->task))
    {
        PJ_LOG(1, (THIS_FILE, "start task:%s fail", name));
        status = PJ_EUNKNOWN;
        goto on_error;
    }

    *pptask = ptask->task;
    return PJ_SUCCESS;
on_error:
    if (ptask->task)
        pj_task_destroy(ptask->task);
    if (ptask->ioq)
        pj_ioqueue_destroy(ptask->ioq);
    if (ptask->ht)
        pj_timer_heap_destroy(ptask->ht);
    if (ptask->lock)
        pj_lock_destroy(ptask->lock);
    pj_pool_release(pool);
    *pptask = NULL;
    return status;
}

void pj_poller_task_destroy(pj_task_t *task)
{
    poller_task_t *ptask;
    if (!task)
        return;
    ptask = pj_task_get_userdata(task);
    pj_task_terminate(ptask->task, PJ_TRUE);
    pj_task_destroy(ptask->task);
    pj_ioqueue_destroy(ptask->ioq);
    pj_timer_heap_destroy(ptask->ht);
    pj_lock_destroy(ptask->lock);
    pj_pool_release(ptask->pool);
}

void *pj_poller_get_user_data(pj_task_t *task)
{
    poller_task_t *ptask;
    PJ_ASSERT_RETURN(task, NULL);
    ptask = pj_task_get_userdata(task);
    return ptask->user_data;
}

pj_ioqueue_t *pj_poller_task_get_ioqueue(pj_task_t *task)
{
    poller_task_t *ptask;
    PJ_ASSERT_RETURN(task, NULL);
    ptask = pj_task_get_userdata(task);
    return ptask->ioq;
}

pj_timer_heap_t *pj_poller_task_get_timerheap(pj_task_t *task)
{
    poller_task_t *ptask;
    PJ_ASSERT_RETURN(task, NULL);
    ptask = pj_task_get_userdata(task);
    return ptask->ht;
}

static pj_bool_t on_signal_msg(pj_task_t *task, pj_task_msg_t *msg)
{
    poller_task_t *ptask = pj_task_get_userdata(task);
    pj_lock_acquire(ptask->lock);
    pj_list_push_back(&ptask->mq, msg);
    pj_lock_release(ptask->lock);
    return PJ_TRUE;
}

static pj_bool_t on_task_run(pj_task_t *task)
{
    poller_task_t *ptask = pj_task_get_userdata(task);
    pj_bool_t *running = pj_task_running_flag_get(task);
    pj_ioqueue_t *ioq = ptask->ioq;
    pj_timer_heap_t *ht = ptask->ht;

    while (*running)
    {
        pj_time_val timeout = {0, 10}, delay = {0, 0};

        pj_lock_acquire(ptask->lock);
        while (!pj_list_empty(&ptask->mq) && *running)
        {
            pj_task_msg_t *msg = (pj_task_msg_t *)ptask->mq.next;
            pj_list_erase(msg);
            pj_task_msg_process(task, msg);
        }
        pj_lock_release(ptask->lock);

        if (*running)
        {
            pj_timer_heap_poll(ht, &delay);
            if (PJ_TIME_VAL_GT(timeout, delay))
                timeout = delay;
            pj_ioqueue_poll(ioq, &timeout);
        }
    }

    pj_lock_acquire(ptask->lock);
    while (!pj_list_empty(&ptask->mq))
    {
        pj_task_msg_t *msg = (pj_task_msg_t *)ptask->mq.next;
        pj_list_erase(msg);
        pj_task_msg_release(msg);
    }
    pj_lock_release(ptask->lock);

    return PJ_TRUE;
}
