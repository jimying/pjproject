#include <pj/assert.h>
#include <pj/errno.h>
#include <pj/pool.h>
#include <pj/string.h>
#include <pjlib-util/poller_task.h>
#include <pjlib-util/thread_pool.h>

#define THIS_FILE "thread_pool.c"

struct pj_thread_pool_t
{
    pj_pool_t *pool;
    int cnt;
    int idx;
    pj_task_t **tasks;
};

typedef struct task_run_info_t
{
    pj_pool_t *pool;
    pj_thread_pool_task_run_t taskfn;
    void *param;
} task_run_info_t;

pj_status_t pj_thread_pool_create(pj_pool_factory *pf, const char *name, int cnt, int maxfd, pj_thread_pool_t **ptp)
{
    pj_status_t status;
    pj_pool_t *pool;
    pj_thread_pool_t *tp;
    pj_task_t *task;
    int i, j;
    char buf[16];

    PJ_ASSERT_RETURN(pf && cnt > 0 && maxfd > 0 && ptp, PJ_EINVAL);
    // PJ_LOG(4, (THIS_FILE, "create thread pool, name:%s, cnt:%d, maxfd:%d", name ? name : "", cnt, maxfd));
    pool = pj_pool_create(pf, name, 512, 512, NULL);
    tp = PJ_POOL_ZALLOC_T(pool, pj_thread_pool_t);
    tp->pool = pool;
    tp->cnt = cnt;
    tp->tasks = pj_pool_zalloc(pool, sizeof(pj_task_t *) * cnt);

    for (i = 0; i < cnt; i++)
    {
        if (name && name[0])
            snprintf(buf, sizeof(buf), "%s_%d", name, i);
        status = pj_poller_task_create(pf, name ? buf : NULL, maxfd, NULL, &task);
        if (status != PJ_SUCCESS)
        {
            PJ_PERROR(1, (THIS_FILE, status, "create task"));
            goto on_error;
        }
        tp->tasks[i] = task;
    }

    *ptp = tp;
    return PJ_SUCCESS;
on_error:
    for (j = 0; j < i; j++)
    {
        pj_poller_task_destroy(tp->tasks[j]);
    }
    pj_pool_release(pool);
    *ptp = NULL;
    return status;
}

pj_status_t pj_thread_pool_destroy(pj_thread_pool_t *tp)
{
    int i;
    PJ_ASSERT_RETURN(tp, PJ_EINVAL);
    if (tp->pool)
    {
        for (i = 0; i < tp->cnt; i++)
        {
            pj_poller_task_destroy(tp->tasks[i]);
        }
        pj_pool_release(tp->pool);
        tp->pool = NULL;
    }
    return PJ_SUCCESS;
}

int pj_thread_pool_get(pj_thread_pool_t *tp)
{
    int idx = tp->idx;
    PJ_ASSERT_RETURN(tp, -1);
    tp->idx = (tp->idx + 1) % tp->cnt;
    return idx;
}

static pj_bool_t on_task_run(void *task, pj_task_msg_t *msg)
{
    task_run_info_t *info = (task_run_info_t *)msg->data;
    (void)task;
    info->taskfn(info->param);
    pj_pool_release(info->pool);
    return PJ_TRUE;
}

pj_status_t pj_thread_pool_push(pj_thread_pool_t *tp, int idx, pj_thread_pool_task_run_t taskfn, void *param)
{
    pj_task_t *task;
    pj_pool_t *pool;
    task_run_info_t *info;

    PJ_ASSERT_RETURN(tp && idx < tp->cnt && taskfn, PJ_EINVAL);
    task = tp->tasks[idx];
    pool = pj_pool_create(tp->pool->factory, "task-run%p", 256, 256, NULL);
    info = PJ_POOL_ZALLOC_T(pool, task_run_info_t);
    info->pool = pool;
    info->taskfn = taskfn;
    info->param = param;

    pj_task_msg_signal_exe(task, on_task_run, -99, info, sizeof(task_run_info_t));

    return PJ_SUCCESS;
}
