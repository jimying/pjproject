#include <pjlib-util/task.h>
#include <pj/list.h>
#include <pj/lock.h>
#include <pj/log.h>
#include <pj/os.h>
#include <pj/pool.h>
#include <pj/string.h>

#define THIS_FILE "task.c"

/** Internal states of the task */
typedef enum
{
    TASK_STATE_IDLE,               /**< no task activity */
    TASK_STATE_START_REQUESTED,    /**< start of the task has been requested, but it's not running yet */
    TASK_STATE_RUNNING,            /**< task is running */
    TASK_STATE_TERMINATE_REQUESTED /**< termination of the task has been requested, but it's still running */
} pj_task_state_e;

struct pj_task_t
{
    char name[PJ_MAX_OBJ_NAME];         /* name of the task */
    pj_pool_t *pool;                    /* memory pool to allocate task data from */
    void *user_data;                    /* user data */
    pj_task_msg_factory_t *msg_factory; /* message pool to allocate task messages from */
    pj_lock_t *mutex;                   /* mutex to protect task data */
    pj_thread_t *thread_handle;         /* thread handle */
    pj_task_state_e state;              /* current task state */
    pj_task_vtable_t vtable;            /* table of virtual methods */
    pj_size_t pending_start;            /* number of pending start requests */
    pj_size_t pending_term;             /* number of pending terminate requests */
    pj_bool_t running;                  /* task is running (PJ_TRUE if even terminate has already been requested) */
    pj_bool_t auto_ready;               /* if PJ_TRUE, task is implicitly ready to process messages */
};

static int PJ_THREAD_FUNC pj_task_run(void *data);
static pj_bool_t pj_task_core_msg_signal(pj_task_t *task, pj_core_task_msg_type type);
static pj_bool_t pj_task_terminate_request(pj_task_t *task);
static pj_bool_t pj_task_start_process_internal(pj_task_t *task);
static pj_bool_t pj_task_terminate_process_internal(pj_task_t *task);

static void pj_task_start_complete_raise(pj_task_t *task);
static void pj_task_terminate_complete_raise(pj_task_t *task);

pj_task_t *pj_task_create(const char *name, pj_pool_t *pool, pj_task_msg_factory_t *msg_factory, void *user_data)
{
    pj_task_t *task = PJ_POOL_ZALLOC_T(pool, pj_task_t);
    task->pool = pool;
    task->msg_factory = msg_factory;
    task->user_data = user_data;

    if (!task->msg_factory)
    {
        task->msg_factory = pj_task_msg_factory_create(0, pool);
    }

    task->state = TASK_STATE_IDLE;
    task->thread_handle = NULL;
    if (pj_lock_create_simple_mutex(pool, NULL, &task->mutex) != PJ_SUCCESS)
    {
        return NULL;
    }

    task->vtable.terminate = pj_task_terminate_request;
    task->vtable.process_start = pj_task_start_process_internal;
    task->vtable.process_terminate = pj_task_terminate_process_internal;

    task->pending_start = 0;
    task->pending_term = 0;
    task->auto_ready = PJ_TRUE;
    pj_task_name_set(task, name);
    return task;
}

pj_bool_t pj_task_destroy(pj_task_t *task)
{
    pj_lock_acquire(task->mutex);
    if (task->state != TASK_STATE_IDLE)
    {
        pj_lock_release(task->mutex);
        pj_task_wait_till_complete(task);
    }
    else
    {
        pj_lock_release(task->mutex);
    }

    PJ_LOG(4, (THIS_FILE, "Destroy Task [%s]", task->name));
    if (task->vtable.destroy)
    {
        task->vtable.destroy(task);
    }

    pj_lock_destroy(task->mutex);
    return PJ_TRUE;
}

pj_bool_t pj_task_start(pj_task_t *task)
{
    pj_bool_t status = PJ_TRUE;
    pj_lock_acquire(task->mutex);
    if (task->state == TASK_STATE_IDLE)
    {
        pj_status_t rv;
        task->state = TASK_STATE_START_REQUESTED;
        PJ_LOG(4, (THIS_FILE, "Start Task [%s]", task->name));
        if (task->vtable.start)
        {
            /* invoke virtual start method */
            task->vtable.start(task);
        }
        else
        {
            /* start new thread by default */
            rv = pj_thread_create(task->pool, task->name, pj_task_run, task, 0, 0, &task->thread_handle);
            if (rv != PJ_SUCCESS)
            {
                task->state = TASK_STATE_IDLE;
                status = PJ_FALSE;
            }
        }
    }
    else
    {
        status = PJ_FALSE;
    }
    pj_lock_release(task->mutex);
    return status;
}

pj_bool_t pj_task_terminate(pj_task_t *task, pj_bool_t wait_till_complete)
{
    pj_bool_t status = PJ_FALSE;
    pj_lock_acquire(task->mutex);
    if (task->state == TASK_STATE_START_REQUESTED || task->state == TASK_STATE_RUNNING)
    {
        task->state = TASK_STATE_TERMINATE_REQUESTED;
    }
    pj_lock_release(task->mutex);

    if (task->state == TASK_STATE_TERMINATE_REQUESTED)
    {
        /* invoke virtual terminate method */
        PJ_LOG(5, (THIS_FILE, "Terminate Task [%s]", task->name));
        if (task->vtable.terminate)
        {
            status = task->vtable.terminate(task);
        }

        if (wait_till_complete == PJ_TRUE && status == PJ_TRUE)
        {
            pj_task_wait_till_complete(task);
        }
    }

    return status;
}

pj_bool_t pj_task_wait_till_complete(pj_task_t *task)
{
    if (task->thread_handle)
    {
        pj_thread_join(task->thread_handle);
        task->thread_handle = NULL;
    }
    return PJ_TRUE;
}

void *pj_task_get_userdata(const pj_task_t *task)
{
    return task->user_data;
}

pj_task_vtable_t *pj_task_vtable_get(pj_task_t *task)
{
    return &task->vtable;
}

void pj_task_name_set(pj_task_t *task, const char *name)
{
    if (name && name[0])
        pj_ansi_snprintf(task->name, sizeof(task->name), "%s", name);
}

const char *pj_task_name_get(const pj_task_t *task)
{
    return task->name;
}

pj_task_msg_t *pj_task_msg_get(pj_task_t *task, pj_size_t size)
{
    if (task->msg_factory)
    {
        return pj_task_msg_acquire(task->msg_factory, size);
    }
    return NULL;
}

pj_bool_t pj_task_msg_signal(pj_task_t *task, pj_task_msg_t *msg)
{
    PJ_LOG(5, (THIS_FILE, "Signal Message to [%s] [%p;%d;%d]",
               task->name, msg, msg->type, msg->sub_type));
    if (task->vtable.signal_msg)
    {
        if (task->vtable.signal_msg(task, msg) == PJ_TRUE)
        {
            return PJ_TRUE;
        }
    }

    PJ_LOG(1, (THIS_FILE, "Failed to Signal Task Message [%s] [%p;%d;%d]",
               task->name, msg, msg->type, msg->sub_type));
    pj_task_msg_release(msg);
    return PJ_FALSE;
}

pj_bool_t pj_task_msg_signal_exe(pj_task_t *task, pj_task_msg_proc_f task_proc, int sub_type, const void *data, pj_size_t len)
{
    pj_task_msg_t *msg = pj_task_msg_get(task, len);
    msg->type = TASK_MSG_USER;
    msg->sub_type = sub_type;
    msg->task_proc = task_proc;
    if (len > 0)
        pj_memcpy(msg->data, data, len);
    return pj_task_msg_signal(task, msg);
}

static pj_bool_t pj_core_task_msg_process(pj_task_t *task, pj_task_msg_t *msg)
{
    switch (msg->sub_type)
    {
    case CORE_TASK_MSG_START_COMPLETE:
        pj_task_start_request_remove(task);
        break;
    case CORE_TASK_MSG_TERMINATE_REQUEST:
        if (task->vtable.process_terminate)
        {
            task->vtable.process_terminate(task);
        }
        break;
    case CORE_TASK_MSG_TERMINATE_COMPLETE:
        pj_task_terminate_request_remove(task);
        break;
    default:
        break;
    }
    return PJ_TRUE;
}

static pj_bool_t pj_task_core_msg_signal(pj_task_t *task, pj_core_task_msg_type type)
{
    if (task)
    {
        pj_task_msg_t *msg = pj_task_msg_get(task, 0);
        /* signal core task message */
        msg->type = TASK_MSG_CORE;
        msg->sub_type = type;
        msg->task_proc = (pj_task_msg_proc_f)pj_core_task_msg_process;
        return pj_task_msg_signal(task, msg);
    }
    return PJ_FALSE;
}

pj_bool_t pj_task_msg_process(pj_task_t *task, pj_task_msg_t *msg)
{
    pj_bool_t status = PJ_FALSE;
    PJ_LOG(5, (THIS_FILE, "Process Message [%s][%p;%d;%d]",
               task->name, msg, msg->type, msg->sub_type));
    if (msg->type == TASK_MSG_CORE)
    {
        status = msg->task_proc(task, msg);
    }
    else
    {
        /*
         * Priority use task_proc() to process message,
         * If task_proc() not specified, try use task virtual method process_msg()
         */
        if (msg->task_proc)
        {
            status = msg->task_proc(task, msg);
        }
        else if (task->vtable.process_msg)
        {
            status = task->vtable.process_msg(task, msg);
        }
    }

    pj_task_msg_release(msg);
    return status;
}

static pj_bool_t pj_task_terminate_request(pj_task_t *task)
{
    return pj_task_core_msg_signal(task, CORE_TASK_MSG_TERMINATE_REQUEST);
}

pj_bool_t pj_task_start_request_process(pj_task_t *task)
{
    return pj_task_start_process_internal(task);
}

static pj_bool_t pj_task_start_process_internal(pj_task_t *task)
{
    if (!task->pending_start)
    {
        /* no child task to start, just raise start-complete event */
        pj_task_start_complete_raise(task);
    }
    return PJ_TRUE;
}

pj_bool_t pj_task_terminate_request_process(pj_task_t *task)
{
    return pj_task_terminate_process_internal(task);
}

static pj_bool_t pj_task_terminate_process_internal(pj_task_t *task)
{
    if (!task->pending_term)
    {
        /* no child task to terminate, just raise terminate-complete event */
        pj_task_terminate_complete_raise(task);
        task->running = PJ_FALSE;
    }
    return PJ_TRUE;
}

void pj_task_auto_ready_set(pj_task_t *task, pj_bool_t auto_ready)
{
    task->auto_ready = auto_ready;
}

pj_bool_t pj_task_ready(pj_task_t *task)
{
    if (task->auto_ready == PJ_TRUE)
    {
        return PJ_FALSE;
    }

    /* start child tasks (if any) */
    if (task->vtable.process_start)
    {
        task->vtable.process_start(task);
    }
    return PJ_TRUE;
}

pj_bool_t *pj_task_running_flag_get(pj_task_t *task)
{
    return &task->running;
}

pj_bool_t pj_task_start_request_add(pj_task_t *task)
{
    task->pending_start++;
    return PJ_TRUE;
}

pj_bool_t pj_task_start_request_remove(pj_task_t *task)
{
    if (!task->pending_start)
    {
        /* error case, no pending start */
        return PJ_FALSE;
    }
    task->pending_start--;
    if (!task->pending_start)
    {
        pj_task_start_complete_raise(task);
    }
    return PJ_TRUE;
}

pj_bool_t pj_task_terminate_request_add(pj_task_t *task)
{
    task->pending_term++;
    return PJ_TRUE;
}

pj_bool_t pj_task_terminate_request_remove(pj_task_t *task)
{
    if (!task->pending_term)
    {
        /* error case, no pending terminate */
        return PJ_FALSE;
    }
    task->pending_term--;
    if (!task->pending_term)
    {
        pj_task_terminate_complete_raise(task);
        task->running = PJ_FALSE;
    }
    return PJ_TRUE;
}

static void pj_task_start_complete_raise(pj_task_t *task)
{
    PJ_LOG(5, (THIS_FILE, "Task Started [%s]", task->name));
    if (task->vtable.on_start_complete)
    {
        task->vtable.on_start_complete(task);
    }
}

static void pj_task_terminate_complete_raise(pj_task_t *task)
{
    PJ_LOG(5, (THIS_FILE, "Task Terminated [%s]", task->name));
    if (task->vtable.on_terminate_complete)
    {
        task->vtable.on_terminate_complete(task);
    }
}

static int PJ_THREAD_FUNC pj_task_run(void *data)
{
    pj_task_t *task = data;

    /* raise pre-run event */
    if (task->vtable.on_pre_run)
    {
        task->vtable.on_pre_run(task);
    }
    pj_lock_acquire(task->mutex);
    task->state = TASK_STATE_RUNNING;
    task->running = PJ_TRUE;
    pj_lock_release(task->mutex);

    if (task->auto_ready == PJ_TRUE)
    {
        /* start child tasks (if any) */
        if (task->vtable.process_start)
        {
            task->vtable.process_start(task);
        }
    }

    /* run task */
    if (task->vtable.run)
    {
        task->vtable.run(task);
    }

    pj_lock_acquire(task->mutex);
    task->state = TASK_STATE_IDLE;
    task->running = PJ_FALSE;
    pj_lock_release(task->mutex);
    /* raise post-run event */
    if (task->vtable.on_post_run)
    {
        task->vtable.on_post_run(task);
    }

    return 0;
}
