#include <pj/pool.h>
#include <pjlib-util/task_msg.h>

struct pj_task_msg_factory_t
{
    void (*destroy)(pj_task_msg_factory_t *msg_factory);
    pj_task_msg_t *(*acquire_msg)(pj_task_msg_factory_t *msg_factory, pj_size_t size);
    void (*release_msg)(pj_task_msg_t *msg);
    pj_pool_t *pool;
    void *obj;
};

/** Dynamic allocation of messages (default size)*/
typedef struct pj_msg_pool_dynamic_t
{
    pj_size_t size;
} pj_msg_pool_dynamic_t;

static pj_task_msg_t *dynamic_pool_acquire_msg(pj_task_msg_factory_t *msg_factory, pj_size_t size)
{
    pj_msg_pool_dynamic_t *dynamic_pool = msg_factory->obj;
    pj_task_msg_t *msg;
    pj_pool_factory *pf;
    pj_pool_t *pool;
    pj_size_t default_size = dynamic_pool->size;

    size += (sizeof(pj_task_msg_t) - 1);
    if (size < default_size)
        size = default_size;

    pf = msg_factory->pool->factory;
    pool = pj_pool_create(pf, "msg_%p", size, 256, NULL);
    msg = pj_pool_zalloc(pool, size);

    msg->pool = pool;
    msg->msg_factory = msg_factory;
    msg->type = TASK_MSG_USER;
    msg->sub_type = 0;
    return msg;
}

static void dynamic_pool_release_msg(pj_task_msg_t *msg)
{
    if (msg)
        pj_pool_release(msg->pool);
}

static void dynamic_pool_destroy(pj_task_msg_factory_t *msg_factory)
{
    PJ_UNUSED_ARG(msg_factory);
    /* do nothing */
}

pj_task_msg_factory_t *pj_task_msg_factory_create(pj_size_t msg_size, pj_pool_t *pool)
{
    pj_task_msg_factory_t *msg_factory;
    pj_msg_pool_dynamic_t *dynamic_pool;

    msg_factory = PJ_POOL_ZALLOC_T(pool, pj_task_msg_factory_t);
    dynamic_pool = PJ_POOL_ZALLOC_T(pool, pj_msg_pool_dynamic_t);
    dynamic_pool->size = msg_size + sizeof(pj_task_msg_t) - 1;

    msg_factory->obj = dynamic_pool;
    msg_factory->pool = pool;
    msg_factory->acquire_msg = dynamic_pool_acquire_msg;
    msg_factory->release_msg = dynamic_pool_release_msg;
    msg_factory->destroy = dynamic_pool_destroy;
    return msg_factory;
}

void pj_task_msg_factory_destroy(pj_task_msg_factory_t *msg_factory)
{
    if (msg_factory->destroy)
        msg_factory->destroy(msg_factory);
}

pj_task_msg_t *pj_task_msg_acquire(pj_task_msg_factory_t *msg_factory, pj_size_t size)
{
    if (!msg_factory->acquire_msg)
        return NULL;
    return msg_factory->acquire_msg(msg_factory, size);
}

void pj_task_msg_release(pj_task_msg_t *msg)
{
    pj_task_msg_factory_t *msg_factory = msg->msg_factory;
    if (msg_factory->release_msg)
        msg_factory->release_msg(msg);
}
