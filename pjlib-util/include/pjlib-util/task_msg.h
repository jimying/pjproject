#ifndef __PJLIB_UTIL_TASK_MSG_H__
#define __PJLIB_UTIL_TASK_MSG_H__

/**
 * @file task_msg.h
 * @brief Task Message Base Definition
 */

#include <pj/types.h>
#include <pj/list.h>

PJ_BEGIN_DECL

/** Enumeration of task message types */
typedef enum
{
    TASK_MSG_CORE = 0, /**< core task message type */
    TASK_MSG_USER = 1  /**< user defined task messages start from here */
} pj_task_msg_type;

/** Enumeration of core task messages */
typedef enum
{
    CORE_TASK_MSG_NONE,                 /**< indefinite message */
    CORE_TASK_MSG_START_COMPLETE,       /**< start-complete message */
    CORE_TASK_MSG_TERMINATE_REQUEST,    /**< terminate-request message */
    CORE_TASK_MSG_TERMINATE_COMPLETE,   /**< terminate-complete message */
} pj_core_task_msg_type;

/** Opaque task message factory declaration */
typedef struct pj_task_msg_factory_t pj_task_msg_factory_t;

/** Opaque task message declaration */
typedef struct pj_task_msg_t pj_task_msg_t;

/** Opaque task message process function declaration */
typedef pj_bool_t (*pj_task_msg_proc_f)(void *task, pj_task_msg_t *msg);

/** Task message is used for inter task communication */
struct pj_task_msg_t
{
    /* list link */
    PJ_DECL_LIST_MEMBER(pj_task_msg_t);
    /** memory pool */
    pj_pool_t *pool;
    /** Message factory the task message is allocated from */
    pj_task_msg_factory_t *msg_factory;
    /** Task msg type */
    int type;
    /** Task msg sub type */
    int sub_type;
    /** Task msg process function */
    pj_task_msg_proc_f task_proc;
    /** Context specific data */
    char data[1];
};

/** Create factory of task messages */
pj_task_msg_factory_t *pj_task_msg_factory_create(pj_size_t msg_size, pj_pool_t *pool);

/** Destroy factory of task messages */
void pj_task_msg_factory_destroy(pj_task_msg_factory_t *msg_factory);

/** Acquire task message from task message factory */
pj_task_msg_t *pj_task_msg_acquire(pj_task_msg_factory_t *msg_factory, pj_size_t size);

/** Realese task message */
void pj_task_msg_release(pj_task_msg_t *msg);

PJ_END_DECL

#endif /* __PJLIB_UTIL_TASK_MSG_H__ */
