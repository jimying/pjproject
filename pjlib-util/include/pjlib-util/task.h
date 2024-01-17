#ifndef __PJLIB_UTIL_TASK_H__
#define __PJLIB_UTIL_TASK_H__

/**
 * @file task.h
 * @brief Thread Execution Abstraction
 */

#include "task_msg.h"

PJ_BEGIN_DECL

/** Opaque task declaration */
typedef struct pj_task_t pj_task_t;
/** Opaque task virtual table declaration */
typedef struct pj_task_vtable_t pj_task_vtable_t;
/** Opaque task method declaration */
typedef pj_bool_t (*pj_task_method_f)(pj_task_t *task);
/** Opaque task event declaration */
typedef void (*pj_task_event_f)(pj_task_t *task);

/** Table of task virtual methods */
struct pj_task_vtable_t
{
    /** Virtual destroy method */
    pj_task_method_f destroy;
    /** Virtual start method*/
    pj_task_method_f start;
    /** Virtual terminate method */
    pj_task_method_f terminate;
    /** Virtual run method*/
    pj_task_method_f run;

    /** Virtual signal_msg method  */
    pj_bool_t (*signal_msg)(pj_task_t *task, pj_task_msg_t *msg);
    /** Virtual process_msg method */
    pj_bool_t (*process_msg)(pj_task_t *task, pj_task_msg_t *msg);

    /** Virtual process_start method */
    pj_bool_t (*process_start)(pj_task_t *task);
    /** Virtual process_terminate method */
    pj_bool_t (*process_terminate)(pj_task_t *task);

    /** Virtual pre-run event handler */
    pj_task_event_f on_pre_run;
    /** Virtual post-run event handler */
    pj_task_event_f on_post_run;
    /** Virtual start-complete event handler */
    pj_task_event_f on_start_complete;
    /** Virtual terminate-complete event handler */
    pj_task_event_f on_terminate_complete;
};

/**
 * Create task.
 * @param name  the task name
 * @param pool  the pool to allocate memory from
 * @param msg_factory the pool of task messages
 * @param user_data  the external user data
 */
pj_task_t *pj_task_create(const char *name, pj_pool_t *pool, pj_task_msg_factory_t *msg_factory, void *user_data);

/**
 * Destroy task.
 * @param task the task to destroy
 */
pj_bool_t pj_task_destroy(pj_task_t *task);

/**
 * Start task.
 * @param task the task to start
 */
pj_bool_t pj_task_start(pj_task_t *task);

/**
 * Terminate task.
 * @param task the task to terminate
 * @param wait_till_complete whether to wait for task to complete or
 *                           process termination asynchronously
 */
pj_bool_t pj_task_terminate(pj_task_t *task, pj_bool_t wait_till_complete);

/**
 * Wait for task till complete.
 * @param task the task to wait for
 */
pj_bool_t pj_task_wait_till_complete(pj_task_t *task);

/**
 * Get (acquire) task message.
 * @param task the task to get task message from
 */
pj_task_msg_t *pj_task_msg_get(pj_task_t *task, pj_size_t size);

/**
 * Signal (post) message to the task.
 * @param task the task to signal message to
 * @param msg the message to signal
 */
pj_bool_t pj_task_msg_signal(pj_task_t *task, pj_task_msg_t *msg);

/**
 * Signal (post) user message to the task
 * @param task      the task to signal message to
 * @param task_proc  the function to process this message
 * @param sub_type  the message type
 * @param data      the message data
 * @param len       the message data lenght
 *
 */
pj_bool_t pj_task_msg_signal_exe(pj_task_t *task, pj_task_msg_proc_f task_proc, int sub_type, const void *data, pj_size_t len);

/**
 * Process message signaled to the task.
 * @param task the task to process message
 * @param msg the message to process
 */
pj_bool_t pj_task_msg_process(pj_task_t *task, pj_task_msg_t *msg);

/**
 * Process task start request.
 * @param task the task being started
 */
pj_bool_t pj_task_start_request_process(pj_task_t *task);

/**
 * Process task termination request.
 * @param task the task being terminated
 */
pj_bool_t pj_task_terminate_request_process(pj_task_t *task);

/**
 * Get user data associated with the task.
 * @param task
 */
void *pj_task_get_userdata(const pj_task_t *task);

/**
 * Get task vtable.
 * @param task the task to get vtable from
 */
pj_task_vtable_t *pj_task_vtable_get(pj_task_t *task);

/**
 * Give a name to the task.
 * @param task the task to give name for
 * @param name the name to set
 */
void pj_task_name_set(pj_task_t *task, const char *name);

/**
 * Get task name.
 * @param task the task to get name from
 */
const char *pj_task_name_get(const pj_task_t *task);

/**
 * Enable/disable auto ready mode.
 * @param task the task to set mode for
 * @param auto_ready the enabled/disabled auto ready mode
 */
void pj_task_auto_ready_set(pj_task_t *task, pj_bool_t auto_ready);

/**
 * Explicitly indicate task is ready to process messages.
 * @param task the task
 */
pj_bool_t pj_task_ready(pj_task_t *task);

/**
 * Get the running flag.
 * @param task the task
 */
pj_bool_t *pj_task_running_flag_get(pj_task_t *task);

/**
 * Add start request.
 * @param task the task
 */
pj_bool_t pj_task_start_request_add(pj_task_t *task);

/**
 * Remove start request.
 * @param task the task
 */
pj_bool_t pj_task_start_request_remove(pj_task_t *task);

/**
 * Add termination request.
 * @param task the task
 */
pj_bool_t pj_task_terminate_request_add(pj_task_t *task);

/**
 * Remove termination request.
 * @param task the task
 */
pj_bool_t pj_task_terminate_request_remove(pj_task_t *task);

PJ_END_DECL

#endif /* __PJLIB_UTIL_TASK_H__ */
