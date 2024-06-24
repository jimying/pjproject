#ifndef __PJUTIL_POLLER_TASK_H__
#define __PJUTIL_POLLER_TASK_H__

#include <pj/types.h>
#include <pjlib-util/task.h>

int pj_poller_task_create(pj_pool_factory *pf, const char *name, int maxfd, void *user_data, pj_task_t **pptask);
void pj_poller_task_destroy(pj_task_t *task);
void *pj_poller_get_user_data(pj_task_t *task);
pj_ioqueue_t *pj_poller_task_get_ioqueue(pj_task_t *task);
pj_timer_heap_t *pj_poller_task_get_timerheap(pj_task_t *task);

#endif
