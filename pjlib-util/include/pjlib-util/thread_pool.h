#ifndef __PJLIB_UTIL_THREAD_POOL_H__
#define __PJLIB_UTIL_THREAD_POOL_H__
#include <pj/types.h>

/** Opaque thread pool declaration */
typedef struct pj_thread_pool_t pj_thread_pool_t;
/** Task run callback */
typedef void (*pj_thread_pool_task_run_t)(void *param);

pj_status_t pj_thread_pool_create(pj_pool_factory *pf, const char *name, int cnt, int maxfd, pj_thread_pool_t **ptp);
pj_status_t pj_thread_pool_destroy(pj_thread_pool_t *tp);
int pj_thread_pool_get(pj_thread_pool_t *tp);
pj_status_t pj_thread_pool_push(pj_thread_pool_t *tp, int idx, pj_thread_pool_task_run_t taskfn, void *param);

#endif
