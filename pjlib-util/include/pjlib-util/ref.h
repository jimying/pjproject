#ifndef __PJLIB_UTIL_REF_H__
#define __PJLIB_UTIL_REF_H__
#include <pj/types.h>

typedef struct pj_ref_t pj_ref_t;
typedef void (*pj_ref_handler)(void *user_data);

pj_status_t pj_ref_create(pj_pool_t *pool, pj_ref_handler on_destroy, void *user_data, pj_ref_t **pref);
void pj_ref_destroy(pj_ref_t *ref);
pj_status_t pj_ref_inc(pj_ref_t *ref);
pj_status_t pj_ref_dec(pj_ref_t *ref);
void pj_ref_set_userdata(pj_ref_t *ref, void *user_data);
void *pj_ref_get_userdata(const pj_ref_t *ref);
void pj_ref_set_destroy_callback(pj_ref_t *ref, pj_ref_handler on_destroy);

#endif
