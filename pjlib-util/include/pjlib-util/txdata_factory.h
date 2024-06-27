#ifndef __PJUTIL_TXDATA_FACTORY_H__
#define __PJUTIL_TXDATA_FACTORY_H__
#include <pjlib.h>

typedef struct pj_txdata_factory_t pj_txdata_factory_t;
typedef struct pj_txdata_t pj_txdata_t;
struct pj_txdata_t
{
    PJ_DECL_LIST_MEMBER(struct pj_txdata_t);
    pj_ioqueue_op_key_t send_key;
    char data[1500];
};

int pj_txdata_factory_create(pj_pool_t *pool, int cnt, int max_cnt, pj_txdata_factory_t **pf);
int pj_txdata_factory_destroy(pj_txdata_factory_t *f);
pj_txdata_t *pj_txdata_acquire(pj_txdata_factory_t *f);
void pj_txdata_release(pj_txdata_factory_t *f, pj_txdata_t *tdata);

#endif
