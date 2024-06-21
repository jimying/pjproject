#include <pjlib-util/txdata_factory.h>
#define THIS_FILE "txdata_factory.c"

int pj_txdata_factory_create(pj_pool_t *pool, int cnt, int max_cnt, pj_txdata_factory_t **pf)
{
    pj_txdata_factory_t *f;
    pj_txdata_t *array;
    int i;

    PJ_ASSERT_RETURN(pool && cnt > 0 && pf, PJ_EINVAL);
    f = PJ_POOL_ZALLOC_T(pool, pj_txdata_factory_t);
    PJ_ASSERT_RETURN(f, PJ_ENOMEM);
    array = pj_pool_alloc(pool, sizeof(pj_txdata_t) * (cnt + 1));
    PJ_ASSERT_RETURN(f, PJ_ENOMEM);
    f->pool = pool;
    f->cnt = cnt;
    f->max_cnt = max_cnt;
    f->dlist = array;
    pj_list_init(f->dlist);
    for (i = 1; i < cnt + 1; i++)
    {
        pj_list_push_back(f->dlist, array + i);
    }
    *pf = f;
    return PJ_SUCCESS;
}

int pj_txdata_factory_destroy(pj_txdata_factory_t *f)
{
    (void)f;
    return PJ_SUCCESS;
}

static int extend_factory_size(pj_txdata_factory_t *f)
{
    int i;
    pj_pool_t *pool = f->pool;
    int cnt = f->cnt;
    pj_txdata_t *array;

    array = pj_pool_alloc(pool, sizeof(pj_txdata_t) * cnt);
    PJ_ASSERT_RETURN(f, PJ_ENOMEM);
    for (i = 0; i < cnt; i++)
    {
        pj_list_push_back(f->dlist, array + i);
    }

    f->cnt *= 2;
    return PJ_SUCCESS;
}

pj_txdata_t *pj_txdata_acquire(pj_txdata_factory_t *f)
{
    pj_txdata_t *tdata;
    if (pj_list_empty(f->dlist))
    {
        if (f->cnt >= f->max_cnt)
        {
            if (f->err_cnt % 100 == 0)
                PJ_LOG(2, (THIS_FILE, "[%s] Can't alloc media tx data in factory(cnt:%d, max_cnt:%d, err_cnt:%u), and can't extend capacity",
                           f->pool->obj_name, f->cnt, f->max_cnt, f->err_cnt + 1));
            f->err_cnt++;
            return NULL;
        }
        PJ_LOG(2, (THIS_FILE, "[%s] Can't alloc media tx data in factory(cnt:%d), extend capacity to %d", f->pool->obj_name, f->cnt, f->cnt * 2));
        if (extend_factory_size(f) != PJ_SUCCESS)
            return NULL;
    }

    tdata = f->dlist->next;
    pj_list_erase(tdata);
    pj_bzero(&tdata->send_key, sizeof(pj_ioqueue_op_key_t));
    tdata->send_key.user_data = tdata;
    return tdata;
}

void pj_txdata_release(pj_txdata_factory_t *f, pj_txdata_t *tdata)
{
    if (!f || !tdata)
        return;
    pj_list_push_back(f->dlist, tdata);
}
