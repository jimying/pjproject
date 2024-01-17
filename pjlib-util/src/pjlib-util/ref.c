#include <pjlib-util/ref.h>
#include <pjlib.h>

#define THIS_FILE "ref.c"
struct pj_ref_t
{
    pj_atomic_t *xref;
    void *user_data;
    pj_ref_handler on_destroy;
};

pj_status_t pj_ref_create(pj_pool_t *pool, pj_ref_handler on_destroy, void *user_data, pj_ref_t **pref)
{
    pj_status_t status;
    pj_ref_t *ref;

    PJ_ASSERT_RETURN(pool && pref, PJ_EINVAL);
    ref = PJ_POOL_ALLOC_T(pool, pj_ref_t);
    ref->user_data = user_data;
    ref->on_destroy = on_destroy;
    status = pj_atomic_create(pool, 1, &ref->xref);
    if (status != PJ_SUCCESS)
    {
        PJ_PERROR(1, (THIS_FILE, status, "create atomic error"));
        *pref = NULL;
        return status;
    }

    *pref = ref;
    return PJ_SUCCESS;
}

void pj_ref_destroy(pj_ref_t *ref)
{
    pj_ref_dec(ref);
}

pj_status_t pj_ref_inc(pj_ref_t *ref)
{
    pj_atomic_inc(ref->xref);
    return PJ_SUCCESS;
}

pj_status_t pj_ref_dec(pj_ref_t *ref)
{
    pj_atomic_value_t n = pj_atomic_dec_and_get(ref->xref);
    if (n == 0)
    {
        if (ref->on_destroy)
            ref->on_destroy(ref->user_data);
    }
    return PJ_SUCCESS;
}

void pj_ref_set_userdata(pj_ref_t *ref, void *user_data)
{
    ref->user_data = user_data;
}

void *pj_ref_get_userdata(const pj_ref_t *ref)
{
    return ref->user_data;
}

void pj_ref_set_destroy_callback(pj_ref_t *ref, pj_ref_handler on_destroy)
{
    ref->on_destroy = on_destroy;
}
