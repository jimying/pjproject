#include <pj/errno.h>
#include <pj/ioqueue.h>
#include <pj/log.h>
#include <pj/pool.h>
#include <pj/sock.h>
#include <pj/string.h>

#define THIS_FILE "ioq_wakeup"

struct pj_ioqueue_wakeup_t {
    pj_sock_t wfd;
    pj_ioqueue_key_t *read_key;
    pj_ioqueue_op_key_t read_op;
    char read_buf[1];
};

static void on_read_complete(pj_ioqueue_key_t *key,
                             pj_ioqueue_op_key_t *op_key,
                             pj_ssize_t bytes_read)
{
    pj_ioqueue_wakeup_t *pw;
    pj_ssize_t read_sz;

    pw = pj_ioqueue_get_user_data(key);

    if (bytes_read > 0) {
        read_sz = PJ_ARRAY_SIZE(pw->read_buf);
        pj_ioqueue_recv(pw->read_key, &pw->read_op, pw->read_buf, &read_sz,
                        PJ_IOQUEUE_ALWAYS_ASYNC);
    }
}

PJ_DEF(pj_status_t) pj_ioqueue_wakeup_create(pj_ioqueue_t *ioqueue,
                                             pj_pool_t *pool)
{
    pj_status_t status;
    pj_ioqueue_base_t *base = (pj_ioqueue_base_t *)ioqueue;
    pj_ioqueue_key_t *read_key = NULL;
    pj_ioqueue_wakeup_t *pw = NULL;
    pj_sock_t rv[2] = {PJ_INVALID_SOCKET, PJ_INVALID_SOCKET};
    pj_ioqueue_callback cb;
    pj_ssize_t read_sz;
    int family;

    pw = PJ_POOL_ZALLOC_T(pool, pj_ioqueue_wakeup_t);
    if (!pw) {
        status = PJ_ENOMEM;
        return status;
    }

#if (defined(PJ_WIN32) && PJ_WIN32 != 0) || \
    (defined(PJ_WIN64) && PJ_WIN64 != 0) || \
    (defined(PJ_WIN32_WINCE) && PJ_WIN32_WINCE != 0)
    family = pj_AF_INET();
#else
    family = pj_AF_UNIX();
#endif
    status = pj_sock_socketpair(family, pj_SOCK_DGRAM(), 0, rv);
    if (status != PJ_SUCCESS) {
        PJ_PERROR(1, (THIS_FILE, status, "create sockpair"));
        goto on_error;
    }

    pj_bzero(&cb, sizeof(cb));
    cb.on_read_complete = on_read_complete;
    status = pj_ioqueue_register_sock(pool, ioqueue, rv[1], pw, &cb, &read_key);
    if (status != PJ_SUCCESS) {
        PJ_PERROR(1, (THIS_FILE, status, "register sock"));
        goto on_error;
    }
    pw->wfd = rv[0];
    pw->read_key = read_key;
    base->wu = pw;

    read_sz = PJ_ARRAY_SIZE(pw->read_buf);
    pj_ioqueue_recv(pw->read_key, &pw->read_op, pw->read_buf, &read_sz,
                    PJ_IOQUEUE_ALWAYS_ASYNC);

    return PJ_SUCCESS;
on_error:
    if (rv[0] != PJ_INVALID_SOCKET)
        pj_sock_close(rv[0]);
    if (read_key)
        pj_ioqueue_unregister(read_key);
    else if (rv[1] != PJ_INVALID_SOCKET)
        pj_sock_close(rv[1]);
    return status;
}

PJ_DEF(pj_status_t) pj_ioqueue_wakeup_destroy(pj_ioqueue_t *ioqueue)
{
    pj_ioqueue_base_t *base = (pj_ioqueue_base_t *)ioqueue;
    if (!base->wu)
        return PJ_EINVALIDOP;
    pj_sock_close(base->wu->wfd);
    pj_ioqueue_unregister(base->wu->read_key);
    base->wu = NULL;
    return PJ_SUCCESS;
}

PJ_DEF(pj_status_t) pj_ioqueue_wakeup_notify(pj_ioqueue_t *ioqueue)
{
    pj_ioqueue_base_t *base = (pj_ioqueue_base_t *)ioqueue;
    pj_ssize_t sz = 1;
    if (!base->wu)
        return PJ_EINVALIDOP;
    pj_sock_send(base->wu->wfd, "w", &sz, 0);
    return PJ_SUCCESS;
}
