#include <pjlib-util/websock_transport.h>
#include <pjlib.h>

#define THIS_FILE "websock_transport.c"

struct pj_ws_transport_t {
    pj_pool_t *pool;
    pj_pool_t *pool_own;
    pj_pool_factory *pf;
    pj_ioqueue_t *ioq;
    pj_timer_heap_t *timer_heap;
    pj_uint32_t max_rx_bufsize;
    pj_activesock_t *asock;
    pj_sock_t sock;
    pj_ws_transport_cb cb;
    void *user_data;
};

static pj_bool_t on_accept_complete(pj_activesock_t *asock, pj_sock_t newsock, const pj_sockaddr_t *src_addr, int src_addr_len);
static pj_bool_t on_connect_complete(pj_activesock_t *asock, pj_status_t status);
static pj_bool_t on_data_read(pj_activesock_t *asock, void *data, pj_size_t size, pj_status_t status, pj_size_t *remainder);
static pj_bool_t on_data_sent(pj_activesock_t *asock, pj_ioqueue_op_key_t *send_key, pj_ssize_t sent);

void pj_ws_transport_param_default(pj_ws_transport_param *param)
{
    pj_bzero(param, sizeof(*param));
    param->max_rx_bufsize = 8000;
}

pj_status_t pj_ws_transport_create(pj_pool_t *pool, pj_ws_transport_param *param, pj_ws_transport_t **pt)
{
    pj_ws_transport_t *tp;
    pj_pool_t *xpool = pool;

    PJ_ASSERT_RETURN(pt, PJ_EINVAL);
    PJ_ASSERT_RETURN(param, PJ_EINVAL);
    PJ_ASSERT_RETURN(param->ioq, PJ_EINVAL);
    *pt = NULL;

    if (!pool) {
        PJ_ASSERT_RETURN(param->pf, PJ_EINVAL);
        xpool = pj_pool_create(param->pf, "ws_tptcp%p", 500, 500, NULL);
        PJ_ASSERT_RETURN(xpool, PJ_ENOMEM);
    }

    tp = PJ_POOL_ZALLOC_T(xpool, pj_ws_transport_t);
    if (!pool)
        tp->pool_own = xpool;
    tp->pool = xpool;
    tp->ioq = param->ioq;
    tp->pf = param->pf;
    tp->user_data = param->user_data;
    tp->max_rx_bufsize = param->max_rx_bufsize;
    tp->sock = PJ_INVALID_SOCKET;
    pj_memcpy(&tp->cb, &param->cb, sizeof(pj_ws_transport_cb));

    *pt = tp;
    return PJ_SUCCESS;
}

pj_status_t pj_ws_transport_destroy(pj_ws_transport_t *tp)
{
    PJ_ASSERT_RETURN(tp, PJ_EINVAL);
    if (tp->asock) {
        pj_activesock_close(tp->asock);
        tp->asock = NULL;
    }

    if (tp->pool_own) {
        pj_pool_release(tp->pool_own);
    }

    return PJ_SUCCESS;
}

void *pj_ws_transport_get_userdata(pj_ws_transport_t *tp)
{
    PJ_ASSERT_RETURN(tp, NULL);
    return tp->user_data;
}

pj_status_t pj_ws_transport_set_userdata(pj_ws_transport_t *tp, void *user_data)
{
    PJ_ASSERT_RETURN(tp, PJ_EINVAL);
    tp->user_data = user_data;
    return PJ_SUCCESS;
}

pj_status_t pj_ws_transport_set_callbacks(pj_ws_transport_t *tp, pj_ws_transport_cb *cb)
{
    PJ_ASSERT_RETURN(tp && cb, PJ_EINVAL);
    pj_memcpy(&tp->cb, cb, sizeof(*cb));
    return PJ_SUCCESS;
}

static void disable_tcp_timewait(pj_sock_t sock)
{
    struct linger so_linger;
    so_linger.l_onoff = 1;
    so_linger.l_linger = 0;
    pj_sock_setsockopt(sock, SOL_SOCKET, SO_LINGER, &so_linger, sizeof(so_linger));
}

pj_status_t pj_ws_transport_start_connect(pj_ws_transport_t *tp, const pj_sockaddr_t *remaddr, int addr_len)
{
    pj_status_t status;
    pj_sockaddr *rmt_addr = (pj_sockaddr *)remaddr;
    pj_ioqueue_t *ioq;
    pj_pool_t *pool;
    int type = pj_SOCK_STREAM();
    int af;
    pj_sock_t sock = PJ_INVALID_SOCKET;
    pj_activesock_t *asock = NULL;
    pj_activesock_cfg cfg;
    pj_activesock_cb cb;

    PJ_ASSERT_RETURN(tp, PJ_EINVAL);
    PJ_ASSERT_RETURN(remaddr, PJ_EINVAL);
    PJ_ASSERT_RETURN(((addr_len == sizeof(pj_sockaddr_in) && rmt_addr->addr.sa_family == pj_AF_INET()) ||
                      (addr_len == sizeof(pj_sockaddr_in6) && rmt_addr->addr.sa_family == pj_AF_INET6())),
                     PJ_EINVAL);

    ioq = tp->ioq;
    pool = tp->pool;
    af = rmt_addr->addr.sa_family;
    status = pj_sock_socket(af, type, 0, &sock);
    if (status != PJ_SUCCESS) {
        PJ_PERROR(1, (THIS_FILE, status, "sock error"));
        return status;
    }

    disable_tcp_timewait(sock);

    pj_activesock_cfg_default(&cfg);
    pj_bzero(&cb, sizeof(cb));
    cb.on_connect_complete = on_connect_complete;
    cb.on_data_read = on_data_read;
    cb.on_data_sent = on_data_sent;
    status = pj_activesock_create(pool, sock, type, &cfg, ioq, &cb, tp, &asock);
    if (status != PJ_SUCCESS) {
        PJ_PERROR(1, (THIS_FILE, status, "asock create error"));
        goto on_error;
    }

    tp->asock = asock;
    tp->sock = sock;
    status = pj_activesock_start_connect(asock, pool, remaddr, addr_len);
    if (status == PJ_SUCCESS) {
        on_connect_complete(asock, PJ_SUCCESS);
        return PJ_SUCCESS;
    }
    if (status != PJ_EPENDING) {
        PJ_PERROR(1, (THIS_FILE, status, "ascock start connect error"));
        goto on_error;
    }

    return PJ_EPENDING;

on_error:
    if (asock) {
        pj_activesock_close(asock);
    } else if (sock > 0) {
        pj_sock_close(sock);
    }
    tp->asock = NULL;
    tp->sock = PJ_INVALID_SOCKET;
    return status;
}

pj_status_t pj_ws_transport_start_listen(pj_ws_transport_t *tp, const pj_sockaddr_t *local_addr, int addr_len)
{
    pj_status_t status;
    pj_ioqueue_t *ioq = tp->ioq;
    pj_pool_t *pool = tp->pool;
    pj_sockaddr *paddr = (pj_sockaddr *)local_addr;
    int af = paddr->addr.sa_family;
    int type = pj_SOCK_STREAM();
    pj_sock_t sock = PJ_INVALID_SOCKET;
    pj_activesock_t *asock = NULL;
    pj_activesock_cfg cfg;
    pj_activesock_cb cb;

    PJ_ASSERT_RETURN(tp, PJ_EINVAL);
    PJ_ASSERT_RETURN(local_addr, PJ_EINVAL);

    status = pj_sock_socket(af, type, 0, &sock);
    if (status != PJ_SUCCESS) {
        PJ_PERROR(1, (THIS_FILE, status, "sock error"));
        return status;
    }

    disable_tcp_timewait(sock);

    status = pj_sock_bind(sock, local_addr, addr_len);
    if (status != PJ_SUCCESS) {
        PJ_PERROR(1, (THIS_FILE, status, "sock bind port=%u", pj_sockaddr_get_port(local_addr)));
        return status;
    }

    status = pj_sock_listen(sock, PJ_SOMAXCONN);
    if (status != PJ_SUCCESS) {
        PJ_PERROR(1, (THIS_FILE, status, "sock listen port=%u", pj_sockaddr_get_port(local_addr)));
        return status;
    }

    pj_activesock_cfg_default(&cfg);
    pj_bzero(&cb, sizeof(cb));
    cb.on_accept_complete = on_accept_complete;
    status = pj_activesock_create(pool, sock, type, &cfg, ioq, &cb, tp, &asock);
    if (status != PJ_SUCCESS) {
        PJ_PERROR(1, (THIS_FILE, status, "asock create error"));
        goto on_error;
    }

    status = pj_activesock_start_accept(asock, pool);
    if (status != PJ_SUCCESS) {
        PJ_PERROR(1, (THIS_FILE, status, "asock accept error"));
        goto on_error;
    }

    tp->asock = asock;
    tp->sock = sock;

    return PJ_SUCCESS;
on_error:
    if (asock) {
        pj_activesock_close(asock);
    } else if (sock > 0) {
        pj_sock_close(sock);
    }
    return status;
}

pj_status_t pj_ws_transport_send(pj_ws_transport_t *tp, pj_ioqueue_op_key_t *send_key, const void *data, pj_ssize_t *size, unsigned flags)
{
    pj_status_t status;

    PJ_ASSERT_RETURN(tp, PJ_EINVAL);
    PJ_ASSERT_RETURN(send_key, PJ_EINVAL);
    PJ_ASSERT_RETURN(data, PJ_EINVAL);
    PJ_ASSERT_RETURN(size && *size > 0, PJ_EINVAL);

    status = pj_activesock_send(tp->asock, send_key, data, size, flags);
    if (status == PJ_SUCCESS) {
        pj_ws_transport_cb *cb = &tp->cb;
        if (cb->on_data_sent)
            cb->on_data_sent(tp, send_key, *size);
        return PJ_SUCCESS;
    }

    if (status != PJ_EPENDING) {
        PJ_PERROR(1, (THIS_FILE, status, "send error"));
        pj_ws_transport_cb *cb = &tp->cb;
        if (cb->on_data_sent)
            cb->on_data_sent(tp, send_key, -status);
    }

    return status;
}

static pj_bool_t on_accept_complete(pj_activesock_t *asock, pj_sock_t newsock, const pj_sockaddr_t *src_addr, int src_addr_len)
{
    pj_status_t status;
    pj_ws_transport_t *tp = pj_activesock_get_user_data(asock);
    pj_ws_transport_t *new_tp;
    pj_ws_transport_param tp_param;
    pj_ioqueue_t *ioq = tp->ioq;
    pj_pool_factory *pf = tp->pf;
    pj_pool_t *pool;
    pj_activesock_t *new_asock = NULL;
    pj_activesock_cfg cfg;
    pj_activesock_cb cb;

    pj_bzero(&tp_param, sizeof(tp_param));
    tp_param.ioq = ioq;
    tp_param.pf = pf;
    tp_param.max_rx_bufsize = tp->max_rx_bufsize;

    status = pj_ws_transport_create(NULL, &tp_param, &new_tp);
    if (status != PJ_SUCCESS) {
        PJ_PERROR(1, (THIS_FILE, status, "%s() new transport error", __FUNCTION__));
        new_tp = NULL;
        goto on_error;
    }
    disable_tcp_timewait(newsock);

    pool = new_tp->pool;
    pj_activesock_cfg_default(&cfg);
    pj_bzero(&cb, sizeof(cb));
    cb.on_data_read = on_data_read;
    cb.on_data_sent = on_data_sent;
    status = pj_activesock_create(pool, newsock, pj_SOCK_STREAM(), &cfg, ioq, &cb, new_tp, &new_asock);
    if (status != PJ_SUCCESS) {
        PJ_PERROR(1, (THIS_FILE, status, "%s() create asock error", __FUNCTION__));
        goto on_error;
    }

    new_tp->asock = new_asock;
    new_tp->sock = newsock;

    status = pj_activesock_start_read(new_asock, pool, tp->max_rx_bufsize, 0);
    if (status != PJ_SUCCESS) {
        PJ_PERROR(1, (THIS_FILE, status, "start read error"));
        goto on_error;
    }

    /*notify accept event*/
    if (tp->cb.on_accept_complete) {
        pj_sockaddr loc;
        int len = sizeof(loc);
        pj_sock_getsockname(newsock, &loc, &len);
        tp->cb.on_accept_complete(tp, new_tp, src_addr, src_addr_len, &loc, len);
    }

    return PJ_TRUE;
on_error:
    if (new_tp)
        pj_ws_transport_destroy(new_tp);
    else if (new_asock)
        pj_activesock_close(new_asock);
    else if (newsock)
        pj_sock_close(newsock);
    return PJ_FALSE;
}

static pj_bool_t on_connect_complete(pj_activesock_t *asock, pj_status_t status)
{
    pj_ws_transport_t *tp = pj_activesock_get_user_data(asock);
    pj_ws_transport_cb *cb = &tp->cb;
    PJ_PERROR(6, (THIS_FILE, status, "%s() %s status:%d", __FUNCTION__, tp->base.pool->obj_name, status));

    if (status == PJ_SUCCESS) {
        status = pj_activesock_start_read(tp->asock, tp->pool, tp->max_rx_bufsize, 0);
        if (status != PJ_SUCCESS) {
            PJ_PERROR(1, (THIS_FILE, status, "start read error"));
        }
    }

    if (cb->on_connect_complete) {
        if (status == PJ_SUCCESS) {
            pj_sockaddr sa;
            int len = sizeof(sa);
            pj_sock_getsockname(tp->sock, &sa, &len);
            return cb->on_connect_complete(tp, status, &sa, len);
        } else {
            return cb->on_connect_complete(tp, status, 0, 0);
        }
    }

    return (status == PJ_SUCCESS ? PJ_TRUE : PJ_FALSE);
}

static pj_bool_t on_data_read(pj_activesock_t *asock, void *data, pj_size_t size, pj_status_t status, pj_size_t *remainder)
{
    pj_ws_transport_t *tp = pj_activesock_get_user_data(asock);
    pj_ws_transport_cb *cb = &tp->cb;

    PJ_PERROR(6, (THIS_FILE, status, "%s() %s status:%d, size:%d", __FUNCTION__, tp->pool->obj_name, status, size));

    if (status != PJ_SUCCESS) {
        PJ_PERROR(2, (THIS_FILE, status, "%s() %s status:%d, size:%lu", __FUNCTION__, tp->pool->obj_name, status, size));
        pj_activesock_close(asock);
        tp->asock = NULL;
    }

    if (cb->on_data_read)
        return cb->on_data_read(tp, data, size, status, remainder);

    return (status == PJ_SUCCESS ? PJ_TRUE : PJ_FALSE);
}

static pj_bool_t on_data_sent(pj_activesock_t *asock, pj_ioqueue_op_key_t *send_key, pj_ssize_t sent)
{
    pj_ws_transport_t *tp = pj_activesock_get_user_data(asock);
    pj_ws_transport_cb *cb = &tp->cb;

    PJ_LOG(6, (THIS_FILE, "%s() %ld", __FUNCTION__, sent));

    if (cb->on_data_sent)
        return cb->on_data_sent(tp, send_key, sent);

    return PJ_TRUE;
}
