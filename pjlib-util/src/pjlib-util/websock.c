#include <pjlib-util/websock.h>
#include <pjlib-util/websock_transport.h>
#include <pjlib-util/http.h>
#include <pjlib.h>
#include <pjlib-util/base64.h>
#include <pjlib-util/sha1.h>

#define THIS_FILE "websock.c"

static pj_str_t PJ_WS_STATUS_CODE_101 = {"101", 3};
static pj_str_t PJ_WS_KEY_NAME_CONNECTION = {"Connection", 10};
static pj_str_t PJ_WS_KEY_NAME_UPGRADE = {"Upgrade", 7};
static pj_str_t PJ_WS_KEY_NAME_SEC_WEBSOCKET_KEY = {"Sec-WebSocket-Key", 17};
static pj_str_t PJ_WS_KEY_NAME_SEC_WEBSOCKET_PROTO = {"Sec-WebSocket-Protocol", 22};
static pj_str_t PJ_WS_KEY_NAME_SEC_WEBSOCKET_VERSION = {"Sec-WebSocket-Version", 21};
static pj_str_t PJ_WS_KEY_NAME_SEC_WEBSOCKET_ACCEPT = {"Sec-WebSocket-Accept", 20};
static pj_str_t PJ_WS_KEY_VALUE_WEBSOCKET = {"websocket", 9};
static const pj_time_val HANDSHAKE_TIMEOUT = {10, 0};
enum {
    TIMER_ID_NONE,
    TIMER_ID_HANDSHAKE,
    TIMER_ID_PING,
    TIMER_ID_CLOSE,
};

struct pj_ws_endpoint {
    pj_pool_factory *pf;
    pj_ioqueue_t *ioq;
    pj_timer_heap_t *timer_heap;
    pj_uint32_t max_rx_bufsize;
    pj_pool_t *pool;
    pj_ws_t *conn_list;
    pj_bool_t msg_logger;
};

struct pj_ws_t {
    PJ_DECL_LIST_MEMBER(struct pj_ws_t);
    pj_pool_t *pool;
    pj_ws_endpoint *endpt;
    pj_ws_cb cb;
    void *user_data;
    pj_bool_t is_srv;
    pj_bool_t is_incoming;
    pj_ws_t *parent;
    pj_ws_readystate state;
    pj_sockaddr loc;
    pj_sockaddr peer;
    pj_ws_transport_t *tp;
    pj_str_t req_msg;

    struct {
        pj_str_t paths[PJ_WS_MAX_PATH_CNT];
        int path_cnt;
        pj_str_t subprotos[PJ_WS_MAX_SUB_PROTO_CNT];
        int proto_cnt;
    } filter;

    pj_str_t req_path;
    pj_str_t query_param;
    pj_str_t subproto;
    pj_bool_t pending_payload;
    pj_ws_rx_data rdata;
    pj_timer_entry timer;
    pj_time_val ping_interval;
    int close_code;
};

static pj_bool_t on_connect_complete(pj_ws_transport_t *t, pj_status_t status, const pj_sockaddr_t *bound_addr, int addr_len);
static pj_bool_t on_accept_complete(pj_ws_transport_t *t,
                                    pj_ws_transport_t *newt,
                                    const pj_sockaddr_t *src_addr,
                                    int src_addr_len,
                                    const pj_sockaddr_t *loc_addr,
                                    int loc_addr_len);
static pj_bool_t on_data_read(pj_ws_transport_t *t, void *data, pj_size_t size, pj_status_t status, pj_size_t *remainder);
static pj_bool_t on_data_sent(pj_ws_transport_t *t, pj_ioqueue_op_key_t *send_key, pj_ssize_t sent);
static void generate_websock_key(char *buf, int *size);
static void generate_websock_accept(const pj_str_t *key, char *buf, int *size);
static pj_bool_t validate_websock_accept(const pj_str_t *accept, const pj_str_t *key);
static pj_bool_t verify_srv_filter(pj_ws_t *srv, pj_ws_t *c, const pj_http_msg *req);
static pj_status_t proc_websock_handshake(pj_ws_t *c, const pj_http_msg *msg);
static void switch_websock_state(pj_ws_t *c, int state);

/* log print message */
static pj_bool_t logger_on_rx_msg(pj_ws_t *c, pj_ws_rx_data *msg, pj_status_t status);
static pj_bool_t logger_on_tx_msg(pj_ws_t *c, pj_ws_tx_data *msg, pj_ssize_t sent);
static pj_bool_t logger_on_connect_complete(pj_ws_t *c, pj_status_t status);
static pj_bool_t logger_on_accept_complete(pj_ws_t *c, const pj_sockaddr_t *src_addr, int src_addr_len);
static void logger_on_state_change(pj_ws_t *c, int state);
static pj_ws_cb mlogger = {
    .on_rx_msg = logger_on_rx_msg,
    .on_tx_msg = logger_on_tx_msg,
    .on_connect_complete = logger_on_connect_complete,
    .on_accept_complete = logger_on_accept_complete,
    .on_state_change = logger_on_state_change,
};

void pj_ws_endpt_cfg_default(pj_ws_endpt_cfg *opt)
{
    pj_bzero(opt, sizeof(*opt));
    opt->max_rx_bufsize = 8000;
    opt->msg_logger = PJ_TRUE;
}

pj_status_t pj_ws_endpt_create(pj_ws_endpt_cfg *opt, pj_ws_endpoint **pendpt)
{
    pj_pool_t *pool;
    pj_ws_endpoint *endpt;
    PJ_ASSERT_RETURN(opt, PJ_EINVAL);
    PJ_ASSERT_RETURN(opt->pf, PJ_EINVAL);
    PJ_ASSERT_RETURN(opt->ioq, PJ_EINVAL);
    PJ_ASSERT_RETURN(opt->timer_heap, PJ_EINVAL);
    PJ_ASSERT_RETURN(pendpt, PJ_EINVAL);

    pool = pj_pool_create(opt->pf, "websock_ept%p", 500, 500, NULL);
    PJ_ASSERT_RETURN(pool, PJ_ENOMEM);

    endpt = PJ_POOL_ALLOC_T(pool, pj_ws_endpoint);
    PJ_ASSERT_RETURN(endpt, PJ_ENOMEM);
    endpt->pf = opt->pf;
    endpt->ioq = opt->ioq;
    endpt->timer_heap = opt->timer_heap;
    endpt->pool = pool;
    endpt->max_rx_bufsize = opt->max_rx_bufsize;
    endpt->msg_logger = opt->msg_logger;
    endpt->conn_list = PJ_POOL_ZALLOC_T(pool, pj_ws_t);
    pj_list_init(endpt->conn_list);

    *pendpt = endpt;
    return PJ_SUCCESS;
}

pj_status_t pj_ws_endpt_destroy(pj_ws_endpoint *endpt)
{
    if (!endpt)
        return PJ_EINVAL;
    while (pj_list_empty(endpt->conn_list) == PJ_FALSE) {
        pj_ws_t *c = endpt->conn_list->next;
        pj_ws_close(c, PJ_WS_SC_NORMAL_CLOSURE, NULL);
    }

    pj_pool_release(endpt->pool);
    return PJ_SUCCESS;
}

static void timer_callback(pj_timer_heap_t *heap, pj_timer_entry *e)
{
    pj_ws_t *c = (pj_ws_t *)e->user_data;
    char buf[160];
    PJ_UNUSED_ARG(heap);

    if (c->timer.id == TIMER_ID_HANDSHAKE) {
        PJ_LOG(2, (THIS_FILE, "#%s: handshake timeout !!", pj_ws_print(c, buf, sizeof(buf))));
        pj_assert(c->state == PJ_WS_STATE_CONNECTING);
        c->timer.id = TIMER_ID_NONE;
        if (c->is_incoming) {
            /* incoming connection no request */
        } else {
            /* outgoing request no response */
            mlogger.on_connect_complete(c, PJ_ETIMEDOUT);
            if (c->cb.on_connect_complete)
                c->cb.on_connect_complete(c, PJ_ETIMEDOUT);
        }
        pj_ws_close(c, PJ_WS_SC_ABNORMAL_CLOSURE, NULL);
    } else if (c->timer.id == TIMER_ID_PING) {
        pj_assert(c->state == PJ_WS_STATE_OPEN);
        pj_ws_send(c, PJ_WS_OP_PING, PJ_TRUE, !c->is_incoming, 0, 0);
        pj_timer_heap_schedule(c->endpt->timer_heap, &c->timer, &c->ping_interval);
    } else if (c->timer.id == TIMER_ID_CLOSE) {
        c->timer.id = TIMER_ID_NONE;
        pj_ws_close(c, c->close_code, NULL);
    }
}

#define CHECK_BUF_LEN()        \
    if (n < 0 || n >= end - p) \
        goto out;              \
    p += n;

static void generate_http_request_msg(const pj_http_uri *http_uri, const pj_ws_http_hdr *hdrs, int hdr_cnt, char *buf, int *size)
{
    int i;
    char *p, *end;
    char websock_key[80];
    int key_len = sizeof(websock_key);
    int n;
    pj_ssize_t path_len;

    p = buf;
    end = p + *size - 3;

    path_len = http_uri->path.slen;
    if (http_uri->query.slen)
        path_len += http_uri->query.slen + 1;
    n = pj_ansi_snprintf(p, end - p, "GET %.*s HTTP/1.1\r\n", (int)path_len, http_uri->path.ptr);
    CHECK_BUF_LEN();
    if (http_uri->port.slen == 0)
        n = pj_ansi_snprintf(p, end - p, "Host: %.*s\r\n", (int)http_uri->host.slen, http_uri->host.ptr);
    else
        n = pj_ansi_snprintf(p, end - p, "Host: %.*s:%.*s\r\n", (int)http_uri->host.slen, http_uri->host.ptr, (int)http_uri->port.slen, http_uri->port.ptr);
    CHECK_BUF_LEN();
    n = pj_ansi_snprintf(p, end - p, "Connection: Upgrade\r\n");
    CHECK_BUF_LEN();
    n = pj_ansi_snprintf(p, end - p, "Upgrade: websocket\r\n");
    CHECK_BUF_LEN();
    n = pj_ansi_snprintf(p, end - p, "Sec-WebSocket-Version: %d\r\n", PJ_WS_VERSION);
    CHECK_BUF_LEN();
    generate_websock_key(websock_key, &key_len);
    n = pj_ansi_snprintf(p, end - p, "Sec-WebSocket-Key: %.*s\r\n", key_len, websock_key);
    CHECK_BUF_LEN();
    for (i = 0; i < hdr_cnt; i++) {
        n = pj_ansi_snprintf(p, end - p, "%.*s: %.*s\r\n", (int)hdrs[i].key.slen, hdrs[i].key.ptr, (int)hdrs[i].val.slen, hdrs[i].val.ptr);
        CHECK_BUF_LEN();
    }

out:
    *p++ = '\r';
    *p++ = '\n';
    *p = '\0';
    *size = p - buf;
}

pj_status_t
pj_ws_connect(pj_ws_endpoint *endpt, const char *url, const pj_ws_cb *cb, void *user_data, pj_ws_http_hdr *hdrs, int hdr_cnt, pj_ws_t **pc)
{
    pj_status_t status;
    pj_ws_t *c;
    pj_pool_t *pool;
    pj_uint16_t port;
    char str_host[PJ_MAX_HOSTNAME];
    pj_str_t host;
    pj_ws_transport_param tp_param;
    pj_http_uri http_uri;
    pj_http_msg msg_dummy;
    char msg_buf[2000];
    int msg_len = sizeof(msg_buf);

    PJ_ASSERT_RETURN(endpt, PJ_EINVAL);
    PJ_ASSERT_RETURN(url && url[0], PJ_EINVAL);
    PJ_ASSERT_RETURN(pc, PJ_EINVAL);

    PJ_LOG(4, (THIS_FILE, "Connecting to url: %s", url));

    pool = pj_pool_create(endpt->pf, "websock_c%p", 1000, 1000, NULL);
    PJ_ASSERT_RETURN(pool, PJ_ENOMEM);

    c = PJ_POOL_ZALLOC_T(pool, pj_ws_t);
    pj_timer_entry_init(&c->timer, TIMER_ID_NONE, c, timer_callback);
    c->pool = pool;
    c->endpt = endpt;
    c->user_data = user_data;
    if (cb)
        pj_memcpy(&c->cb, cb, sizeof(*cb));

    /* parse url */
    status = pj_http_uri_parse(url, &http_uri);
    if (status != PJ_SUCCESS) {
        PJ_PERROR(1, (THIS_FILE, status, "parse url:%s error", url));
        goto on_error;
    }
    port = pj_http_uri_port(&http_uri);
    pj_ansi_snprintf(str_host, sizeof(str_host), "%.*s:%u", (int)http_uri.host.slen, http_uri.host.ptr, port);
    host = pj_str(str_host);
    status = pj_sockaddr_parse(pj_AF_UNSPEC(), 0, &host, &c->peer);
    if (status != PJ_SUCCESS) {
        PJ_PERROR(1, (THIS_FILE, status, "parse sockaddr:%s error", url));
        goto on_error;
    }

    pj_strdup_with_null(pool, &c->req_path, &http_uri.path);
    pj_strdup_with_null(pool, &c->query_param, &http_uri.query);
    generate_http_request_msg(&http_uri, hdrs, hdr_cnt, msg_buf, &msg_len);
    status = pj_http_msg_parse(msg_buf, msg_len, &msg_dummy, NULL);
    if (status != PJ_SUCCESS) {
        PJ_PERROR(1, (THIS_FILE, status, "request message"));
        goto on_error;
    }
    pj_http_msg_find_hdr(&msg_dummy, &PJ_WS_KEY_NAME_SEC_WEBSOCKET_PROTO, &c->subproto);
    pj_strdup2_with_null(pool, &c->req_msg, msg_buf);

    pj_ws_transport_param_default(&tp_param);
    tp_param.ioq = endpt->ioq;
    tp_param.pf = endpt->pf;
    tp_param.timer_heap = endpt->timer_heap;
    tp_param.max_rx_bufsize = endpt->max_rx_bufsize;
    tp_param.user_data = c;
    tp_param.cb.on_connect_complete = on_connect_complete;
    tp_param.cb.on_data_read = on_data_read;
    tp_param.cb.on_data_sent = on_data_sent;

    status = pj_ws_transport_create(pool, &tp_param, &c->tp);
    if (status != PJ_SUCCESS) {
        PJ_PERROR(1, (THIS_FILE, status, "transport create error"));
        goto on_error;
    }

    switch_websock_state(c, PJ_WS_STATE_CONNECTING);
    *pc = c;
    status = pj_ws_transport_start_connect(c->tp, &c->peer, pj_sockaddr_get_len(&c->peer));
    if (status != PJ_EPENDING) {
        PJ_PERROR(1, (THIS_FILE, status, "transport start connect error"));
        goto on_error;
    }

    pj_list_push_front(endpt->conn_list, c);
    return status;
on_error:
    pj_pool_release(c->pool);
    *pc = NULL;
    return status;
}

pj_status_t pj_ws_close(pj_ws_t *c, int code, const char *reason)
{
    PJ_UNUSED_ARG(code);
    PJ_UNUSED_ARG(reason);
    PJ_ASSERT_RETURN(c, PJ_EINVAL);
    c->close_code = code;
    if (c->state == PJ_WS_STATE_OPEN)
        switch_websock_state(c, PJ_WS_STATE_CLOSING);
    pj_list_erase(c);
    pj_ws_transport_destroy(c->tp);
    switch_websock_state(c, PJ_WS_STATE_CLOSED);
    pj_pool_release(c->pool);

    return PJ_SUCCESS;
}

static void delay_close(pj_ws_t *c, int code)
{
    pj_time_val delay = {0, 0};
    if (c->timer.id != TIMER_ID_NONE)
        pj_timer_heap_cancel(c->endpt->timer_heap, &c->timer);
    c->close_code = code;
    c->timer.id = TIMER_ID_CLOSE;
    pj_timer_heap_schedule(c->endpt->timer_heap, &c->timer, &delay);
}

pj_status_t pj_ws_send(pj_ws_t *c, int opcode, pj_bool_t fini, pj_bool_t mask, const void *data, pj_size_t len)
{
    pj_status_t status;
    pj_pool_t *pool;
    char *tx_buf;
    char *p;
    char *mkey = 0;
    char *pdata = 0;
    pj_ssize_t tx_len;
    pj_ws_tx_data *tdata;

    PJ_ASSERT_RETURN(c, PJ_EINVAL);
    if (c->state != PJ_WS_STATE_OPEN) {
        PJ_LOG(1, (THIS_FILE, "Can't send in state %s !", pj_ws_state_str(c->state)));
        return PJ_EINVALIDOP;
    }

    pool = pj_pool_create(c->endpt->pf, "ws_tdata%p", 1000, 1000, NULL);
    tx_buf = (char *)pj_pool_alloc(pool, len + sizeof(pj_ws_frame_hdr));
    p = tx_buf;

    *p++ = (fini << 7) | (opcode & 0x0f);
    if (len <= 125) {
        *p++ = (mask << 7) | (len & 0x7f);
    } else if (len <= 0xffff) {
        *p++ = (mask << 7) | 126;
        *((pj_uint16_t *)p) = pj_htons(len);
        p += 2;
    } else {
        *p++ = (mask << 7) | 127;
        *((pj_uint64_t *)p) = pj_htonll(len);
        p += 8;
    }
    if (mask) {
        pj_create_random_string(p, 4);
        mkey = p;
        p += 4;
    }

    pdata = p;
    if (len > 0) {
        pj_memcpy(p, data, len);
        p += len;

        if (mask) {
            pj_size_t i = 0;
            for (i = 0; i < len; i++)
                pdata[i] = pdata[i] ^ mkey[i % 4];
        }
    }

    tx_len = p - tx_buf;
    tdata = PJ_POOL_ZALLOC_T(pool, pj_ws_tx_data);
    tdata->pool = pool;
    tdata->hdr.fin = fini;
    tdata->hdr.opcode = opcode;
    tdata->hdr.mask = mask;
    tdata->hdr.len = len;
    tdata->data = (void *)data;
    tdata->send_key.user_data = tdata;
    status = pj_ws_transport_send(c->tp, &tdata->send_key, tx_buf, &tx_len, 0);
    if (status == PJ_SUCCESS)
        return PJ_SUCCESS;

    if (status != PJ_EPENDING) {
        PJ_PERROR(1, (THIS_FILE, status, "send error"));
        return status;
    }

    return PJ_EPENDING;
}

pj_status_t pj_ws_send_text(pj_ws_t *c, const char *text, pj_size_t len)
{
    PJ_ASSERT_RETURN(c && text && len, PJ_EINVAL);
    return pj_ws_send(c, PJ_WS_OP_TEXT, PJ_TRUE, !c->is_incoming, text, len);
}

pj_status_t pj_ws_listen(pj_ws_endpoint *endpt, pj_sockaddr_t *local_addr, pj_ws_cb *cb, void *user_data, pj_ws_t **s)
{
    pj_status_t status;
    pj_ws_t *ws;
    pj_pool_t *pool;
    pj_ws_transport_param tp_param;
    pj_ws_transport_t *tp = NULL;
    char sbuf[200];

    PJ_ASSERT_RETURN(endpt, PJ_EINVAL);
    PJ_ASSERT_RETURN(local_addr, PJ_EINVAL);
    pool = pj_pool_create(endpt->pf, "ws_srv%p", 1000, 1000, NULL);
    ws = PJ_POOL_ZALLOC_T(pool, pj_ws_t);
    ws->pool = pool;
    ws->endpt = endpt;
    ws->is_srv = PJ_TRUE;
    ws->user_data = user_data;
    if (cb)
        pj_memcpy(&ws->cb, cb, sizeof(*cb));

    pj_ws_transport_param_default(&tp_param);
    tp_param.ioq = endpt->ioq;
    tp_param.pf = endpt->pf;
    tp_param.timer_heap = endpt->timer_heap;
    tp_param.max_rx_bufsize = endpt->max_rx_bufsize;
    tp_param.user_data = ws;
    tp_param.cb.on_accept_complete = on_accept_complete;

    pj_sockaddr_print(local_addr, sbuf, sizeof(sbuf), 3);
    PJ_LOG(4, (THIS_FILE, "Listen %s", sbuf));

    status = pj_ws_transport_create(pool, &tp_param, &tp);
    if (status != PJ_SUCCESS) {
        PJ_PERROR(1, (THIS_FILE, status, "server create transport"));
        goto on_error;
    }

    ws->tp = tp;
    status = pj_ws_transport_start_listen(tp, local_addr, pj_sockaddr_get_len(local_addr));
    if (status != PJ_SUCCESS) {
        PJ_PERROR(1, (THIS_FILE, status, "server start accept"));
        goto on_error;
    }

    pj_list_push_front(endpt->conn_list, ws);
    *s = ws;
    return PJ_SUCCESS;

on_error:
    if (tp)
        pj_ws_transport_destroy(tp);
    pj_pool_release(pool);
    return status;
}

pj_status_t pj_ws_set_callbacks(pj_ws_t *c, const pj_ws_cb *cb)
{
    PJ_ASSERT_RETURN(c, PJ_EINVAL);
    if (cb) {
        pj_memcpy(&c->cb, cb, sizeof(*cb));
    } else {
        pj_bzero(&c->cb, sizeof(c->cb));
    }
    return PJ_SUCCESS;
}

pj_status_t pj_ws_set_userdata(pj_ws_t *c, void *user_data)
{
    PJ_ASSERT_RETURN(c, PJ_EINVAL);
    c->user_data = user_data;
    return PJ_SUCCESS;
}

int pj_ws_get_ready_state(pj_ws_t *c)
{
    PJ_ASSERT_RETURN(c, -1);
    return c->state;
}

int pj_ws_get_close_code(pj_ws_t *c)
{
    PJ_ASSERT_RETURN(c, -1);
    return c->close_code;
}

void *pj_ws_get_userdata(pj_ws_t *c)
{
    PJ_ASSERT_RETURN(c, NULL);
    return c->user_data;
}

pj_pool_t * pj_ws_get_pool(pj_ws_t *c)
{
    PJ_ASSERT_RETURN(c, NULL);
    return c->pool;
}

pj_status_t pj_ws_enable_ping(pj_ws_t *c, pj_time_val *t)
{
    PJ_ASSERT_RETURN(c, PJ_EINVAL);
    PJ_ASSERT_RETURN(!c->is_srv, PJ_EINVALIDOP);

    if (t && PJ_TIME_VAL_MSEC(*t)) {
        if (c->state != PJ_WS_STATE_OPEN) {
            PJ_LOG(2, (THIS_FILE, "%s state is not OPEN", c->pool->obj_name));
            return PJ_EINVALIDOP;
        }

        if (c->timer.id != TIMER_ID_NONE) {
            return PJ_EIGNORED;
        }

        pj_timer_heap_schedule(c->endpt->timer_heap, &c->timer, t);
        c->timer.id = TIMER_ID_PING;
        c->ping_interval = *t;
    } else {
        if (c->timer.id != TIMER_ID_PING) {
            return PJ_EIGNORED;
        }
        pj_timer_heap_cancel(c->endpt->timer_heap, &c->timer);
        c->timer.id = TIMER_ID_NONE;
    }

    return PJ_SUCCESS;
}

pj_bool_t pj_ws_is_incoming(pj_ws_t *c)
{
    PJ_ASSERT_RETURN(c, PJ_FALSE);
    return c->is_incoming;
}

const char *pj_ws_get_request_path(pj_ws_t *c)
{
    PJ_ASSERT_RETURN(c, NULL);
    return c->req_path.ptr;
}

const char *pj_ws_get_query_param(pj_ws_t *c)
{
    PJ_ASSERT_RETURN(c, NULL);
    return c->query_param.ptr;
}

const char *pj_ws_get_subproto(pj_ws_t *c)
{
    PJ_ASSERT_RETURN(c, NULL);
    return c->subproto.ptr;
}

const char *pj_ws_print(pj_ws_t *c, char *buf, int len)
{
    char laddr[80], raddr[80];
    char *p = buf;
    char *end = buf + len - 1;
    int n;
    PJ_ASSERT_RETURN(c, NULL);
    PJ_ASSERT_RETURN(buf, NULL);
    PJ_ASSERT_RETURN(len > 0, NULL);

    n = pj_ansi_snprintf(p, end - p, "%s", c->pool->obj_name);
    CHECK_BUF_LEN();
    n = pj_ansi_snprintf(p, end - p, "(%s ", c->req_path.ptr);
    CHECK_BUF_LEN();
    if (c->query_param.slen > 0) {
        n = pj_ansi_snprintf(p, end - p, "%s ", c->query_param.ptr);
        CHECK_BUF_LEN();
    }
    if (c->subproto.slen > 0) {
        n = pj_ansi_snprintf(p, end - p, "%s ", c->subproto.ptr);
        CHECK_BUF_LEN();
    }
    if (c->loc.addr.sa_family) {
        pj_sockaddr_print(&c->loc, laddr, sizeof(laddr), 3);
    }
    else {
        pj_ansi_snprintf(laddr, sizeof(laddr), "%s", "?");
    }
    pj_sockaddr_print(&c->peer, raddr, sizeof(raddr), 3);
    n = pj_ansi_snprintf(p, end - p, "%s %s %s)", laddr, c->is_incoming ? "<-" : "->", raddr);
    CHECK_BUF_LEN();

out:
    *p = '\0';
    return buf;
}

const char *pj_ws_opcode_str(int opcode)
{
    switch (opcode) {
    case PJ_WS_OP_TEXT:
        return "TEXT";
    case PJ_WS_OP_BIN:
        return "BIN";
    case PJ_WS_OP_CONTN:
        return "CONTN";
    case PJ_WS_OP_PING:
        return "PING";
    case PJ_WS_OP_PONG:
        return "PONG";
    case PJ_WS_OP_CLOSE:
        return "CLOSE";
    default:
        break;
    }
    return "?";
}

const char *pj_ws_state_str(int state)
{
    switch (state) {
    case PJ_WS_STATE_CONNECTING:
        return "CONNECTING";
    case PJ_WS_STATE_OPEN:
        return "OPEN";
    case PJ_WS_STATE_CLOSING:
        return "CLOSING";
    case PJ_WS_STATE_CLOSED:
        return "CLOSED";
    default:
        break;
    }
    return "?";
}

pj_status_t pj_ws_set_support_path(pj_ws_t *srv, pj_str_t paths[], int cnt)
{
    int i = 0;
    PJ_ASSERT_RETURN(srv, PJ_EINVAL);
    PJ_ASSERT_RETURN(srv->is_srv, PJ_EINVALIDOP);
    PJ_ASSERT_RETURN(cnt <= PJ_WS_MAX_PATH_CNT, PJ_ETOOMANY);

    for (i = 0; i < cnt; i++) {
        pj_strdup_with_null(srv->pool, &srv->filter.paths[i], &paths[i]);
    }
    srv->filter.path_cnt = cnt;

    return PJ_SUCCESS;
}
pj_status_t pj_ws_set_support_subproto(pj_ws_t *srv, pj_str_t protos[], int cnt)
{
    int i = 0;
    PJ_ASSERT_RETURN(srv, PJ_EINVAL);
    PJ_ASSERT_RETURN(srv->is_srv, PJ_EINVALIDOP);
    PJ_ASSERT_RETURN(cnt <= PJ_WS_MAX_SUB_PROTO_CNT, PJ_ETOOMANY);

    for (i = 0; i < cnt; i++) {
        pj_strdup_with_null(srv->pool, &srv->filter.subprotos[i], &protos[i]);
    }
    srv->filter.proto_cnt = cnt;

    return PJ_SUCCESS;
}

static pj_bool_t on_connect_complete(pj_ws_transport_t *t, pj_status_t status, const pj_sockaddr_t *bound_addr, int addr_len)
{
    pj_ws_t *c = (pj_ws_t *)pj_ws_transport_get_userdata(t);

    PJ_PERROR(6, (THIS_FILE, status, "%s() %s status:%d", __FUNCTION__, c->pool->obj_name, status));

    if (status != PJ_SUCCESS) {
        mlogger.on_connect_complete(c, status);
        if (c->cb.on_connect_complete)
            c->cb.on_connect_complete(c, status);
        delay_close(c, PJ_WS_SC_ABNORMAL_CLOSURE);
        return PJ_FALSE;
    }

    /* store local bound addr*/
    PJ_UNUSED_ARG(addr_len);
    pj_sockaddr_cp(&c->loc, bound_addr);

    /*create and send http request */
    {
        pj_pool_t *pool = pj_pool_create(c->endpt->pf, "ws_tdata%p", 500, 500, NULL);
        pj_ws_tx_data *tdata = PJ_POOL_ZALLOC_T(pool, pj_ws_tx_data);
        char *buf = c->req_msg.ptr;
        pj_ssize_t size = c->req_msg.slen;

        PJ_LOG(5, (THIS_FILE, "TX to %s:\n%s", c->pool->obj_name, buf));

        tdata->pool = pool;
        tdata->data = buf;
        tdata->hdr.len = size;
        tdata->send_key.user_data = tdata;
        pj_ws_transport_send(c->tp, &tdata->send_key, buf, &size, 0);

        /* start timer to check if recv peer response timeout */
        c->timer.id = TIMER_ID_HANDSHAKE;
        pj_timer_heap_schedule(c->endpt->timer_heap, &c->timer, &HANDSHAKE_TIMEOUT);
    }

    return PJ_TRUE;
}

static pj_bool_t on_accept_complete(pj_ws_transport_t *t,
                                    pj_ws_transport_t *newt,
                                    const pj_sockaddr_t *src_addr,
                                    int src_addr_len,
                                    const pj_sockaddr_t *loc_addr,
                                    int loc_addr_len)
{
    PJ_UNUSED_ARG(src_addr_len);
    PJ_UNUSED_ARG(loc_addr_len);
    pj_ws_t *parent = (pj_ws_t *)pj_ws_transport_get_userdata(t);
    pj_ws_t *newc;
    pj_ws_endpoint *endpt = parent->endpt;
    pj_ws_transport_cb tp_cb;
    pj_pool_t *pool;

    /* new websocket connection */
    pool = pj_pool_create(endpt->pf, "websock_s%p", 1000, 1000, NULL);
    newc = PJ_POOL_ZALLOC_T(pool, pj_ws_t);
    pj_timer_entry_init(&newc->timer, TIMER_ID_NONE, newc, timer_callback);
    newc->pool = pool;
    newc->endpt = endpt;
    newc->is_incoming = PJ_TRUE;
    pj_sockaddr_cp(&newc->peer, src_addr);
    pj_sockaddr_cp(&newc->loc, loc_addr);
    newc->tp = newt;
    newc->parent = parent;
    switch_websock_state(newc, PJ_WS_STATE_CONNECTING);

    /* setup transport callbacks */
    pj_bzero(&tp_cb, sizeof(tp_cb));
    tp_cb.on_data_read = on_data_read;
    tp_cb.on_data_sent = on_data_sent;
    pj_ws_transport_set_callbacks(newt, &tp_cb);
    pj_ws_transport_set_userdata(newt, newc);

    pj_list_push_front(endpt->conn_list, newc);

    /* start timer to check if recv peer request timeout */
    newc->timer.id = TIMER_ID_HANDSHAKE;
    pj_timer_heap_schedule(endpt->timer_heap, &newc->timer, &HANDSHAKE_TIMEOUT);

    return PJ_TRUE;
}

static void unmask_payload(pj_uint8_t *mkey, pj_uint8_t *p, pj_uint64_t len, pj_uint64_t last_idx)
{
    pj_uint64_t i;
    if (len <= 0)
        return;
    for (i = 0; i < len; i++) {
        p[i] = p[i] ^ mkey[(i + last_idx) % 4];
    }
}

static pj_status_t http_reply_forbidden(pj_ws_t *c)
{
    pj_pool_t *pool;
    pj_ws_tx_data *tdata;
    char *p, *end;
    pj_ssize_t tx_len;

    pool = pj_pool_create(c->endpt->pf, "websock_tdata%p", 1000, 1000, NULL);
    tdata = PJ_POOL_ZALLOC_T(pool, pj_ws_tx_data);
    p = (char *)pj_pool_alloc(pool, 1000);
    end = p + 1000;
    tdata->pool = pool;
    tdata->data = p;
    tdata->send_key.user_data = tdata;

    p += pj_ansi_snprintf(p, end - p,
                          "HTTP/1.1 403 Forbidden\r\n"
                          "Content-Length: 0\r\n"
                          "\r\n");
    tx_len = p - (char *)tdata->data;
    PJ_LOG(5, (THIS_FILE, "TX to %s:\n%.*s", c->pool->obj_name, (int)tx_len, (char *)tdata->data));
    pj_ws_transport_send(c->tp, &tdata->send_key, tdata->data, &tx_len, 0);

    return PJ_SUCCESS;
}

static pj_status_t http_reply_switching(pj_ws_t *c, const pj_str_t *websock_key)
{
    pj_pool_t *pool;
    pj_ws_tx_data *tdata;
    char *p, *end;
    pj_ssize_t tx_len;
    char accept[200];
    int accept_len = sizeof(accept);

    pool = pj_pool_create(c->endpt->pf, "websock_tdata%p", 1000, 1000, NULL);
    tdata = PJ_POOL_ZALLOC_T(pool, pj_ws_tx_data);
    p = (char *)pj_pool_alloc(pool, 1000);
    end = p + 1000;
    tdata->pool = pool;
    tdata->data = p;
    tdata->send_key.user_data = tdata;

    p += pj_ansi_snprintf(p, end - p,
                          "HTTP/1.1 101 Switching Protocols\r\n"
                          "Upgrade:websocket\r\n"
                          "Connection: Upgrade\r\n");
    generate_websock_accept(websock_key, accept, &accept_len);
    p += pj_ansi_snprintf(p, end - p, "Sec-WebSocket-Accept: %.*s\r\n", accept_len, accept);

    if (c->subproto.slen > 0) {
        p += pj_ansi_snprintf(p, end - p, "Sec-WebSocket-Protocol: %.*s\r\n", (int)c->subproto.slen, c->subproto.ptr);
    }
    *p++ = '\r';
    *p++ = '\n';
    tx_len = p - (char *)tdata->data;

    PJ_LOG(5, (THIS_FILE, "TX to %s:\n%.*s", c->pool->obj_name, (int)tx_len, (char *)tdata->data));
    pj_ws_transport_send(c->tp, &tdata->send_key, tdata->data, &tx_len, 0);

    return PJ_SUCCESS;
}

static pj_bool_t on_data_read(pj_ws_transport_t *t, void *data, pj_size_t size, pj_status_t status, pj_size_t *remainder)
{
    pj_ws_t *c = (pj_ws_t *)pj_ws_transport_get_userdata(t);
    pj_size_t left_size = size;
    char *pdata = (char *)data;
    pj_ws_rx_data *rdata = &c->rdata;
    pj_http_msg http_msg;
    pj_size_t http_msg_len;
    pj_bool_t rc = PJ_TRUE;

    if (status != PJ_SUCCESS) {
        if (c->cb.on_rx_msg)
            c->cb.on_rx_msg(c, NULL, status);
        delay_close(c, PJ_WS_SC_ABNORMAL_CLOSURE);
        return PJ_FALSE;
    }

again:
    if (c->state == PJ_WS_STATE_CONNECTING) {
        /* parse http message */
        PJ_LOG(5, (THIS_FILE, "%s start parse http msg:\n%.*s", c->pool->obj_name, (int)left_size, pdata));
        status = pj_http_msg_parse(pdata, left_size, &http_msg, &http_msg_len);
        if (status != PJ_SUCCESS)
            PJ_PERROR(2, (THIS_FILE, status, "parse http msg"));
        if (status == PJ_EPENDING) {
            /* has pending data to read */
            goto on_pending;
        }
        if (status != PJ_SUCCESS) {
            if (c->is_incoming) {
                http_reply_forbidden(c);
                delay_close(c, PJ_WS_SC_PROTOCOL_ERROR);
                return PJ_FALSE;
            }
            goto on_connect_error;
        }
    }

    if (c->state == PJ_WS_STATE_CONNECTING && c->is_incoming == PJ_FALSE) {
        /* Outgoing websock connection recv http response */
        status = proc_websock_handshake(c, &http_msg);
        if (status != PJ_SUCCESS) {
            goto on_connect_error;
        }

        /* change state to connected */
        switch_websock_state(c, PJ_WS_STATE_OPEN);
        mlogger.on_connect_complete(c, PJ_SUCCESS);
        if (c->cb.on_connect_complete)
            c->cb.on_connect_complete(c, PJ_SUCCESS);

        /* left size */
        left_size -= http_msg_len;
        pdata += http_msg_len;
    } else if (c->state == PJ_WS_STATE_CONNECTING && c->is_incoming == PJ_TRUE) {
        /* Incoming websock connection recv http request */
        pj_ws_t *parent = c->parent;
        pj_str_t websock_key;

        status = proc_websock_handshake(c, &http_msg);
        if (status != PJ_SUCCESS) {
            http_reply_forbidden(c);
            delay_close(c, PJ_WS_SC_PROTOCOL_ERROR);
            return PJ_FALSE;
        }

        /* reply 101 */
        pj_http_msg_find_hdr(&http_msg, &PJ_WS_KEY_NAME_SEC_WEBSOCKET_KEY, &websock_key);
        http_reply_switching(c, &websock_key);

        /* change state to connected */
        mlogger.on_accept_complete(c, &c->peer, pj_sockaddr_get_len(&c->peer));
        if (parent->cb.on_accept_complete) {
            c->state = PJ_WS_STATE_OPEN;
            parent->cb.on_accept_complete(c, &c->peer, pj_sockaddr_get_len(&c->peer));
        }
        switch_websock_state(c, PJ_WS_STATE_OPEN);

        left_size -= http_msg_len;
        pdata += http_msg_len;
    } else if (c->state == PJ_WS_STATE_OPEN) {
        pj_uint8_t *p = (pj_uint8_t *)pdata;
        pj_uint8_t *paylod = NULL;
        pj_uint64_t len = 0;
        pj_ws_frame_hdr *hdr = &rdata->hdr;
        pj_uint8_t *mkey = hdr->mkey;
        pj_uint64_t expect_len;

        if (c->pending_payload == PJ_FALSE) {
            expect_len = 2;
            if (left_size < expect_len) {
                goto on_pending;
            }

            pj_bzero(rdata, sizeof(*rdata));
            hdr->fin = p[0] >> 7;
            hdr->opcode = p[0] & 0x0f;
            hdr->mask = p[1] >> 7;
            len = p[1] & 0x7f;
            if (hdr->mask)
                expect_len += 4;
            if (left_size < expect_len) {
                goto on_pending;
            }
            p += 2;

            if (len <= 125) {
                expect_len += len;
            } else if (len == 126) {
                expect_len += 2; /* 16bit length */
                if (left_size < expect_len) {
                    goto on_pending;
                }

                len = pj_ntohs(*(pj_uint16_t *)p);
                expect_len += len;
                p += 2;
            } else {
                expect_len += 8; /* 64bit length */
                if (left_size < expect_len) {
                    goto on_pending;
                }

                len = pj_ntohll(*(pj_uint64_t *)p);
                expect_len += len;
                p += 8;
            }

            hdr->len = len;

            if (hdr->mask) {
                pj_memcpy(hdr->mkey, p, 4);
                p += 4;
            }

            if (left_size < expect_len) {
                left_size -= (expect_len - len);
                pdata = (char *)p;
                goto on_pending_payload;
            }

            if (len > 0 && hdr->mask)
                unmask_payload(mkey, p, len, rdata->has_read);
            paylod = p;
            p += len;
        } else {
            expect_len = hdr->len - rdata->has_read;
            if (left_size < expect_len) {
                goto on_pending_payload;
            }

            len = expect_len;
            if (len > 0 && hdr->mask)
                unmask_payload(mkey, p, len, rdata->has_read);
            paylod = p;
            p += len;
        }

        /* Notify recv msg event */
        rdata->data = paylod;
        rdata->data_len = len;
        rdata->has_read += len;

        mlogger.on_rx_msg(c, rdata, status);
        if (c->cb.on_rx_msg) {
            if (rdata->hdr.opcode == PJ_WS_OP_TEXT || rdata->hdr.opcode == PJ_WS_OP_BIN)
                rc = c->cb.on_rx_msg(c, rdata, status);
        }
        if (rdata->hdr.opcode == PJ_WS_OP_PING) {
            /* response pong */
            pj_ws_send(c, PJ_WS_OP_PONG, PJ_TRUE, !c->is_incoming, NULL, 0);
        } else if (rdata->hdr.opcode == PJ_WS_OP_CLOSE) {
            delay_close(c, PJ_WS_SC_GOING_AWAY);
            return PJ_FALSE;
        }
        if (c->cb.on_rx_msg && rc == PJ_FALSE)
            return PJ_FALSE;

        c->pending_payload = PJ_FALSE;

        /* left size */
        len = p - (pj_uint8_t *)pdata;
        left_size -= len;
        pdata += len;
    }

    if (left_size > 0)
        goto again;
    return PJ_TRUE;

on_pending:
    *remainder = left_size;
    if (*remainder >= c->endpt->max_rx_bufsize) {
        PJ_LOG(2, (THIS_FILE, "!!!read buffer is full (%u/%lu)", c->endpt->max_rx_bufsize, left_size));
        *remainder = 0;
    }
    if (*remainder > 0 && data != pdata) {
        pj_memmove(data, pdata, *remainder);
    }
    return PJ_TRUE;

on_pending_payload:
    *remainder = left_size;
    c->pending_payload = PJ_TRUE;
    if (*remainder >= c->endpt->max_rx_bufsize) {
        pj_uint64_t exclude_len = 0;
        if (rdata->has_read == 0) {
            /* Exclude the frame header */
            exclude_len = 2;
            if (rdata->hdr.len > 0xffff)
                exclude_len += 8;
            else if (rdata->hdr.len > 125)
                exclude_len += 2;
            if (rdata->hdr.mask)
                exclude_len += 4;
        }
        rdata->data = pdata + exclude_len;
        rdata->data_len = c->endpt->max_rx_bufsize - exclude_len;
        if (rdata->data_len > 0 && rdata->hdr.mask)
            unmask_payload(rdata->hdr.mkey, (pj_uint8_t *)rdata->data, rdata->data_len, rdata->has_read);
        rdata->has_read += rdata->data_len;
        mlogger.on_rx_msg(c, rdata, status);
        if (c->cb.on_rx_msg) {
            if (!c->cb.on_rx_msg(c, rdata, status))
                return PJ_FALSE;
        }
        *remainder = 0;
    }

    if (*remainder > 0 && data != pdata) {
        pj_memmove(data, pdata, *remainder);
    }
    return PJ_TRUE;
on_connect_error:
    mlogger.on_connect_complete(c, -PJ_WS_SC_PROTOCOL_ERROR);
    if (c->cb.on_connect_complete)
        c->cb.on_connect_complete(c, -PJ_WS_SC_PROTOCOL_ERROR);
    delay_close(c, PJ_WS_SC_PROTOCOL_ERROR);
    return PJ_FALSE;
}

static pj_bool_t on_data_sent(pj_ws_transport_t *t, pj_ioqueue_op_key_t *send_key, pj_ssize_t sent)
{
    pj_ws_t *c = (pj_ws_t *)pj_ws_transport_get_userdata(t);
    pj_ws_tx_data *tdata = (pj_ws_tx_data *)send_key->user_data;
    PJ_LOG(6, (THIS_FILE, "%s() %s sent:%d", __FUNCTION__, c->pool->obj_name, sent));

    if (c->state == PJ_WS_STATE_OPEN)
    {
        mlogger.on_tx_msg(c, tdata, sent);
        if (c->cb.on_tx_msg)
            c->cb.on_tx_msg(c, tdata, sent);
    }

    pj_pool_release(tdata->pool);

    return PJ_TRUE;
}

static void generate_websock_key(char *buf, int *size)
{
    pj_uint8_t nonce[16];
    pj_create_random_string((char *)nonce, 16);
    pj_base64_encode((pj_uint8_t *)nonce, 16, buf, size);
}

static void generate_websock_accept(const pj_str_t *key, char *buf, int *size)
{
    pj_str_t salt = {"258EAFA5-E914-47DA-95CA-C5AB0DC85B11", 36};
    pj_sha1_context ctx;
    pj_uint8_t sha1[PJ_SHA1_DIGEST_SIZE];
    int len = *size;

    pj_sha1_init(&ctx);
    pj_sha1_update(&ctx, (pj_uint8_t *)key->ptr, key->slen);
    pj_sha1_update(&ctx, (pj_uint8_t *)salt.ptr, salt.slen);
    pj_sha1_final(&ctx, sha1);

    pj_base64_encode(sha1, PJ_SHA1_DIGEST_SIZE, buf, &len);
    buf[len] = '\0';
}

static pj_bool_t validate_websock_accept(const pj_str_t *accept, const pj_str_t *key)
{
    char buf[512];
    int len = sizeof(buf);

    generate_websock_accept(key, buf, &len);

    PJ_LOG(6, (THIS_FILE, "validate accept:%.*s, out:%.*s", (int)accept->slen, accept->ptr, len, buf));

    if (pj_stricmp2(accept, buf) == 0)
        return PJ_TRUE;

    return PJ_FALSE;
}

static pj_bool_t verify_srv_filter(pj_ws_t *srv, pj_ws_t *c, const pj_http_msg *req)
{
    int i;
    pj_bool_t found = PJ_FALSE;
    pj_str_t *path = req->start_line.u.req_line.path;
    pj_str_t req_path, query_param, subproto;
    char *p;

    pj_strset(&query_param, NULL, 0);
    p = pj_strchr(path, '?');
    if (p)
    {
        pj_strset3(&req_path, path->ptr, p);
        if (p + 1 < path->ptr + path->slen)
            pj_strset3(&query_param, p + 1, path->ptr + path->slen);
    }
    else
    {
        pj_strassign(&req_path, path);
    }

    /* check if request path support */
    if (srv->filter.path_cnt > 0) {
        for (i = 0; i < srv->filter.path_cnt; i++) {
            if (!pj_stricmp(&srv->filter.paths[i], &req_path)) {
                found = PJ_TRUE;
                pj_strdup_with_null(c->pool, &c->req_path, &req_path);
                break;
            }
        }

        if (found == PJ_FALSE) {
            PJ_LOG(1, (THIS_FILE, "%s() not support path: %.*s", __FUNCTION__, (int)req_path.slen, req_path.ptr));
            return PJ_FALSE;
        }
    } else {
        pj_strdup_with_null(c->pool, &c->req_path, &req_path);
    }

    /* set query param */
    pj_strdup_with_null(c->pool, &c->query_param, &query_param);

    /* check if sub-proto support */
    pj_http_msg_find_hdr(req, &PJ_WS_KEY_NAME_SEC_WEBSOCKET_PROTO, &subproto);
    if (srv->filter.proto_cnt > 0) {
        if (subproto.slen == 0) {
            PJ_LOG(1, (THIS_FILE, "%s() request no subproto", __FUNCTION__));
            return PJ_FALSE;
        }

        found = PJ_FALSE;
        for (i = 0; i < srv->filter.proto_cnt; i++) {
            pj_str_t *proto = &srv->filter.subprotos[i];
            pj_ssize_t found_idx = 0;
            pj_str_t token = {0};
            while (found_idx != subproto.slen) {
                found_idx = pj_strtok2(&subproto, ",", &token, (found_idx + token.slen));

                pj_str_t *xproto = pj_strtrim(&token);
                if (!pj_stricmp(proto, xproto)) {
                    found = PJ_TRUE;
                    pj_strdup_with_null(c->pool, &c->subproto, proto);
                    break;
                }
            }

            if (found)
                break;
        }

        if (found == PJ_FALSE) {
            PJ_LOG(1, (THIS_FILE, "%s() not support subprotol: %.*s", __FUNCTION__, (int)subproto.slen, subproto.ptr));
            return PJ_FALSE;
        }
    } else {
        if (subproto.slen > 0) {
            /* default choose the first sub-protol that request */
            pj_str_t token;
            pj_strtok2(&subproto, ",", &token, 0);
            pj_strdup_with_null(c->pool, &c->subproto, &token);
        }
    }

    return PJ_TRUE;
}

static pj_status_t proc_websock_handshake(pj_ws_t *c, const pj_http_msg *msg)
{
    pj_status_t status;
    pj_str_t s;

    if (c->is_incoming) {
        if (pj_http_msg_is_response(msg) == PJ_TRUE)
            return PJ_EINVAL;
    } else {
        if (pj_http_msg_is_response(msg) == PJ_FALSE)
            return PJ_EINVAL;
        if (pj_strcmp(msg->start_line.u.status_line.status, &PJ_WS_STATUS_CODE_101))
            return PJ_EINVAL;
    }

    status = pj_http_msg_find_hdr(msg, &PJ_WS_KEY_NAME_UPGRADE, &s);
    if (status != PJ_SUCCESS)
        return PJ_EINVAL;
    if (pj_stricmp(&s, &PJ_WS_KEY_VALUE_WEBSOCKET))
        return PJ_EINVAL;

    status = pj_http_msg_find_hdr(msg, &PJ_WS_KEY_NAME_CONNECTION, &s);
    if (status != PJ_SUCCESS)
        return PJ_EINVAL;
    if (pj_stricmp(&s, &PJ_WS_KEY_NAME_UPGRADE))
        return PJ_EINVAL;

    if (c->is_incoming) {
        status = pj_http_msg_find_hdr(msg, &PJ_WS_KEY_NAME_SEC_WEBSOCKET_VERSION, &s);
        if (status != PJ_SUCCESS)
            return PJ_EINVAL;
        if (pj_strtol(&s) != PJ_WS_VERSION)
            return PJ_EINVAL;

        status = pj_http_msg_find_hdr(msg, &PJ_WS_KEY_NAME_SEC_WEBSOCKET_KEY, &s);
        if (status != PJ_SUCCESS)
            return PJ_EINVAL;

        if (verify_srv_filter(c->parent, c, msg) == PJ_FALSE) {
            return PJ_EINVAL;
        }
    } else {
        pj_http_msg req_msg;
        pj_str_t websock_key;
        pj_str_t websock_accept;
        pj_str_t rx_subproto;

        pj_http_msg_parse(c->req_msg.ptr, c->req_msg.slen, &req_msg, NULL);
        pj_http_msg_find_hdr(&req_msg, &PJ_WS_KEY_NAME_SEC_WEBSOCKET_KEY, &websock_key);
        pj_http_msg_find_hdr(msg, &PJ_WS_KEY_NAME_SEC_WEBSOCKET_ACCEPT, &websock_accept);

        if (!validate_websock_accept(&websock_accept, &websock_key)) {
            PJ_LOG(1, (THIS_FILE, "validate websock-accept fail"));
            return PJ_EINVAL;
        }

        pj_http_msg_find_hdr(msg, &PJ_WS_KEY_NAME_SEC_WEBSOCKET_PROTO, &rx_subproto);
        if (rx_subproto.slen > 0)
            pj_strdup_with_null(c->pool, &c->subproto, &rx_subproto);
    }

    return PJ_SUCCESS;
}

static void switch_websock_state(pj_ws_t *c, int state)
{
    if (c->is_srv)
        return;
    c->state = state;

    if (state == PJ_WS_STATE_OPEN) {
        if (c->timer.id == TIMER_ID_HANDSHAKE) {
            pj_timer_heap_cancel(c->endpt->timer_heap, &c->timer);
            c->timer.id = TIMER_ID_NONE;
        }
    } else if (state == PJ_WS_STATE_CLOSING || state == PJ_WS_STATE_CLOSED) {
        if (c->timer.id != TIMER_ID_NONE) {
            pj_timer_heap_cancel(c->endpt->timer_heap, &c->timer);
            c->timer.id = TIMER_ID_NONE;
        }
    }

    mlogger.on_state_change(c, state);
    if (c->cb.on_state_change)
        c->cb.on_state_change(c, state);
}

static pj_bool_t logger_on_rx_msg(pj_ws_t *c, pj_ws_rx_data *msg, pj_status_t status)
{
    pj_ws_frame_hdr *hdr;
    char *data;
    char buf[160];

    if (!c->endpt->msg_logger)
        return PJ_FALSE;

    if (status != PJ_SUCCESS)
    {
        PJ_PERROR(2, (THIS_FILE, status, "Disconnect with %s",
                      pj_ws_print(c, buf, sizeof(buf))));
        return PJ_FALSE;
    }

    hdr = &msg->hdr;
    data = (char *)msg->data;

    if (hdr->opcode == PJ_WS_OP_TEXT) {
        PJ_LOG(4, (THIS_FILE,
                   "RX from %s: TEXT %s %d\n%.*s",
                   pj_ws_print(c, buf, sizeof(buf)),
                   hdr->mask ? " m" : "-m",
                   (int)msg->data_len, (int)msg->data_len, data));
    }
    else {
        PJ_LOG(4, (THIS_FILE, "RX from %s: %s", pj_ws_print(c, buf, sizeof(buf)),
                   pj_ws_opcode_str(hdr->opcode)));
    }
    return PJ_TRUE;
}

static pj_bool_t logger_on_tx_msg(pj_ws_t *c, pj_ws_tx_data *msg, pj_ssize_t sent)
{
    pj_ws_frame_hdr *hdr;
    char *data;
    char buf[160];
    PJ_UNUSED_ARG(sent);

    if (!c->endpt->msg_logger)
        return PJ_FALSE;

    hdr = &msg->hdr;
    data = (char *)msg->data;

    if (hdr->opcode == PJ_WS_OP_TEXT) {
        PJ_LOG(4, (THIS_FILE,
                   "TX to   %s: TEXT %s %d\n%.*s",
                   pj_ws_print(c, buf, sizeof(buf)),
                   hdr->mask ? " m" : "-m",
                   (int)hdr->len, (int)hdr->len, data));
    }
    else {
        PJ_LOG(4, (THIS_FILE, "TX to   %s: %s", pj_ws_print(c, buf, sizeof(buf)),
                   pj_ws_opcode_str(hdr->opcode)));
    }
    return PJ_TRUE;
}

static pj_bool_t logger_on_connect_complete(pj_ws_t *c, pj_status_t status)
{
    char buf[160];
    if (!c->endpt->msg_logger)
        return PJ_FALSE;
    if (status != PJ_SUCCESS)
        PJ_PERROR(2, (THIS_FILE, status, "%s: connect error", pj_ws_print(c, buf, sizeof(buf))));
    else
        PJ_LOG(4, (THIS_FILE, "%s connect success", pj_ws_print(c, buf, sizeof(buf))));
    return PJ_TRUE;
}
static pj_bool_t logger_on_accept_complete(pj_ws_t *c, const pj_sockaddr_t *src_addr, int src_addr_len)
{
    char buf[160];
    PJ_UNUSED_ARG(src_addr);
    PJ_UNUSED_ARG(src_addr_len);

    if (!c->endpt->msg_logger)
        return PJ_FALSE;
    PJ_LOG(4, (THIS_FILE, "%s: accept complete", pj_ws_print(c, buf, sizeof(buf))));
    return PJ_TRUE;
}

static void logger_on_state_change(pj_ws_t *c, int state)
{
    char buf[160];
    if (!c->endpt->msg_logger)
        return;
    PJ_LOG(4, (THIS_FILE, "%s: state change to %s", pj_ws_print(c, buf, sizeof(buf)), pj_ws_state_str(state)));
}
