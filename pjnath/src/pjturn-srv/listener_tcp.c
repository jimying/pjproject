/* 
 * Copyright (C) 2008-2011 Teluu Inc. (http://www.teluu.com)
 * Copyright (C) 2003-2008 Benny Prijono <benny@prijono.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA 
 */
#include "turn.h"
#include <pj/compat/socket.h>

#if PJ_HAS_TCP

struct accept_op
{
    pj_ioqueue_op_key_t op_key;
    pj_sock_t           sock;
    pj_sockaddr         src_addr;
    int                 src_addr_len;
};

struct tcp_listener
{
    pj_turn_listener         base;
    pj_ioqueue_key_t        *key;
    unsigned                 accept_cnt;
    struct accept_op        *accept_op; /* Array of accept_op's */
};


static void lis_on_accept_complete(pj_ioqueue_key_t *key, 
                                   pj_ioqueue_op_key_t *op_key, 
                                   pj_sock_t sock, 
                                   pj_status_t status);
static pj_status_t lis_destroy(pj_turn_listener *listener);
static void transport_create(pj_sock_t sock, pj_turn_listener *lis,
                             pj_sockaddr_t *src_addr, int src_addr_len);

/*
 * Create a new listener on the specified port.
 */
PJ_DEF(pj_status_t) pj_turn_listener_create_tcp(pj_turn_srv *srv,
                                                int af,
                                                const pj_str_t *bound_addr,
                                                unsigned port,
                                                unsigned concurrency_cnt,
                                                unsigned flags,
                                                pj_turn_listener **p_listener)
{
    pj_pool_t *pool;
    struct tcp_listener *tcp_lis;
    pj_ioqueue_callback ioqueue_cb;
    unsigned i;
    pj_status_t status;

    /* Create structure */
    pool = pj_pool_create(srv->core.pf, "tcpl%p", 1000, 1000, NULL);
    tcp_lis = PJ_POOL_ZALLOC_T(pool, struct tcp_listener);
    tcp_lis->base.pool = pool;
    tcp_lis->base.obj_name = pool->obj_name;
    tcp_lis->base.server = srv;
    tcp_lis->base.tp_type = PJ_TURN_TP_TCP;
    tcp_lis->base.sock = PJ_INVALID_SOCKET;
    //tcp_lis->base.sendto = &tcp_sendto;
    tcp_lis->base.destroy = &lis_destroy;
    tcp_lis->accept_cnt = concurrency_cnt;
    tcp_lis->base.flags = flags;

    /* Create socket */
    status = pj_sock_socket(af, pj_SOCK_STREAM(), 0, &tcp_lis->base.sock);
    if (status != PJ_SUCCESS)
        goto on_error;

    /* Disable TIME_WAIT */
    pj_util_disable_tcp_timewait(tcp_lis->base.sock);

    /* Init bind address */
    status = pj_sockaddr_init(af, &tcp_lis->base.addr, bound_addr, 
                              (pj_uint16_t)port);
    if (status != PJ_SUCCESS) 
        goto on_error;
    
    /* Create info */
    pj_ansi_strxcpy(tcp_lis->base.info, "TCP:", sizeof(tcp_lis->base.info));
    pj_sockaddr_print(&tcp_lis->base.addr, tcp_lis->base.info+4, 
                      sizeof(tcp_lis->base.info)-4, 3);

    /* set bound listen ip */
    if (bound_addr) {
        pj_strdup_with_null(pool, &tcp_lis->base.listen_ip, bound_addr);
    }

    /* Bind socket */
    status = pj_sock_bind(tcp_lis->base.sock, &tcp_lis->base.addr, 
                          pj_sockaddr_get_len(&tcp_lis->base.addr));
    if (status != PJ_SUCCESS)
        goto on_error;

    /* Listen() */
    status = pj_sock_listen(tcp_lis->base.sock, 5);
    if (status != PJ_SUCCESS)
        goto on_error;

    /* Register to ioqueue */
    pj_bzero(&ioqueue_cb, sizeof(ioqueue_cb));
    ioqueue_cb.on_accept_complete = &lis_on_accept_complete;
    status = pj_ioqueue_register_sock(pool, srv->core.ioqueue, tcp_lis->base.sock,
                                      tcp_lis, &ioqueue_cb, &tcp_lis->key);

    /* Create op keys */
    tcp_lis->accept_op = (struct accept_op*)pj_pool_calloc(pool, concurrency_cnt,
                                                    sizeof(struct accept_op));

    /* Create each accept_op and kick off read operation */
    for (i=0; i<concurrency_cnt; ++i) {
        lis_on_accept_complete(tcp_lis->key, &tcp_lis->accept_op[i].op_key, 
                               PJ_INVALID_SOCKET, PJ_EPENDING);
    }

    /* Done */
    PJ_LOG(4,(tcp_lis->base.obj_name, "Listener %s created", 
           tcp_lis->base.info));

    *p_listener = &tcp_lis->base;
    return PJ_SUCCESS;


on_error:
    lis_destroy(&tcp_lis->base);
    return status;
}


/*
 * Destroy listener.
 */
static pj_status_t lis_destroy(pj_turn_listener *listener)
{
    struct tcp_listener *tcp_lis = (struct tcp_listener *)listener;
    unsigned i;

    if (tcp_lis->key) {
        pj_ioqueue_unregister(tcp_lis->key);
        tcp_lis->key = NULL;
        tcp_lis->base.sock = PJ_INVALID_SOCKET;
    } else if (tcp_lis->base.sock != PJ_INVALID_SOCKET) {
        pj_sock_close(tcp_lis->base.sock);
        tcp_lis->base.sock = PJ_INVALID_SOCKET;
    }

    for (i=0; i<tcp_lis->accept_cnt; ++i) {
        /* Nothing to do */
    }

    if (tcp_lis->base.pool) {
        pj_pool_t *pool = tcp_lis->base.pool;

        PJ_LOG(4,(tcp_lis->base.obj_name, "Listener %s destroyed", 
                  tcp_lis->base.info));

        tcp_lis->base.pool = NULL;
        pj_pool_release(pool);
    }
    return PJ_SUCCESS;
}


/*
 * Callback on new TCP connection.
 */
static void lis_on_accept_complete(pj_ioqueue_key_t *key, 
                                   pj_ioqueue_op_key_t *op_key, 
                                   pj_sock_t sock, 
                                   pj_status_t status)
{
    struct tcp_listener *tcp_lis;
    struct accept_op *accept_op = (struct accept_op*) op_key;

    tcp_lis = (struct tcp_listener*) pj_ioqueue_get_user_data(key);

    PJ_UNUSED_ARG(sock);

    do {
        /* Report new connection. */
        if (status == PJ_SUCCESS) {
            char addr[PJ_INET6_ADDRSTRLEN+8];
            PJ_LOG(5,(tcp_lis->base.obj_name, "Incoming TCP from %s",
                      pj_sockaddr_print(&accept_op->src_addr, addr,
                                        sizeof(addr), 3)));
            transport_create(accept_op->sock, &tcp_lis->base,
                             &accept_op->src_addr, accept_op->src_addr_len);
        } else if (status != PJ_EPENDING && status != PJ_STATUS_FROM_OS(PJ_BLOCKING_ERROR_VAL)) {
            PJ_PERROR(2, (tcp_lis->base.obj_name, status, "accept(%d)", status));
        }

        /* Prepare next accept() */
        accept_op->src_addr_len = sizeof(accept_op->src_addr);
        status = pj_ioqueue_accept(key, op_key, &accept_op->sock,
                                   NULL,
                                   &accept_op->src_addr,
                                   &accept_op->src_addr_len);

    } while (status != PJ_EPENDING && status != PJ_ECANCELLED &&
             status != PJ_STATUS_FROM_OS(PJ_BLOCKING_ERROR_VAL));
}


/****************************************************************************/
/*
 * Transport
 */
enum
{
    TIMER_NONE,
    TIMER_DESTROY
};

struct recv_op
{
    pj_ioqueue_op_key_t op_key;
    pj_turn_pkt         pkt;
};

struct tcp_transport
{
    pj_turn_transport    base;
    pj_pool_t           *pool;
    pj_timer_entry       timer;

    pj_turn_allocation  *alloc;
    int                  ref_cnt;

    pj_sock_t            sock;
    pj_activesock_t     *asock;
    struct recv_op       recv_op;

    pj_list              tx_pending_list;
    pj_lock_t           *pending_lock;
};

struct tcp_tx_data
{
    PJ_DECL_LIST_MEMBER(struct tcp_tx_data);
    pj_pool_t *pool;
    pj_ioqueue_op_key_t send_key;
    char pkt[PJ_TURN_MAX_PKT_LEN];
    pj_size_t size;
};

static pj_bool_t tcp_on_data_read(pj_activesock_t *asock,
                                  void *data,
                                  pj_size_t bytes_read,
                                  pj_status_t status,
                                  pj_size_t *remainder);

static pj_bool_t tcp_on_data_sent(pj_activesock_t *asock,
                                  pj_ioqueue_op_key_t *send_key,
                                  pj_ssize_t sent);

static pj_status_t tcp_sendto(pj_turn_transport *tp,
                              const void *packet,
                              pj_size_t size,
                              unsigned flag,
                              const pj_sockaddr_t *addr,
                              int addr_len);
static void tcp_destroy(struct tcp_transport *tcp);
static void tcp_add_ref(pj_turn_transport *tp,
                        pj_turn_allocation *alloc);
static void tcp_dec_ref(pj_turn_transport *tp,
                        pj_turn_allocation *alloc);
static void timer_callback(pj_timer_heap_t *timer_heap,
                           pj_timer_entry *entry);

static void transport_create(pj_sock_t sock, pj_turn_listener *lis,
                             pj_sockaddr_t *src_addr, int src_addr_len)
{
    pj_pool_t *pool;
    struct tcp_transport *tcp;
    pj_status_t status;
    const pj_turn_config *pcfg = pj_turn_get_config();
    pj_activesock_cfg asock_opt;
    pj_activesock_cb asock_cb;
    void *readbuf[1];
    unsigned rbufsize;

    pool = pj_pool_create(lis->server->core.pf, "tcp%p", 1000, 1000, NULL);

    tcp = PJ_POOL_ZALLOC_T(pool, struct tcp_transport);
    tcp->base.obj_name = pool->obj_name;
    tcp->base.listener = lis;
    tcp->base.info = lis->info;
    tcp->base.sendto = &tcp_sendto;
    tcp->base.add_ref = &tcp_add_ref;
    tcp->base.dec_ref = &tcp_dec_ref;
    tcp->pool = pool;
    tcp->sock = sock;

    pj_timer_entry_init(&tcp->timer, TIMER_NONE, tcp, &timer_callback);
    pj_list_init(&tcp->tx_pending_list);
    status = pj_lock_create_simple_mutex(pool, "tptcp_txpending%p",
                                         &tcp->pending_lock);
    if (status != PJ_SUCCESS) {
        PJ_PERROR(1, (tcp->base.obj_name, status, "create mutex"));
        tcp_destroy(tcp);
        return;
    }

    /* set sock buffer size */
    pj_util_set_sock_buf_size(sock, PJ_TURN_TCP_SOCK_BUF_SIZE);

        /* set tos */
    if (pcfg->dscp_tcp > 0)
        pj_turn_set_tos(sock, pcfg->dscp_tcp);

    /* Create active socket */
    pj_activesock_cfg_default(&asock_opt);
    pj_bzero(&asock_cb, sizeof(asock_cb));
    asock_cb.on_data_read = tcp_on_data_read;
    asock_cb.on_data_sent = tcp_on_data_sent;
    status = pj_activesock_create(pool, sock, pj_SOCK_STREAM(), &asock_opt,
                                  lis->server->core.ioqueue, &asock_cb, tcp,
                                  &tcp->asock);
    if (status != PJ_SUCCESS) {
        PJ_PERROR(1, (tcp->base.obj_name, status, "create activesock"));
        tcp_destroy(tcp);
        return;
    }

    /* Init pkt */
    tcp->recv_op.pkt.pool = pj_pool_create(lis->server->core.pf, "tcpkt%p", 
                                           1000, 1000, NULL);
    tcp->recv_op.pkt.transport = &tcp->base;
    tcp->recv_op.pkt.src.tp_type = PJ_TURN_TP_TCP;
    tcp->recv_op.pkt.src_addr_len = src_addr_len;
    pj_memcpy(&tcp->recv_op.pkt.src.clt_addr, src_addr, src_addr_len);

    /* Start read */
    readbuf[0] = tcp->recv_op.pkt.pkt;
    rbufsize = sizeof(tcp->recv_op.pkt.pkt);
    status = pj_activesock_start_read2(tcp->asock, pool, rbufsize, readbuf, 0);
    if (status != PJ_SUCCESS) {
        PJ_PERROR(1, (tcp->base.obj_name, status, "activesock start read"));
        tcp_destroy(tcp);
    }
    /* Should not access transport from now, it may have been destroyed */
}


static void tcp_destroy(struct tcp_transport *tcp)
{
    if (tcp->asock) {
        pj_activesock_close(tcp->asock);
        tcp->asock = NULL;
        tcp->sock = PJ_INVALID_SOCKET;
    } else if (tcp->sock != PJ_INVALID_SOCKET) {
        pj_sock_close(tcp->sock);
        tcp->sock = PJ_INVALID_SOCKET;
    }

    if (tcp->timer.id != TIMER_NONE) {
        pj_timer_heap_cancel(tcp->base.listener->server->core.timer_heap,
                             &tcp->timer);
        tcp->timer.id = TIMER_NONE;
    }

    if (tcp->recv_op.pkt.pool) {
        pj_pool_release(tcp->recv_op.pkt.pool);
        tcp->recv_op.pkt.pool = NULL;
    }

    if (tcp->pool) {
        pj_lock_acquire(tcp->pending_lock);
        while(!pj_list_empty(&tcp->tx_pending_list)) {
            struct tcp_tx_data *tdata =
                (struct tcp_tx_data *)tcp->tx_pending_list.next;
            pj_list_erase(tdata);
            pj_pool_release(tdata->pool);
        }
        pj_lock_release(tcp->pending_lock);
        pj_lock_destroy(tcp->pending_lock);

        pj_pool_release(tcp->pool);
        tcp->pool = NULL;
    }
}

static void delay_tcp_destroy(struct tcp_transport *tcp)
{
    pj_time_val delay = {0, 100};

    if (tcp->asock) {
        pj_activesock_close(tcp->asock);
        tcp->asock = NULL;
        tcp->sock = PJ_INVALID_SOCKET;
    } else if (tcp->sock != PJ_INVALID_SOCKET) {
        pj_sock_close(tcp->sock);
        tcp->sock = PJ_INVALID_SOCKET;
    }

    if (tcp->timer.id != TIMER_NONE) {
        pj_timer_heap_cancel(tcp->base.listener->server->core.timer_heap,
                             &tcp->timer);
    }
    tcp->timer.id = TIMER_DESTROY;
    pj_timer_heap_schedule(tcp->base.listener->server->core.timer_heap,
                           &tcp->timer, &delay);
}

static void timer_callback(pj_timer_heap_t *timer_heap,
                           pj_timer_entry *entry)
{
    struct tcp_transport *tcp = (struct tcp_transport*) entry->user_data;

    PJ_UNUSED_ARG(timer_heap);

    entry->id = TIMER_NONE;
    tcp_destroy(tcp);
}

static pj_bool_t tcp_on_data_read(pj_activesock_t *asock,
                                  void *data,
                                  pj_size_t bytes_read,
                                  pj_status_t status,
                                  pj_size_t *remainder)
{
    struct tcp_transport *tcp =
        (struct tcp_transport *)pj_activesock_get_user_data(asock);
    pj_turn_pkt *pkt = &tcp->recv_op.pkt;
    PJ_UNUSED_ARG(data);

    if (status != PJ_SUCCESS && status != PJ_EPENDING) {
        /* TCP connection closed/error. Notify client and then destroy
         * ourselves.
         */
        PJ_PERROR(5, (tcp->base.obj_name, status, "TCP socket closed"));
        if (tcp->alloc) {
            pj_turn_allocation_on_transport_closed(tcp->alloc, &tcp->base);
            tcp->alloc = NULL;
        }

        delay_tcp_destroy(tcp);
        return PJ_FALSE;
    } else if (bytes_read > 0) {
        /* Report to server or allocation, if we have allocation */
        pj_size_t left_len;
        pj_uint16_t *pd;
        pj_uint16_t typ;
        pj_size_t len;

        // pj_gettimeofday(&pkt->rx_time);
        pkt->len = bytes_read;
        left_len = pkt->len;

        for (;;) {
            if (left_len < 4)
                break;

            pd = (pj_uint16_t *)pkt->pkt;
            typ = pj_ntohs(*pd);
            len = pj_ntohs(*(pd + 1));

            if (typ < 0x4000) {
                len += sizeof(pj_stun_msg_hdr);
            } else if (typ < 0x8000) {
                len += sizeof(pj_turn_channel_data);
                /* 4 byte alignment */
                while (len & 0x3)
                    len++;
            } else {
                PJ_LOG(2, ("TCP", "Bad msg typ: 0x%04x", typ));
                pkt->len = 0; // reset pkt
                break;
            }

            /* check data size */
            if (left_len < len) {
                // no enough, wait more ..
                break;
            }

            /* Parse a whole msg */
            pkt->len = len;
            if (tcp->alloc) {
                pj_turn_allocation_on_rx_client_pkt(tcp->alloc, pkt);
            } else {
                pj_turn_srv_on_rx_pkt(tcp->base.listener->server, pkt);
            }

            /* Continue to parse */
            left_len -= len;
            pkt->len = left_len;
            if (left_len > 0)
                pj_memmove(pkt->pkt, pkt->pkt + len, left_len);
        }

        /* Reset pool */
        // pj_pool_reset(recv_op->pkt.pool);

        /* If packet is full discard it */
        if (pkt->len == sizeof(pkt->pkt)) {
            PJ_LOG(4, (tcp->base.obj_name, "Buffer discarded"));
            pkt->len = 0;
        }

        *remainder = pkt->len;
    }
    return PJ_TRUE;
}

static pj_bool_t tcp_on_data_sent(pj_activesock_t *asock,
                                  pj_ioqueue_op_key_t *send_key,
                                  pj_ssize_t sent)
{
    struct tcp_transport *tcp =
        (struct tcp_transport *)pj_activesock_get_user_data(asock);
    struct tcp_tx_data *tdata = (struct tcp_tx_data *)send_key->user_data;
    PJ_UNUSED_ARG(sent);

    pj_lock_acquire(tcp->pending_lock);
    pj_list_erase(tdata);
    pj_lock_release(tcp->pending_lock);
    pj_pool_release(tdata->pool);

    return sent > 0 ? PJ_TRUE : PJ_FALSE;
}

static pj_status_t tcp_sendto(pj_turn_transport *tp,
                              const void *packet,
                              pj_size_t size,
                              unsigned flag,
                              const pj_sockaddr_t *addr,
                              int addr_len)
{
    struct tcp_transport *tcp = (struct tcp_transport *)tp;
    pj_status_t status;
    pj_ssize_t length = (pj_ssize_t)size, sent;
    pj_pool_factory *pf = tcp->base.listener->pool->factory;
    pj_pool_t *pool;
    struct tcp_tx_data *tdata;

    PJ_UNUSED_ARG(addr);
    PJ_UNUSED_ARG(addr_len);

    /* 4 byte alignment */
    while (length & 0x3)
        length++;

    pool = pj_pool_create(pf, "tcptdata%p",
                          sizeof(struct tcp_tx_data) + 168,
                          1000, NULL);
    tdata = PJ_POOL_ZALLOC_T(pool, struct tcp_tx_data);
    tdata->pool = pool;
    tdata->send_key.user_data = tdata;
    tdata->size = (pj_size_t)length;
    pj_memcpy(tdata->pkt, packet, size);

    sent = length;
    status = pj_activesock_send(tcp->asock, &tdata->send_key, tdata->pkt, &sent,
                                flag);

    if (status != PJ_SUCCESS) {
        PJ_PERROR(2, (tcp->base.obj_name, status, "send error(%d)", status));
    }

    if (status == PJ_EPENDING) {
        pj_lock_acquire(tcp->pending_lock);
        pj_list_push_back(&tcp->tx_pending_list, tdata);
        pj_lock_release(tcp->pending_lock);
    }
    else {
        pj_pool_release(pool);
    }

    return status;
}

static void tcp_add_ref(pj_turn_transport *tp,
                        pj_turn_allocation *alloc)
{
    struct tcp_transport *tcp = (struct tcp_transport *)tp;
    ++tcp->ref_cnt;
    tcp->alloc = alloc;
}

static void tcp_dec_ref(pj_turn_transport *tp,
                        pj_turn_allocation *alloc)
{
    PJ_UNUSED_ARG(alloc);
    struct tcp_transport *tcp = (struct tcp_transport *)tp;

    --tcp->ref_cnt;
    if (tcp->ref_cnt == 0)
        delay_tcp_destroy(tcp);
}

#else        /* PJ_HAS_TCP */

/* To avoid empty translation unit warning */
int listener_tcp_dummy = 0;

#endif        /* PJ_HAS_TCP */

