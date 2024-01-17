#ifndef __PJLIB_UTIL_WS_TRANSPORT_H__
#define __PJLIB_UTIL_WS_TRANSPORT_H__

#include <pj/types.h>
#include <pj/ioqueue.h>

PJ_BEGIN_DECL

typedef struct pj_ws_transport_t pj_ws_transport_t;
typedef struct pj_ws_transport_cb {
    pj_bool_t (*on_connect_complete)(pj_ws_transport_t *t, pj_status_t status, const pj_sockaddr_t *bound_addr, int addr_len);
    pj_bool_t (*on_accept_complete)(pj_ws_transport_t *t,
                                    pj_ws_transport_t *newt,
                                    const pj_sockaddr_t *src_addr,
                                    int src_addr_len,
                                    const pj_sockaddr_t *loc_addr,
                                    int loc_addr_len);
    pj_bool_t (*on_data_read)(pj_ws_transport_t *t, void *data, pj_size_t size, pj_status_t status, pj_size_t *remainder);
    pj_bool_t (*on_data_sent)(pj_ws_transport_t *t, pj_ioqueue_op_key_t *send_key, pj_ssize_t sent);
} pj_ws_transport_cb;

typedef struct pj_ws_transport_param {
    pj_ioqueue_t *ioq;
    pj_timer_heap_t *timer_heap;
    pj_pool_factory *pf;
    pj_uint32_t max_rx_bufsize;
    pj_ws_transport_cb cb;
    void *user_data;
} pj_ws_transport_param;

void pj_ws_transport_param_default(pj_ws_transport_param *param);
pj_status_t pj_ws_transport_create(pj_pool_t *pool, pj_ws_transport_param *param, pj_ws_transport_t **pt);
pj_status_t pj_ws_transport_destroy(pj_ws_transport_t *tp);
void *pj_ws_transport_get_userdata(pj_ws_transport_t *tp);
pj_status_t pj_ws_transport_set_userdata(pj_ws_transport_t *tp, void *user_data);
pj_status_t pj_ws_transport_set_callbacks(pj_ws_transport_t *tp, pj_ws_transport_cb *cb);
pj_status_t pj_ws_transport_start_connect(pj_ws_transport_t *tp, const pj_sockaddr_t *remaddr, int addr_len);
pj_status_t pj_ws_transport_start_listen(pj_ws_transport_t *tp, const pj_sockaddr_t *local_addr, int addr_len);
pj_status_t pj_ws_transport_send(pj_ws_transport_t *tp, pj_ioqueue_op_key_t *send_key, const void *data, pj_ssize_t *size, unsigned flags);

PJ_END_DECL

#endif
