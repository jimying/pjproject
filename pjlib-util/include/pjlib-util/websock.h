#ifndef __PJLIB_UTIL_WS_H__
#define __PJLIB_UTIL_WS_H__

#include <pj/types.h>
#include <pj/ioqueue.h>

PJ_BEGIN_DECL

#define PJ_WS_VERSION           13
#define PJ_WS_MAX_PATH_CNT      8
#define PJ_WS_MAX_SUB_PROTO_CNT 8

typedef struct pj_ws_endpoint pj_ws_endpoint;
typedef struct pj_ws_t pj_ws_t;

typedef struct pj_ws_frame_hdr {
    unsigned fin:1;
    unsigned rsv1:1;
    unsigned rsv2:1;
    unsigned rsv3:1;
    unsigned opcode:4;
    unsigned mask:1;
    pj_uint64_t len;
    pj_uint8_t mkey[4];
} pj_ws_frame_hdr;

typedef enum pj_ws_opcode {
    PJ_WS_OP_CONTN = 0x0,
    PJ_WS_OP_TEXT = 0x1,
    PJ_WS_OP_BIN = 0x2,
    PJ_WS_OP_CLOSE = 0x8,
    PJ_WS_OP_PING = 0x9,
    PJ_WS_OP_PONG = 0xa,
} pj_ws_opcode;

typedef enum pj_ws_scode {
    PJ_WS_SC_NORMAL_CLOSURE = 1000,
    PJ_WS_SC_GOING_AWAY = 1001,
    PJ_WS_SC_PROTOCOL_ERROR = 1002,
    PJ_WS_SC_UNSUPPORTED_DATA = 1003,
    PJ_WS_SC_ABNORMAL_CLOSURE = 1006,
    PJ_WS_SC_INVALID_PAYLOAD = 1007,
    PJ_WS_SC_POLICY_VIOLATION = 1008,
    PJ_WS_SC_MESSAGE_TOO_BIG = 1009,
    PJ_WS_SC_EXTENSION_ERROR = 1010,
    PJ_WS_SC_INTERNAL_ERROR = 1011,
} pj_ws_scode;

typedef enum pj_ws_readystate {
    PJ_WS_STATE_CONNECTING = 1,
    PJ_WS_STATE_OPEN,
    PJ_WS_STATE_CLOSING,
    PJ_WS_STATE_CLOSED,
} pj_ws_readystate;

typedef struct pj_ws_tx_data {
    pj_pool_t *pool;
    pj_ws_frame_hdr hdr;
    void *data;
    pj_ioqueue_op_key_t send_key;
} pj_ws_tx_data;

typedef struct pj_ws_rx_data {
    pj_pool_t *pool;
    pj_ws_frame_hdr hdr;
    void *data;
    pj_uint64_t data_len;
    pj_uint64_t has_read;
} pj_ws_rx_data;

typedef struct pj_ws_cb {
    pj_bool_t (*on_connect_complete)(pj_ws_t *c, pj_status_t status);
    pj_bool_t (*on_accept_complete)(pj_ws_t *c, const pj_sockaddr_t *src_addr, int src_addr_len);
    pj_bool_t (*on_rx_msg)(pj_ws_t *c, pj_ws_rx_data *msg, pj_status_t status);
    pj_bool_t (*on_tx_msg)(pj_ws_t *c, pj_ws_tx_data *msg, pj_ssize_t sent);
    void (*on_state_change)(pj_ws_t *c, int state);
} pj_ws_cb;

typedef struct pj_ws_http_hdr {
    pj_str_t key;
    pj_str_t val;
} pj_ws_http_hdr;

typedef struct pj_ws_endpt_cfg {
    pj_pool_factory *pf;
    pj_ioqueue_t *ioq;
    pj_timer_heap_t *timer_heap;
    pj_uint32_t max_rx_bufsize;
    pj_bool_t msg_logger;
} pj_ws_endpt_cfg;

void pj_ws_endpt_cfg_default(pj_ws_endpt_cfg *opt);
pj_status_t pj_ws_endpt_create(pj_ws_endpt_cfg *opt, pj_ws_endpoint **pendpt);
pj_status_t pj_ws_endpt_destroy(pj_ws_endpoint *endpt);
pj_status_t pj_ws_listen(pj_ws_endpoint *endpt, pj_sockaddr_t *local_addr, pj_ws_cb *cb, void *user_data, pj_ws_t **s);
pj_status_t pj_ws_connect(pj_ws_endpoint *endpt, const char *url, const pj_ws_cb *cb, void *user_data, pj_ws_http_hdr *hdrs, int hdr_cnt, pj_ws_t **pc);
pj_status_t pj_ws_close(pj_ws_t *c, int code, const char *reason);
pj_status_t pj_ws_send(pj_ws_t *c, int opcode, pj_bool_t fini, pj_bool_t mask, const void *data, pj_size_t len);
pj_status_t pj_ws_send_text(pj_ws_t *c, const char *text, pj_size_t len);
pj_status_t pj_ws_set_support_path(pj_ws_t *srv, pj_str_t paths[], int cnt);
pj_status_t pj_ws_set_support_subproto(pj_ws_t *srv, pj_str_t protos[], int cnt);
pj_status_t pj_ws_set_callbacks(pj_ws_t *c, const pj_ws_cb *cb);
pj_status_t pj_ws_set_userdata(pj_ws_t *c, void *user_data);
void *pj_ws_get_userdata(pj_ws_t *c);
pj_pool_t *pj_ws_get_pool(pj_ws_t *c);
pj_status_t pj_ws_enable_ping(pj_ws_t *c, pj_time_val *t);
pj_bool_t pj_ws_is_incoming(pj_ws_t *c);
int pj_ws_get_ready_state(pj_ws_t *c);
int pj_ws_get_close_code(pj_ws_t *c);
const char *pj_ws_get_request_path(pj_ws_t *c);
const char *pj_ws_get_query_param(pj_ws_t *c);
const char *pj_ws_get_subproto(pj_ws_t *c);
const char *pj_ws_print(pj_ws_t *c, char *buf, int len);
const char *pj_ws_opcode_str(int opcode);
const char *pj_ws_state_str(int state);

PJ_END_DECL

#endif
