#ifndef __PJLIB_UTIL_HTTP_H__
#define __PJLIB_UTIL_HTTP_H__
#include <pjlib.h>

PJ_BEGIN_DECL

typedef struct pj_http_uri {
    pj_str_t scheme;
    pj_str_t user;
    pj_str_t pass;
    pj_str_t host;
    pj_str_t port;
    pj_str_t path;
    pj_str_t query;
} pj_http_uri;

PJ_DECL(pj_status_t) pj_http_uri_parse(const char *str_url, pj_http_uri *uri);
PJ_DECL(pj_bool_t) pj_http_uri_istls(const pj_http_uri *uri);
PJ_DECL(pj_uint16_t) pj_http_uri_port(const pj_http_uri *uri);

#ifndef PJ_HTTP_MAX_HEADERS
#  define PJ_HTTP_MAX_HEADERS 16
#endif

typedef struct pj_http_hdr {
    pj_str_t key;
    pj_str_t val;
} pj_http_hdr;

typedef struct pj_http_req_line {
    pj_str_t *method;
    pj_str_t *path;
    pj_str_t *version;
} pj_http_req_line;

typedef struct pj_http_status_line {
    pj_str_t *version;
    pj_str_t *status;
    pj_str_t *reason;
} pj_http_status_line;

typedef struct pj_http_start_line {
    pj_str_t s, s2, s3;
    union {
        pj_http_req_line req_line;
        pj_http_status_line status_line;
    } u;
} pj_http_start_line;

typedef struct pj_http_msg {
    pj_http_start_line start_line;
    pj_http_hdr hdrs[PJ_HTTP_MAX_HEADERS];
    int hdr_cnt;
    pj_str_t body;
} pj_http_msg;

pj_status_t pj_http_msg_parse(const void *data, pj_size_t size, pj_http_msg *msg, pj_size_t *msg_len);
pj_status_t pj_http_msg_find_hdr(const pj_http_msg *msg, const pj_str_t *k, pj_str_t *v);
pj_bool_t pj_http_msg_is_response(const pj_http_msg *msg);

PJ_END_DECL
#endif
