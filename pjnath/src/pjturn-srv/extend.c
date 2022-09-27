#include <pjlib.h>
#include <pjlib-util.h>
#include "turn.h"

#if PJ_HAS_TCP
struct accept_op {
    pj_ioqueue_op_key_t op_key;
    pj_sock_t sock;
    pj_sockaddr src_addr;
    int src_addr_len;
};

struct tcp_transport {
    pj_pool_t *pool;
    pj_timer_entry timer;
    pj_sock_t sock;
    pj_ioqueue_key_t *key;
    pj_ioqueue_op_key_t send_op;
    pj_ioqueue_op_key_t recv_op;
    char recv_buf[800];
};

struct pj_http_admin {
    pj_pool_t *pool;
    const char *obj_name;
    pj_turn_srv *srv;
    pj_pool_factory *pf;
    pj_ioqueue_t *ioqueue;
    /** Client info (IP address and port) */
    char info[80];

    /** listener socket */
    pj_sock_t sock;
    pj_ioqueue_key_t *key;

    /** Bound address */
    pj_sockaddr addr;

    /** Array of accept_op's	*/
    struct accept_op *accept_op;
};

static struct pj_http_admin *g_http_admin = NULL;


static void lis_on_accept_complete(pj_ioqueue_key_t *key,
				   pj_ioqueue_op_key_t *op_key, pj_sock_t sock,
				   pj_status_t status);
static void http_on_read_complete(pj_ioqueue_key_t *key,
				  pj_ioqueue_op_key_t *op_key,
				  pj_ssize_t bytes_read);

static void tcp_destroy(struct tcp_transport *tcp)
{
    if (tcp->key) {
	pj_ioqueue_unregister(tcp->key);
	tcp->key = NULL;
	tcp->sock = PJ_INVALID_SOCKET;
    } else if (tcp->sock != PJ_INVALID_SOCKET) {
	pj_sock_close(tcp->sock);
	tcp->sock = PJ_INVALID_SOCKET;
    }

    if (tcp->pool) {
	pj_pool_release(tcp->pool);
    }
}

static void delay_tcp_destroy(struct tcp_transport *tcp)
{
    pj_time_val delay = {0, 100};
    pj_timer_heap_t *timer_heap = g_http_admin->srv->core.timer_heap;

    if (tcp->key) {
	pj_ioqueue_unregister(tcp->key);
	tcp->key = NULL;
	tcp->sock = PJ_INVALID_SOCKET;
    } else if (tcp->sock != PJ_INVALID_SOCKET) {
	pj_sock_close(tcp->sock);
	tcp->sock = PJ_INVALID_SOCKET;
    }

    if (tcp->timer.id)
	pj_timer_heap_cancel(timer_heap, &tcp->timer);
    tcp->timer.id = 1;
    pj_timer_heap_schedule(timer_heap, &tcp->timer, &delay);
}

static void timer_callback(pj_timer_heap_t *timer_heap, pj_timer_entry *entry)
{
    struct tcp_transport *tcp = (struct tcp_transport *)entry->user_data;
    PJ_UNUSED_ARG(timer_heap);
    tcp_destroy(tcp);
}

static void transport_create(struct pj_http_admin *http_admin, pj_sock_t sock,
			     pj_sockaddr_t *src_addr, int src_addr_len)
{
    pj_pool_t *pool;
    struct tcp_transport *tcp;
    pj_ioqueue_callback cb;
    pj_status_t status;

    pool = pj_pool_create(http_admin->pf, "http_cli%p", 1000, 1000, NULL);

    tcp = PJ_POOL_ZALLOC_T(pool, struct tcp_transport);
    tcp->pool = pool;
    tcp->sock = sock;
    pj_timer_entry_init(&tcp->timer, 0, tcp, &timer_callback);

    /* Register to ioqueue */
    pj_bzero(&cb, sizeof(cb));
    cb.on_read_complete = &http_on_read_complete;
    status = pj_ioqueue_register_sock(pool, http_admin->ioqueue, sock,
				      tcp, &cb, &tcp->key);
    if (status != PJ_SUCCESS) {
	tcp_destroy(tcp);
	return;
    }

    http_on_read_complete(tcp->key, &tcp->recv_op, -PJ_EPENDING);
}

static int dump_turn_status(pj_turn_srv *srv, char *pb, int max_len)
{
    char addr[80];
    pj_hash_iterator_t itbuf, *it;
    pj_time_val now;
    pj_parsed_time pt;
    unsigned i;
    char *p = pb;

    pj_gettimeofday(&now);
    pj_time_decode(&now, &pt);

    p += pj_ansi_sprintf(p, "Current time   : %04d-%02d-%02d %02d:%02d:%02d\n",
			 pt.year, pt.mon + 1, pt.day, pt.hour, pt.min, pt.sec);

    for (i = 0; i < srv->core.lis_cnt; ++i) {
	pj_turn_listener *lis = srv->core.listener[i];
	p += pj_ansi_sprintf(p, "Server address : %s\n", lis->info);
    }

    p += pj_ansi_sprintf(p, "Worker threads : %d\n", srv->core.thread_cnt);
    p += pj_ansi_sprintf(p, "Total mem usage: %u.%03uMB\n",
			 (unsigned)(g_cp.used_size / 1000000 - 1),
			 (unsigned)((g_cp.used_size % 1000000) / 1000));
    p += pj_ansi_sprintf(p, "UDP port range : %u %u %u (next/min/max)\n",
			 srv->ports.next_udp, srv->ports.min_udp,
			 srv->ports.max_udp);
    p += pj_ansi_sprintf(p, "TCP port range : %u %u %u (next/min/max)\n",
			 srv->ports.next_tcp, srv->ports.min_tcp,
			 srv->ports.max_tcp);
    p += pj_ansi_sprintf(p, "Clients        : %u\n\n",
			 pj_hash_count(srv->tables.alloc));

    if (pj_hash_count(srv->tables.alloc) == 0) {
	goto done_line;
    }

    p += pj_ansi_sprintf(p, "#    Client addr.          Alloc addr.            Username Lftm Expy #prm #chl\n");
    p += pj_ansi_sprintf(p, "------------------------------------------------------------------------------\n");

    it = pj_hash_first(srv->tables.alloc, &itbuf);
    i = 1;
    while (it) {
	pj_turn_allocation *alloc =
	    (pj_turn_allocation *)pj_hash_this(srv->tables.alloc, it);
	char buf[500];
	int n;
	n = pj_ansi_sprintf(
	    buf, "%-3d %-22s %-22s %-8.*s %-4d %-4ld %-4d %-4d\n", i,
	    alloc->info,
	    pj_sockaddr_print(&alloc->relay.hkey.addr, addr, sizeof(addr), 3),
	    (int)alloc->cred.data.static_cred.username.slen,
	    alloc->cred.data.static_cred.username.ptr, alloc->relay.lifetime,
	    alloc->relay.expiry.sec - now.sec, pj_hash_count(alloc->peer_table),
	    pj_hash_count(alloc->ch_table));
	if (p - pb + n > max_len)
	    break;
	p += pj_ansi_sprintf(p, "%s", buf);

	it = pj_hash_next(srv->tables.alloc, it);
	++i;
    }
done_line:
    return p - pb;
}

static int handle_http_req(struct tcp_transport *tcp, char *data,
			   pj_ssize_t len)
{
    PJ_UNUSED_ARG(len);
    char *p = data + 6, *p2;
    pj_bool_t valid_req = PJ_FALSE;
    pj_str_t http_ver;
    pj_pool_t *tmp_pool;
    char *rsp_data, *rsp_body;

    enum
    {
	MAX_BODY_LEN = 511 * 1024
    };

    // search 'HTTP/1.1'
    while (1) {
	if (p[0] == '\0' || p[0] == '\r')
	    break;
	if (p[0] != 'H') {
	    p++;
	    continue;
	}
	if (p[0] == 'H' && p[1] == 'T' && p[2] == 'T' && p[3] == 'P' &&
	    p[4] == '/') {
	    p += 5;
	    p2 = p;
	    while (*p != '\r' && *p != '\n' && *p != '\0') {
		p++;
	    }
	    if (p - p2 > 0) {
		http_ver.ptr = p2;
		http_ver.slen = p - p2;
		valid_req = PJ_TRUE;
	    }
	    break;
	}
    }

    if (valid_req == PJ_FALSE) {
	return PJ_EINVALIDOP;
    }

    /* generate http response */
    tmp_pool = pj_pool_create(g_http_admin->srv->core.pf, NULL,
			      1024 * 1024 + 1000, 1000, NULL);
    PJ_ASSERT_RETURN(tmp_pool, PJ_ENOMEM);
    rsp_data = pj_pool_zalloc(tmp_pool, MAX_BODY_LEN + 512);
    rsp_body = pj_pool_zalloc(tmp_pool, MAX_BODY_LEN);

    // body
    p = rsp_body;
    p += pj_ansi_sprintf(p, "<html>\n<head>\n");
    p += pj_ansi_sprintf(p, " <title>Turn Server Status</title>\n");
    p += pj_ansi_sprintf(p, "</head>\n<body>\n");
    p += pj_ansi_sprintf(p, "<h2>Turn Server Status</h2>\n");
    p += pj_ansi_sprintf(p, "<hr size=\"1\"/>\n<pre style=\"font-size: 16px\">\n");

    p += dump_turn_status(g_http_admin->srv, p, MAX_BODY_LEN - (p - rsp_body) - 32);

    p += pj_ansi_sprintf(p, "</pre>\n</body>\n</html>\n");

    // http header + body
    p2 = rsp_data;
    p2 += pj_ansi_sprintf(p2, "HTTP/%.*s 200 OK\r\n", (int)http_ver.slen,
			  http_ver.ptr);
    p2 += pj_ansi_sprintf(p2, "Content-Type: text/html;charset=UTF-8\r\n");
    p2 += pj_ansi_sprintf(p2, "Content-Length: %lu\r\n\r\n", p - rsp_body);
    p2 += pj_ansi_sprintf(p2, "%s", rsp_body);

    // send rsp
    len = p2 - rsp_data;
    pj_ioqueue_send(tcp->key, &tcp->send_op, rsp_data, &len, 0);

    pj_pool_release(tmp_pool);

    return PJ_SUCCESS;
}

static void http_on_read_complete(pj_ioqueue_key_t *key, 
				 pj_ioqueue_op_key_t *op_key, 
				 pj_ssize_t bytes_read)
{
    pj_status_t status;
    struct tcp_transport *tcp =
	(struct tcp_transport *)pj_ioqueue_get_user_data(key);

    do {
	if (bytes_read > 0) {
	    PJ_LOG(5, (tcp->pool->obj_name, "read: %.*s", bytes_read,
		       tcp->recv_buf));
	    if (pj_ansi_strncmp(tcp->recv_buf, "GET /", 5) == 0) {
		handle_http_req(tcp, tcp->recv_buf, bytes_read);
	    } else {
		delay_tcp_destroy(tcp);
		return;
	    }
	} else if (bytes_read != -PJ_EPENDING &&
		   bytes_read != -PJ_STATUS_FROM_OS(PJ_BLOCKING_ERROR_VAL)) {
	    /* TCP connection closed/error. Notify client and then destroy
	     * ourselves.
	     * Note: the -PJ_EPENDING is the value passed during init.
	     */
	    if (bytes_read != 0) {
		PJ_PERROR(2, (tcp->pool->obj_name, -bytes_read,
			      "TCP socket error(%d)", -bytes_read));
	    } else {
		PJ_LOG(4, (tcp->pool->obj_name, "TCP socket closed"));
	    }
	    delay_tcp_destroy(tcp);
	    return;
	}

	/* Read next packet */
	bytes_read = sizeof(tcp->recv_buf);
	pj_bzero(tcp->recv_buf, sizeof(tcp->recv_buf));
	status =
	    pj_ioqueue_recv(tcp->key, op_key, tcp->recv_buf, &bytes_read, 0);

	if (status != PJ_EPENDING && status != PJ_SUCCESS)
	    bytes_read = -status;

    } while (status != PJ_EPENDING && status != PJ_ECANCELLED);
}

/**
 * Callback on new TCP connection.
 */
static void lis_on_accept_complete(pj_ioqueue_key_t *key,
				   pj_ioqueue_op_key_t *op_key, pj_sock_t sock,
				   pj_status_t status)
{
    struct accept_op *accept_op = (struct accept_op *)op_key;

    struct pj_http_admin *http_admin =
	(struct pj_http_admin *)pj_ioqueue_get_user_data(key);

    PJ_UNUSED_ARG(sock);

    do {
	/* Report new connection. */
	if (status == PJ_SUCCESS) {
	    char addr[PJ_INET6_ADDRSTRLEN + 8];
	    PJ_LOG(4, (http_admin->obj_name, "Incoming TCP from %s",
		       pj_sockaddr_print(&accept_op->src_addr, addr,
					 sizeof(addr), 3)));
	    transport_create(http_admin, accept_op->sock, &accept_op->src_addr,
			     accept_op->src_addr_len);
	} else if (status != PJ_EPENDING &&
		   status != PJ_STATUS_FROM_OS(PJ_BLOCKING_ERROR_VAL)) {
	}

	/* Prepare next accept() */
	accept_op->src_addr_len = sizeof(accept_op->src_addr);
	status =
	    pj_ioqueue_accept(key, op_key, &accept_op->sock, NULL,
			      &accept_op->src_addr, &accept_op->src_addr_len);

    } while (status != PJ_EPENDING && status != PJ_ECANCELLED &&
	     status != PJ_STATUS_FROM_OS(PJ_BLOCKING_ERROR_VAL));
}

pj_status_t pj_turn_create_http_admin(pj_turn_srv *srv, int af,
				      const pj_str_t *bound_addr, unsigned port,
				      unsigned concurrency_cnt)
{
    pj_status_t status;
    pj_pool_t *pool;
    pj_sock_t sock = PJ_INVALID_SOCKET;
    unsigned i;
    pj_ioqueue_callback ioqueue_cb;

    pool = pj_pool_create(srv->core.pf, "http_admin", 1000, 1000, NULL);
    g_http_admin = PJ_POOL_ZALLOC_T(pool, struct pj_http_admin);
    g_http_admin->pool = pool;
    g_http_admin->obj_name = pool->obj_name;
    g_http_admin->srv = srv;
    g_http_admin->pf = srv->core.pf;
    g_http_admin->ioqueue = srv->core.ioqueue;

    /* Create socket */
    status = pj_sock_socket(af, pj_SOCK_STREAM(), 0, &sock);
    if (status != PJ_SUCCESS)
	goto on_error;
    g_http_admin->sock = sock;

    pj_util_disable_tcp_timewait(sock);

    /* Init bind address */
    status = pj_sockaddr_init(af, &g_http_admin->addr, bound_addr,
			      (pj_uint16_t)port);
    if (status != PJ_SUCCESS)
	goto on_error;

    /* Create info */
    pj_ansi_strcpy(g_http_admin->info, "HTTP:");
    pj_sockaddr_print(&g_http_admin->addr, g_http_admin->info + 5,
		      sizeof(g_http_admin->info) - 5, 3);

    /* Bind socket */
    status = pj_sock_bind(sock, &g_http_admin->addr,
			  pj_sockaddr_get_len(&g_http_admin->addr));
    if (status != PJ_SUCCESS)
	goto on_error;

    /* Listen() */
    status = pj_sock_listen(sock, 5);
    if (status != PJ_SUCCESS)
	goto on_error;

    /* Register to ioqueue */
    pj_bzero(&ioqueue_cb, sizeof(ioqueue_cb));
    ioqueue_cb.on_accept_complete = &lis_on_accept_complete;
    status =
	pj_ioqueue_register_sock(pool, g_http_admin->ioqueue, sock,
				 g_http_admin, &ioqueue_cb, &g_http_admin->key);
    if (status != PJ_SUCCESS)
	goto on_error;

    /* Create op keys */
    g_http_admin->accept_op = (struct accept_op *)pj_pool_calloc(
	pool, concurrency_cnt, sizeof(struct accept_op));

    /* Create each accept_op and kick off read operation */
    for (i = 0; i < concurrency_cnt; ++i) {
	lis_on_accept_complete(g_http_admin->key,
			       &g_http_admin->accept_op[i].op_key,
			       PJ_INVALID_SOCKET, PJ_EPENDING);
    }

    /* Done */
    PJ_LOG(4,
	   (g_http_admin->obj_name, "Listener %s created", g_http_admin->info));

    return PJ_SUCCESS;
on_error:
    if (sock != PJ_INVALID_SOCKET)
	pj_sock_close(sock);

    return status;
}

void pj_turn_destroy_http_admin()
{
    if (g_http_admin) {
	if (g_http_admin->key)
	    pj_ioqueue_unregister(g_http_admin->key);
	pj_pool_release(g_http_admin->pool);
    }
}
#endif


/****************************************************************************/
pj_turn_config *g_turn_cfg = NULL;

pj_status_t pj_turn_config_init(pj_pool_factory *pf)
{
    pj_turn_config *pcfg;
    pj_pool_t *pool = pj_pool_create(pf, "turn-config", 1000, 1000, NULL);
    PJ_ASSERT_RETURN(pool, PJ_ENOMEM);

    pcfg = PJ_POOL_ZALLOC_T(pool, pj_turn_config);
    pcfg->pool = pool;
    pcfg->listening_port = 3478;
    pcfg->relay_threads = 0;
    pcfg->min_port = PJ_TURN_MIN_PORT;
    pcfg->max_port = PJ_TURN_MAX_PORT;

    g_turn_cfg = pcfg;
    return PJ_SUCCESS;
}

void pj_turn_config_destroy(void)
{
    if (g_turn_cfg) {
	pj_pool_release(g_turn_cfg->pool);
	g_turn_cfg = NULL;
    }
}

pj_status_t pj_turn_config_load(void)
{
    pj_status_t rc;
    pj_turn_config *pcfg = g_turn_cfg;
    char tmp_buf[50 * 1024];
    pj_pool_t *tmp_pool;
    pj_oshandle_t fd;
    pj_size_t fsize;
    char *fdata;
    pj_scanner *scanner;

    if (!pj_file_exists(PJ_TURN_CONFIG_FILE)) {
	PJ_LOG(1, (pcfg->pool->obj_name, "%s not exists", PJ_TURN_CONFIG_FILE));
	return PJ_EEXISTS;
    }

    tmp_pool = pj_pool_create_on_buf(NULL, tmp_buf, sizeof(tmp_buf));

    rc = pj_file_open(tmp_pool, PJ_TURN_CONFIG_FILE, PJ_O_RDONLY, &fd);
    if (rc != PJ_SUCCESS) {
	PJ_PERROR(2, (pcfg->pool->obj_name, rc, "open turn config(%d)", rc));
	return rc;
    }

    fsize = pj_file_size(PJ_TURN_CONFIG_FILE);
    fdata = pj_pool_alloc(tmp_pool, fsize);
    rc = pj_file_read(fd, fdata, (pj_ssize_t *)&fsize);
    if (rc != PJ_SUCCESS) {
	pj_file_close(fd);
	PJ_PERROR(2, (pcfg->pool->obj_name, rc, "read file(%d)", rc));
	return rc;
    }
    pj_file_close(fd);

    scanner = PJ_POOL_ALLOC_T(tmp_pool, pj_scanner);
    pj_scan_init(scanner, fdata, fsize, 0, NULL);

    while (!pj_scan_is_eof(scanner)) {
	pj_str_t key, val;

	if (pj_isspace(*scanner->curptr)) {
	    scanner->curptr++;
	    continue;
	}

	if (*scanner->curptr == '#') {
	    pj_scan_skip_line(scanner);
	    continue;
	}

	pj_scan_get_until_chr(scanner, "=\r\n", &key);
	if (*scanner->curptr != '=') {
	    // current line not match 'key = val'
	    pj_scan_get_char(scanner);
	    continue;
	}
	pj_scan_get_char(scanner); // skip '='
	pj_scan_get_until_chr(scanner, " \t\r\n", &val);

	pj_strtrim(&key);
	pj_strtrim(&val);

	if (key.slen == 0)
	    continue;

	if (pj_strcmp2(&key, "listening-port") == 0) {
	    int port = pj_strtol(&val);
	    if (port < 0 || port > 65535) {
		PJ_LOG(2, (pcfg->pool->obj_name, "invalid listening-port = %d",
			   port));
		continue;
	    }
	    pcfg->listening_port = port;
	}

	else if (pj_strcmp2(&key, "realm") == 0) {
	    if (!val.slen)
		continue;
	    pj_strdup_with_null(pcfg->pool, &pcfg->realm, &val);
	}

	else if (pj_strcmp2(&key, "min-port") == 0) {
	    int port = pj_strtol(&val);
	    if (port < 0 || port > 65535) {
		PJ_LOG(2,
		       (pcfg->pool->obj_name, "invalid min-port = %d", port));
		continue;
	    }
	    pcfg->min_port = port;
	}

	else if (pj_strcmp2(&key, "max-port") == 0) {
	    int port = pj_strtol(&val);
	    if (port < 0 || port > 65535) {
		PJ_LOG(2,
		       (pcfg->pool->obj_name, "invalid max-port = %d", port));
		continue;
	    }
	    pcfg->max_port = port;
	}

	else if (pj_strcmp2(&key, "relay-threads") == 0) {
	    int n = pj_strtol(&val);
	    if (n < 0) {
		PJ_LOG(2,
		       (pcfg->pool->obj_name, "invalid relay-threads = %d", n));
		continue;
	    }
	    pcfg->relay_threads = n;
	}

	else if (pj_strcmp2(&key, "user") == 0) {
	    pj_str_t token;
	    pj_str_t usr, pwd;
	    int idx;
	    pj_turn_user_acc *acc;
	    if (pcfg->user_cnt == PJ_ARRAY_SIZE(pcfg->users)) {
		continue;
	    }

	    // user
	    idx = pj_strtok2(&val, ":", &token, 0);
	    if (idx == val.slen) {
		PJ_LOG(2, (pcfg->pool->obj_name, "invalid user = %.*s",
			   (int)val.slen, val.ptr));
		continue;
	    }
	    usr = token;

	    // password
	    idx = pj_strtok2(&val, ":", &token, idx + token.slen);
	    if (idx == val.slen) {
		PJ_LOG(2, (pcfg->pool->obj_name, "invalid user = %.*s",
			   (int)val.slen, val.ptr));
		continue;
	    }
	    pwd = token;

	    acc = pcfg->users + pcfg->user_cnt;
	    pj_strdup_with_null(pcfg->pool, &acc->usr, &usr);
	    pj_strdup_with_null(pcfg->pool, &acc->pwd, &pwd);
	    pcfg->user_cnt++;
	}

	else if (pj_strcmp2(&key, "dscp_udp") == 0) {
	    pcfg->dscp_udp = pj_strtol(&val);
	}

	else if (pj_strcmp2(&key, "dscp_tcp") == 0) {
	    pcfg->dscp_tcp = pj_strtol(&val);
	}
    }

    pj_scan_fini(scanner);

    return PJ_SUCCESS;
}

void pj_turn_config_print(void)
{
    const pj_turn_config *pcfg = g_turn_cfg;
    pj_uint32_t i;

    puts("Turn config:");
    printf("\tlistening-port: %u\n", pcfg->listening_port);
    printf("\trealm: %.*s\n", (int)pcfg->realm.slen, pcfg->realm.ptr);
    printf("\trelay-threads: %u\n", pcfg->relay_threads);
    printf("\tmin-port: %u\n", pcfg->min_port);
    printf("\tmax-port: %u\n", pcfg->max_port);
    printf("\ttos: %d(0x%x) %d(0x%x)\n", pcfg->dscp_udp, pcfg->dscp_udp << 2,
	   pcfg->dscp_tcp, pcfg->dscp_tcp << 2);
    printf("\tusers:\n");
    for (i = 0; i < pcfg->user_cnt; i++) {
	const pj_turn_user_acc *acc = pcfg->users + i;
	printf("\t  %u. %.*s:%.*s\n", i+1, (int)acc->usr.slen, acc->usr.ptr,
	       (int)acc->pwd.slen, acc->pwd.ptr);
    }
}

const pj_turn_config *pj_turn_get_config(void)
{
    return g_turn_cfg;
}

pj_status_t pj_turn_set_tos(pj_sock_t sock, int dscp)
{
    pj_qos_params param;
    if (dscp < 0)
	return PJ_EINVAL;

    pj_bzero(&param, sizeof(param));
    param.flags = PJ_QOS_PARAM_HAS_DSCP;
    param.dscp_val = dscp;
    return pj_sock_set_qos_params(sock, &param);
}
