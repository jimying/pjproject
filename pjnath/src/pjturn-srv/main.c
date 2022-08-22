/* $Id$ */
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
#include "auth.h"
#include <pjlib-util/getopt.h>
#if !(defined(PJ_WIN32) || defined(PJ_WIN64))
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#endif

#define REALM		"pjsip.org"
#define LOG_LEVEL	4
#define THIS_FILE   "main.c"

static pj_caching_pool g_cp;
static pj_bool_t g_daemon = PJ_FALSE;
static pj_sem_t *g_sem;

#if !PJ_HAS_THREADS
static pj_turn_srv *g_srv;
#endif

#include "extend.c"

static void dump_status(pj_turn_srv *srv)
{
    char addr[80];
    pj_hash_iterator_t itbuf, *it;
    pj_time_val now;
    unsigned i;

    for (i=0; i<srv->core.lis_cnt; ++i) {
	pj_turn_listener *lis = srv->core.listener[i];
	printf("Server address : %s\n", lis->info);
    }

#if PJ_HAS_THREADS
    printf("Worker threads : %d\n", srv->core.thread_cnt);
#endif
    printf("Total mem usage: %u.%03uMB\n", (unsigned)(g_cp.used_size / 1000000), 
	   (unsigned)((g_cp.used_size % 1000000)/1000));
    printf("UDP port range : %u %u %u (next/min/max)\n", srv->ports.next_udp,
	   srv->ports.min_udp, srv->ports.max_udp);
    printf("TCP port range : %u %u %u (next/min/max)\n", srv->ports.next_tcp,
	   srv->ports.min_tcp, srv->ports.max_tcp);
    printf("Clients #      : %u\n", pj_hash_count(srv->tables.alloc));

    puts("");

    if (pj_hash_count(srv->tables.alloc)==0) {
	return;
    }

    puts("#    Client addr.          Alloc addr.            Username Lftm Expy #prm #chl");
    puts("------------------------------------------------------------------------------");

    pj_gettimeofday(&now);

    it = pj_hash_first(srv->tables.alloc, &itbuf);
    i=1;
    while (it) {
	pj_turn_allocation *alloc = (pj_turn_allocation*) 
				    pj_hash_this(srv->tables.alloc, it);
	printf("%-3d %-22s %-22s %-8.*s %-4d %-4ld %-4d %-4d\n",
	       i,
	       alloc->info,
	       pj_sockaddr_print(&alloc->relay.hkey.addr, addr, sizeof(addr), 3),
	       (int)alloc->cred.data.static_cred.username.slen,
	       alloc->cred.data.static_cred.username.ptr,
	       alloc->relay.lifetime,
	       alloc->relay.expiry.sec - now.sec,
	       pj_hash_count(alloc->peer_table), 
	       pj_hash_count(alloc->ch_table));

	it = pj_hash_next(srv->tables.alloc, it);
	++i;
    }
}

static void menu(void)
{
    puts("");
    puts("Menu:");
    puts(" d   Dump status");
    puts(" q   Quit");
    printf(">> ");
}

static void console_main(pj_turn_srv *srv)
{
    pj_bool_t quit = PJ_FALSE;

    while (!quit) {
	char line[10];
	
	menu();
	    
	if (fgets(line, sizeof(line), stdin) == NULL) {
        pj_sem_wait(g_sem);
        break;
    }

	switch (line[0]) {
	case 'd':
	    dump_status(srv);
	    break;
	case 'q':
	    quit = PJ_TRUE;
	    break;
	}
    }
}

static void parse_args(int argc, char **argv)
{
    struct pj_getopt_option opts[] = {
	{"help", 0, 0, 'h'},
	{"daemon", 0, 0, 'o'},
	{NULL, 0, 0, 0},
    };

    int opt_index;
    int c = 0;
    pj_optind = 0;
    while ((c = pj_getopt_long(argc, argv, "ho", opts, &opt_index)) != -1) {
	switch (c) {
	case 'o':
	    g_daemon = PJ_TRUE;
	    break;
	default:
	    puts("Usage:");
	    puts("  -h,--help        Print help");
	    puts("  -o,--daemon      Start process as daemon");
	    exit(0);
	}
    }
}

static int sys_daemon(void)
{
#if !(defined(PJ_WIN32) || defined(PJ_WIN64))
    pid_t pid;

    pid = fork();
    if (-1 == pid)
	return errno;
    else if (pid > 0)
	exit(0);

    if (-1 == setsid())
	return errno;

    (void)signal(SIGHUP, SIG_IGN);

    pid = fork();
    if (-1 == pid)
	return errno;
    else if (pid > 0)
	exit(0);

    (void)umask(0);

    /* Redirect standard files to /dev/null */
    if (freopen("/dev/null", "r", stdin) == NULL)
	return errno;
    if (freopen("/dev/null", "w", stdout) == NULL)
	return errno;
    // if (freopen("/dev/null", "w", stderr) == NULL)
    // return errno;

    return 0;
#else
    return PJ_ENOTSUP;
#endif
}

#if !(defined(PJ_WIN32) || defined(PJ_WIN64))
static void sig_handler(int sig)
{
    switch (sig) {
    case SIGINT:
    case SIGTERM:
#if PJ_HAS_THREADS
	pj_sem_post(g_sem);
#else
	pj_turn_srv_stop(g_srv);
#endif
	break;
    }
}
#endif

static void init_sig_handler()
{
    static char tmp_buf[1000];
    pj_pool_t *tmp_pool = pj_pool_create_on_buf(NULL, tmp_buf, sizeof(tmp_buf));
    pj_sem_create(tmp_pool, NULL, 0, 1, &g_sem);

#if !(defined(PJ_WIN32) || defined(PJ_WIN64))
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    if (g_daemon) {
	pj_log_set_level(1);
	sys_daemon();	
    }
#endif
}

static void dump_pid()
{
    char tmp_buf[1000];
    pj_pool_t *tmp_pool = pj_pool_create_on_buf(NULL, tmp_buf, sizeof(tmp_buf));
    pj_oshandle_t fd = NULL;
    pj_status_t rc;
    pj_str_t str_pid;

    rc = pj_file_open(tmp_pool, "./turnserver.pid", PJ_O_WRONLY, &fd);
    if (rc != PJ_SUCCESS) {
	PJ_PERROR(1, (THIS_FILE, rc, "open pid file error"));
	return;
    }

    str_pid.ptr = pj_pool_zalloc(tmp_pool, 32);
    str_pid.slen = pj_ansi_sprintf(str_pid.ptr, "%u", pj_getpid());
    pj_file_write(fd, str_pid.ptr, &str_pid.slen);
    pj_file_close(fd);
}

static void log_callback(int level, const char *data, int len)
{
    fprintf(level < 2 ? stderr : stdout, "%.*s", len, data);
}

int main(int argc, char **argv)
{
    pj_turn_srv *srv;
    pj_turn_listener *listener;
    pj_status_t status;
    const pj_turn_config *pcfg;
    int nworkers;
    pj_sockaddr addr_list[16];
    pj_uint32_t addr_cnt = PJ_ARRAY_SIZE(addr_list);
    int i;

    status = pj_init();
    if (status != PJ_SUCCESS) {
	PJ_PERROR(1, (THIS_FILE, status, "pj_init() error(%d)", status));
	return status;
    }

    pj_log_set_log_func(log_callback);
    pj_log_set_level(LOG_LEVEL);

    // pj_dump_config();
    pjlib_util_init();

    parse_args(argc, argv);
    init_sig_handler();

    pjnath_init();

    pj_caching_pool_init(&g_cp, NULL, 64 * 1024 * 1024);

    pj_turn_config_init(&g_cp.factory);
    pj_turn_config_load();
    pj_turn_config_print();
    pcfg = pj_turn_get_config();

    pj_turn_auth_init(REALM);

    status = pj_turn_srv_create(&g_cp.factory, &srv);
    if (status != PJ_SUCCESS) {
	PJ_PERROR(1, (THIS_FILE, status, "Error creating server"));
	return status;
    }

    nworkers = srv->core.thread_cnt;

    status = pj_enum_ip_interface(pj_AF_INET(), &addr_cnt, addr_list);
    if (status != PJ_SUCCESS) {
	PJ_PERROR(1, (THIS_FILE, status, "Error enum ip interface"));
	return status;
    }

    for (i = 0; i < addr_cnt; i++) {
	char ip[80];
	pj_str_t sip;
	pj_sockaddr_print(&addr_list[i], ip, sizeof(ip), 0);
	sip = pj_str(ip);
	status = pj_turn_listener_create_udp(srv, pj_AF_INET(), &sip,
					     pcfg->listening_port, nworkers, 0,
					     &listener);
	if (status != PJ_SUCCESS) {
	    PJ_PERROR(1,
		      (THIS_FILE, status, "Error creating UDP listener %.*s:%d",
		       (int)sip.slen, sip.ptr, pcfg->listening_port));
	    return status;
	}

	status = pj_turn_srv_add_listener(srv, listener);
	if (status != PJ_SUCCESS) {
	    PJ_PERROR(1,
		      (THIS_FILE, status, "Error adding UDP listener %.*s:%d",
		       (int)sip.slen, sip.ptr, pcfg->listening_port));
	    return status;
	}

#if PJ_HAS_TCP
	status = pj_turn_listener_create_tcp(srv, pj_AF_INET(), &sip,
					     pcfg->listening_port, nworkers, 0,
					     &listener);
	if (status != PJ_SUCCESS) {
	    PJ_PERROR(1,
		      (THIS_FILE, status, "Error creating TCP listener %.*s:%d",
		       (int)sip.slen, sip.ptr, pcfg->listening_port));
	    return status;
	}

	status = pj_turn_srv_add_listener(srv, listener);
	if (status != PJ_SUCCESS) {
	    PJ_PERROR(1,
		      (THIS_FILE, status, "Error adding TCP listener %.*s:%d",
		       (int)sip.slen, sip.ptr, pcfg->listening_port));
	    return status;
	}
#endif
    }

#if PJ_HAS_TCP
    status = pj_turn_create_http_admin(srv, pj_AF_INET(), NULL,
				       pcfg->listening_port - 1, 1);
    if (status != PJ_SUCCESS) {
	PJ_PERROR(1, (THIS_FILE, status, "Error creating HTTP listener %d",
		      pcfg->listening_port - 1));
    }
#endif

    puts("Server is running");
    if (g_daemon) {
	dump_pid();
    }

#if PJ_HAS_THREADS
    console_main(srv);
#else
    g_srv = srv;
    while (!srv->core.quit) {
	pj_turn_srv_handle_events(srv);
    }
#endif

#if PJ_HAS_TCP
    pj_turn_destroy_http_admin();
#endif
    pj_turn_srv_destroy(srv);
    pj_turn_config_destroy();
    pj_caching_pool_destroy(&g_cp);
    pj_shutdown();

    return 0;
}

