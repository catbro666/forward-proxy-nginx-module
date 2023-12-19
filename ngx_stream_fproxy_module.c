
/*
 * Copyright (C) Zhefeng Chen
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>

#include "ngx_stream_fproxy_module.h"


typedef struct {
    ngx_addr_t                      *addr;
    ngx_stream_complex_value_t      *value;
#if (NGX_HAVE_TRANSPARENT_PROXY)
    ngx_uint_t                       transparent; /* unsigned  transparent:1; */
#endif
} ngx_stream_upstream_local_t;

typedef struct {
    ngx_uint_t                       enabled_protocols;
#if (NGX_STREAM_SSL)
    ngx_flag_t                       ssl_optional;
#endif
    ngx_uint_t                       auth_methods;
    ngx_hash_keys_arrays_t          *userpw_keys;
    ngx_hash_t                       userpw_hash;

    ngx_msec_t                       negotiate_timeout;
    ngx_msec_t                       connect_timeout;
    ngx_msec_t                       response_timeout;
    ngx_msec_t                       timeout;
    ngx_uint_t                       requests;
    ngx_uint_t                       responses;
    ngx_msec_t                       next_upstream_timeout;
    size_t                           buffer_size;
    ngx_stream_complex_value_t      *upload_rate;
    ngx_stream_complex_value_t      *download_rate;
    ngx_uint_t                       next_upstream_tries;
    ngx_flag_t                       next_upstream;
    ngx_flag_t                       half_close;
    ngx_stream_upstream_local_t     *local;
    ngx_flag_t                       socket_keepalive;

} ngx_stream_fproxy_srv_conf_t;


typedef struct {
    NGX_STREAM_FPROXY_STATE         state;  /* current state */
    NGX_STREAM_FPROXY_TYPE          type;   /* proxy type */
    ngx_stream_upstream_resolved_t  resolved;
    ngx_str_t                       cred;   /* username/password */
    u_char                          *pos;   /* the current parse position */
    ngx_str_t                       res;    /* response content */
    ngx_uint_t                      rc;    /* return code */
    u_char                          method; /* selected mothod */
} ngx_stream_fproxy_ctx_t;

static const char *HTTP_METHODS[] = {
    "GET ", "PUT ", "HEAD ", "POST ", "TRACE ", "PATCH ", "DELETE ", "OPTION "
};

static const size_t HTTP_METHOD_LENS[] = {
     4,      4,      5,       5,       6,        6,        7,         7
};
static int HTTP_METHODS_NUM = sizeof(HTTP_METHODS) / sizeof(char *);

static const ngx_str_t res200 =
    ngx_string("HTTP/1.0 200 Connection established\r\n\r\n");
static const ngx_str_t res400 = 
    ngx_string("HTTP/1.1 400 Bad Request\r\n\r\n");
static const ngx_str_t res407 =
    ngx_string("HTTP/1.1 407 Proxy Authentication Required\r\n"
               "Proxy-Authenticate: Basic realm=\"test\"\r\n\r\n");
static const ngx_str_t res500 =
    ngx_string("HTTP/1.1 500 Internal Server Error\r\n\r\n");
static const ngx_str_t res502 =
    ngx_string("HTTP/1.1 502 Bad Gateway\r\n\r\n");

#if (NGX_STREAM_SSL)
static ngx_int_t ngx_stream_fproxy_ssl_handler(ngx_stream_session_t *s);
#endif
static void ngx_stream_fproxy_handler(ngx_stream_session_t *s);
static ssize_t ngx_stream_fproxy_recv_from_client(ngx_event_t *ev);
static void ngx_stream_fproxy_greeting_handler(ngx_event_t *ev);
static void ngx_stream_fproxy_socks5_method_select(ngx_stream_session_t *s);
static void ngx_stream_fproxy_socks5_auth(ngx_event_t *ev);
static void ngx_stream_fproxy_socks5_waiting_request(ngx_event_t *ev);
static void ngx_stream_fproxy_http_request_line(ngx_event_t *ev);
static ngx_int_t ngx_stream_fproxy_parse_request_line(ngx_stream_session_t *s,
    u_char *b, u_char *e);
static void ngx_stream_fproxy_http_request_headers(ngx_event_t *ev);
static ngx_int_t ngx_stream_fproxy_basic_auth(ngx_hash_t *hash,
    ngx_str_t *uname, ngx_str_t *pw);
static ngx_int_t ngx_stream_fproxy_parse_url(ngx_stream_session_t *s,
    u_char *b, u_char *e);
static void ngx_stream_fproxy_resolve(ngx_stream_session_t *s);
static ngx_int_t ngx_stream_fproxy_set_local(ngx_stream_session_t *s,
    ngx_stream_upstream_t *u, ngx_stream_upstream_local_t *local);
static void ngx_stream_fproxy_connect(ngx_stream_session_t *s);
static void ngx_stream_fproxy_init_upstream(ngx_stream_session_t *s);
static void ngx_stream_fproxy_resolve_handler(ngx_resolver_ctx_t *ctx);
static void ngx_stream_fproxy_upstream_handler(ngx_event_t *ev);
static void ngx_stream_fproxy_downstream_handler(ngx_event_t *ev);
static void ngx_stream_fproxy_process_connection(ngx_event_t *ev,
    ngx_uint_t from_upstream);
static void ngx_stream_fproxy_connect_handler(ngx_event_t *ev);
static ngx_int_t ngx_stream_fproxy_test_connect(ngx_connection_t *c);
static void ngx_stream_fproxy_process(ngx_stream_session_t *s,
    ngx_uint_t from_upstream, ngx_uint_t do_write);
static ngx_int_t ngx_stream_fproxy_test_finalize(ngx_stream_session_t *s,
    ngx_uint_t from_upstream);
static void ngx_stream_fproxy_next_upstream(ngx_stream_session_t *s);
static void ngx_stream_fproxy_finalize(ngx_stream_session_t *s, ngx_uint_t rc);
static void ngx_stream_fproxy_response(ngx_stream_session_t *s, ngx_uint_t rc);
static void ngx_stream_fproxy_response_handler(ngx_event_t *ev);
static u_char *ngx_stream_fproxy_log_error(ngx_log_t *log, u_char *buf,
    size_t len);

static void *ngx_stream_fproxy_create_srv_conf(ngx_conf_t *cf);
static char *ngx_stream_fproxy_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_stream_fproxy_protocols(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_stream_fproxy_user_passwd(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_stream_fproxy_bind(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static ngx_int_t ngx_stream_fproxy_postconfiguration(ngx_conf_t* cf);


static ngx_conf_bitmask_t ngx_stream_fproxy_protocol_types[] = {
    { ngx_string("HTTP"),   NGX_STREAM_FPROXY_PROTOCOL_HTTP },
    { ngx_string("SOCKS5"), NGX_STREAM_FPROXY_PROTOCOL_SOCKS5 },
    { ngx_null_string, 0 }
};

static ngx_conf_bitmask_t ngx_stream_fproxy_auth_methods[] = {
    { ngx_string("BASIC"), NGX_STREAM_FPROXY_AUTH_BASIC },
    { ngx_null_string, 0 }
};


static ngx_command_t  ngx_stream_fproxy_commands[] = {

    { ngx_string("fproxy_protocols"),
      NGX_STREAM_SRV_CONF|NGX_CONF_1MORE,
      ngx_stream_fproxy_protocols,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_fproxy_srv_conf_t, enabled_protocols),
      &ngx_stream_fproxy_protocol_types },

 #if (NGX_STREAM_SSL)
    { ngx_string("fproxy_ssl_optional"),
      NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_fproxy_srv_conf_t, ssl_optional),
      NULL },
#endif

    { ngx_string("fproxy_auth_methods"),
      NGX_STREAM_SRV_CONF|NGX_CONF_1MORE,
      ngx_conf_set_bitmask_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_fproxy_srv_conf_t, auth_methods),
      &ngx_stream_fproxy_auth_methods },

    { ngx_string("fproxy_user_passwd"),
      NGX_STREAM_SRV_CONF|NGX_CONF_TAKE2,
      ngx_stream_fproxy_user_passwd,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("fproxy_bind"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE12,
      ngx_stream_fproxy_bind,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("fproxy_socket_keepalive"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_fproxy_srv_conf_t, socket_keepalive),
      NULL },

    { ngx_string("fproxy_negotiate_timeout"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_fproxy_srv_conf_t, negotiate_timeout),
      NULL },

    { ngx_string("fproxy_connect_timeout"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_fproxy_srv_conf_t, connect_timeout),
      NULL },

    { ngx_string("fproxy_response_timeout"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_fproxy_srv_conf_t, response_timeout),
      NULL },

    { ngx_string("fproxy_timeout"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_fproxy_srv_conf_t, timeout),
      NULL },

    { ngx_string("fproxy_buffer_size"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_fproxy_srv_conf_t, buffer_size),
      NULL },

    { ngx_string("fproxy_upload_rate"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_stream_set_complex_value_size_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_fproxy_srv_conf_t, upload_rate),
      NULL },

    { ngx_string("fproxy_download_rate"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_stream_set_complex_value_size_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_fproxy_srv_conf_t, download_rate),
      NULL },

    { ngx_string("fproxy_next_upstream"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_fproxy_srv_conf_t, next_upstream),
      NULL },

    { ngx_string("fproxy_next_upstream_tries"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_fproxy_srv_conf_t, next_upstream_tries),
      NULL },

    { ngx_string("fproxy_next_upstream_timeout"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_fproxy_srv_conf_t, next_upstream_timeout),
      NULL },

    { ngx_string("fproxy_half_close"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_fproxy_srv_conf_t, half_close),
      NULL },


      ngx_null_command
};


static ngx_stream_module_t  ngx_stream_fproxy_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_stream_fproxy_postconfiguration,   /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_stream_fproxy_create_srv_conf,      /* create server configuration */
    ngx_stream_fproxy_merge_srv_conf        /* merge server configuration */
};


ngx_module_t  ngx_stream_fproxy_module = {
    NGX_MODULE_V1,
    &ngx_stream_fproxy_module_ctx,          /* module context */
    ngx_stream_fproxy_commands,             /* module directives */
    NGX_STREAM_MODULE,                     /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_stream_fproxy_ssl_handler(ngx_stream_session_t *s)
{
    ngx_stream_fproxy_srv_conf_t    *fscf;
    ngx_connection_t                *c;
    u_char                           buf[1];
    ssize_t                          n;
    ngx_err_t                        err;
    ngx_event_t                     *rev;

    c = s->connection;

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "stream fproxy ssl handler");

    n = recv(c->fd, (char *) buf, 1, MSG_PEEK);

    err = ngx_socket_errno;

    if (n == -1) {
        if (err == NGX_EAGAIN) {
            rev = c->read;
            rev->ready = 0;

            if (!rev->timer_set) {
                fscf = ngx_stream_get_module_srv_conf(s,
                                                      ngx_stream_fproxy_module);
                ngx_add_timer(rev, fscf->negotiate_timeout);
                ngx_reusable_connection(c, 1);
            }

            if (ngx_handle_read_event(rev, 0) != NGX_OK) {
                ngx_stream_finalize_session(s,
                    NGX_STREAM_INTERNAL_SERVER_ERROR);
            }

            return NGX_AGAIN;
        }

        ngx_connection_error(c, err, "recv() failed");
        ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return NGX_ERROR;
    }

    if (n == 1) {

        if (buf[0] & 0x80 /* SSLv2 */ || buf[0] == 0x16 /* SSLv3/TLSv1 */) {
            return NGX_DECLINED;

        } else {    /* non-ssl connection */
            return NGX_OK;
        }
    }

    ngx_log_error(NGX_LOG_INFO, c->log, 0, "client closed connection");
    ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
    return NGX_ERROR;
}


static void
ngx_stream_fproxy_handler(ngx_stream_session_t *s)
{
    ngx_connection_t                 *c;
    ngx_stream_fproxy_ctx_t          *ctx;
    ngx_event_t                      *rev;
    ngx_stream_fproxy_srv_conf_t     *fscf;
    ngx_stream_upstream_t            *u;
    u_char                           *p;

    c = s->connection;

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "fproxy connection handler");

    c->log->action = "waiting greeting";

    ctx = ngx_palloc(c->pool, sizeof(ngx_stream_fproxy_ctx_t));
    if (ctx == NULL) {
        goto err;
    }

    ngx_stream_set_ctx(s, ctx, ngx_stream_fproxy_module);

    u = ngx_pcalloc(c->pool, sizeof(ngx_stream_upstream_t));
    if (u == NULL) {
        goto err;
    }

    s->upstream = u;

    s->log_handler = ngx_stream_fproxy_log_error;

    rev = c->read;
    rev->handler = ngx_stream_fproxy_greeting_handler;
    ctx->state = NGX_STREAM_FPROXY_STATE_GREETING;

    fscf = ngx_stream_get_module_srv_conf(s, ngx_stream_fproxy_module);

    p = ngx_pnalloc(c->pool, fscf->buffer_size);
    if (p == NULL) {
        goto err;
    }

    u->downstream_buf.start = p;
    u->downstream_buf.end = p + fscf->buffer_size;
    u->downstream_buf.pos = p;
    u->downstream_buf.last = p;

    if (rev->ready) {
        rev->handler(rev);
        return;
    }

    ngx_add_timer(rev, fscf->negotiate_timeout);
    ngx_reusable_connection(c, 1); /* XXX */

    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        goto err;
    }

    return;
err:
   ngx_stream_fproxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
   return;
}


static ssize_t
ngx_stream_fproxy_recv_from_client(ngx_event_t *ev)
{
    ngx_connection_t                *c;
    ngx_stream_session_t            *s;
    ngx_stream_upstream_t           *u;
    ngx_buf_t                       *b;
    size_t                           size;
    ssize_t                          n;

    c = ev->data;
    s = c->data;
    u = s->upstream;
    b = &u->downstream_buf;

    size = b->end - b->last;

    if (size == 0) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0, "fproxy buffer size too small");
        return NGX_ERROR;
    }

    size = ngx_min(size, 4096);

    if (ev->ready) {
        n = c->recv(c, b->last, size);

        if (n > 0) {
            b->last += n;
        }

        return n;
    }

    return NGX_AGAIN;
}


static void
ngx_stream_fproxy_greeting_handler(ngx_event_t *ev)
{
    ngx_stream_fproxy_ctx_t         *ctx;
    ngx_stream_fproxy_srv_conf_t    *fscf;
    ngx_connection_t                *c;
    ngx_stream_session_t            *s;
    ngx_stream_upstream_t           *u;
    ngx_buf_t                       *b;
    size_t                           size;
    ssize_t                          n;
    u_char                          *data;
    u_char                          *last;
    u_char                          *p;
    int                              i;

    c = ev->data;
    s = c->data;
    u = s->upstream;
    b = &u->downstream_buf;

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "stream fproxy greeting handler");

    if (ev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT,
                      "waiting greeting timed out");
        goto ok;
    }

    if (c->close) {
        goto ok;
    }

    c->log->action = "reading greeting";
    n = ngx_stream_fproxy_recv_from_client(ev);

    if (n == NGX_AGAIN) {
        if (ngx_handle_read_event(ev, 0) != NGX_OK) {
            goto err;
        }
    }

    if (n == NGX_ERROR) {
        goto err;
    } 

    if (n == 0) {
        goto ok;
    }

    /* doesn't delete the timer here until the whole negotiation complete */

    /* at least 3 bytes for socks5 */
    if (n < 3) {
        goto bad;
    }

    ngx_reusable_connection(c, 0);

    data = b->start;
    last = b->last;

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_fproxy_module);
    fscf = ngx_stream_get_module_srv_conf(s, ngx_stream_fproxy_module);

    /* socks5 |VER|NMETHODS|METHODS|
     *        | 1 |   1    | 1-255 | */
    if (fscf->enabled_protocols & NGX_STREAM_FPROXY_PROTOCOL_SOCKS5
        && data[0] == NGX_STREAM_FPROXY_SOCKS5_VERSION) {
        if (data[1] == 0 || data[1] != n - 2) {
            goto bad;
        }

        ctx->type = NGX_STREAM_FPROXY_TYPE_SOCKS5; 
        ctx->state = NGX_STREAM_FPROXY_STATE_SOCKS5_METHOD_SELECT; 
        return ngx_stream_fproxy_socks5_method_select(s);
    }

    if (fscf->enabled_protocols & NGX_STREAM_FPROXY_PROTOCOL_HTTP) {
        p = ngx_strlchr(data, last, ' ');
        if (p) {
            size = p - data + 1; 
            /* https */
            if (size == 8 && !ngx_strncmp(data, "CONNECT ", 8)) {
                ctx->type = NGX_STREAM_FPROXY_TYPE_HTTPS; 
                ctx->state = NGX_STREAM_FPROXY_STATE_HTTP_REQUEST_LINE; 
                return ngx_stream_fproxy_http_request_line(ev);
            }

            /* http */
            for (i = 0; i < HTTP_METHODS_NUM; ++i) {
                if (size == HTTP_METHOD_LENS[i] &&
                    !ngx_strncmp(data, HTTP_METHODS[i], size)) {
                    ctx->type = NGX_STREAM_FPROXY_TYPE_HTTP; 
                    ctx->state = NGX_STREAM_FPROXY_STATE_HTTP_REQUEST_LINE; 
                    return ngx_stream_fproxy_http_request_line(ev);
                }
            }
        }
    }

bad:
    return ngx_stream_fproxy_finalize(s, NGX_STREAM_BAD_REQUEST);
err:
    return ngx_stream_fproxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
ok:
    return ngx_stream_fproxy_finalize(s, NGX_STREAM_OK);
}


static void
ngx_stream_fproxy_socks5_method_select(ngx_stream_session_t *s)
{
    ngx_connection_t                *c;
    ngx_stream_upstream_t           *u;
    ngx_buf_t                       *b;
    ngx_stream_fproxy_ctx_t         *ctx;
    ngx_stream_fproxy_srv_conf_t    *fscf;
    u_char                          *p;
    u_char                          *buf;

    c = s->connection;

    u = s->upstream;
    b = &u->downstream_buf;

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "stream fproxy process socks5 method select");

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_fproxy_module);
    fscf = ngx_stream_get_module_srv_conf(s, ngx_stream_fproxy_module);

    buf = ngx_palloc(c->pool, 2);
    if (buf == NULL) {
        return ngx_stream_fproxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
    }

    ctx->res.data = buf;
    ctx->res.len = 2;

    buf[0] = NGX_STREAM_FPROXY_SOCKS5_VERSION;
    buf[1] = NGX_STREAM_FPROXY_SOCKS5_AUTH_NO_ACCEPT;

    if (fscf->auth_methods & NGX_STREAM_FPROXY_AUTH_BASIC) {
        for (p = b->start + 2; p < b->last; p++) {
            if (*p == NGX_STREAM_FPROXY_SOCKS5_AUTH_BASIC) {
                buf[1] = NGX_STREAM_FPROXY_SOCKS5_AUTH_BASIC;
                break;
            }
        }

    } else {
        for (p = b->start + 2; p < b->last; p++) {
            if (*p == NGX_STREAM_FPROXY_SOCKS5_AUTH_NO_AUTH) {
                buf[1] = NGX_STREAM_FPROXY_SOCKS5_AUTH_NO_AUTH;
                break;
            }
        }
    }

    if (buf[1] == NGX_STREAM_FPROXY_SOCKS5_AUTH_NO_ACCEPT) {
        return ngx_stream_fproxy_response(s, NGX_STREAM_METHOD_NO_ACCEPT);

    } else {
        ctx->method = buf[1];
        ctx->pos = b->last;
        return ngx_stream_fproxy_response(s, NGX_STREAM_METHOD_ACCEPTED);
    }
}


static void
ngx_stream_fproxy_socks5_auth(ngx_event_t *ev)
{
    ngx_connection_t                *c;
    ngx_stream_session_t            *s;
    ngx_stream_upstream_t           *u;
    ngx_buf_t                       *b;
    ngx_stream_fproxy_ctx_t         *ctx;
    ngx_stream_fproxy_srv_conf_t    *fscf;
    u_char                          *p;
    ssize_t                          n;
    ngx_str_t                        uname;
    ngx_str_t                        pw;
    u_char                          *buf;

    c = ev->data;
    s = c->data;
    u = s->upstream;
    b = &u->downstream_buf;

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "stream fproxy process socks5 auth");

    if (ev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT,
                      "waiting socks5 auth request timed out");
        return ngx_stream_fproxy_finalize(s, NGX_STREAM_OK);
    }

    if (c->close) {
        return ngx_stream_fproxy_finalize(s, NGX_STREAM_OK);
    }

    c->log->action = "reading socks5 auth request";
    n = ngx_stream_fproxy_recv_from_client(ev);

    if (n == NGX_AGAIN) {
        ev->handler = ngx_stream_fproxy_socks5_auth;
        if (ngx_handle_read_event(ev, 0) != NGX_OK) {
            return ngx_stream_fproxy_finalize(s,
                        NGX_STREAM_INTERNAL_SERVER_ERROR);
        }
        return;
    }

    if (n == NGX_ERROR) {
        return ngx_stream_fproxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
    } 

    if (n == 0) {
        return ngx_stream_fproxy_finalize(s, NGX_STREAM_OK);
    }

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_fproxy_module);
    p = ctx->pos;

    /* +----+------+----------+------+----------+
       |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
       +----+------+----------+------+----------+
       | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
       +----+------+----------+------+----------+ */
    if (n < 5 || *p != NGX_STREAM_FPROXY_SOCKS5_BASIC_VERSION) {
        goto forbid;
    }

    uname.data = p + 2;
    uname.len = *(p + 1);
    pw.data = p + 3 + uname.len;
    pw.len = *(p + 2 + uname.len);

    if (uname.len + pw.len + 3 != (size_t)n) {
        goto forbid;
    }

    buf = ngx_palloc(c->pool, 2);
    if (buf == NULL) {
        return ngx_stream_fproxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
    }

    ctx->res.data = buf;
    ctx->res.len = 2;

    buf[0] = NGX_STREAM_FPROXY_SOCKS5_BASIC_VERSION;
    buf[1] = NGX_STREAM_FPROXY_SOCKS5_AUTH_FAILURE;

    fscf = ngx_stream_get_module_srv_conf(s, ngx_stream_fproxy_module);

    if (ngx_stream_fproxy_basic_auth(&fscf->userpw_hash, &uname, &pw)
        != NGX_OK) {
        goto forbid;
    }
 
    ctx->pos = b->last;
    buf[1] = NGX_STREAM_FPROXY_SOCKS5_AUTH_SUCCESS;
    return ngx_stream_fproxy_response(s, NGX_STREAM_AUTH_OK);

forbid:
    return ngx_stream_fproxy_response(s, NGX_STREAM_FORBIDDEN);
}


static void
ngx_stream_fproxy_socks5_waiting_request(ngx_event_t *ev)
{
    ngx_connection_t                *c;
    ngx_stream_session_t            *s;
    ngx_stream_fproxy_ctx_t         *ctx;
    u_char                          *p;
    ssize_t                          n;
    u_char                          *buf = NULL;
    ngx_listening_t                 *listen;
    struct sockaddr                 *sa;
    struct sockaddr_in              *sin;
    struct sockaddr_in6             *sin6;
    u_char                           host_len;
    ngx_int_t                        ret;

    c = ev->data;
    s = c->data;

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "stream fproxy process socks5 request");

    if (ev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT,
                      "waiting socks5 request timed out");
        return ngx_stream_fproxy_finalize(s, NGX_STREAM_OK);
    }

    if (c->close) {
        return ngx_stream_fproxy_finalize(s, NGX_STREAM_OK);
    }

    c->log->action = "reading socks5 request";
    n = ngx_stream_fproxy_recv_from_client(ev);

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_fproxy_module);

    if (n == NGX_AGAIN) {
        ev->handler = ngx_stream_fproxy_socks5_waiting_request;
        if (ngx_handle_read_event(ev, 0) != NGX_OK) {
            return ngx_stream_fproxy_finalize(s,
                        NGX_STREAM_INTERNAL_SERVER_ERROR);
        }
        return;
    }

    if (n == NGX_ERROR) {
        return ngx_stream_fproxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
    }

    if (n == 0) {
        return ngx_stream_fproxy_finalize(s, NGX_STREAM_OK);
    }

    listen = c->listening;
    sa = listen->sockaddr;
    /*  Reply:
     *  +----+-----+-------+------+----------+----------+
        |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
        +----+-----+-------+------+----------+----------+
        | 1  |  1  | X'00' |  1   | Variable |    2     |
        +----+-----+-------+------+----------+----------+ */
    if (sa->sa_family == AF_INET) {
        buf = ngx_pcalloc(c->pool, 10);
        ctx->res.len = 10;
        
    } else if (sa->sa_family == AF_INET6) {
        buf = ngx_pcalloc(c->pool, 22);
        ctx->res.len = 22;
    }

    if (buf == NULL) {
        return ngx_stream_fproxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
    }

    ctx->res.data = buf;
    buf[0] = NGX_STREAM_FPROXY_SOCKS5_VERSION;
    buf[1] = NGX_STREAM_FPROXY_SOCKS5_REPLY_SUCCEEDED;
    /* buf[2] = 0x00; */

    if (sa->sa_family == AF_INET) {
        sin = (struct sockaddr_in *)sa;

        buf[3] = NGX_STREAM_FPROXY_SOCKS5_ATYPE_IPV4;
        ngx_memcpy(buf + 4, (u_char *)&sin->sin_addr, 4);
        ngx_memcpy(buf + 8, (u_char *)&sin->sin_port, 2);
        
    } else if (sa->sa_family == AF_INET6) {
        sin6 = (struct sockaddr_in6 *)sa;

        buf[3] = NGX_STREAM_FPROXY_SOCKS5_ATYPE_IPV6;
        ngx_memcpy(buf + 4, (u_char *)&sin6->sin6_addr, 16);
        ngx_memcpy(buf + 20, (u_char *)&sin6->sin6_port, 2);
    }

    p = ctx->pos;

    /*  Request: 
     *  +----+-----+-------+------+----------+----------+
        |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
        +----+-----+-------+------+----------+----------+
        | 1  |  1  | X'00' |  1   | Variable |    2     |
        +----+-----+-------+------+----------+----------+ */
    if (n < 7 || *p != NGX_STREAM_FPROXY_SOCKS5_VERSION ||
        *(p + 2) != 0) {
        goto bad;
    }

    if (*(p + 1) != NGX_STREAM_FPROXY_SOCKS5_CMD_CONNECT) {
        buf[1] = NGX_STREAM_FPROXY_SOCKS5_REPLY_COMMAND_UNSUPPORTED;
        return ngx_stream_fproxy_response(s, NGX_STREAM_BAD_REQUEST);
    }

    switch (*(p + 3)) {
    case  NGX_STREAM_FPROXY_SOCKS5_ATYPE_IPV4:
        if (n != 10) {
            goto bad;
        }

        ctx->resolved.sockaddr = ngx_pcalloc(c->pool, sizeof(struct sockaddr_in));
        if (ctx->resolved.sockaddr == NULL) {
            goto err;
        }

        sin = (struct sockaddr_in *)ctx->resolved.sockaddr;
        sin->sin_family = AF_INET; 
        ngx_memcpy(&sin->sin_port, p + 8, 2);
        ngx_memcpy(&sin->sin_addr, p + 4, 4);

        ctx->resolved.socklen = sizeof(struct sockaddr_in);
        ctx->resolved.naddrs = 1;
        ctx->resolved.host.data = ngx_pcalloc(c->pool, NGX_INET_ADDRSTRLEN);
        if (ctx->resolved.host.data == NULL) {
            goto err;
        }

        ctx->resolved.host.len = ngx_inet_ntop(AF_INET, ctx->resolved.sockaddr,
            ctx->resolved.host.data, NGX_INET_ADDRSTRLEN);
        ctx->resolved.port = ntohs(sin->sin_port);
        break;
    case  NGX_STREAM_FPROXY_SOCKS5_ATYPE_IPV6:
        if (n != 22) {
            goto bad;
        }

        ctx->resolved.sockaddr = ngx_pcalloc(c->pool, sizeof(struct sockaddr_in6));
        if (ctx->resolved.sockaddr == NULL) {
            goto err;
        }

        sin6 = (struct sockaddr_in6 *)ctx->resolved.sockaddr;
        sin6->sin6_family = AF_INET6; 
        ngx_memcpy(&sin6->sin6_port, p + 20, 2);
        ngx_memcpy(&sin6->sin6_addr, p + 4, 16);

        ctx->resolved.socklen = sizeof(struct sockaddr_in6);
        ctx->resolved.naddrs = 1;
        ctx->resolved.host.data = ngx_pcalloc(c->pool, NGX_INET6_ADDRSTRLEN);
        if (ctx->resolved.host.data == NULL) {
            goto err;
        }

        ctx->resolved.host.len = ngx_inet6_ntop(
            (u_char *)ctx->resolved.sockaddr,
            ctx->resolved.host.data, NGX_INET6_ADDRSTRLEN);
        ctx->resolved.port = ntohs(sin6->sin6_port);

        break;
    case  NGX_STREAM_FPROXY_SOCKS5_ATYPE_DOMAIN:
        host_len = *(p + 4);
        if (n != 7 + host_len) {
            goto bad;
        }

        ret = ngx_stream_fproxy_parse_url(s, p + 5, p + 5 + host_len);
        if (ret == NGX_ERROR) {
            goto bad;
        }

        ctx->resolved.port = ntohs(*(in_port_t *) (p + 5 + host_len));
        break;
    default:
        buf[1] = NGX_STREAM_FPROXY_SOCKS5_REPLY_ATYPE_UNSUPPORTED;
        return ngx_stream_fproxy_response(s, NGX_STREAM_BAD_REQUEST);
    }

    return ngx_stream_fproxy_resolve(s);

err:
    return ngx_stream_fproxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
bad:
    buf[1] = NGX_STREAM_FPROXY_SOCKS5_REPLY_BAD_REQUEST;
    return ngx_stream_fproxy_response(s, NGX_STREAM_BAD_REQUEST);
}


static void
ngx_stream_fproxy_http_request_line(ngx_event_t *ev)
{
    ngx_connection_t                *c;
    ngx_stream_session_t            *s;
    ngx_stream_upstream_t           *u;
    ngx_buf_t                       *b;
    ngx_stream_fproxy_ctx_t         *ctx;
    ngx_stream_fproxy_srv_conf_t    *fscf;
    u_char                          *line_end;
    ngx_int_t                        ret;
    ssize_t                          n;

    c = ev->data;
    s = c->data;
    u = s->upstream;
    b = &u->downstream_buf;

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "stream fproxy process http request line");

    if (ev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT,
                      "waiting request line timed out");
        return ngx_stream_fproxy_finalize(s, NGX_STREAM_OK);
    }

    if (c->close) {
        return ngx_stream_fproxy_finalize(s, NGX_STREAM_OK);
    }

    while (1) {
        line_end = ngx_strnstr(b->start, "\r\n", b->last - b->start);

        /* already received the whole request line */
        if (line_end) {
            break;
        }

        c->log->action = "reading http request line";
        n = ngx_stream_fproxy_recv_from_client(ev);

        if (n == NGX_AGAIN) {
            ev->handler = ngx_stream_fproxy_http_request_line;
            if (ngx_handle_read_event(ev, 0) != NGX_OK) {
                return ngx_stream_fproxy_response(s,
                            NGX_STREAM_INTERNAL_SERVER_ERROR);
            }
            return;
        }

        if (n == NGX_ERROR) {
            return ngx_stream_fproxy_response(s, NGX_STREAM_BAD_REQUEST);
        } 

        if (n == 0) {
            return ngx_stream_fproxy_finalize(s, NGX_STREAM_OK);
        }
    }

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_fproxy_module);
    fscf = ngx_stream_get_module_srv_conf(s, ngx_stream_fproxy_module);
    c->log->action = "parsing http request line";

    ret = ngx_stream_fproxy_parse_request_line(s, b->start, line_end);
    if (ret == NGX_ERROR) {
        return ngx_stream_fproxy_response(s, NGX_STREAM_BAD_REQUEST);
    }

    if (!(fscf->auth_methods & NGX_STREAM_FPROXY_AUTH_BASIC) &&
        ctx->resolved.host.data) {
        /* No need to parse headers, start to resolve host */
        ngx_stream_fproxy_resolve(s);

    } else {
        ctx->state = NGX_STREAM_FPROXY_STATE_HTTP_REQUEST_HEADERS;
        ctx->pos = line_end + 2;    /* move to the start of next line */
        ngx_stream_fproxy_http_request_headers(ev);
    }

    return;
}


static void
ngx_stream_fproxy_http_request_headers(ngx_event_t *ev)
{
    ngx_connection_t                *c;
    ngx_stream_session_t            *s;
    ngx_stream_upstream_t           *u;
    ngx_buf_t                       *b;
    ngx_stream_fproxy_ctx_t         *ctx;
    ngx_stream_fproxy_srv_conf_t    *fscf;
    u_char                          *line_end;
    u_char                          *p;
    ngx_int_t                        ret;
    ngx_int_t                        search_host;
    ngx_int_t                        search_cred;
    ngx_str_t                        auth;
    ngx_str_t                        uname;
    ngx_str_t                        pw;
    ssize_t                          n;

    c = ev->data;
    s = c->data;
    u = s->upstream;
    b = &u->downstream_buf;

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "stream fproxy process http request headers");

    if (ev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT,
                      "waiting request headers timed out");
        return ngx_stream_fproxy_finalize(s, NGX_STREAM_OK);
    }

    if (c->close) {
        return ngx_stream_fproxy_finalize(s, NGX_STREAM_OK);
    }

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_fproxy_module);
    fscf = ngx_stream_get_module_srv_conf(s, ngx_stream_fproxy_module);

    search_host = !ctx->resolved.host.data;
    search_cred = !ctx->cred.data &&
                  (fscf->auth_methods & NGX_STREAM_FPROXY_AUTH_BASIC);

    while (1) {
        if (b->last - ctx->pos >= 2 &&
            *ctx->pos == '\r' && *(ctx->pos+1) == '\n') {
            break;
        }

        line_end = ngx_strnstr(ctx->pos, "\r\n", b->last - ctx->pos);

        if (line_end) {
            c->log->action = "parsing http request headers";

            p = ctx->pos;
            ctx->pos = line_end + 2;    /* move to the start of next line */

            for (; *p == ' '; p++) {}   /* skip spaces */

            if (search_host && (line_end - p > 5) &&
                !ngx_strncasecmp(p, (u_char *)"Host:", 5)) {
                search_host = 0;

                for (p = p + 5; *p == ' '; p++) {}  /* skip spaces */

                if (p >= line_end) {
                    goto bad;
                }
                ret = ngx_stream_fproxy_parse_url(s, p, line_end);

                if (ret == NGX_ERROR) {
                    goto bad;
                }

                if (search_cred) {
                    continue;   /* continue searching credential */

                } else {
                    break;      /* over */
                }
            }

            if (search_cred && (line_end - p > 20) &&
                !ngx_strncasecmp(p, (u_char *)"Proxy-Authorization:", 20)) {
                search_cred = 0;

                for (p = p + 20; *p == ' '; p++) {}  /* skip spaces */

                if (line_end - p < 7 ||
                    ngx_strncasecmp(p, (u_char *)"Basic ", 6)) {
                    goto forbid;
                }

                for (p = p + 6; *p == ' '; p++) {}  /* skip spaces */

                if (p < line_end) {
                    ctx->cred.data = p;
                    for (; *p != ' ' && *p != CR; p++) {}
                    ctx->cred.len = p - ctx->cred.data;

                } else {
                    goto forbid;
                }

                if (search_host) {
                    continue;   /* continue searching host */

                } else {
                    break;      /* over */
                }
            }

        } else {
            c->log->action = "reading http request headers";
            n = ngx_stream_fproxy_recv_from_client(ev);

            if (n == NGX_AGAIN) {
                ev->handler = ngx_stream_fproxy_http_request_headers;
                if (ngx_handle_read_event(ev, 0) != NGX_OK) {
                    goto err;
                }
                return;
            }

            if (n == NGX_ERROR) {
                goto bad;
            } 

            if (n == 0) {
                return ngx_stream_fproxy_finalize(s, NGX_STREAM_OK);
            }
        }
    }

    if (!ctx->resolved.host.data) {
        goto bad;
    }

    /* do authentication as necessary */
    if (fscf->auth_methods & NGX_STREAM_FPROXY_AUTH_BASIC) {
        if (!ctx->cred.data) {
            goto forbid;
        }

        auth.len = ngx_base64_decoded_length(ctx->cred.len);
        auth.data = ngx_pnalloc(c->pool, auth.len + 1);
        if (auth.data == NULL) {
            goto err;
        }

        if (ngx_decode_base64(&auth, &ctx->cred) != NGX_OK) {
            goto forbid;
        }

        auth.data[auth.len] = '\0';

        p = ngx_strlchr(auth.data, auth.data + auth.len, ':');
        if (p == NULL || p == auth.data) {
            goto forbid;
        }

        uname.data = auth.data;
        uname.len = p - auth.data;
        pw.data = p + 1;
        pw.len = auth.len - uname.len - 1;

        if (ngx_stream_fproxy_basic_auth(&fscf->userpw_hash, &uname, &pw)
            != NGX_OK) {
            goto forbid;
        }
    }

    return ngx_stream_fproxy_resolve(s);

forbid:
    return ngx_stream_fproxy_response(s, NGX_STREAM_FORBIDDEN);
bad:
    return ngx_stream_fproxy_response(s, NGX_STREAM_BAD_REQUEST);
err:
    return ngx_stream_fproxy_response(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
}


static ngx_int_t
ngx_stream_fproxy_basic_auth(ngx_hash_t *hash, ngx_str_t *uname, ngx_str_t *pw)
{
    ngx_str_t       *expected_pw;
    ngx_uint_t       key;

   key = ngx_hash_key(uname->data, uname->len);
   expected_pw = ngx_hash_find(hash, key, uname->data, uname->len);

   if (!expected_pw || expected_pw->len != pw->len ||
       ngx_strncmp(expected_pw->data, pw->data, pw->len)) {
       return NGX_DECLINED;
   }

   return NGX_OK;
}


static ngx_int_t
ngx_stream_fproxy_parse_url(ngx_stream_session_t *s, u_char *b, u_char *e)
{
    ngx_stream_fproxy_ctx_t         *ctx;
    ngx_str_t                        host;
    ngx_url_t                        url;
    ngx_stream_upstream_resolved_t  *resolved;

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_fproxy_module);

    host.data = b;
    host.len = e - b;

    ngx_memzero(&url, sizeof(ngx_url_t));

    url.url = host;
    url.no_resolve = 1;

    if (ngx_parse_url(s->connection->pool, &url) != NGX_OK) {
        if (url.err) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                          "%s in url \"%V\"", url.err, &url.url);
        }

        return NGX_ERROR;
    }

    resolved = &ctx->resolved;

    if (url.addrs) {
        resolved->sockaddr = url.addrs[0].sockaddr;
        resolved->socklen = url.addrs[0].socklen;
        resolved->name = url.addrs[0].name;
        resolved->naddrs = 1;
    }

    resolved->host = url.host;
    resolved->port = url.port;
    resolved->no_port = 0;

    if (url.no_port) {      /* default port */
        if (ctx->type == NGX_STREAM_FPROXY_TYPE_HTTP) {
            resolved->port = 80;
        } else if (ctx->type == NGX_STREAM_FPROXY_TYPE_HTTPS) {
            resolved->port = 443;
        }
    }
   
    return NGX_OK;
}


/* modified from ngx_http_parse_request_line in src/http/ngx_http_parse.c */
static ngx_int_t
ngx_stream_fproxy_parse_request_line(ngx_stream_session_t *s, u_char *b,
                                     u_char *e)
{
    u_char  c, ch, *p;
    ngx_stream_fproxy_ctx_t         *ctx;
    u_char                          *host = NULL;
    u_char                          *host_port_end = NULL;
    ngx_int_t                        ret;

    enum {
        sw_start = 0,
        sw_spaces_before_uri,
        sw_scheme,
        sw_host_start,
        sw_host,
        sw_host_end,
        sw_host_ip_literal,
        sw_port,
        sw_done
    } state;

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_fproxy_module);

    state = sw_start;

    /* we only care about the scheme/host/port, so we didn't check other parts.
     * leave for the upstream to do it :) */
    for (p = b; p < e; p++) {
        ch = *p;

        switch (state) {
        case sw_start:  /* we already checked method, skip directly */
            if (ch == ' ') {
                state = sw_spaces_before_uri;
            }
            break;

        case sw_spaces_before_uri:
            if (ch == '/') {
                state = sw_done;
                break;
            }

            switch (ch) {
            case ' ':
                break;
            default:
                p--;
                state = sw_scheme;
                break;
            }
            break;

        case sw_scheme:
            state = sw_host_start;

            if (e > p + 7 && !ngx_strncmp(p, "http://", 7)) {
                if (ctx->type != NGX_STREAM_FPROXY_TYPE_HTTP) {
                    return NGX_ERROR;
                }
                p += 6;
                break;

            } else if (e > p + 8 && !ngx_strncmp(p, "https://", 8)) {
                if (ctx->type != NGX_STREAM_FPROXY_TYPE_HTTPS) {
                    return NGX_ERROR;
                }
                p += 7;
                break;
            }

            /* fall through */

        case sw_host_start:
            host = p;
            if (ch == '[') {
                state = sw_host_ip_literal;
                break;
            }

            state = sw_host;

            /* fall through */

        case sw_host:
            c = (u_char) (ch | 0x20);
            if (c >= 'a' && c <= 'z') {
                break;
            }

            if ((ch >= '0' && ch <= '9') || ch == '.' || ch == '-') {
                break;
            }

            /* fall through */

        case sw_host_end:
            switch (ch) {
            case ':':
                state = sw_port;
                break;
            case '/':
            case '?':
            case ' ':
            case CR:    /* add CR to facilitate parsing of the host header */
                host_port_end = p;
                state = sw_done;
                break;
            default:
                return NGX_ERROR;
            }
            break;

        case sw_host_ip_literal:
            if (ch >= '0' && ch <= '9') {
                break;
            }

            c = (u_char) (ch | 0x20);
            if (c >= 'a' && c <= 'z') {
                break;
            }

            switch (ch) {
            case ':':
                break;
            case ']':
                state = sw_host_end;
                break;
            case '-':
            case '.':
            case '_':
            case '~':
                /* unreserved */
                break;
            case '!':
            case '$':
            case '&':
            case '\'':
            case '(':
            case ')':
            case '*':
            case '+':
            case ',':
            case ';':
            case '=':
                /* sub-delims */
                break;
            default:
                return NGX_ERROR;
            }
            break;

        case sw_port:
            if (ch >= '0' && ch <= '9') {
                break;
            }

            switch (ch) {
            case '/':
                host_port_end = p;
                state = sw_done;
                break;
            case '?':
                host_port_end = p;
                state = sw_done;
                break;
            case ' ':
            case CR:    /* add CR to facilitate parsing of the host header */
                host_port_end = p;
                state = sw_done;
                break;
            default:
                return NGX_ERROR;
            }
            break;

        case sw_done:
            goto done;
            break;
        }
    }

    return NGX_ERROR;

done:
    if (host) {
        if (host == host_port_end) {
            return NGX_ERROR;
        }

        ret = ngx_stream_fproxy_parse_url(s, host, host_port_end);
        if (ret == NGX_ERROR) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static void
ngx_stream_fproxy_resolve(ngx_stream_session_t *s)
{
    ngx_str_t                        *host;
    ngx_connection_t                 *c;
    ngx_resolver_ctx_t               *ctx, temp;
    ngx_stream_upstream_t            *u;
    ngx_stream_core_srv_conf_t       *cscf;
    ngx_stream_fproxy_srv_conf_t     *fscf;
    ngx_stream_fproxy_ctx_t          *fctx;

    c = s->connection;
    u = s->upstream;

    fscf = ngx_stream_get_module_srv_conf(s, ngx_stream_fproxy_module);
    fctx = ngx_stream_get_module_ctx(s, ngx_stream_fproxy_module);

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "fproxy resolve the upstream host");

    fctx->state = fctx->type == NGX_STREAM_FPROXY_TYPE_SOCKS5 ?
                  NGX_STREAM_FPROXY_STATE_SOCKS5_RESOLVING :
                  NGX_STREAM_FPROXY_STATE_HTTP_RESOLVING;

    u->requests = 1;

    u->peer.log = c->log;
    u->peer.log_error = NGX_ERROR_ERR;

    if (ngx_stream_fproxy_set_local(s, u, fscf->local) != NGX_OK) {
        goto err;
    }

    if (fscf->socket_keepalive) {
        u->peer.so_keepalive = 1;
    }

    u->peer.type = c->type;
    u->start_sec = ngx_time();

    c->read->handler = ngx_stream_fproxy_downstream_handler;

    s->upstream_states = ngx_array_create(c->pool, 1,
                                          sizeof(ngx_stream_upstream_state_t));
    if (s->upstream_states == NULL) {
        goto err;
    }

    if (c->read->ready) {
        ngx_post_event(c->read, &ngx_posted_events);
    }

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    u->resolved = &fctx->resolved;
    
    if (fctx->resolved.sockaddr) {
        if (ngx_stream_upstream_create_round_robin_peer(s, u->resolved)
            != NGX_OK) {
            goto err;
        }

        ngx_stream_fproxy_connect(s);
        return;
    }

    host = &u->resolved->host;
    temp.name = *host;

    cscf = ngx_stream_get_module_srv_conf(s, ngx_stream_core_module);

    ctx = ngx_resolve_start(cscf->resolver, &temp);
    if (ctx == NULL) {
        goto err;
    }

    if (ctx == NGX_NO_RESOLVER) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                      "no resolver defined to resolve %V", host);
        goto err;
    }

    ctx->name = *host;
    ctx->handler = ngx_stream_fproxy_resolve_handler;
    ctx->data = s;
    ctx->timeout = cscf->resolver_timeout;

    u->resolved->ctx = ctx;

    if (ngx_resolve_name(ctx) != NGX_OK) {
        u->resolved->ctx = NULL;
        goto err;
    }

    return;

err:
    return ngx_stream_fproxy_response(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
}


static ngx_int_t
ngx_stream_fproxy_set_local(ngx_stream_session_t *s, ngx_stream_upstream_t *u,
    ngx_stream_upstream_local_t *local)
{
    ngx_int_t    rc;
    ngx_str_t    val;
    ngx_addr_t  *addr;

    if (local == NULL) {
        u->peer.local = NULL;
        return NGX_OK;
    }

#if (NGX_HAVE_TRANSPARENT_PROXY)
    u->peer.transparent = local->transparent;
#endif

    if (local->value == NULL) {
        u->peer.local = local->addr;
        return NGX_OK;
    }

    if (ngx_stream_complex_value(s, local->value, &val) != NGX_OK) {
        return NGX_ERROR;
    }

    if (val.len == 0) {
        return NGX_OK;
    }

    addr = ngx_palloc(s->connection->pool, sizeof(ngx_addr_t));
    if (addr == NULL) {
        return NGX_ERROR;
    }

    rc = ngx_parse_addr_port(s->connection->pool, addr, val.data, val.len);
    if (rc == NGX_ERROR) {
        return NGX_ERROR;
    }

    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "invalid local address \"%V\"", &val);
        return NGX_OK;
    }

    addr->name = val;
    u->peer.local = addr;

    return NGX_OK;
}


static void
ngx_stream_fproxy_connect(ngx_stream_session_t *s)
{
    ngx_int_t                     rc;
    ngx_connection_t             *c, *pc;
    ngx_stream_upstream_t        *u;
    ngx_stream_fproxy_srv_conf_t  *fscf;

    c = s->connection;

    c->log->action = "connecting to upstream";

    fscf = ngx_stream_get_module_srv_conf(s, ngx_stream_fproxy_module);

    u = s->upstream;

    u->connected = 0;

    if (u->state) {
        u->state->response_time = ngx_current_msec - u->start_time;
    }

    u->state = ngx_array_push(s->upstream_states);
    if (u->state == NULL) {
        ngx_stream_fproxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    ngx_memzero(u->state, sizeof(ngx_stream_upstream_state_t));

    u->start_time = ngx_current_msec;

    u->state->connect_time = (ngx_msec_t) -1;
    u->state->first_byte_time = (ngx_msec_t) -1;
    u->state->response_time = (ngx_msec_t) -1;

    rc = ngx_event_connect_peer(&u->peer);

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0, "proxy connect: %i", rc);

    if (rc == NGX_ERROR) {
        ngx_stream_fproxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    u->state->peer = u->peer.name;

    if (rc == NGX_BUSY) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "no live upstreams");
        ngx_stream_fproxy_finalize(s, NGX_STREAM_BAD_GATEWAY);
        return;
    }

    if (rc == NGX_DECLINED) {
        ngx_stream_fproxy_next_upstream(s);
        return;
    }

    /* rc == NGX_OK || rc == NGX_AGAIN || rc == NGX_DONE */

    pc = u->peer.connection;

    pc->data = s;
    pc->log = c->log;
    pc->pool = c->pool;
    pc->read->log = c->log;
    pc->write->log = c->log;

    if (rc != NGX_AGAIN) {
        ngx_stream_fproxy_init_upstream(s);
        return;
    }

    pc->read->handler = ngx_stream_fproxy_connect_handler;
    pc->write->handler = ngx_stream_fproxy_connect_handler;

    ngx_add_timer(pc->write, fscf->connect_timeout);
}


static void
ngx_stream_fproxy_init_upstream(ngx_stream_session_t *s)
{
    u_char                       *p;
    ngx_chain_t                  *cl;
    ngx_connection_t             *c, *pc;
    ngx_log_handler_pt            handler;
    ngx_stream_upstream_t        *u;
    ngx_stream_core_srv_conf_t   *cscf;
    ngx_stream_fproxy_srv_conf_t  *fscf;
    ngx_stream_fproxy_ctx_t       *ctx;

    u = s->upstream;
    pc = u->peer.connection;

    cscf = ngx_stream_get_module_srv_conf(s, ngx_stream_core_module);

    if (pc->type == SOCK_STREAM
        && cscf->tcp_nodelay
        && ngx_tcp_nodelay(pc) != NGX_OK)
    {
        ngx_stream_fproxy_next_upstream(s);
        return;
    }

    fscf = ngx_stream_get_module_srv_conf(s, ngx_stream_fproxy_module);
    ctx = ngx_stream_get_module_ctx(s, ngx_stream_fproxy_module);


    c = s->connection;

    if (c->log->log_level >= NGX_LOG_INFO) {
        ngx_str_t  str;
        u_char     addr[NGX_SOCKADDR_STRLEN];

        str.len = NGX_SOCKADDR_STRLEN;
        str.data = addr;

        if (ngx_connection_local_sockaddr(pc, &str, 1) == NGX_OK) {
            handler = c->log->handler;
            c->log->handler = NULL;

            ngx_log_error(NGX_LOG_INFO, c->log, 0,
                          "%sproxy %V connected to %V",
                          pc->type == SOCK_DGRAM ? "udp " : "",
                          &str, u->peer.name);

            c->log->handler = handler;
        }
    }

    u->state->connect_time = ngx_current_msec - u->start_time;

    if (u->peer.notify) {
        u->peer.notify(&u->peer, u->peer.data,
                       NGX_STREAM_UPSTREAM_NOTIFY_CONNECT);
    }

    if (u->upstream_buf.start == NULL) {
        p = ngx_pnalloc(c->pool, fscf->buffer_size);
        if (p == NULL) {
            ngx_stream_fproxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        u->upstream_buf.start = p;
        u->upstream_buf.end = p + fscf->buffer_size;
        u->upstream_buf.pos = p;
        u->upstream_buf.last = p;
    }

    if (ctx->type == NGX_STREAM_FPROXY_TYPE_HTTP) {
        ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                       "stream fproxy add previosly read data: %uz",
                       u->downstream_buf.last - u->downstream_buf.start);
        cl = ngx_chain_get_free_buf(c->pool, &u->free);
        if (cl == NULL) {
            ngx_stream_fproxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        cl->buf->pos = u->downstream_buf.start;
        cl->buf->last = u->downstream_buf.last;
        cl->buf->temporary = 1;
        cl->buf->flush = 1;
        cl->buf->last_buf = 0;
        cl->buf->tag = (ngx_buf_tag_t) &ngx_stream_fproxy_module;

        cl->next = u->upstream_out;
        u->upstream_out = cl;

    } else {
        /* otherwise, clear the buffer */
        u->upstream_buf.last = u->upstream_buf.start;
    }

    u->upload_rate = ngx_stream_complex_value_size(s, fscf->upload_rate, 0);
    u->download_rate = ngx_stream_complex_value_size(s, fscf->download_rate, 0);

    u->connected = 1;

    pc->read->handler = ngx_stream_fproxy_upstream_handler;
    pc->write->handler = ngx_stream_fproxy_upstream_handler;

    if (pc->read->ready) {
        ngx_post_event(pc->read, &ngx_posted_events);
    }

    switch (ctx->type) {
    case NGX_STREAM_FPROXY_TYPE_HTTP:
        ctx->state = NGX_STREAM_FPROXY_STATE_HTTP_PROXYING;
        c->write->handler = ngx_stream_fproxy_downstream_handler;
        return ngx_stream_fproxy_process(s, 0, 1);
        break;
    default:
        break;
    }

    return ngx_stream_fproxy_response(s, NGX_STREAM_OK);
}


static void
ngx_stream_fproxy_downstream_handler(ngx_event_t *ev)
{
    ngx_stream_fproxy_process_connection(ev, ev->write);
}


static void
ngx_stream_fproxy_resolve_handler(ngx_resolver_ctx_t *ctx)
{
    ngx_stream_session_t            *s;
    ngx_stream_upstream_t           *u;
    ngx_stream_fproxy_srv_conf_t     *fscf;
    ngx_stream_upstream_resolved_t  *ur;

    s = ctx->data;

    u = s->upstream;
    ur = u->resolved;

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "stream upstream resolve");

    if (ctx->state) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "%V could not be resolved (%i: %s)",
                      &ctx->name, ctx->state,
                      ngx_resolver_strerror(ctx->state));

        ngx_stream_fproxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    ur->naddrs = ctx->naddrs;
    ur->addrs = ctx->addrs;

#if (NGX_DEBUG)
    {
    u_char      text[NGX_SOCKADDR_STRLEN];
    ngx_str_t   addr;
    ngx_uint_t  i;

    addr.data = text;

    for (i = 0; i < ctx->naddrs; i++) {
        addr.len = ngx_sock_ntop(ur->addrs[i].sockaddr, ur->addrs[i].socklen,
                                 text, NGX_SOCKADDR_STRLEN, 0);

        ngx_log_debug1(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                       "name was resolved to %V", &addr);
    }
    }
#endif

    if (ngx_stream_upstream_create_round_robin_peer(s, ur) != NGX_OK) {
        ngx_stream_fproxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    ngx_resolve_name_done(ctx);
    ur->ctx = NULL;

    u->peer.start_time = ngx_current_msec;

    fscf = ngx_stream_get_module_srv_conf(s, ngx_stream_fproxy_module);

    if (fscf->next_upstream_tries
        && u->peer.tries > fscf->next_upstream_tries)
    {
        u->peer.tries = fscf->next_upstream_tries;
    }

    ngx_stream_fproxy_connect(s);
}


static void
ngx_stream_fproxy_upstream_handler(ngx_event_t *ev)
{
    ngx_stream_fproxy_process_connection(ev, !ev->write);
}


static void
ngx_stream_fproxy_process_connection(ngx_event_t *ev, ngx_uint_t from_upstream)
{
    ngx_connection_t             *c, *pc;
    ngx_stream_session_t         *s;
    ngx_stream_upstream_t        *u;
    ngx_stream_fproxy_srv_conf_t  *fscf;

    c = ev->data;
    s = c->data;
    u = s->upstream;

    if (c->close) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0, "shutdown timeout");
        ngx_stream_fproxy_finalize(s, NGX_STREAM_OK);
        return;
    }

    c = s->connection;
    pc = u->peer.connection;

    fscf = ngx_stream_get_module_srv_conf(s, ngx_stream_fproxy_module);

    if (ev->timedout) {
        ev->timedout = 0;

        if (ev->delayed) {
            ev->delayed = 0;

            if (!ev->ready) {
                if (ngx_handle_read_event(ev, 0) != NGX_OK) {
                    ngx_stream_fproxy_finalize(s,
                                              NGX_STREAM_INTERNAL_SERVER_ERROR);
                    return;
                }

                if (u->connected && !c->read->delayed && !pc->read->delayed) {
                    ngx_add_timer(c->write, fscf->timeout);
                }

                return;
            }

        } else {
            ngx_connection_error(c, NGX_ETIMEDOUT, "connection timed out");

            ngx_stream_fproxy_finalize(s, NGX_STREAM_OK);

            return;
        }

    } else if (ev->delayed) {

        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                       "stream connection delayed");

        if (ngx_handle_read_event(ev, 0) != NGX_OK) {
            ngx_stream_fproxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        }

        return;
    }

    if (from_upstream && !u->connected) {
        return;
    }

    ngx_stream_fproxy_process(s, from_upstream, ev->write);
}


static void
ngx_stream_fproxy_connect_handler(ngx_event_t *ev)
{
    ngx_connection_t      *c;
    ngx_stream_session_t  *s;

    c = ev->data;
    s = c->data;

    if (ev->timedout) {
        ngx_log_error(NGX_LOG_ERR, c->log, NGX_ETIMEDOUT, "upstream timed out");
        ngx_stream_fproxy_next_upstream(s);
        return;
    }

    ngx_del_timer(c->write);

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "stream fproxy connect upstream");

    if (ngx_stream_fproxy_test_connect(c) != NGX_OK) {
        ngx_stream_fproxy_next_upstream(s);
        return;
    }

    ngx_stream_fproxy_init_upstream(s);
}


static ngx_int_t
ngx_stream_fproxy_test_connect(ngx_connection_t *c)
{
    int        err;
    socklen_t  len;

#if (NGX_HAVE_KQUEUE)

    if (ngx_event_flags & NGX_USE_KQUEUE_EVENT)  {
        err = c->write->kq_errno ? c->write->kq_errno : c->read->kq_errno;

        if (err) {
            (void) ngx_connection_error(c, err,
                                    "kevent() reported that connect() failed");
            return NGX_ERROR;
        }

    } else
#endif
    {
        err = 0;
        len = sizeof(int);

        /*
         * BSDs and Linux return 0 and set a pending error in err
         * Solaris returns -1 and sets errno
         */

        if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, (void *) &err, &len)
            == -1)
        {
            err = ngx_socket_errno;
        }

        if (err) {
            (void) ngx_connection_error(c, err, "connect() failed");
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static void
ngx_stream_fproxy_process(ngx_stream_session_t *s, ngx_uint_t from_upstream,
    ngx_uint_t do_write)
{
    char                         *recv_action, *send_action;
    off_t                        *received, limit;
    size_t                        size, limit_rate;
    ssize_t                       n;
    ngx_buf_t                    *b;
    ngx_int_t                     rc;
    ngx_uint_t                    flags, *packets;
    ngx_msec_t                    delay;
    ngx_chain_t                  *cl, **ll, **out, **busy;
    ngx_connection_t             *c, *pc, *src, *dst;
    ngx_stream_upstream_t        *u;
    ngx_stream_fproxy_srv_conf_t  *fscf;

    u = s->upstream;

    c = s->connection;
    pc = u->connected ? u->peer.connection : NULL;

    fscf = ngx_stream_get_module_srv_conf(s, ngx_stream_fproxy_module);

    if (from_upstream) {
        src = pc;
        dst = c;
        b = &u->upstream_buf;
        limit_rate = u->download_rate;
        received = &u->received;
        packets = &u->responses;
        out = &u->downstream_out;
        busy = &u->downstream_busy;
        recv_action = "fproxying and reading from upstream";
        send_action = "fproxying and sending to client";

    } else {
        src = c;
        dst = pc;
        b = &u->downstream_buf;
        limit_rate = u->upload_rate;
        received = &s->received;
        packets = &u->requests;
        out = &u->upstream_out;
        busy = &u->upstream_busy;
        recv_action = "fproxying and reading from client";
        send_action = "fproxying and sending to upstream";
    }

    for ( ;; ) {

        if (do_write && dst) {

            if (*out || *busy || dst->buffered) {
                c->log->action = send_action;

                rc = ngx_stream_top_filter(s, *out, from_upstream);

                if (rc == NGX_ERROR) {
                    ngx_stream_fproxy_finalize(s, NGX_STREAM_OK);
                    return;
                }

                ngx_chain_update_chains(c->pool, &u->free, busy, out,
                                      (ngx_buf_tag_t) &ngx_stream_fproxy_module);

                if (*busy == NULL) {
                    b->pos = b->start;
                    b->last = b->start;
                }
            }
        }

        size = b->end - b->last;

        if (size && src->read->ready && !src->read->delayed) {

            if (limit_rate) {
                limit = (off_t) limit_rate * (ngx_time() - u->start_sec + 1)
                        - *received;

                if (limit <= 0) {
                    src->read->delayed = 1;
                    delay = (ngx_msec_t) (- limit * 1000 / limit_rate + 1);
                    ngx_add_timer(src->read, delay);
                    break;
                }

                if (c->type == SOCK_STREAM && (off_t) size > limit) {
                    size = (size_t) limit;
                }
            }

            c->log->action = recv_action;

            n = src->recv(src, b->last, size);

            if (n == NGX_AGAIN) {
                break;
            }

            if (n == NGX_ERROR) {
                src->read->eof = 1;
                n = 0;
            }

            if (n >= 0) {
                if (limit_rate) {
                    delay = (ngx_msec_t) (n * 1000 / limit_rate);

                    if (delay > 0) {
                        src->read->delayed = 1;
                        ngx_add_timer(src->read, delay);
                    }
                }

                if (from_upstream) {
                    if (u->state->first_byte_time == (ngx_msec_t) -1) {
                        u->state->first_byte_time = ngx_current_msec
                                                    - u->start_time;
                    }
                }

                for (ll = out; *ll; ll = &(*ll)->next) { /* void */ }

                cl = ngx_chain_get_free_buf(c->pool, &u->free);
                if (cl == NULL) {
                    ngx_stream_fproxy_finalize(s,
                                              NGX_STREAM_INTERNAL_SERVER_ERROR);
                    return;
                }

                *ll = cl;

                cl->buf->pos = b->last;
                cl->buf->last = b->last + n;
                cl->buf->tag = (ngx_buf_tag_t) &ngx_stream_fproxy_module;

                cl->buf->temporary = (n ? 1 : 0);
                cl->buf->last_buf = src->read->eof;
                cl->buf->flush = !src->read->eof;

                (*packets)++;
                *received += n;
                b->last += n;
                do_write = 1;

                continue;
            }
        }

        break;
    }

    c->log->action = "fproxying connection";

    if (ngx_stream_fproxy_test_finalize(s, from_upstream) == NGX_OK) {
        return;
    }

    flags = src->read->eof ? NGX_CLOSE_EVENT : 0;

    if (ngx_handle_read_event(src->read, flags) != NGX_OK) {
        ngx_stream_fproxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    if (dst) {

        if (dst->type == SOCK_STREAM && fscf->half_close
            && src->read->eof && !u->half_closed && !dst->buffered)
        {
            if (ngx_shutdown_socket(dst->fd, NGX_WRITE_SHUTDOWN) == -1) {
                ngx_connection_error(c, ngx_socket_errno,
                                     ngx_shutdown_socket_n " failed");

                ngx_stream_fproxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
                return;
            }

            u->half_closed = 1;
            ngx_log_debug1(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                           "stream fproxy %s socket shutdown",
                           from_upstream ? "client" : "upstream");
        }

        if (ngx_handle_write_event(dst->write, 0) != NGX_OK) {
            ngx_stream_fproxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        if (!c->read->delayed && !pc->read->delayed) {
            ngx_add_timer(c->write, fscf->timeout);

        } else if (c->write->timer_set) {
            ngx_del_timer(c->write);
        }
    }
}


static ngx_int_t
ngx_stream_fproxy_test_finalize(ngx_stream_session_t *s,
    ngx_uint_t from_upstream)
{
    ngx_connection_t             *c, *pc;
    ngx_log_handler_pt            handler;
    ngx_stream_upstream_t        *u;
    ngx_stream_fproxy_srv_conf_t  *fscf;

    fscf = ngx_stream_get_module_srv_conf(s, ngx_stream_fproxy_module);

    c = s->connection;
    u = s->upstream;
    pc = u->connected ? u->peer.connection : NULL;

    /* c->type == SOCK_STREAM */

    if (pc == NULL
        || (!c->read->eof && !pc->read->eof)
        || (!c->read->eof && c->buffered)
        || (!pc->read->eof && pc->buffered))
    {
        return NGX_DECLINED;
    }

    if (fscf->half_close) {
        /* avoid closing live connections until both read ends get EOF */
        if (!(c->read->eof && pc->read->eof && !c->buffered && !pc->buffered)) {
             return NGX_DECLINED;
        }
    }

    handler = c->log->handler;
    c->log->handler = NULL;

    ngx_log_error(NGX_LOG_INFO, c->log, 0,
                  "%s disconnected"
                  ", bytes from/to client:%O/%O"
                  ", bytes from/to upstream:%O/%O",
                  from_upstream ? "upstream" : "client",
                  s->received, c->sent, u->received, pc ? pc->sent : 0);

    c->log->handler = handler;

    ngx_stream_fproxy_finalize(s, NGX_STREAM_OK);

    return NGX_OK;
}


static void
ngx_stream_fproxy_next_upstream(ngx_stream_session_t *s)
{
    ngx_msec_t                    timeout;
    ngx_connection_t             *pc;
    ngx_stream_upstream_t        *u;
    ngx_stream_fproxy_srv_conf_t  *fscf;

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "stream proxy next upstream");

    u = s->upstream;
    pc = u->peer.connection;

    if (pc && pc->buffered) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "buffered data on next upstream");
        ngx_stream_fproxy_response(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    if (u->peer.sockaddr) {
        u->peer.free(&u->peer, u->peer.data, NGX_PEER_FAILED);
        u->peer.sockaddr = NULL;
    }

    fscf = ngx_stream_get_module_srv_conf(s, ngx_stream_fproxy_module);

    timeout = fscf->next_upstream_timeout;

    if (u->peer.tries == 0
        || !fscf->next_upstream
        || (timeout && ngx_current_msec - u->peer.start_time >= timeout))
    {
        ngx_stream_fproxy_response(s, NGX_STREAM_BAD_GATEWAY);
        return;
    }

    if (pc) {
        ngx_log_debug1(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                       "close proxy upstream connection: %d", pc->fd);


        u->state->bytes_received = u->received;
        u->state->bytes_sent = pc->sent;

        ngx_close_connection(pc);
        u->peer.connection = NULL;
    }

    ngx_stream_fproxy_connect(s);
}


static void
ngx_stream_fproxy_finalize(ngx_stream_session_t *s, ngx_uint_t rc)
{
    ngx_uint_t              state;
    ngx_connection_t       *pc;
    ngx_stream_upstream_t  *u;

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "finalize stream fproxy: %i", rc);

    u = s->upstream;

    if (u == NULL) {
        goto noupstream;
    }

    if (u->resolved && u->resolved->ctx) {
        ngx_resolve_name_done(u->resolved->ctx);
        u->resolved->ctx = NULL;
    }

    pc = u->peer.connection;

    if (u->state) {
        if (u->state->response_time == (ngx_msec_t) -1) {
            u->state->response_time = ngx_current_msec - u->start_time;
        }

        if (pc) {
            u->state->bytes_received = u->received;
            u->state->bytes_sent = pc->sent;
        }
    }

    if (u->peer.free && u->peer.sockaddr) {
        state = 0;

        u->peer.free(&u->peer, u->peer.data, state);
        u->peer.sockaddr = NULL;
    }

    if (pc) {
        ngx_log_debug1(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                       "close stream fproxy upstream connection: %d", pc->fd);

        ngx_close_connection(pc);
        u->peer.connection = NULL;
    }

noupstream:

    ngx_stream_finalize_session(s, rc);
}


static void
ngx_stream_fproxy_response(ngx_stream_session_t *s, ngx_uint_t rc)
{
    ngx_stream_fproxy_ctx_t         *ctx;
    ngx_connection_t                *c;
    ssize_t                          n;
    ngx_stream_fproxy_srv_conf_t    *fscf;
    ngx_str_t                       *res;

    c = s->connection;

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "send response to client");
    c->log->action = "sending response to client";

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_fproxy_module);

    res = &ctx->res;

    if (ctx->type == NGX_STREAM_FPROXY_TYPE_SOCKS5) {
        if (rc == NGX_STREAM_OK) {
            ctx->state = NGX_STREAM_FPROXY_STATE_SOCKS5_REPLY;
        } else if (rc == NGX_STREAM_METHOD_ACCEPTED) {
            ctx->state = NGX_STREAM_FPROXY_STATE_SOCKS5_METHOD_ACCEPTED;
        } else if (rc == NGX_STREAM_AUTH_OK) {
            ctx->state = NGX_STREAM_FPROXY_STATE_SOCKS5_AUTH_RESPONSE;
        } else {
            ctx->state = NGX_STREAM_FPROXY_STATE_SOCKS5_FAIL_REPLY;
        }

        switch (rc) {
        case NGX_STREAM_INTERNAL_SERVER_ERROR:
            res->data[1] = NGX_STREAM_FPROXY_SOCKS5_REPLY_SERVER_FAILURE;
            break;
        case NGX_STREAM_BAD_GATEWAY:
            res->data[1] = NGX_STREAM_FPROXY_SOCKS5_REPLY_HOST_UNREACHABLE;
            break;
        default:    /* already set the REP for other cases */
            break;
        }

    } else {
        ctx->state = NGX_STREAM_OK ? NGX_STREAM_FPROXY_STATE_HTTP_RESPONSE : 
                                     NGX_STREAM_FPROXY_STATE_HTTP_FAIL_RESPONSE;
        
        switch (rc) {
        case NGX_STREAM_OK:
            *res = res200;
            break;
        case NGX_STREAM_BAD_REQUEST:
            *res = res400;
            break;
        case NGX_STREAM_FORBIDDEN:
            *res = res407;
            break;
        case NGX_STREAM_INTERNAL_SERVER_ERROR:
            *res = res500;
            break;
        case NGX_STREAM_BAD_GATEWAY:
            *res = res502;
            break;
        }
    }

    n = c->send(c, res->data, res->len);

    if (n == NGX_AGAIN) {
        ctx->rc = rc;

        /* our timeout timer is set on the rev */
        c->read->handler = ngx_stream_fproxy_response_handler;
        c->write->handler = ngx_stream_fproxy_response_handler;
        if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
            ngx_stream_fproxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        fscf = ngx_stream_get_module_srv_conf(s, ngx_stream_fproxy_module);
        ngx_add_timer(c->write, fscf->response_timeout);
    }

    if ((size_t)n == res->len) { 
        if (rc == NGX_STREAM_OK) {
            ctx->state = (ctx->type == NGX_STREAM_FPROXY_TYPE_SOCKS5) ?
                NGX_STREAM_FPROXY_STATE_SOCKS5_PROXYING :
                NGX_STREAM_FPROXY_STATE_HTTP_PROXYING;
            c->write->handler = ngx_stream_fproxy_downstream_handler;
            return ngx_stream_fproxy_process(s, 0 ,1);

        } else if (rc == NGX_STREAM_METHOD_ACCEPTED){
            if (ctx->method == NGX_STREAM_FPROXY_SOCKS5_AUTH_BASIC) {
                return ngx_stream_fproxy_socks5_auth(c->read);

            } else {

                return ngx_stream_fproxy_socks5_waiting_request(c->read);
            }

        } else if (rc == NGX_STREAM_AUTH_OK){
            return ngx_stream_fproxy_socks5_waiting_request(c->read);
        }
    }

    /* NGX_ERROR, n = 0, n < len */
    return ngx_stream_fproxy_finalize(s, rc);
}


static void
ngx_stream_fproxy_response_handler(ngx_event_t *ev)
{
    ngx_stream_fproxy_ctx_t     *ctx;
    ngx_connection_t            *c;
    ngx_stream_session_t        *s;
    ssize_t                      n;
    ngx_str_t                   *res;

    c = ev->data;
    s = c->data;

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_fproxy_module);

    if (ev->timedout) {
        ngx_log_error(NGX_LOG_ERR, c->log, NGX_ETIMEDOUT, "fproxy response timeout");
        goto end;
    }

    if (c->close) {
        goto end;
    }

    res = &ctx->res;
    n = c->send(c, res->data, res->len);

    if (n == NGX_AGAIN) {
        if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
            ngx_stream_fproxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }
    }

    if (ev->timer_set) {
        ngx_del_timer(ev);
    }

    if ((size_t)n == res->len) {
        if (ctx->state == NGX_STREAM_FPROXY_STATE_HTTP_RESPONSE ||
            ctx->state == NGX_STREAM_FPROXY_STATE_SOCKS5_REPLY) {
            ctx->state = (ctx->type == NGX_STREAM_FPROXY_TYPE_SOCKS5) ?
                NGX_STREAM_FPROXY_STATE_SOCKS5_PROXYING :
                NGX_STREAM_FPROXY_STATE_HTTP_PROXYING;
            c->read->handler = ngx_stream_fproxy_downstream_handler;
            c->write->handler = ngx_stream_fproxy_downstream_handler;
            return ngx_stream_fproxy_process(s, 0 ,1);

        } else if (ctx->state == NGX_STREAM_FPROXY_STATE_SOCKS5_METHOD_ACCEPTED) {
            if (ctx->method == NGX_STREAM_FPROXY_SOCKS5_AUTH_BASIC) {
                return ngx_stream_fproxy_socks5_auth(c->read);

            } else {
                return ngx_stream_fproxy_socks5_waiting_request(c->read);
            }

        } else if (ctx->state == NGX_STREAM_FPROXY_STATE_SOCKS5_AUTH_RESPONSE) {
            return ngx_stream_fproxy_socks5_waiting_request(c->read);
        }
    }

end:
    ngx_stream_fproxy_finalize(s, ctx->rc);
}


static u_char *
ngx_stream_fproxy_log_error(ngx_log_t *log, u_char *buf, size_t len)
{
    u_char                 *p;
    ngx_connection_t       *pc;
    ngx_stream_session_t   *s;
    ngx_stream_upstream_t  *u;

    s = log->data;

    u = s->upstream;

    p = buf;

    if (u->peer.name) {
        p = ngx_snprintf(p, len, ", upstream: \"%V\"", u->peer.name);
        len -= p - buf;
    }

    pc = u->peer.connection;

    p = ngx_snprintf(p, len,
                     ", bytes from/to client:%O/%O"
                     ", bytes from/to upstream:%O/%O",
                     s->received, s->connection->sent,
                     u->received, pc ? pc->sent : 0);

    return p;
}


static void *
ngx_stream_fproxy_create_srv_conf(ngx_conf_t *cf)
{
    ngx_stream_fproxy_srv_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_fproxy_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->enabled_protocols = 0;
     *     conf->auth_methods = 0;
     *     conf->userpw_keys = NULL;
     *     conf->userpw_hash = {0, NULL};
     */

    conf->ssl_optional = NGX_CONF_UNSET;
    conf->negotiate_timeout = NGX_CONF_UNSET_MSEC;
    conf->connect_timeout = NGX_CONF_UNSET_MSEC;
    conf->response_timeout = NGX_CONF_UNSET_MSEC;
    conf->timeout = NGX_CONF_UNSET_MSEC;
    conf->next_upstream_timeout = NGX_CONF_UNSET_MSEC;
    conf->buffer_size = NGX_CONF_UNSET_SIZE;
    conf->upload_rate = NGX_CONF_UNSET_PTR;
    conf->download_rate = NGX_CONF_UNSET_PTR;
    conf->requests = NGX_CONF_UNSET_UINT;
    conf->responses = NGX_CONF_UNSET_UINT;
    conf->next_upstream_tries = NGX_CONF_UNSET_UINT;
    conf->next_upstream = NGX_CONF_UNSET;
    conf->local = NGX_CONF_UNSET_PTR;
    conf->socket_keepalive = NGX_CONF_UNSET;
    conf->half_close = NGX_CONF_UNSET;


    return conf;
}


static char *
ngx_stream_fproxy_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_stream_fproxy_srv_conf_t *prev = parent;
    ngx_stream_fproxy_srv_conf_t *conf = child;

    ngx_conf_merge_msec_value(conf->negotiate_timeout,
                              prev->negotiate_timeout, 60000);

    ngx_conf_merge_msec_value(conf->connect_timeout,
                              prev->connect_timeout, 60000);

    ngx_conf_merge_msec_value(conf->response_timeout,
                              prev->response_timeout, 30000);

    ngx_conf_merge_msec_value(conf->timeout,
                              prev->timeout, 10 * 60000);

    ngx_conf_merge_msec_value(conf->next_upstream_timeout,
                              prev->next_upstream_timeout, 0);

    ngx_conf_merge_size_value(conf->buffer_size,
                              prev->buffer_size, 16384);

    ngx_conf_merge_ptr_value(conf->upload_rate, prev->upload_rate, NULL);

    ngx_conf_merge_ptr_value(conf->download_rate, prev->download_rate, NULL);

    ngx_conf_merge_uint_value(conf->requests,
                              prev->requests, 0);

    ngx_conf_merge_uint_value(conf->responses,
                              prev->responses, NGX_MAX_INT32_VALUE);

    ngx_conf_merge_uint_value(conf->next_upstream_tries,
                              prev->next_upstream_tries, 0);

    ngx_conf_merge_value(conf->next_upstream, prev->next_upstream, 1);

    ngx_conf_merge_ptr_value(conf->local, prev->local, NULL);

    ngx_conf_merge_value(conf->socket_keepalive,
                              prev->socket_keepalive, 0);

    ngx_conf_merge_value(conf->half_close, prev->half_close, 0);

    return NGX_CONF_OK;
}


static char *
ngx_stream_fproxy_protocols(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_fproxy_srv_conf_t        *fscf = conf;
    ngx_stream_core_srv_conf_t          *cscf;

    if (fscf->enabled_protocols) {
        return "is duplicate";
    }

    cscf = ngx_stream_conf_get_module_srv_conf(cf, ngx_stream_core_module);

    cscf->handler = ngx_stream_fproxy_handler;

    return ngx_conf_set_bitmask_slot(cf, cmd, conf);
}


static char *
ngx_stream_fproxy_bind(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_fproxy_srv_conf_t        *fscf = conf;

    ngx_int_t                            rc;
    ngx_str_t                           *value;
    ngx_stream_complex_value_t           cv;
    ngx_stream_upstream_local_t         *local;
    ngx_stream_compile_complex_value_t   ccv;

    if (fscf->local != NGX_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (cf->args->nelts == 2 && ngx_strcmp(value[1].data, "off") == 0) {
        fscf->local = NULL;
        return NGX_CONF_OK;
    }

    ngx_memzero(&ccv, sizeof(ngx_stream_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &cv;

    if (ngx_stream_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    local = ngx_pcalloc(cf->pool, sizeof(ngx_stream_upstream_local_t));
    if (local == NULL) {
        return NGX_CONF_ERROR;
    }

    fscf->local = local;

    if (cv.lengths) {
        local->value = ngx_palloc(cf->pool, sizeof(ngx_stream_complex_value_t));
        if (local->value == NULL) {
            return NGX_CONF_ERROR;
        }

        *local->value = cv;

    } else {
        local->addr = ngx_palloc(cf->pool, sizeof(ngx_addr_t));
        if (local->addr == NULL) {
            return NGX_CONF_ERROR;
        }

        rc = ngx_parse_addr_port(cf->pool, local->addr, value[1].data,
                                 value[1].len);

        switch (rc) {
        case NGX_OK:
            local->addr->name = value[1];
            break;

        case NGX_DECLINED:
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid address \"%V\"", &value[1]);
            /* fall through */

        default:
            return NGX_CONF_ERROR;
        }
    }

    if (cf->args->nelts > 2) {
        if (ngx_strcmp(value[2].data, "transparent") == 0) {
#if (NGX_HAVE_TRANSPARENT_PROXY)
            ngx_core_conf_t  *ccf;

            ccf = (ngx_core_conf_t *) ngx_get_conf(cf->cycle->conf_ctx,
                                                   ngx_core_module);

            ccf->transparent = 1;
            local->transparent = 1;
#else
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "transparent proxying is not supported "
                               "on this platform, ignored");
#endif
        } else {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid parameter \"%V\"", &value[2]);
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}


static char *
ngx_stream_fproxy_user_passwd(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_int_t                            rc;
    ngx_stream_fproxy_srv_conf_t        *fscf = conf;
    ngx_str_t                           *value;
    ngx_str_t                           *pw;

    value = cf->args->elts;

    if (ngx_strlchr(value[1].data, value[1].data + value[1].len, ':')) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "user name contains ':'");
        return NGX_CONF_ERROR;
    }

    if (fscf->userpw_keys == NULL) {
        fscf->userpw_keys = ngx_pcalloc(cf->pool,
                                             sizeof(ngx_hash_keys_arrays_t));
        if (fscf->userpw_keys == NULL) {
            return NGX_CONF_ERROR;
        }

        fscf->userpw_keys->pool = cf->pool;
        fscf->userpw_keys->temp_pool = cf->temp_pool;

        if (ngx_hash_keys_array_init(fscf->userpw_keys, NGX_HASH_SMALL)
            != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    pw = ngx_palloc(cf->pool, sizeof(ngx_str_t));

    if (pw == NULL) {
        return NGX_CONF_ERROR;
    }
    
    pw->len = value[2].len;
    pw->data = ngx_palloc(cf->pool, pw->len);

    if (pw->data == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memcpy(pw->data, value[2].data, pw->len);
 
    rc = ngx_hash_add_key(fscf->userpw_keys, &value[1], pw,
                          NGX_HASH_READONLY_KEY);

    if (rc == NGX_ERROR) {
        return NGX_CONF_ERROR;
    }

    if (rc == NGX_BUSY) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "conflicting user name \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_stream_fproxy_postconfiguration(ngx_conf_t* cf)
{
    ngx_stream_fproxy_srv_conf_t    *fscf;
    ngx_hash_init_t                  hash;
#if (NGX_STREAM_SSL)
    ngx_stream_handler_pt           *h;
    ngx_stream_core_main_conf_t     *cmcf;
#endif

    fscf = ngx_stream_conf_get_module_srv_conf(cf, ngx_stream_fproxy_module);

    if (fscf->userpw_keys) {
        hash.hash = &fscf->userpw_hash;
        hash.key = ngx_hash_key;
        hash.max_size = ngx_max(128, fscf->userpw_keys->keys.nelts);
        hash.bucket_size = ngx_align(64, ngx_cacheline_size);;
        hash.name = "userpw_hash";
        hash.pool = cf->pool;
        hash.temp_pool = cf->temp_pool;

        if (ngx_hash_init(&hash, fscf->userpw_keys->keys.elts,
                          fscf->userpw_keys->keys.nelts) != NGX_OK) {
            return NGX_ERROR;
        }
    }

#if (NGX_STREAM_SSL)
    if (fscf->ssl_optional) {
        cmcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_core_module);

        h = ngx_array_push(&cmcf->phases[NGX_STREAM_SSL_PHASE].handlers);

        if (h == NULL) {
            return NGX_ERROR;
        }

        *h = ngx_stream_fproxy_ssl_handler;
    }
#endif

    return NGX_OK;
}
