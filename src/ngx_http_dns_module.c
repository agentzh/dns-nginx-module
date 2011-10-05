#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include "ngx_http_dns_module.h"


static char * ngx_http_dns_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char * ngx_http_dns_raw_query(ngx_conf_t *cf, ngx_command_t *cmd,
        void *conf);
static void * ngx_http_dns_create_loc_conf(ngx_conf_t *cf);
static char * ngx_http_dns_merge_loc_conf(ngx_conf_t *cf, void *parent,
        void *child);
static ngx_int_t ngx_http_dns_handler(ngx_http_request_t *r);
static void ngx_http_dns_finalize_request(ngx_http_request_t *r,
        ngx_http_dns_ctx_t *ctx, ngx_int_t rc);
static void ngx_http_dns_resolve_handler(ngx_resolver_ctx_t *rctx);
static void ngx_http_dns_cleanup(void *data);


static ngx_command_t ngx_http_dns_cmds[] = {

    { ngx_string("dns_raw_query"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF
          |NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
      ngx_http_dns_raw_query,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("dns_pass"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
      ngx_http_dns_pass,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("dns_total_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_dns_loc_conf_t, total_timeout),
      NULL },

    { ngx_string("dns_resend_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_dns_loc_conf_t, resend_timeout),
      NULL },

      ngx_null_command
};


static ngx_http_module_t ngx_http_dns_module_ctx = {
    NULL,    /* preconfiguration */
    NULL,    /* postconfiguration */

    NULL,    /* create_main_conf */
    NULL,    /* merge_main_conf */

    NULL,    /* create_srv_conf */
    NULL,    /* merge_srv_conf */

    ngx_http_dns_create_loc_conf,    /* create_loc_conf */
    ngx_http_dns_merge_loc_conf      /* merge_loc_conf */
};


ngx_module_t ngx_http_dns_module = {
    NGX_MODULE_V1,
    &ngx_http_dns_module_ctx,           /* module context */
    ngx_http_dns_cmds,                  /* module directives */
    NGX_HTTP_MODULE,                    /* module type */
    NULL,    /* init master */
    NULL,    /* init module */
    NULL,    /* init process */
    NULL,    /* init thread */
    NULL,    /* exit thread */
    NULL,    /* exit process */
    NULL,    /* exit master */
    NGX_MODULE_V1_PADDING
};


static void *
ngx_http_dns_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_dns_loc_conf_t             *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_dns_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc:
     *      conf->resolver = NULL;
     *
     */

    conf->total_timeout = NGX_CONF_UNSET_MSEC;
    conf->resend_timeout = NGX_CONF_UNSET_MSEC;
    conf->cache_expire = NGX_CONF_UNSET_MSEC;

    return conf;
}


static char *
ngx_http_dns_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_dns_loc_conf_t *prev = parent;
    ngx_http_dns_loc_conf_t *conf = child;

    ngx_conf_merge_msec_value(conf->total_timeout,
                              prev->total_timeout, 3000);

    ngx_conf_merge_msec_value(conf->resend_timeout,
                              prev->resend_timeout, 500);

    ngx_conf_merge_msec_value(conf->cache_expire,
                              prev->cache_expire, 30000);

    if (conf->resolver == NULL) {

        if (prev->resolver == NULL) {

            /*
             * create dummy resolver in http {} context
             * to inherit it in all servers
             */

            prev->resolver = ngx_resolver_create(cf, NULL);
            if (prev->resolver == NULL) {
                return NGX_CONF_ERROR;
            }
        }

        conf->resolver = prev->resolver;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_dns_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_dns_loc_conf_t *dlcf = conf;

    ngx_str_t                  *value;
    ngx_url_t                   u;
    ngx_int_t                   n;
    u_char                     *p, *last;
    size_t                      len;
    ngx_http_core_loc_conf_t   *clcf;

    if (dlcf->resolver) {
        return "is duplicate";
    }

    value = cf->args->elts;

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.host = value[1];

    last = u.host.data + u.host.len;
    p = ngx_strlchr(u.host.data, last, ':');

    if (p != NULL){
        p++;
        len = last - p;
        u.host.len -= len + 1;

        if (len == 0) {
            return "takes empty port";
        }

        n = ngx_atoi(p, len);

        if (n < 1 || n > 65536) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid port %s", p);
            return NGX_CONF_ERROR;
        }

        u.port = (in_port_t) n;

    } else {
        u.port = 53;
    }

    if (ngx_inet_resolve_host(cf->pool, &u) != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%V: %s", &u.host, u.err);
        return NGX_CONF_ERROR;
    }

    dlcf->resolver = ngx_resolver_create(cf, &u.addrs[0]);
    if (dlcf->resolver == NULL) {
        return NGX_OK;
    }

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_dns_handler;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_dns_handler(ngx_http_request_t *r)
{
    ngx_str_t                       host = ngx_string("www.google.com");
    ngx_resolver_ctx_t             *rctx, temp;
    ngx_http_dns_ctx_t             *ctx;
    ngx_http_cleanup_t             *cln;
    ngx_http_dns_loc_conf_t        *dlcf;

    temp.name.data = host.data;
    temp.name.len = host.len;

    dlcf = ngx_http_get_module_loc_conf(r, ngx_http_dns_module);

    rctx = ngx_resolve_start(dlcf->resolver, &temp);
    if (rctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (rctx == NGX_NO_RESOLVER) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "no resolver defined to resolve %V", host);
        return NGX_HTTP_BAD_GATEWAY;
    }

    rctx->name = host;
    rctx->type = NGX_RESOLVE_A;
    rctx->handler = ngx_http_dns_resolve_handler;
    rctx->data = r;
    rctx->timeout = dlcf->total_timeout;

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_dns_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_http_set_ctx(r, ctx, ngx_http_dns_module);

    ctx->resolver_ctx = rctx;

    if (ngx_resolve_name(rctx) != NGX_OK) {
        ctx->resolver_ctx = NULL;
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    cln = ngx_http_cleanup_add(r, 0);
    if (cln == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    cln->handler = ngx_http_dns_cleanup;
    cln->data = r;
    ctx->cleanup = &cln->handler;

    r->main->count++;

    return NGX_DONE;
}


static void
ngx_http_dns_resolve_handler(ngx_resolver_ctx_t *rctx)
{
    ngx_http_request_t            *r;
    ngx_http_dns_ctx_t            *ctx;
    in_addr_t                      addr;
    ngx_uint_t                     i;
    ngx_chain_t                   *cl;
    ngx_buf_t                     *b;
    size_t                         len;

    r = rctx->data;

    ctx = ngx_http_get_module_ctx(r, ngx_http_dns_module);

    if (rctx->state) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "%V could not be resolved (%i: %s)",
                      &rctx->name, rctx->state,
                      ngx_resolver_strerror(rctx->state));

        ngx_http_dns_finalize_request(r, ctx, NGX_HTTP_BAD_GATEWAY);
        return;
    }

    len = ngx_pagesize;

    b = ngx_create_temp_buf(r->pool, len);

    for (i = 0; i < rctx->naddrs; i++) {
        addr = ntohl(rctx->addrs[i]);

        b->last = ngx_snprintf(b->last, b->end - b->last,
                       "name was resolved to %ud.%ud.%ud.%ud\n",
                       (addr >> 24) & 0xff, (addr >> 16) & 0xff,
                       (addr >> 8) & 0xff, addr & 0xff);
    }

    ngx_resolve_name_done(rctx);
    ctx->resolver_ctx = NULL;

    cl = ngx_alloc_chain_link(r->pool);
    cl->buf = b;
    cl->next = NULL;

    r->headers_out.status = NGX_HTTP_OK;
    ngx_http_send_header(r);
    ctx->header_sent = 1;

    ngx_http_output_filter(r, cl);

    ngx_http_dns_finalize_request(r, ctx, NGX_OK);
    return;
}


static void
ngx_http_dns_finalize_request(ngx_http_request_t *r, ngx_http_dns_ctx_t *ctx,
        ngx_int_t rc)
{
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "finalize http dns request: %i", rc);

    if (ctx == NULL) {
        return;
    }

    if (ctx->cleanup) {
        *ctx->cleanup = NULL;
        ctx->cleanup = NULL;
    }

    if (ctx->resolver_ctx) {
        ngx_resolve_name_done(ctx->resolver_ctx);
        ctx->resolver_ctx = NULL;
    }

    if (ctx->header_sent
        && rc != NGX_HTTP_REQUEST_TIME_OUT
        && (rc == NGX_ERROR || rc >= NGX_HTTP_SPECIAL_RESPONSE))
    {
        rc = 0;
    }

    if (rc == NGX_DECLINED) {
        return;
    }

    r->connection->log->action = "sending to client";

    if (rc == 0) {
        rc = ngx_http_send_special(r, NGX_HTTP_LAST);
    }

    ngx_http_finalize_request(r, rc);
}


static void
ngx_http_dns_cleanup(void *data)
{
    ngx_http_request_t *r = data;

    ngx_http_dns_ctx_t  *ctx;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "cleanup http upstream request: \"%V\"", &r->uri);

    ctx = ngx_http_get_module_ctx(r, ngx_http_dns_module);

    if (ctx && ctx->resolver_ctx) {
        ngx_resolve_name_done(ctx->resolver_ctx);
        ctx->resolver_ctx = NULL;
    }

    ngx_http_dns_finalize_request(r, ctx, NGX_DONE);
}


static char *
ngx_http_dns_raw_query(ngx_conf_t *cf, ngx_command_t *cmd,
        void *conf)
{
    /* TODO */
    return NGX_CONF_OK;
}

