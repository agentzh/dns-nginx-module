#ifndef NGX_HTTP_DNS_MODULE_H
#define NGX_HTTP_DNS_MODULE_H


#include <ngx_config.h>
#include <ngx_core.h>
#include <nginx.h>


extern ngx_module_t ngx_http_dns_module;


typedef struct {
    ngx_resolver_t      *resolver;

    ngx_msec_t       total_timeout;
    ngx_msec_t       resend_timeout;
    ngx_msec_t       cache_expire;
} ngx_http_dns_loc_conf_t;


typedef struct {
    ngx_resolver_ctx_t          *resolver_ctx;
    unsigned                     header_sent;

    ngx_http_cleanup_pt             *cleanup;
} ngx_http_dns_ctx_t;


#endif /* NGX_HTTP_DNS_MODULE_H */

