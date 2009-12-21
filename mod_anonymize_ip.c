#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_request.h"

#include "apr_strings.h"

module AP_MODULE_DECLARE_DATA anonymize_ip_module;

typedef struct {
	int mask;
	const char *dir;
	apr_table_t *exceptions;
} aip_cfg;

static
int aip_post_read_request(request_rec *r)
{
	aip_cfg *cfg = ap_get_module_config(r->per_dir_config,
			&anonymize_ip_module);

	if (r->main || cfg->mask <= 0 || apr_table_get(cfg->exceptions, r->uri))
		return DECLINED;

	if (r->connection->remote_addr->sa.sin.sin_addr.s_addr != htonl(0x7F000001)) {
		uint32_t mask = ~((1U << cfg->mask) - 1);
		r->connection->remote_addr->sa.sin.sin_addr.s_addr &= htonl(mask);
		r->connection->remote_ip = apr_pstrdup(r->connection->pool,
				inet_ntoa(r->connection->remote_addr->sa.sin.sin_addr));
	}

	return DECLINED;
}

static
void *aip_create_dir_config(apr_pool_t *p, char *dir)
{
	aip_cfg *cfg = apr_pcalloc(p, sizeof(aip_cfg));

	cfg->dir = dir;
	cfg->mask = -1;
	cfg->exceptions = apr_table_make(p, 0);

	return cfg;
}

static
void *aip_merge_dir_config(apr_pool_t *p, void *parent, void *current)
{
	aip_cfg *parent_cfg = (aip_cfg *) parent;
	aip_cfg *current_cfg = (aip_cfg *) current;
	aip_cfg *cfg = apr_pcalloc(p, sizeof(aip_cfg));

	cfg->dir = apr_pstrdup(p, current_cfg->dir);
	cfg->mask = current_cfg->mask < 0 ? parent_cfg->mask : current_cfg->mask;
	cfg->exceptions = apr_table_overlay(p, parent_cfg->exceptions, current_cfg->exceptions);

	return cfg;
}

static
void *aip_create_srv_config(apr_pool_t *p, server_rec *s)
{
	aip_cfg *cfg = apr_pcalloc(p, sizeof(aip_cfg));

	cfg->dir = NULL;
	cfg->mask = -1;
	cfg->exceptions = apr_table_make(p, 0);

	return cfg;
}

static
void *aip_merge_srv_config(apr_pool_t *p, void *parent, void *current)
{
	aip_cfg *parent_cfg = (aip_cfg *) parent;
	aip_cfg *current_cfg = (aip_cfg *) current;
	aip_cfg *cfg = apr_pcalloc(p, sizeof(aip_cfg));

	cfg->dir = current_cfg->dir == NULL ? parent_cfg->dir : current_cfg->dir;
	cfg->mask = current_cfg->mask < 0 ? parent_cfg->mask : current_cfg->mask;
	cfg->exceptions = apr_table_overlay(p, parent_cfg->exceptions, current_cfg->exceptions);

	return cfg;
}

static
const char *cmd_anonymize_ip(cmd_parms *cmd, void *mconfig, const char *arg)
{
	aip_cfg *cfg = (aip_cfg *) mconfig;
	cfg->mask = atoi(arg);
	return NULL;
}

static
const char *cmd_anonymize_ip_exclude(cmd_parms *cmd, void *mconfig, const char *arg)
{
	aip_cfg *cfg = (aip_cfg *) mconfig;
	apr_table_set(cfg->exceptions, arg, "true");
	return NULL;
}

static
const command_rec aip_cmds[] = {
	AP_INIT_TAKE1(
			"AnonymizeIP",
			cmd_anonymize_ip,
			NULL,
			RSRC_CONF,
			"number of bits that should be anonymized"),
	AP_INIT_TAKE1(
			"AnonymizeIPException",
			cmd_anonymize_ip_exclude,
			NULL,
			RSRC_CONF,
			"exclude URLs from anonymization"),
	{ NULL }
};

static
void aip_register_hooks(apr_pool_t *p)
{
	ap_hook_post_read_request(aip_post_read_request, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA anonymize_ip_module = {
	STANDARD20_MODULE_STUFF,
	aip_create_dir_config,    /* per-directory config creater */
	aip_merge_dir_config,     /* dir config merger */
	aip_create_srv_config,    /* server config creator */
	aip_merge_srv_config,     /* server config merger */
	aip_cmds,                 /* command table */
	aip_register_hooks        /* set up other request processing hooks */
};
