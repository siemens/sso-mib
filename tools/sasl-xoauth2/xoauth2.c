/*
 * SPDX-FileCopyrightText: (C) 2026 Siemens AG
 * SPDX-License-Identifier: MIT
 *
 * cyrus-sasl XOAUTH2 client plugin backed by the Microsoft Identity
 * Broker (sso-mib). The access token is acquired for the SASL authname; a
 * matching account must already exist, and the broker may prompt for sign-in
 * or consent.
 *
 * Environment variables:
 *   MIB_SASL_CLIENT_ID : Azure client application ID (required)
 *   MIB_SASL_AUTHORITY : Entra ID authority URL (optional)
 *   MIB_SASL_SCOPES    : whitespace/comma separated scopes (optional)
 *
 * Default scopes: offline_access and IMAP.AccessAsUser.All.
 *
 * Note: mech_step blocks (D-Bus + possible interactive sign-in/MFA, can take
 * minutes). The SASL client API is synchronous, so event-loop clients should
 * run the SASL exchange off their main thread.
 */

#include "sso-mib.h"

#include <sasl/sasl.h>
#include <sasl/saslplug.h>
#include <stdlib.h>
#include <string.h>

typedef enum {
	MIB_SASL_INITIAL,
	MIB_SASL_TOKEN_SENT,
	MIB_SASL_ERROR_SENT,
} MIBSaslState;

typedef struct {
	MIBSaslState state;
	gchar *username;
	gchar *response;
} MIBSaslConn;

static void finish_oparams(sasl_out_params_t *oparams)
{
	oparams->doneflag = 1;
	oparams->mech_ssf = 0;
	oparams->maxoutbuf = 0;
	oparams->encode_context = NULL;
	oparams->decode_context = NULL;
	oparams->encode = NULL;
	oparams->decode = NULL;
	oparams->param_version = 0;
}

static gboolean has_control_chars(const gchar *s)
{
	if (!s)
		return FALSE;
	for (; *s; s++) {
		if (g_ascii_iscntrl(*s))
			return TRUE;
	}
	return FALSE;
}

static GSList *build_scopes(void)
{
	const gchar *env = getenv("MIB_SASL_SCOPES");
	GSList *scopes = NULL;
	gchar **parts;

	if (env && *env) {
		parts = g_strsplit_set(env, " \t,", -1);
		for (gchar **p = parts; *p; p++) {
			if (**p)
				scopes = g_slist_prepend(scopes, g_strdup(*p));
		}
		scopes = g_slist_reverse(scopes);
		g_strfreev(parts);
	}

	if (!scopes) {
		scopes = g_slist_append(scopes, g_strdup("offline_access"));
		scopes = g_slist_append(
			scopes,
			g_strdup("https://outlook.office365.com/IMAP.AccessAsUser.All"));
	}
	return scopes;
}

static gchar *acquire_access_token(const gchar *upn, const gchar **errmsg)
{
	const gchar *client_id = getenv("MIB_SASL_CLIENT_ID");
	const gchar *authority = getenv("MIB_SASL_AUTHORITY");
	MIBClientApp *app;
	MIBPrt *prt;
	GSList *scopes;
	gchar *token = NULL;

	if (!client_id || !*client_id) {
		*errmsg = "sso-mib-sasl-xoauth2: MIB_SASL_CLIENT_ID is required";
		return NULL;
	}
	if (!authority || !*authority)
		authority = MIB_AUTHORITY_COMMON;

	/* Per-login D-Bus setup is fine for typical clients such as isync. */
	app = mib_public_client_app_new(client_id, authority, NULL, NULL);
	if (!app) {
		*errmsg = "sso-mib-sasl-xoauth2: failed to create client application";
		return NULL;
	}

	scopes = build_scopes();
	/* This API tries silent acquisition first, prompting only if it fails. */
	prt = mib_client_app_acquire_token_interactive(
		app, scopes, MIB_PROMPT_UNSET, upn, NULL, NULL, NULL);
	g_slist_free_full(scopes, g_free);
	if (!prt) {
		*errmsg = "sso-mib-sasl-xoauth2: token acquisition failed "
				  "(sign-in, consent, or MFA may be required)";
		goto out_app;
	}

	token = g_strdup(mib_prt_get_access_token(prt));
	g_object_unref(prt);
	if (!token || !*token) {
		g_free(token);
		token = NULL;
		*errmsg = "sso-mib-sasl-xoauth2: broker returned no access token";
	}

out_app:
	g_object_unref(app);
	return token;
}

static gchar *read_authname(const sasl_utils_t *utils,
							sasl_interact_t **prompt_need)
{
	const sasl_interact_t *p;
	sasl_getsimple_t *cb = NULL;
	const char *val = NULL;
	void *ctx = NULL;
	unsigned len = 0;

	if (prompt_need && *prompt_need) {
		for (p = *prompt_need; p->id != SASL_CB_LIST_END; p++) {
			if (p->id == SASL_CB_AUTHNAME && p->result)
				return g_strndup(p->result,
								 p->len ? p->len : strlen(p->result));
		}
	}

	if (utils->getcallback(utils->conn, SASL_CB_AUTHNAME,
						   (sasl_callback_ft *)&cb, &ctx) != SASL_OK ||
		!cb)
		return NULL;

	if (cb(ctx, SASL_CB_AUTHNAME, &val, &len) != SASL_OK || !val)
		return NULL;

	return g_strndup(val, len ? len : strlen(val));
}

static int request_authname(sasl_client_params_t *params,
							sasl_interact_t **prompt_need)
{
	sasl_interact_t *p;

	if (!prompt_need)
		return SASL_BADPARAM;

	p = params->utils->malloc(sizeof(*p) * 2);
	if (!p)
		return SASL_NOMEM;
	memset(p, 0, sizeof(*p) * 2);
	p[0].id = SASL_CB_AUTHNAME;
	p[0].prompt = "Username";
	p[0].defresult = "";
	p[1].id = SASL_CB_LIST_END;

	*prompt_need = p;
	return SASL_INTERACT;
}

static int initial_step(MIBSaslConn *conn, sasl_client_params_t *params,
						sasl_interact_t **prompt_need, const char **clientout,
						unsigned *clientoutlen, sasl_out_params_t *oparams)
{
	const sasl_utils_t *utils = params->utils;
	gchar *username, *token;
	const gchar *errmsg = "sso-mib-sasl-xoauth2: unknown error";
	int err;

	int interacted = prompt_need && *prompt_need;

	username = read_authname(utils, prompt_need);
	if (interacted) {
		utils->free(*prompt_need);
		*prompt_need = NULL;
	}
	if (!username) {
		if (interacted) {
			utils->seterror(utils->conn, 0,
							"sso-mib-sasl-xoauth2: authname not provided");
			return SASL_BADPARAM;
		}
		return request_authname(params, prompt_need);
	}

	if (!*username || has_control_chars(username)) {
		g_free(username);
		utils->seterror(utils->conn, 0, "sso-mib-sasl-xoauth2: invalid authname");
		return SASL_BADPARAM;
	}

	err = params->canon_user(utils->conn, username, strlen(username),
							 SASL_CU_AUTHID | SASL_CU_AUTHZID, oparams);
	if (err != SASL_OK) {
		g_free(username);
		return err;
	}

	g_free(conn->username);
	conn->username = g_strdup(oparams->authid ? oparams->authid : username);
	g_free(username);
	if (!*conn->username || has_control_chars(conn->username)) {
		g_free(conn->username);
		conn->username = NULL;
		utils->seterror(utils->conn, 0, "sso-mib-sasl-xoauth2: invalid authname");
		return SASL_BADPARAM;
	}

	token = acquire_access_token(conn->username, &errmsg);
	if (!token) {
		utils->seterror(utils->conn, 0, "%s", errmsg);
		return SASL_FAIL;
	}

	/* XOAUTH2 initial client response, raw (the application base64-encodes it) */
	conn->response = g_strdup_printf("user=%s\001auth=Bearer %s\001\001",
									 conn->username, token);
	g_free(token);

	*clientout = conn->response;
	*clientoutlen = strlen(conn->response);
	conn->state = MIB_SASL_TOKEN_SENT;
	return SASL_CONTINUE;
}

/* A token rejected by the server is reported without another sign-in attempt. */
static int token_sent_step(sasl_client_params_t *params, const char *serverin,
						   unsigned serverinlen, const char **clientout,
						   unsigned *clientoutlen, sasl_out_params_t *oparams)
{
	if (!serverin || serverinlen == 0) {
		finish_oparams(oparams);
		return SASL_OK;
	}

	/* JSON error challenge: reply with an empty response; the server then
	 * sends the final failure. */
	gchar *msg = g_strndup(serverin, serverinlen);
	for (gchar *p = msg; *p; p++) {
		if (g_ascii_iscntrl(*p))
			*p = ' ';
	}
	g_strstrip(msg);
	if (!*msg)
		params->utils->seterror(params->utils->conn, 0,
								"sso-mib-sasl-xoauth2: server rejected the token");
	else
		params->utils->seterror(
			params->utils->conn, 0,
			"sso-mib-sasl-xoauth2: server rejected the token: %s", msg);
	g_free(msg);
	*clientout = "";
	*clientoutlen = 0;
	return SASL_CONTINUE;
}

static int mech_new(G_GNUC_UNUSED void *glob_context,
					G_GNUC_UNUSED sasl_client_params_t *params, void **context)
{
	MIBSaslConn *conn = g_new0(MIBSaslConn, 1);

	conn->state = MIB_SASL_INITIAL;
	*context = conn;
	return SASL_OK;
}

static int mech_step(void *context, sasl_client_params_t *params,
					 const char *serverin, unsigned serverinlen,
					 sasl_interact_t **prompt_need, const char **clientout,
					 unsigned *clientoutlen, sasl_out_params_t *oparams)
{
	MIBSaslConn *conn = context;

	if (!conn || !clientout || !clientoutlen || !oparams)
		return SASL_BADPARAM;
	*clientout = NULL;
	*clientoutlen = 0;

	if (conn->state == MIB_SASL_TOKEN_SENT) {
		int rc = token_sent_step(params, serverin, serverinlen, clientout,
								 clientoutlen, oparams);
		if (rc == SASL_CONTINUE)
			conn->state = MIB_SASL_ERROR_SENT;
		return rc;
	}
	if (conn->state == MIB_SASL_ERROR_SENT)
		return SASL_BADAUTH;

	return initial_step(conn, params, prompt_need, clientout, clientoutlen,
						oparams);
}

static void mech_dispose(void *context, G_GNUC_UNUSED const sasl_utils_t *utils)
{
	MIBSaslConn *conn = context;

	if (!conn)
		return;
	g_free(conn->username);
	g_free(conn->response);
	g_free(conn);
}

static sasl_client_plug_t mib_sasl_xoauth2_plugins[] = { {
	.mech_name = "XOAUTH2",
	.max_ssf = 0,
	.security_flags = SASL_SEC_NOANONYMOUS,
	.features = SASL_FEAT_WANT_CLIENT_FIRST,
	.required_prompts = NULL,
	.mech_new = mech_new,
	.mech_step = mech_step,
	.mech_dispose = mech_dispose,
	.idle = NULL,
} };

int sasl_client_plug_init(const sasl_utils_t *utils, int max_version,
						  int *out_version, sasl_client_plug_t **plug_list,
						  int *plug_count)
{
	if (max_version < SASL_CLIENT_PLUG_VERSION) {
		utils->seterror(utils->conn, 0,
						"sso-mib-sasl-xoauth2: need version %d, got %d",
						SASL_CLIENT_PLUG_VERSION, max_version);
		return SASL_BADVERS;
	}

	*out_version = SASL_CLIENT_PLUG_VERSION;
	*plug_list = mib_sasl_xoauth2_plugins;
	*plug_count = G_N_ELEMENTS(mib_sasl_xoauth2_plugins);
	return SASL_OK;
}
