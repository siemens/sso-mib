/*
 * SPDX-FileCopyrightText: (C) 2026 Siemens
 * SPDX-License-Identifier: MIT
 *
 * This example reimplements the native messaging host of the
 * "linux-entra-sso" browser extension
 * (https://github.com/siemens/linux-entra-sso) on top of sso-mib.
 *
 * It speaks the WebExtension native messaging protocol on stdin/stdout.
 * The implementation is just for experimental purposes, but should be
 * functionally equivalent to the original host.
 *
 * Supported commands:
 *   - getAccounts
 *   - acquireTokenSilently
 *   - acquirePrtSsoCookie
 *   - getVersion
 */

#include "json-processing.h"
#include "native-messaging.h"
#include "sso-mib.h"

#include <gio/gio.h>
#include <glib-unix.h>
#include <json-glib/json-glib.h>

#include <unistd.h>

#define EDGE_BROWSER_CLIENT_ID "d7b530a4-7680-4c23-a8bf-c52c121d2e87"
#define APP_REDIRECT_URI \
	"https://login.microsoftonline.com/common/oauth2/nativeclient"
#define BROKER_DBUS_NAME "com.microsoft.identity.broker1"

/* protocol version */
#define LINUX_ENTRA_SSO_VERSION "1.10.0"

typedef struct {
	MIBClientApp *app;
	GMainLoop *loop;
	gboolean broker_online;
	gboolean broker_state_known;
	/* MIBAccount, keyed by UPN */
	GHashTable *accounts;
} HostContext;

/*
 * State of one in-flight request. The parser reference keeps the strings
 * borrowed from the request object alive until the last callback ran.
 */
typedef struct _Request Request;
typedef void (*AccountReadyFunc)(Request *req, MIBAccount *account);

struct _Request {
	HostContext *ctx;
	const gchar *cmd;
	JsonParser *parser;
	JsonObject *request;
	const gchar *upn;
	AccountReadyFunc on_account;
};

static Request *request_new(HostContext *ctx, const gchar *cmd,
							JsonParser *parser, JsonObject *request)
{
	Request *req = g_new0(Request, 1);

	req->ctx = ctx;
	req->cmd = cmd;
	req->parser = g_object_ref(parser);
	req->request = request;
	return req;
}

static void request_free(Request *req)
{
	g_object_unref(req->parser);
	g_free(req);
}

static void request_fail(Request *req, const gchar *message, GError *error)
{
	if (error) {
		g_autofree gchar *detail =
			g_strdup_printf("%s: %s", message, error->message);
		g_error_free(error);
		respond_error(req->cmd, detail);
	} else {
		respond_error(req->cmd, message);
	}
	request_free(req);
}

/* sends the object built in builder as response and completes the request */
static void request_respond(Request *req, JsonBuilder *builder)
{
	nm_send(req->cmd, json_builder_get_root(builder));
	g_object_unref(builder);
	request_free(req);
}

static void on_account_ready(GObject *source, GAsyncResult *res,
							 gpointer user_data)
{
	(void)source;
	Request *req = user_data;
	GError *error = NULL;
	MIBAccount *account =
		mib_client_app_get_account_by_upn_finish(req->ctx->app, res, &error);

	if (!account) {
		request_fail(req, "no matching account found", error);
		return;
	}

	/* the cache takes over the reference and outlives the request */
	g_hash_table_insert(req->ctx->accounts, g_strdup(req->upn), account);
	req->on_account(req, account);
}

/* resolves the request's account from the cache or the broker */
static void request_resolve_account(Request *req, AccountReadyFunc on_account)
{
	const gchar *upn = received_username(req->request);
	MIBAccount *cached;

	/* without a UPN the broker lookup would pick an arbitrary account */
	if (!upn) {
		request_fail(req, "request without account username", NULL);
		return;
	}
	req->upn = upn;
	req->on_account = on_account;

	cached = g_hash_table_lookup(req->ctx->accounts, upn);
	if (cached) {
		on_account(req, cached);
		return;
	}

	mib_client_app_get_account_by_upn_async(req->ctx->app, upn,
											on_account_ready, req);
}

/* --- command handlers ---------------------------------------------------- */

static void on_accounts_ready(GObject *source, GAsyncResult *res,
							  gpointer user_data)
{
	(void)source;
	Request *req = user_data;
	GError *error = NULL;
	GSList *accounts =
		mib_client_app_get_accounts_finish(req->ctx->app, res, &error);

	if (error) {
		request_fail(req, "failed to query accounts", error);
		return;
	}

	JsonBuilder *builder = json_builder_new();
	json_builder_begin_object(builder);
	json_builder_set_member_name(builder, "accounts");
	json_builder_begin_array(builder);
	for (GSList *it = accounts; it; it = g_slist_next(it))
		account_build(builder, MIB_ACCOUNT(it->data));
	json_builder_end_array(builder);
	json_builder_end_object(builder);

	g_slist_free_full(accounts, (GDestroyNotify)g_object_unref);
	request_respond(req, builder);
}

static void handle_get_accounts(Request *req)
{
	mib_client_app_get_accounts_async(req->ctx->app, on_accounts_ready, req);
}

static void on_token_ready(GObject *source, GAsyncResult *res,
						   gpointer user_data)
{
	(void)source;
	Request *req = user_data;
	GError *error = NULL;
	MIBPrt *token =
		mib_client_app_acquire_token_silent_finish(req->ctx->app, res, &error);

	if (!token) {
		request_fail(req, "failed to acquire token silently", error);
		return;
	}

	JsonBuilder *builder = json_builder_new();
	json_builder_begin_object(builder);
	json_builder_set_member_name(builder, "brokerTokenResponse");
	json_builder_begin_object(builder);
	json_builder_set_member_name(builder, "accessToken");
	json_builder_add_string_value(builder, mib_prt_get_access_token(token));
	json_builder_set_member_name(builder, "expiresOn");
	/* the extension compares this against Date.now(), i.e. milliseconds */
	json_builder_add_int_value(builder,
							   (gint64)mib_prt_get_expires_on(token) * 1000);
	add_optional_string(builder, "idToken", mib_prt_get_id_token(token));
	json_builder_end_object(builder);
	json_builder_end_object(builder);

	g_object_unref(token);
	request_respond(req, builder);
}

static void on_account_for_token(Request *req, MIBAccount *account)
{
	GSList *scopes = build_scopes(req->request);

	mib_client_app_acquire_token_silent_async(
		req->ctx->app, account, scopes, NULL, NULL, NULL, on_token_ready, req);
	g_slist_free(scopes);
}

static void handle_acquire_token_silently(Request *req)
{
	request_resolve_account(req, on_account_for_token);
}

static void on_cookie_ready(GObject *source, GAsyncResult *res,
							gpointer user_data)
{
	(void)source;
	Request *req = user_data;
	GError *error = NULL;
	MIBPrtSsoCookie *cookie = mib_client_app_acquire_prt_sso_cookie_finish(
		req->ctx->app, res, &error);

	if (!cookie) {
		request_fail(req, "failed to acquire PRT SSO cookie", error);
		return;
	}

	JsonBuilder *builder = json_builder_new();
	json_builder_begin_object(builder);
	json_builder_set_member_name(builder, "cookieName");
	json_builder_add_string_value(builder, mib_prt_sso_cookie_get_name(cookie));
	json_builder_set_member_name(builder, "cookieContent");
	json_builder_add_string_value(builder,
								  mib_prt_sso_cookie_get_content(cookie));
	json_builder_end_object(builder);

	g_object_unref(cookie);
	request_respond(req, builder);
}

static void on_account_for_cookie(Request *req, MIBAccount *account)
{
	const gchar *sso_url = MIB_SSO_URL_DEFAULT;
	GSList *scopes;

	if (json_object_has_member(req->request, "ssoUrl")) {
		const gchar *url =
			json_object_get_string_member(req->request, "ssoUrl");
		if (url && *url)
			sso_url = url;
	}

	scopes = build_scopes(req->request);
	mib_client_app_acquire_prt_sso_cookie_async(req->ctx->app, account, sso_url,
												scopes, on_cookie_ready, req);
	g_slist_free(scopes);
}

static void handle_acquire_prt_sso_cookie(Request *req)
{
	request_resolve_account(req, on_account_for_cookie);
}

static void on_version_ready(GObject *source, GAsyncResult *res,
							 gpointer user_data)
{
	(void)source;
	Request *req = user_data;
	GError *error = NULL;
	gchar *broker_version = mib_client_app_get_linux_broker_version_finish(
		req->ctx->app, res, &error);

	if (!broker_version) {
		request_fail(req, "failed to query broker version", error);
		return;
	}

	JsonBuilder *builder = json_builder_new();
	json_builder_begin_object(builder);
	json_builder_set_member_name(builder, "linuxBrokerVersion");
	json_builder_add_string_value(builder, broker_version);
	json_builder_set_member_name(builder, "native");
	json_builder_add_string_value(builder, LINUX_ENTRA_SSO_VERSION);
	json_builder_end_object(builder);

	g_free(broker_version);
	request_respond(req, builder);
}

static void handle_get_version(Request *req)
{
	mib_client_app_get_linux_broker_version_async(
		req->ctx->app, LINUX_ENTRA_SSO_VERSION, on_version_ready, req);
}

static const struct {
	const gchar *name;
	void (*handle)(Request *req);
} commands[] = {
	{ "getAccounts", handle_get_accounts },
	{ "acquireTokenSilently", handle_acquire_token_silently },
	{ "acquirePrtSsoCookie", handle_acquire_prt_sso_cookie },
	{ "getVersion", handle_get_version },
};

static void dispatch(HostContext *ctx, const gchar *data, gsize len)
{
	g_autoptr(JsonParser) parser = json_parser_new();
	g_autoptr(GError) error = NULL;
	JsonNode *root;
	JsonObject *request;
	const gchar *cmd;

	if (!json_parser_load_from_data(parser, data, len, &error)) {
		g_printerr("failed to parse message: %s\n", error->message);
		return;
	}

	root = json_parser_get_root(parser);
	if (!root || !JSON_NODE_HOLDS_OBJECT(root)) {
		g_printerr("received message is not a JSON object\n");
		return;
	}

	request = json_node_get_object(root);
	cmd = json_object_has_member(request, "command") ?
			  json_object_get_string_member(request, "command") :
			  NULL;
	if (!cmd) {
		g_printerr("received message without command\n");
		return;
	}

	for (gsize i = 0; i < G_N_ELEMENTS(commands); i++) {
		if (g_strcmp0(cmd, commands[i].name) != 0)
			continue;
		commands[i].handle(request_new(ctx, commands[i].name, parser, request));
		return;
	}

	g_printerr("unknown command: %s\n", cmd);
}

static gboolean on_stdin_ready(gint fd, GIOCondition condition,
							   gpointer user_data)
{
	HostContext *ctx = user_data;
	gchar *buffer = NULL;
	gsize len = 0;

	if (condition & (G_IO_HUP | G_IO_ERR)) {
		g_main_loop_quit(ctx->loop);
		return G_SOURCE_REMOVE;
	}

	if (!nm_read_message(fd, &buffer, &len)) {
		g_main_loop_quit(ctx->loop);
		return G_SOURCE_REMOVE;
	}

	dispatch(ctx, buffer, len);
	g_free(buffer);
	return G_SOURCE_CONTINUE;
}

/* --- broker state monitoring --------------------------------------------- */

static void report_broker_state(HostContext *ctx, gboolean online)
{
	if (ctx->broker_state_known && ctx->broker_online == online)
		return;
	ctx->broker_online = online;
	ctx->broker_state_known = TRUE;
	nm_send("brokerStateChanged",
			make_string_node(online ? "online" : "offline"));
}

static void on_broker_appeared(GDBusConnection *connection, const gchar *name,
							   const gchar *name_owner, gpointer user_data)
{
	(void)connection;
	(void)name;
	(void)name_owner;
	report_broker_state(user_data, TRUE);
}

static void on_broker_vanished(GDBusConnection *connection, const gchar *name,
							   gpointer user_data)
{
	HostContext *ctx = user_data;

	(void)connection;
	(void)name;

	/* accounts may have changed while the broker was gone */
	g_hash_table_remove_all(ctx->accounts);
	report_broker_state(ctx, FALSE);
}

int main(void)
{
	HostContext ctx = {
		.app = NULL,
		.loop = NULL,
		.broker_online = FALSE,
		.broker_state_known = FALSE,
		.accounts = NULL,
	};

	ctx.app = mib_public_client_app_new(EDGE_BROWSER_CLIENT_ID,
										MIB_AUTHORITY_COMMON, NULL, NULL);
	if (!ctx.app) {
		g_printerr("failed to create client app\n");
		return 1;
	}
	mib_client_app_set_redirect_uri(ctx.app, APP_REDIRECT_URI);

	ctx.accounts =
		g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_object_unref);
	ctx.loop = g_main_loop_new(NULL, FALSE);

	guint watch_id = g_bus_watch_name(G_BUS_TYPE_SESSION, BROKER_DBUS_NAME,
									  G_BUS_NAME_WATCHER_FLAGS_NONE,
									  on_broker_appeared, on_broker_vanished,
									  &ctx, NULL);
	g_unix_fd_add(STDIN_FILENO, G_IO_IN | G_IO_HUP | G_IO_ERR, on_stdin_ready,
				  &ctx);

	g_printerr("Running as native messaging instance.\n");
	g_main_loop_run(ctx.loop);

	g_bus_unwatch_name(watch_id);
	g_main_loop_unref(ctx.loop);
	g_hash_table_destroy(ctx.accounts);
	g_clear_object(&ctx.app);
	return 0;
}
