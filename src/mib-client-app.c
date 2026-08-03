/*
 * SPDX-FileCopyrightText: (C) 2025 Siemens
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include "identity-broker.h"
#include "mib-account-impl.h"
#include "mib-client-app-impl.h"
#include "mib-pop-params-impl.h"
#include "mib-prt-impl.h"
#include "mib-prt-sso-cookie-impl.h"
#include "mib-utils.h"

#define DBUS_BROKER_NAME "com.microsoft.identity.broker1"
#define DBUS_BROKER_PATH "/com/microsoft/identity/broker1"

// according to https://msal-python.readthedocs.io/en/latest/#publicclientapplication
#define MIB_MS_BROKER_REDIRECT_URI \
	"https://login.microsoftonline.com/common/oauth2/nativeclient"

// MSAL does not define any lower-bound (yet)
#define MIB_REQUIRED_BROKER_PROTOCOL_VERSION "0.0"

/*
 * Values from MSAL runtime (internal interface)
 */
enum AuthorizationType {
	AT_NONE = 0,
	AT_CACHED_REFRESH_TOKEN = 1,
	AT_IMPORTED_REFRESH_TOKEN = 2,
	AT_USERNAME_PASSWORD = 3,
	AT_WINDOWS_INTEGRATED_AUTH = 4,
	AT_AUTH_CODE = 5,
	AT_INTERACTIVE = 6,
	AT_CERTIFICATE = 7,
	AT_PRT_SSO_COOKIE = 8,
	AT_COMPLETE_BROKER_RESULT = 9,
	AT_DEVICE_INFO_REQUEST = 10,
	AT_SIGN_OUT_INTERACTIVE = 11,
	AT_SIGN_OUT_SILENT = 12,
	AT_ACCOUNT_TRANSFER = 13
};

struct _MIBClientApp {
	GObject parent_instance;

	gchar client_id[UUID_STR_LEN];
	gchar correlation_id[UUID_STR_LEN];
	gchar *authority;
	gchar *redirect_uri;
	mibdbusIdentityBroker1 *broker;
	GCancellable *cancellable;
	int log_level;
	/* enforce an interactive login on acquireTokenInteractive */
	char enforce_interactive;
};
G_DEFINE_TYPE(MIBClientApp, mib_client_app, G_TYPE_OBJECT)

typedef struct {
	GSList *scopes;
	enum MIB_PROMPT prompt;
	gchar *domain_hint;
	gchar *claims_challenge;
	MIBPopParams *pop_params;
	gchar *login_hint;
	MIBAccount *account;
} InteractiveAsyncCtx;

static void interactive_async_ctx_free(gpointer data)
{
	InteractiveAsyncCtx *ctx = data;
	g_free(ctx->login_hint);
	g_free(ctx->domain_hint);
	g_free(ctx->claims_challenge);
	g_clear_object(&ctx->pop_params);
	g_clear_object(&ctx->account);
	g_slist_free_full(ctx->scopes, g_free);
	g_free(ctx);
}

static void mib_client_app_finalize(GObject *gobject)
{
	MIBClientApp *priv = MIB_CLIENT_APP(gobject);
	g_clear_object(&priv->cancellable);
	g_clear_object(&priv->broker);
	g_clear_pointer(&priv->authority, g_free);
	g_clear_pointer(&priv->redirect_uri, g_free);
	G_OBJECT_CLASS(mib_client_app_parent_class)->finalize(gobject);
}

static void mib_client_app_class_init(MIBClientAppClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS(klass);
	object_class->finalize = mib_client_app_finalize;
}

static void mib_client_app_init(MIBClientApp *self)
{
	const gchar *loglevel = g_getenv("MIB_LOG_LEVEL");
	if (loglevel) {
		self->log_level = atoi(loglevel);
	}
}

MIBClientApp *mib_public_client_app_new(const gchar *client_id,
										const gchar *authority,
										GCancellable *cancellable,
										GError **error)
{
	uuid_t correlation_id;

	g_assert(client_id);
	g_assert(authority);

	uuid_t client_uuid;
	if (uuid_parse(client_id, client_uuid) != 0) {
		g_warning("client id is not a UUID\n");
		return NULL;
	}

	MIBClientApp *self = g_object_new(MIB_TYPE_CLIENT_APP, NULL);
	uuid_unparse_lower(client_uuid, self->client_id);
	uuid_generate_random(correlation_id);
	uuid_unparse_lower(correlation_id, self->correlation_id);
	self->authority = g_strdup(authority);
	self->redirect_uri = mib_client_app_get_broker_redirect_uri(self);

	if (cancellable) {
		self->cancellable = g_object_ref(cancellable);
	}

	self->broker = mib_dbus_identity_broker1_proxy_new_for_bus_sync(
		G_BUS_TYPE_SESSION,
		G_DBUS_PROXY_FLAGS_DO_NOT_AUTO_START_AT_CONSTRUCTION, DBUS_BROKER_NAME,
		DBUS_BROKER_PATH, self->cancellable, error);

	if (!self->broker) {
		if (error && *error)
			g_dbus_error_strip_remote_error(*error);
		g_prefix_error(error, "Failed to create broker proxy: ");
		g_clear_object(&self);
	}
	return self;
}

static gchar *mib_prompt_to_str(enum MIB_PROMPT prompt)
{
	/* todo: return space separated list of enabled entries */
	if (prompt & MIB_PROMPT_SELECT_ACCOUNT) {
		return g_strdup("select_account");
	} else if (prompt & MIB_PROMPT_CONSENT) {
		return g_strdup("consent");
	} else if (prompt & MIB_PROMPT_LOGIN) {
		return g_strdup("login");
	} else if (prompt & MIB_PROMPT_NONE) {
		return g_strdup("none");
	} else {
		return g_strdup("");
	}
}

static gchar *get_accounts_prepare_request(MIBClientApp *app)
{
	JsonBuilder *builder;
	JsonNode *root;

	builder = json_builder_new();
	json_builder_begin_object(builder);
	json_builder_set_member_name(builder, "clientId");
	json_builder_add_string_value(builder, mib_client_app_get_client_id(app));
	json_builder_set_member_name(builder, "redirectUri");
	json_builder_add_string_value(builder, app->redirect_uri);
	json_builder_end_object(builder);
	root = json_builder_get_root(builder);
	g_object_unref(builder);
	JsonObject *params = json_node_get_object(root);
	debug_print_json_object("mib_client_app_get_accounts", "request", params);
	gchar *data = json_object_to_string(params);
	json_node_unref(root);
	return data;
}

static GSList *get_accounts_process_response(const gchar *response)
{
	JsonArray *accounts_array = NULL;
	GSList *accounts_list = NULL;
	MIBAccount *mib_account = NULL;

	JsonObject *accounts = json_object_from_string(response);
	if (!accounts) {
		g_warning("could not parse accounts response");
		return NULL;
	}
	debug_print_json_object("mib_client_app_get_accounts", "response",
							accounts);

	if (!json_object_has_member(accounts, "accounts")) {
		json_object_unref(accounts);
		return NULL;
	}

	accounts_array = json_object_get_array_member(accounts, "accounts");
	for (guint i = 0; i < json_array_get_length(accounts_array); i++) {
		JsonObject *account = json_array_get_object_element(accounts_array, i);
		mib_account = mib_account_from_json(account);
		if (!mib_account) {
			g_warning("error parsing account data");
			break;
		}
		accounts_list = g_slist_prepend(accounts_list, mib_account);
	}
	json_object_unref(accounts);
	return g_slist_reverse(accounts_list);
}

GSList *mib_client_app_get_accounts(MIBClientApp *app)
{
	GError *error = NULL;
	gchar *response = NULL;
	gchar *data = NULL;
	GSList *accounts = NULL;
	gboolean ok;

	g_assert(app);

	data = get_accounts_prepare_request(app);

	ok = mib_dbus_identity_broker1_call_get_accounts_sync(
		mib_client_app_get_broker(app), MIB_REQUIRED_BROKER_PROTOCOL_VERSION,
		mib_client_app_get_correlation_id(app), data, &response,
		mib_client_app_get_cancellable(app), &error);
	g_free(data);
	if (!ok) {
		g_warning("could not get accounts: %s", error->message);
		g_error_free(error);
		return NULL;
	}

	accounts = get_accounts_process_response(response);
	g_free(response);
	return accounts;
}

static void get_accounts_async_cb(GObject *source_object, GAsyncResult *res,
								  gpointer user_data)
{
	GTask *task = G_TASK(user_data);
	mibdbusIdentityBroker1 *proxy = MIB_DBUS_IDENTITY_BROKER1(source_object);
	GError *error = NULL;
	gchar *response = NULL;
	gboolean ok;

	ok = mib_dbus_identity_broker1_call_get_accounts_finish(proxy, &response,
															res, &error);
	if (!ok) {
		g_task_return_error(task, error);
	} else {
		GSList *accounts = get_accounts_process_response(response);
		g_free(response);
		g_task_return_pointer(task, accounts, NULL);
	}
	g_object_unref(task);
}

void mib_client_app_get_accounts_async(MIBClientApp *app,
									   GAsyncReadyCallback callback,
									   gpointer user_data)
{
	GTask *task;
	gchar *data;

	g_assert(app);

	task = g_task_new(app, mib_client_app_get_cancellable(app), callback,
					  user_data);
	data = get_accounts_prepare_request(app);

	mib_dbus_identity_broker1_call_get_accounts(
		mib_client_app_get_broker(app), MIB_REQUIRED_BROKER_PROTOCOL_VERSION,
		mib_client_app_get_correlation_id(app), data,
		mib_client_app_get_cancellable(app), get_accounts_async_cb, task);
	g_free(data);
}

GSList *mib_client_app_get_accounts_finish(MIBClientApp *app,
										   GAsyncResult *result, GError **error)
{
	g_assert(app);
	g_assert(g_task_is_valid(result, app));

	return g_task_propagate_pointer(G_TASK(result), error);
}

MIBAccount *mib_client_app_get_account_by_upn(MIBClientApp *app,
											  const gchar *upn)
{
	GSList *accounts = mib_client_app_get_accounts(app);
	MIBAccount *account;

	g_assert(app);

	account = find_account_by_upn(accounts, upn);
	g_slist_free_full(accounts, (GDestroyNotify)g_object_unref);
	return account;
}

static void get_account_by_upn_async_cb(GObject *source_object,
										GAsyncResult *res, gpointer user_data)
{
	GTask *task = G_TASK(user_data);
	MIBClientApp *app = MIB_CLIENT_APP(source_object);
	const gchar *upn = g_task_get_task_data(task);
	GError *error = NULL;
	GSList *accounts;

	accounts = mib_client_app_get_accounts_finish(app, res, &error);
	if (error) {
		g_task_return_error(task, error);
	} else {
		MIBAccount *account = find_account_by_upn(accounts, upn);
		g_slist_free_full(accounts, (GDestroyNotify)g_object_unref);
		if (account) {
			g_task_return_pointer(task, account, g_object_unref);
		} else {
			g_task_return_new_error(task, G_IO_ERROR, G_IO_ERROR_NOT_FOUND,
									"no account matching the UPN was found");
		}
	}
	g_object_unref(task);
}

void mib_client_app_get_account_by_upn_async(MIBClientApp *app,
											 const gchar *upn,
											 GAsyncReadyCallback callback,
											 gpointer user_data)
{
	GTask *task;

	g_assert(app);

	task = g_task_new(app, mib_client_app_get_cancellable(app), callback,
					  user_data);
	g_task_set_task_data(task, g_strdup(upn), g_free);

	mib_client_app_get_accounts_async(app, get_account_by_upn_async_cb, task);
}

MIBAccount *mib_client_app_get_account_by_upn_finish(MIBClientApp *app,
													 GAsyncResult *result,
													 GError **error)
{
	g_assert(app);
	g_assert(g_task_is_valid(result, app));

	return g_task_propagate_pointer(G_TASK(result), error);
}

mibdbusIdentityBroker1 *mib_client_app_get_broker(MIBClientApp *self)
{
	g_assert(self);
	return self->broker;
}
const gchar *mib_client_app_get_client_id(const MIBClientApp *self)
{
	g_assert(self);
	return self->client_id;
}
const gchar *mib_client_app_get_correlation_id(const MIBClientApp *self)
{
	g_assert(self);
	return self->correlation_id;
}
const gchar *mib_client_app_get_authority(const MIBClientApp *self)
{
	g_assert(self);
	return self->authority;
}
GCancellable *mib_client_app_get_cancellable(MIBClientApp *self)
{
	g_assert(self);
	return self->cancellable;
}

gchar *mib_client_app_get_broker_redirect_uri(const MIBClientApp *self)
{
	g_assert(self);
	return g_strdup(MIB_MS_BROKER_REDIRECT_URI);
}

void mib_client_app_set_redirect_uri(MIBClientApp *self, const gchar *uri)
{
	g_assert(self);
	g_assert(uri);
	g_free(self->redirect_uri);
	self->redirect_uri = g_strdup(uri);
}

int mib_client_app_get_enforce_interactive(const MIBClientApp *self)
{
	g_assert(self);
	return (int)self->enforce_interactive;
}

void mib_client_app_set_enforce_interactive(MIBClientApp *self, int enforce)
{
	g_assert(self);
	self->enforce_interactive = (char)enforce;
}

static gchar *
linux_broker_version_prepare_request(MIBClientApp *app,
									 const gchar *msal_cpp_version)
{
	JsonObject *params;
	gchar *params_data;

	params = json_object_new();
	json_object_set_string_member(params, "msalCppVersion", msal_cpp_version);
	debug_print_json_object("mib_get_linux_broker_version", "request", params);
	params_data = json_object_to_string(params);
	json_object_unref(params);
	return params_data;
}

static gchar *linux_broker_version_process_response(const gchar *response)
{
	gchar *version = NULL;
	JsonObject *version_json = json_object_from_string(response);
	if (!version_json)
		goto err;
	debug_print_json_object("mib_get_linux_broker_version", "response",
							version_json);

	if (!json_object_has_member(version_json, "linuxBrokerVersion")) {
		goto err;
	}
	version = g_strdup(
		json_object_get_string_member(version_json, "linuxBrokerVersion"));
err:
	if (version_json)
		json_object_unref(version_json);
	return version;
}

gchar *mib_client_app_get_linux_broker_version(MIBClientApp *app,
											   const gchar *msal_cpp_version)
{
	GError *error = NULL;
	gchar *params_data;
	gchar *response;
	gchar *version = NULL;
	gboolean ok;

	g_assert(app);
	g_assert(msal_cpp_version);

	params_data = linux_broker_version_prepare_request(app, msal_cpp_version);
	if (!params_data) {
		return NULL;
	}

	ok = mib_dbus_identity_broker1_call_get_linux_broker_version_sync(
		mib_client_app_get_broker(app), MIB_REQUIRED_BROKER_PROTOCOL_VERSION,
		mib_client_app_get_correlation_id(app), params_data, &response,
		mib_client_app_get_cancellable(app), &error);
	g_free(params_data);
	if (!ok) {
		g_warning("could not get Linux broker version: %s", error->message);
		g_error_free(error);
		return NULL;
	}

	version = linux_broker_version_process_response(response);
	g_free(response);
	return version;
}

static void get_linux_broker_version_async_cb(GObject *source_object,
											  GAsyncResult *res,
											  gpointer user_data)
{
	GTask *task = G_TASK(user_data);
	mibdbusIdentityBroker1 *proxy = MIB_DBUS_IDENTITY_BROKER1(source_object);
	GError *error = NULL;
	gchar *response = NULL;
	gboolean ok;

	ok = mib_dbus_identity_broker1_call_get_linux_broker_version_finish(
		proxy, &response, res, &error);
	if (!ok) {
		g_task_return_error(task, error);
	} else {
		gchar *version = linux_broker_version_process_response(response);
		g_free(response);
		if (version) {
			g_task_return_pointer(task, version, g_free);
		} else {
			g_task_return_new_error(task, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
									"could not parse broker version response");
		}
	}
	g_object_unref(task);
}

void mib_client_app_get_linux_broker_version_async(
	MIBClientApp *app, const gchar *msal_cpp_version,
	GAsyncReadyCallback callback, gpointer user_data)
{
	GTask *task;
	gchar *params_data;

	g_assert(app);
	g_assert(msal_cpp_version);

	task = g_task_new(app, mib_client_app_get_cancellable(app), callback,
					  user_data);
	params_data = linux_broker_version_prepare_request(app, msal_cpp_version);

	mib_dbus_identity_broker1_call_get_linux_broker_version(
		mib_client_app_get_broker(app), MIB_REQUIRED_BROKER_PROTOCOL_VERSION,
		mib_client_app_get_correlation_id(app), params_data,
		mib_client_app_get_cancellable(app), get_linux_broker_version_async_cb,
		task);
	g_free(params_data);
}

gchar *mib_client_app_get_linux_broker_version_finish(MIBClientApp *app,
													  GAsyncResult *result,
													  GError **error)
{
	g_assert(app);
	g_assert(g_task_is_valid(result, app));

	return g_task_propagate_pointer(G_TASK(result), error);
}

static JsonObject *
prepare_prt_auth_params(MIBClientApp *app, MIBAccount *account, GSList *scopes,
						const gchar *claims_challenge, MIBPopParams *pop_params,
						const gchar *renew_token, JsonObject *extra_params,
						const gchar *sso_url, enum AuthorizationType auth_type)
{
	// {
	//  'accessTokenToRenew': renew_token,
	//  'account': account,
	//  'authority': context['authority']
	//  'authorizationType': 8 (cookie with sso_url), 1 otherwise
	//  'clientId': client_id,
	//  'redirectUri':
	//  '<context['authority']>/oauth2/nativeclient',
	//  'requestedScopes': ["https://graph.microsoft.com/.default"],
	//  'username': account['username'],
	//  'ssoUrl': sso_url,
	// }

	JsonArray *scopes_json = mib_scopes_to_json(scopes);
	JsonObject *account_json = mib_account_to_json(account);

	JsonNode *account_node = json_node_new(JSON_NODE_OBJECT);
	json_node_set_object(account_node, account_json);
	json_object_unref(account_json);
	JsonNode *scopes_node = json_node_new(JSON_NODE_ARRAY);
	json_node_set_array(scopes_node, scopes_json);
	json_array_unref(scopes_json);
	const gchar *username = mib_account_get_username(account);

	JsonBuilder *builder = json_builder_new();
	json_builder_begin_object(builder);
	if (renew_token) {
		json_builder_set_member_name(builder, "accessTokenToRenew");
		json_builder_add_string_value(builder, renew_token);
	}
	json_builder_set_member_name(builder, "account");
	json_builder_add_value(builder, account_node);
	json_builder_set_member_name(builder, "authority");
	json_builder_add_string_value(builder, mib_client_app_get_authority(app));
	json_builder_set_member_name(builder, "authorizationType");
	json_builder_add_int_value(builder, auth_type);
	json_builder_set_member_name(builder, "clientId");
	json_builder_add_string_value(builder, mib_client_app_get_client_id(app));
	if (claims_challenge) {
		json_builder_set_member_name(builder, "decodedClaims");
		json_builder_add_string_value(builder, claims_challenge);
	}
	if (pop_params) {
		JsonObject *auth_scheme = mib_pop_params_to_json(pop_params);
		JsonNode *auth_scheme_node = json_node_new(JSON_NODE_OBJECT);
		json_node_set_object(auth_scheme_node, auth_scheme);
		json_object_unref(auth_scheme);
		json_builder_set_member_name(builder, "popParams");
		json_builder_add_value(builder, auth_scheme_node);
	}
	if (extra_params) {
		JsonNode *extra_params_node = json_node_new(JSON_NODE_OBJECT);
		json_node_set_object(extra_params_node, extra_params);
		json_builder_set_member_name(
			builder, "additionalQueryParametersForAuthorization");
		json_builder_add_value(builder, extra_params_node);
	}
	json_builder_set_member_name(builder, "redirectUri");
	json_builder_add_string_value(builder, app->redirect_uri);
	json_builder_set_member_name(builder, "requestedScopes");
	json_builder_add_value(builder, scopes_node);
	json_builder_set_member_name(builder, "username");
	json_builder_add_string_value(builder, username);
	if (sso_url) {
		json_builder_set_member_name(builder, "ssoUrl");
		json_builder_add_string_value(builder, sso_url);
	}
	json_builder_end_object(builder);

	JsonNode *root = json_builder_get_root(builder);
	JsonObject *auth_params = json_node_get_object(root);
	json_object_ref(auth_params);
	g_object_unref(builder);
	json_node_unref(root);
	return auth_params;
}

static gchar *acquire_token_silent_prepare_request(
	MIBClientApp *app, MIBAccount *account, GSList *scopes,
	const gchar *claims_challenge, MIBPopParams *pop_params,
	const gchar *renew_token)
{
	JsonObject *auth_params = prepare_prt_auth_params(
		app, account, scopes, claims_challenge, pop_params, renew_token, NULL,
		NULL, AT_CACHED_REFRESH_TOKEN);
	JsonNode *auth_params_node = json_node_new(JSON_NODE_OBJECT);
	json_node_set_object(auth_params_node, auth_params);
	json_object_unref(auth_params);

	JsonObject *params_obj = json_object_new();
	json_object_set_member(params_obj, "authParameters", auth_params_node);
	debug_print_json_object("mib_acquire_token_silent", "request", params_obj);
	gchar *data = json_object_to_string(params_obj);
	json_object_unref(params_obj);

	return data;
}

MIBPrt *mib_client_app_acquire_token_silent(MIBClientApp *app,
											MIBAccount *account, GSList *scopes,
											const gchar *claims_challenge,
											MIBPopParams *auth_scheme,
											const gchar *id_token)
{
	GError *error = NULL;
	gchar *response;
	gboolean ok;
	JsonObject *token_json;

	g_assert(app);
	g_assert(account);
	g_assert(scopes);

	gchar *data = acquire_token_silent_prepare_request(
		app, account, scopes, claims_challenge, auth_scheme, id_token);
	if (!data) {
		return NULL;
	}

	ok = mib_dbus_identity_broker1_call_acquire_token_silently_sync(
		mib_client_app_get_broker(app), MIB_REQUIRED_BROKER_PROTOCOL_VERSION,
		mib_client_app_get_correlation_id(app), data, &response,
		mib_client_app_get_cancellable(app), &error);
	g_free(data);
	if (!ok) {
		g_warning("could not acquire token: %s", error->message);
		g_error_free(error);
		return NULL;
	}
	token_json = json_object_from_string(response);
	g_free(response);
	if (!token_json) {
		g_warning("could not parse token response");
		return NULL;
	}
	debug_print_json_object("mib_acquire_token_silent", "response", token_json);

	MIBPrt *token = mib_prt_from_json(token_json, account);
	json_object_unref(token_json);
	return token;
}

static void acquire_token_silent_async_cb(GObject *source_object,
										  GAsyncResult *res, gpointer user_data)
{
	GTask *task = G_TASK(user_data);
	mibdbusIdentityBroker1 *proxy = MIB_DBUS_IDENTITY_BROKER1(source_object);
	MIBAccount *account = g_task_get_task_data(task);
	GError *error = NULL;
	gchar *response = NULL;
	gboolean ok;

	ok = mib_dbus_identity_broker1_call_acquire_token_silently_finish(
		proxy, &response, res, &error);
	if (!ok) {
		g_task_return_error(task, error);
	} else {
		JsonObject *token_json = json_object_from_string(response);
		g_free(response);
		if (!token_json) {
			g_task_return_new_error(task, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
									"could not parse token response");
		} else {
			debug_print_json_object("mib_acquire_token_silent", "response",
									token_json);
			MIBPrt *token = mib_prt_from_json(token_json, account);
			json_object_unref(token_json);
			if (token) {
				g_task_return_pointer(task, token, g_object_unref);
			} else {
				g_task_return_new_error(task, G_IO_ERROR,
										G_IO_ERROR_INVALID_DATA,
										"could not parse token from response");
			}
		}
	}
	g_object_unref(task);
}

void mib_client_app_acquire_token_silent_async(
	MIBClientApp *app, MIBAccount *account, GSList *scopes,
	const gchar *claims_challenge, MIBPopParams *auth_scheme,
	const gchar *id_token, GAsyncReadyCallback callback, gpointer user_data)
{
	GTask *task;
	gchar *data;

	g_assert(app);
	g_assert(account);
	g_assert(scopes);

	task = g_task_new(app, mib_client_app_get_cancellable(app), callback,
					  user_data);
	g_task_set_task_data(task, g_object_ref(account), g_object_unref);

	data = acquire_token_silent_prepare_request(
		app, account, scopes, claims_challenge, auth_scheme, id_token);

	mib_dbus_identity_broker1_call_acquire_token_silently(
		mib_client_app_get_broker(app), MIB_REQUIRED_BROKER_PROTOCOL_VERSION,
		mib_client_app_get_correlation_id(app), data,
		mib_client_app_get_cancellable(app), acquire_token_silent_async_cb,
		task);
	g_free(data);
}

MIBPrt *mib_client_app_acquire_token_silent_finish(MIBClientApp *app,
												   GAsyncResult *result,
												   GError **error)
{
	g_assert(app);
	g_assert(g_task_is_valid(result, app));

	return g_task_propagate_pointer(G_TASK(result), error);
}

static gchar *acquire_token_interactive_prepare_request(
	MIBClientApp *app, GSList *scopes, enum MIB_PROMPT prompt,
	MIBAccount *account, MIB_ARG_UNUSED const gchar *domain_hint,
	const gchar *claims_challenge, MIBPopParams *pop_params,
	JsonObject *extra_params)
{
	JsonObject *auth_params = prepare_prt_auth_params(
		app, account, scopes, claims_challenge, pop_params, NULL, extra_params,
		NULL, AT_INTERACTIVE);

	/* TODO: check if this is the correct key */
	if (prompt != MIB_PROMPT_UNSET) {
		gchar *prompt_str = mib_prompt_to_str(prompt);
		json_object_set_string_member(auth_params, "prompt", prompt_str);
		g_free(prompt_str);
	}
	JsonNode *auth_params_node = json_node_new(JSON_NODE_OBJECT);
	json_node_set_object(auth_params_node, auth_params);

	JsonObject *params_obj = json_object_new();
	/* if a re-auth is requested, clear the account */
	if (prompt & MIB_PROMPT_SELECT_ACCOUNT) {
		json_object_remove_member(auth_params, "account");
		json_object_remove_member(auth_params, "username");
	}
	json_object_unref(auth_params);

	json_object_set_member(params_obj, "authParameters", auth_params_node);
	debug_print_json_object("mib_acquire_token_interactive", "request",
							params_obj);
	gchar *data = json_object_to_string(params_obj);
	json_object_unref(params_obj);
	return data;
}

static MIBPrt *acquire_token_interactive_process_response(const gchar *response,
														  MIBAccount *account)
{
	MIBPrt *token = NULL;
	JsonObject *token_json = json_object_from_string(response);
	if (!token_json) {
		g_warning("could not parse token response");
		return NULL;
	}
	debug_print_json_object("mib_acquire_token_interactive", "response",
							token_json);
	token = mib_prt_from_json(token_json, account);
	json_object_unref(token_json);

	return token;
}

MIBPrt *mib_client_app_acquire_token_interactive(
	MIBClientApp *app, GSList *scopes, enum MIB_PROMPT prompt,
	const gchar *login_hint, const gchar *domain_hint,
	const gchar *claims_challenge, MIBPopParams *pop_params)
{
	MIBPrt *token = NULL;
	gchar *response = NULL;
	GError *error = NULL;
	gboolean ok;

	g_assert(app);
	g_assert(scopes);

	MIBAccount *account = mib_client_app_get_account_by_upn(app, login_hint);
	if (!account) {
		return NULL;
	}

	/* first try silent, on error try interactive */
	if (!mib_client_app_get_enforce_interactive(app)) {
		token = mib_client_app_acquire_token_silent(
			app, account, scopes, claims_challenge, pop_params, NULL);
	}
	if (!token) {
		gchar *data = acquire_token_interactive_prepare_request(
			app, scopes, prompt, account, domain_hint, claims_challenge,
			pop_params, NULL);

		/* disable dbus timeout before call and restore after as user input is needed */
		mibdbusIdentityBroker1 *gd_proxy = mib_client_app_get_broker(app);
		g_dbus_proxy_set_default_timeout((GDBusProxy *)gd_proxy, G_MAXINT);
		ok = mib_dbus_identity_broker1_call_acquire_token_interactively_sync(
			gd_proxy, MIB_REQUIRED_BROKER_PROTOCOL_VERSION,
			mib_client_app_get_correlation_id(app), data, &response,
			mib_client_app_get_cancellable(app), &error);
		g_free(data);
		g_dbus_proxy_set_default_timeout((GDBusProxy *)gd_proxy, -1);
		if (!ok) {
			g_warning("could not acquire token: %s", error->message);
			g_error_free(error);
			goto err;
		}

		token = acquire_token_interactive_process_response(response, account);
		g_free(response);
	}
err:
	g_clear_object(&account);
	return token;
}

static void acquire_token_interactive_async_cb(GObject *source_object,
											   GAsyncResult *res,
											   gpointer user_data)
{
	GTask *task = G_TASK(user_data);
	mibdbusIdentityBroker1 *proxy = MIB_DBUS_IDENTITY_BROKER1(source_object);
	InteractiveAsyncCtx *ctx = g_task_get_task_data(task);
	GError *error = NULL;
	gchar *response = NULL;
	gboolean ok;

	/* restore default dbus timeout */
	g_dbus_proxy_set_default_timeout((GDBusProxy *)proxy, -1);

	ok = mib_dbus_identity_broker1_call_acquire_token_interactively_finish(
		proxy, &response, res, &error);
	if (!ok) {
		g_task_return_error(task, error);
	} else {
		MIBPrt *token =
			acquire_token_interactive_process_response(response, ctx->account);
		g_free(response);
		if (token) {
			g_task_return_pointer(task, token, g_object_unref);
		} else {
			g_task_return_new_error(
				task, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
				"could not parse interactive token response");
		}
	}
	g_object_unref(task);
}

static void interactive_async_start_interactive(GTask *task)
{
	InteractiveAsyncCtx *ctx = g_task_get_task_data(task);
	MIBClientApp *app = g_task_get_source_object(task);

	gchar *data = acquire_token_interactive_prepare_request(
		app, ctx->scopes, ctx->prompt, ctx->account, ctx->domain_hint,
		ctx->claims_challenge, ctx->pop_params, NULL);

	/* disable dbus timeout as user input is needed */
	mibdbusIdentityBroker1 *gd_proxy = mib_client_app_get_broker(app);
	g_dbus_proxy_set_default_timeout((GDBusProxy *)gd_proxy, G_MAXINT);

	mib_dbus_identity_broker1_call_acquire_token_interactively(
		gd_proxy, MIB_REQUIRED_BROKER_PROTOCOL_VERSION,
		mib_client_app_get_correlation_id(app), data,
		mib_client_app_get_cancellable(app), acquire_token_interactive_async_cb,
		task);
	g_free(data);
}

static void interactive_silent_cb(GObject *source_object, GAsyncResult *res,
								  gpointer user_data)
{
	GTask *task = G_TASK(user_data);
	mibdbusIdentityBroker1 *proxy = MIB_DBUS_IDENTITY_BROKER1(source_object);
	InteractiveAsyncCtx *ctx = g_task_get_task_data(task);
	GError *error = NULL;
	gchar *response = NULL;
	gboolean ok;

	ok = mib_dbus_identity_broker1_call_acquire_token_silently_finish(
		proxy, &response, res, &error);
	if (ok) {
		JsonObject *token_json = json_object_from_string(response);
		g_free(response);
		if (token_json) {
			debug_print_json_object("mib_acquire_token_silent", "response",
									token_json);
			MIBPrt *token = mib_prt_from_json(token_json, ctx->account);
			json_object_unref(token_json);
			if (token) {
				g_task_return_pointer(task, token, g_object_unref);
				g_object_unref(task);
				return;
			}
		}
	} else {
		g_error_free(error);
	}

	/* Silent failed, fall back to interactive */
	interactive_async_start_interactive(task);
}

static void interactive_get_accounts_cb(GObject *source_object,
										GAsyncResult *res, gpointer user_data)
{
	GTask *task = G_TASK(user_data);
	mibdbusIdentityBroker1 *proxy = MIB_DBUS_IDENTITY_BROKER1(source_object);
	InteractiveAsyncCtx *ctx = g_task_get_task_data(task);
	MIBClientApp *app = g_task_get_source_object(task);
	GError *error = NULL;
	gchar *response = NULL;
	gboolean ok;

	ok = mib_dbus_identity_broker1_call_get_accounts_finish(proxy, &response,
															res, &error);
	if (!ok) {
		g_task_return_error(task, error);
		g_object_unref(task);
		return;
	}

	GSList *accounts = get_accounts_process_response(response);
	g_free(response);

	MIBAccount *account = find_account_by_upn(accounts, ctx->login_hint);

	if (!account) {
		g_slist_free_full(accounts, (GDestroyNotify)g_object_unref);
		g_task_return_new_error(task, G_IO_ERROR, G_IO_ERROR_NOT_FOUND,
								"could not find account for login hint");
		g_object_unref(task);
		return;
	}

	ctx->account = account;
	g_slist_free_full(accounts, (GDestroyNotify)g_object_unref);

	/* Try silent first (unless enforce_interactive) */
	if (!mib_client_app_get_enforce_interactive(app)) {
		gchar *data = acquire_token_silent_prepare_request(
			app, ctx->account, ctx->scopes, ctx->claims_challenge,
			ctx->pop_params, NULL);

		mib_dbus_identity_broker1_call_acquire_token_silently(
			mib_client_app_get_broker(app),
			MIB_REQUIRED_BROKER_PROTOCOL_VERSION,
			mib_client_app_get_correlation_id(app), data,
			mib_client_app_get_cancellable(app), interactive_silent_cb, task);
		g_free(data);
		return;
	}

	/* Go straight to interactive */
	interactive_async_start_interactive(task);
}

void mib_client_app_acquire_token_interactive_async(
	MIBClientApp *app, GSList *scopes, enum MIB_PROMPT prompt,
	const gchar *login_hint, const gchar *domain_hint,
	const gchar *claims_challenge, MIBPopParams *pop_params,
	GAsyncReadyCallback callback, gpointer user_data)
{
	GTask *task;
	InteractiveAsyncCtx *ctx;

	g_assert(app);
	g_assert(scopes);

	task = g_task_new(app, mib_client_app_get_cancellable(app), callback,
					  user_data);

	ctx = g_new0(InteractiveAsyncCtx, 1);
	ctx->scopes = g_slist_copy_deep(scopes, copy_string, NULL);
	ctx->prompt = prompt;
	ctx->login_hint = g_strdup(login_hint);
	ctx->domain_hint = g_strdup(domain_hint);
	ctx->claims_challenge = g_strdup(claims_challenge);
	ctx->pop_params = pop_params ? g_object_ref(pop_params) : NULL;
	g_task_set_task_data(task, ctx, interactive_async_ctx_free);

	/* Step 1: get accounts async */
	gchar *data = get_accounts_prepare_request(app);
	mib_dbus_identity_broker1_call_get_accounts(
		mib_client_app_get_broker(app), MIB_REQUIRED_BROKER_PROTOCOL_VERSION,
		mib_client_app_get_correlation_id(app), data,
		mib_client_app_get_cancellable(app), interactive_get_accounts_cb, task);
	g_free(data);
}

MIBPrt *mib_client_app_acquire_token_interactive_finish(MIBClientApp *app,
														GAsyncResult *result,
														GError **error)
{
	g_assert(app);
	g_assert(g_task_is_valid(result, app));

	return g_task_propagate_pointer(G_TASK(result), error);
}

static gchar *acquire_prt_sso_cookie_request_prepare(MIBClientApp *app,
													 MIBAccount *account,
													 GSList *scopes,
													 const gchar *sso_url)
{
	// {
	//  'account': account,
	//  'authParameters': params,
	//  'ssoUrl': sso_url
	// }
	gchar *data = NULL;

	JsonObject *auth_params =
		prepare_prt_auth_params(app, account, scopes, NULL, NULL, NULL, NULL,
								sso_url, AT_PRT_SSO_COOKIE);
	JsonObject *account_json = mib_account_to_json(account);

	JsonObject *params_obj = json_object_new();
	JsonNode *account_node = json_node_new(JSON_NODE_OBJECT);
	json_node_set_object(account_node, account_json);
	json_object_unref(account_json);
	JsonNode *auth_params_node = json_node_new(JSON_NODE_OBJECT);
	json_node_set_object(auth_params_node, auth_params);
	json_object_unref(auth_params);
	JsonNode *sso_url_node = json_node_new(JSON_NODE_VALUE);
	json_node_set_string(sso_url_node, sso_url);

	json_object_set_member(params_obj, "account", account_node);
	json_object_set_member(params_obj, "authParameters", auth_params_node);
	json_object_set_member(params_obj, "ssoUrl", sso_url_node);

	debug_print_json_object("mib_acquire_prt_sso_cookie", "request",
							params_obj);
	data = json_object_to_string(params_obj);
	json_object_unref(params_obj);

	return data;
}

static MIBPrtSsoCookie *
acquire_prt_sso_cookie_process_response(const gchar *response)
{
	MIBPrtSsoCookie *cookie = NULL;
	JsonObject *cookie_json = json_object_from_string(response);
	if (!cookie_json) {
		g_warning("could not parse PRT SSO cookie response");
		return NULL;
	}
	debug_print_json_object("mib_acquire_prt_sso_cookie", "response",
							cookie_json);
	cookie = mib_prt_sso_cookie_from_json(cookie_json);
	json_object_unref(cookie_json);
	return cookie;
}

MIBPrtSsoCookie *mib_client_app_acquire_prt_sso_cookie(MIBClientApp *app,
													   MIBAccount *account,
													   const gchar *sso_url,
													   GSList *scopes)
{
	MIBPrtSsoCookie *cookie = NULL;
	gchar *data;
	GError *error = NULL;
	gchar *response;
	gboolean ok;

	g_assert(app);
	g_assert(account);
	g_assert(sso_url);
	g_assert(scopes);

	data =
		acquire_prt_sso_cookie_request_prepare(app, account, scopes, sso_url);

	ok = mib_dbus_identity_broker1_call_acquire_prt_sso_cookie_sync(
		mib_client_app_get_broker(app), MIB_REQUIRED_BROKER_PROTOCOL_VERSION,
		mib_client_app_get_correlation_id(app), data, &response,
		mib_client_app_get_cancellable(app), &error);
	g_free(data);
	if (!ok) {
		g_warning("could not acquire PRT SSO cookie: %s", error->message);
		g_error_free(error);
		return NULL;
	}
	cookie = acquire_prt_sso_cookie_process_response(response);
	g_free(response);
	return cookie;
}

static void acquire_prt_sso_cookie_async_cb(GObject *source_object,
											GAsyncResult *res,
											gpointer user_data)
{
	GTask *task = G_TASK(user_data);
	mibdbusIdentityBroker1 *proxy = MIB_DBUS_IDENTITY_BROKER1(source_object);
	GError *error = NULL;
	gchar *response = NULL;
	gboolean ok;

	ok = mib_dbus_identity_broker1_call_acquire_prt_sso_cookie_finish(
		proxy, &response, res, &error);
	if (!ok) {
		g_task_return_error(task, error);
	} else {
		MIBPrtSsoCookie *cookie =
			acquire_prt_sso_cookie_process_response(response);
		g_free(response);
		if (cookie) {
			g_task_return_pointer(task, cookie, g_object_unref);
		} else {
			g_task_return_new_error(task, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
									"could not parse PRT SSO cookie response");
		}
	}
	g_object_unref(task);
}

void mib_client_app_acquire_prt_sso_cookie_async(
	MIBClientApp *app, MIBAccount *account, const gchar *sso_url,
	GSList *scopes, GAsyncReadyCallback callback, gpointer user_data)
{
	GTask *task;
	gchar *data;

	g_assert(app);
	g_assert(account);
	g_assert(sso_url);
	g_assert(scopes);

	task = g_task_new(app, mib_client_app_get_cancellable(app), callback,
					  user_data);

	data =
		acquire_prt_sso_cookie_request_prepare(app, account, scopes, sso_url);

	mib_dbus_identity_broker1_call_acquire_prt_sso_cookie(
		mib_client_app_get_broker(app), MIB_REQUIRED_BROKER_PROTOCOL_VERSION,
		mib_client_app_get_correlation_id(app), data,
		mib_client_app_get_cancellable(app), acquire_prt_sso_cookie_async_cb,
		task);
	g_free(data);
}

MIBPrtSsoCookie *mib_client_app_acquire_prt_sso_cookie_finish(
	MIBClientApp *app, GAsyncResult *result, GError **error)
{
	g_assert(app);
	g_assert(g_task_is_valid(result, app));

	return g_task_propagate_pointer(G_TASK(result), error);
}

static gchar *generate_signed_http_request_prepare_request(
	MIBClientApp *app, MIBAccount *account, MIBPopParams *pop_params)
{
	gchar *data = NULL;
	const gchar *account_id = NULL;
	JsonObject *pop_params_json = NULL;
	JsonObject *params;

	if (pop_params) {
		pop_params_json = mib_pop_params_to_json(pop_params);
	} else {
		pop_params_json = json_object_new();
	}
	account_id = mib_account_get_home_account_id(account);
	json_object_set_string_member(pop_params_json, "homeAccountId", account_id);

	params = json_object_new();
	json_object_set_string_member(params, "clientId",
								  mib_client_app_get_client_id(app));
	json_object_set_object_member(params, "popParams", pop_params_json);

	debug_print_json_object("mib_generate_signed_http_request", "request",
							params);

	data = json_object_to_string(params);
	json_object_unref(params);
	return data;
}

static gchar *
generate_signed_http_request_process_response(const gchar *response)
{
	gchar *access_token = NULL;
	JsonObject *token_json = json_object_from_string(response);
	if (!token_json) {
		g_warning("could not parse signed HTTP request response");
		return NULL;
	}
	debug_print_json_object("mib_generate_signed_http_request", "response",
							token_json);

	if (!json_object_has_member(token_json, "signedHttpRequest")) {
		g_warning("response json is missing 'signedHttpRequest'");
		goto err;
	}
	access_token = g_strdup(
		json_object_get_string_member(token_json, "signedHttpRequest"));
err:
	json_object_unref(token_json);
	return access_token;
}

gchar *mib_client_app_generate_signed_http_request(MIBClientApp *app,
												   MIBAccount *account,
												   MIBPopParams *pop_params)
{
	GError *error = NULL;
	gboolean ok;
	gchar *response;
	gchar *data = NULL;
	gchar *access_token = NULL;

	g_assert(app);
	g_assert(account);

	data =
		generate_signed_http_request_prepare_request(app, account, pop_params);

	ok = mib_dbus_identity_broker1_call_generate_signed_http_request_sync(
		mib_client_app_get_broker(app), MIB_REQUIRED_BROKER_PROTOCOL_VERSION,
		mib_client_app_get_correlation_id(app), data, &response,
		mib_client_app_get_cancellable(app), &error);
	g_free(data);
	if (!ok) {
		g_warning("could not generate signed HTTP request: %s", error->message);
		g_error_free(error);
		return NULL;
	}
	access_token = generate_signed_http_request_process_response(response);
	g_free(response);
	return access_token;
}

static void generate_signed_http_request_async_cb(GObject *source_object,
												  GAsyncResult *res,
												  gpointer user_data)
{
	GTask *task = G_TASK(user_data);
	mibdbusIdentityBroker1 *proxy = MIB_DBUS_IDENTITY_BROKER1(source_object);
	GError *error = NULL;
	gchar *response = NULL;
	gboolean ok;

	ok = mib_dbus_identity_broker1_call_generate_signed_http_request_finish(
		proxy, &response, res, &error);
	if (!ok) {
		g_task_return_error(task, error);
	} else {
		gchar *access_token =
			generate_signed_http_request_process_response(response);
		g_free(response);
		if (access_token) {
			g_task_return_pointer(task, access_token, g_free);
		} else {
			g_task_return_new_error(
				task, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
				"could not parse signed HTTP request response");
		}
	}
	g_object_unref(task);
}

void mib_client_app_generate_signed_http_request_async(
	MIBClientApp *app, MIBAccount *account, MIBPopParams *pop_params,
	GAsyncReadyCallback callback, gpointer user_data)
{
	GTask *task;
	gchar *data;

	g_assert(app);
	g_assert(account);

	task = g_task_new(app, mib_client_app_get_cancellable(app), callback,
					  user_data);

	data =
		generate_signed_http_request_prepare_request(app, account, pop_params);

	mib_dbus_identity_broker1_call_generate_signed_http_request(
		mib_client_app_get_broker(app), MIB_REQUIRED_BROKER_PROTOCOL_VERSION,
		mib_client_app_get_correlation_id(app), data,
		mib_client_app_get_cancellable(app),
		generate_signed_http_request_async_cb, task);
	g_free(data);
}

gchar *mib_client_app_generate_signed_http_request_finish(MIBClientApp *app,
														  GAsyncResult *result,
														  GError **error)
{
	g_assert(app);
	g_assert(g_task_is_valid(result, app));

	return g_task_propagate_pointer(G_TASK(result), error);
}

static gchar *remove_account_prepare_request(MIBClientApp *app,
											 MIBAccount *account)
{
	JsonObject *params = json_object_new();
	json_object_set_string_member(params, "clientId", app->client_id);
	json_object_set_object_member(params, "account",
								  mib_account_to_json(account));

	debug_print_json_object("mib_remove_account", "request", params);

	gchar *data = json_object_to_string(params);
	json_object_unref(params);
	return data;
}

static void remove_account_process_response(const gchar *response)
{
	JsonObject *resp_json = json_object_from_string(response);
	debug_print_json_object("mib_remove_account", "response", resp_json);
	if (resp_json)
		json_object_unref(resp_json);
}

int mib_client_app_remove_account(MIBClientApp *app, MIBAccount *account)
{
	GError *error = NULL;
	gboolean ok;
	gchar *response = NULL;
	gchar *data = NULL;

	g_assert(app);
	g_assert(account);

	data = remove_account_prepare_request(app, account);
	ok = mib_dbus_identity_broker1_call_remove_account_sync(
		mib_client_app_get_broker(app), MIB_REQUIRED_BROKER_PROTOCOL_VERSION,
		mib_client_app_get_correlation_id(app), data, &response,
		mib_client_app_get_cancellable(app), &error);
	g_free(data);

	if (!ok) {
		g_warning("could not remove account: %s", error->message);
		g_error_free(error);
		return -1;
	}
	remove_account_process_response(response);
	g_free(response);
	return 0;
}

static void remove_account_async_cb(GObject *source_object, GAsyncResult *res,
									gpointer user_data)
{
	GTask *task = G_TASK(user_data);
	mibdbusIdentityBroker1 *proxy = MIB_DBUS_IDENTITY_BROKER1(source_object);
	GError *error = NULL;
	gchar *response = NULL;
	gboolean ok;

	ok = mib_dbus_identity_broker1_call_remove_account_finish(proxy, &response,
															  res, &error);
	if (!ok) {
		g_task_return_error(task, error);
	} else {
		remove_account_process_response(response);
		g_free(response);
		g_task_return_int(task, 0);
	}
	g_object_unref(task);
}

void mib_client_app_remove_account_async(MIBClientApp *app, MIBAccount *account,
										 GAsyncReadyCallback callback,
										 gpointer user_data)
{
	GTask *task;
	gchar *data;

	g_assert(app);
	g_assert(account);

	task = g_task_new(app, mib_client_app_get_cancellable(app), callback,
					  user_data);

	data = remove_account_prepare_request(app, account);

	mib_dbus_identity_broker1_call_remove_account(
		mib_client_app_get_broker(app), MIB_REQUIRED_BROKER_PROTOCOL_VERSION,
		mib_client_app_get_correlation_id(app), data,
		mib_client_app_get_cancellable(app), remove_account_async_cb, task);
	g_free(data);
}

int mib_client_app_remove_account_finish(MIBClientApp *app,
										 GAsyncResult *result, GError **error)
{
	g_assert(app);
	g_assert(g_task_is_valid(result, app));

	gboolean ok = g_task_propagate_int(G_TASK(result), error) == 0;
	return ok ? 0 : -1;
}
