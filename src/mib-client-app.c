/*
 * SPDX-FileCopyrightText: (C) 2025 Siemens
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include "identity-broker.h"
#include "mib-account-impl.h"
#include "mib-client-app-impl.h"
#include "mib-account-impl.h"
#include "mib-pop-params-impl.h"
#include "mib-prt-impl.h"
#include "mib-prt-sso-cookie-impl.h"
#include "mib-utils.h"

#define DBUS_BROKER_NAME "com.microsoft.identity.broker1"
#define DBUS_BROKER_PATH "/com/microsoft/identity/broker1"

// according to https://msal-python.readthedocs.io/en/latest/#publicclientapplication
#define MIB_MS_BROKER_REDIRECT_URI_FMT \
	"ms-appx-web://Microsoft.AAD.BrokerPlugin/%s"

// MSAL does not define any lower-bound (yet)
#define MIB_REQUIRED_BROKER_PROTOCOL_VERSION "0.0"

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

static void mib_client_app_finalize(GObject *gobject)
{
	MIBClientApp *priv =
		mib_client_app_get_instance_private(MIB_CLIENT_APP(gobject));
	g_clear_object(&priv->cancellable);
	g_clear_object(&priv->broker);
	if (priv->cancellable) {
		g_clear_object(&priv->cancellable);
	}
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

	if (strlen(client_id) != UUID_STR_LEN - 1) {
		g_warning("client id is not a UUID\n");
		return NULL;
	}

	MIBClientApp *self = g_object_new(MIB_TYPE_CLIENT_APP, NULL);
	strncpy(self->client_id, client_id, UUID_STR_LEN - 1);
	uuid_generate_random(correlation_id);
	uuid_unparse_lower(correlation_id, self->correlation_id);
	self->authority = g_strdup(authority);
	self->redirect_uri = mib_client_app_get_broker_redirect_uri(self);

	if (cancellable) {
		self->cancellable = g_object_ref(cancellable);
	}

	self->broker = mib_dbus_identity_broker1_proxy_new_for_bus_sync(
		G_BUS_TYPE_SESSION, G_DBUS_PROXY_FLAGS_NONE, DBUS_BROKER_NAME,
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

static JsonObject *mib_client_app_get_accounts_raw(MIBClientApp *app)
{
	GError *error = NULL;
	gchar *response = NULL;
	JsonBuilder *builder;
	JsonNode *root;
	gboolean ok;

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
	debug_print_json_object("mib_client_app_get_accounts_raw", "request",
							params);
	gchar *data = json_object_to_string(params);
	json_node_unref(root);

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
	JsonObject *accounts = json_object_from_string(response);
	debug_print_json_object("mib_client_app_get_accounts_raw", "response",
							accounts);
	g_free(response);
	return accounts;
}

static JsonObject *mib_client_app_get_account_by_upn_raw(MIBClientApp *app,
														 const gchar *upn)
{
	JsonObject *accounts = mib_client_app_get_accounts_raw(app);
	JsonObject *account = NULL;
	if (!accounts) {
		return NULL;
	}
	JsonArray *accounts_array =
		json_object_get_array_member(accounts, "accounts");
	if (!accounts_array) {
		goto err;
	}
	for (guint i = 0; i < json_array_get_length(accounts_array); i++) {
		account = json_array_get_object_element(accounts_array, i);
		if (!upn) {
			g_debug("no upn provided");
			break;
		}
		if (!json_object_has_member(account, "username"))
			break;
		const gchar *username =
			json_object_get_string_member(account, "username");
		if (g_strcmp0(username, upn) == 0) {
			g_debug("account matching UPN found");
			break;
		}
	}
	json_object_ref(account);
err:
	json_object_unref(accounts);
	return account;
}

GSList *mib_client_app_get_accounts(MIBClientApp *self)
{
	g_assert(self);

	JsonObject *accounts = mib_client_app_get_accounts_raw(self);
	if (!accounts) {
		return NULL;
	}
	if (!json_object_has_member(accounts, "accounts")) {
		json_object_unref(accounts);
		return NULL;
	}
	JsonArray *accounts_array =
		json_object_get_array_member(accounts, "accounts");
	GSList *accounts_list = NULL;
	MIBAccount *mib_account = NULL;
	for (guint i = 0; i < json_array_get_length(accounts_array); i++) {
		JsonObject *account = json_array_get_object_element(accounts_array, i);
		mib_account = mib_account_from_json(account);
		if (!mib_account) {
			g_warning("error parsing account data");
			break;
		}
		accounts_list = g_slist_append(accounts_list, mib_account);
	}
	json_object_unref(accounts);
	return accounts_list;
}

MIBAccount *mib_client_app_get_account_by_upn(MIBClientApp *app,
											  const gchar *upn)
{
	g_assert(app);

	MIBAccount *mib_account = NULL;
	JsonObject *account = mib_client_app_get_account_by_upn_raw(app, upn);
	if (!account) {
		return NULL;
	}
	mib_account = mib_account_from_json(account);
	json_object_unref(account);
	return mib_account;
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
	return g_strdup_printf(MIB_MS_BROKER_REDIRECT_URI_FMT, self->client_id);
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

static JsonObject *
mib_get_linux_broker_version_raw(MIBClientApp *app,
								 const gchar *msal_cpp_version)
{
	GError *error = NULL;
	JsonObject *params;
	gchar *params_data;
	gchar *response;
	gboolean ok;

	params = json_object_new();
	json_object_set_string_member(params, "msalCppVersion", msal_cpp_version);
	debug_print_json_object("mib_get_linux_broker_version_raw", "request",
							params);
	params_data = json_object_to_string(params);
	json_object_unref(params);
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
	JsonObject *version = json_object_from_string(response);
	if (!version)
		goto err;
	debug_print_json_object("mib_get_linux_broker_version_raw", "response",
							version);
err:
	g_free(response);
	return version;
}

gchar *mib_client_app_get_linux_broker_version(MIBClientApp *app,
											   const gchar *msal_cpp_version)
{
	g_assert(app);
	g_assert(msal_cpp_version);

	JsonObject *version_json;
	gchar *version;
	version_json = mib_get_linux_broker_version_raw(app, msal_cpp_version);
	if (!version_json ||
		!json_object_has_member(version_json, "linuxBrokerVersion")) {
		return NULL;
	}
	version = g_strdup(
		json_object_get_string_member(version_json, "linuxBrokerVersion"));
	json_object_unref(version_json);
	return version;
}

static JsonObject *
prepare_prt_auth_params(MIBClientApp *app, JsonObject *account,
						JsonArray *scopes, const gchar *claims_challenge,
						JsonObject *auth_scheme, const gchar *renew_token,
						JsonObject *extra_params, const gchar *sso_url)
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
	int auth_type = sso_url ? 8 : 1;

	JsonNode *account_node = json_node_new(JSON_NODE_OBJECT);
	json_node_set_object(account_node, account);
	JsonNode *scopes_node = json_node_new(JSON_NODE_ARRAY);
	json_node_set_array(scopes_node, scopes);
	const gchar *username = json_object_get_string_member(account, "username");

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
	if (auth_scheme) {
		JsonNode *auth_scheme_node = json_node_new(JSON_NODE_OBJECT);
		json_node_set_object(auth_scheme_node, auth_scheme);
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

static JsonObject *
mib_acquire_token_silent_raw(MIBClientApp *app, JsonObject *account,
							 JsonArray *scopes, const gchar *claims_challenge,
							 JsonObject *auth_scheme, const gchar *renew_token)
{
	GError *error = NULL;
	gchar *response;
	gboolean ok;
	JsonObject *token;
	JsonObject *auth_params =
		prepare_prt_auth_params(app, account, scopes, claims_challenge,
								auth_scheme, renew_token, NULL, NULL);
	JsonNode *auth_params_node = json_node_new(JSON_NODE_OBJECT);
	json_node_set_object(auth_params_node, auth_params);
	json_object_unref(auth_params);

	JsonObject *params_obj = json_object_new();
	json_object_set_member(params_obj, "authParameters", auth_params_node);
	debug_print_json_object("mib_acquire_token_silent_raw", "request",
							params_obj);
	gchar *data = json_object_to_string(params_obj);
	json_object_unref(params_obj);

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
	token = json_object_from_string(response);
	debug_print_json_object("mib_acquire_token_silent_raw", "response", token);
	g_free(response);
	return token;
}

MIBPrt *mib_client_app_acquire_token_silent(MIBClientApp *app,
											MIBAccount *account, GSList *scopes,
											const gchar *claims_challenge,
											MIBPopParams *auth_scheme,
											const gchar *id_token)
{
	g_assert(app);
	g_assert(account);
	g_assert(scopes);

	JsonObject *account_json = mib_account_to_json(account);
	JsonArray *scopes_array = mib_scopes_to_json(scopes);
	JsonObject *pop_params = auth_scheme ? mib_pop_params_to_json(auth_scheme) :
										   NULL;
	JsonObject *token_json =
		mib_acquire_token_silent_raw(app, account_json, scopes_array,
									 claims_challenge, pop_params, id_token);
	json_object_unref(account_json);
	json_array_unref(scopes_array);
	if (pop_params) {
		json_object_unref(pop_params);
	}
	if (!token_json) {
		return NULL;
	}
	MIBPrt *token = mib_prt_from_json(token_json);
	json_object_unref(token_json);
	return token;
}

static JsonObject *mib_acquire_token_interactive_raw(
	MIBClientApp *app, JsonArray *scopes, enum MIB_PROMPT prompt,
	JsonObject *account, MIB_ARG_UNUSED const gchar *domain_hint,
	const gchar *claims_challenge, JsonObject *auth_scheme,
	JsonObject *extra_params)
{
	GError *error = NULL;
	gchar *response;
	gboolean ok;
	JsonObject *token;

	JsonObject *auth_params =
		prepare_prt_auth_params(app, account, scopes, claims_challenge,
								auth_scheme, NULL, extra_params, NULL);

	/* TODO: check if this is the correct key */
	if (prompt != MIB_PROMPT_UNSET) {
		gchar *prompt_str = mib_prompt_to_str(prompt);
		json_object_set_string_member(auth_params, "prompt", prompt_str);
		g_free(prompt_str);
	}
	JsonNode *auth_params_node = json_node_new(JSON_NODE_OBJECT);
	json_node_set_object(auth_params_node, auth_params);
	json_object_unref(auth_params);

	JsonObject *params_obj = json_object_new();
	/* if a re-auth is requested, clear the account */
	if (prompt & MIB_PROMPT_SELECT_ACCOUNT) {
		json_object_remove_member(auth_params, "account");
		json_object_remove_member(auth_params, "username");
	} else {
		json_object_set_object_member(params_obj, "account",
									  json_object_ref(account));
	}
	json_object_set_member(params_obj, "authParameters", auth_params_node);
	debug_print_json_object("mib_acquire_token_interactive_raw", "request",
							params_obj);
	gchar *data = json_object_to_string(params_obj);
	json_object_unref(params_obj);

	/* disable dbus timeout before call and restore after as user input is needed */
	mibdbusIdentityBroker1 *gd_proxy = mib_client_app_get_broker(app);
	g_dbus_proxy_set_default_timeout((GDBusProxy *)gd_proxy, G_MAXINT);
	ok = mib_dbus_identity_broker1_call_acquire_token_interactively_sync(
		gd_proxy, MIB_REQUIRED_BROKER_PROTOCOL_VERSION,
		mib_client_app_get_correlation_id(app), data, &response,
		mib_client_app_get_cancellable(app), &error);
	g_dbus_proxy_set_default_timeout((GDBusProxy *)gd_proxy, -1);

	g_free(data);
	if (!ok) {
		g_warning("could not acquire token: %s", error->message);
		g_error_free(error);
		return NULL;
	}
	token = json_object_from_string(response);
	debug_print_json_object("mib_acquire_token_interactive_raw", "response",
							token);
	g_free(response);
	return token;
}

MIBPrt *mib_client_app_acquire_token_interactive(
	MIBClientApp *app, GSList *scopes, enum MIB_PROMPT prompt,
	const gchar *login_hint, const gchar *domain_hint,
	const gchar *claims_challenge, MIBPopParams *auth_scheme)
{
	g_assert(app);
	g_assert(scopes);

	MIBPrt *token = NULL;
	JsonObject *token_json = NULL;
	JsonObject *account_json =
		mib_client_app_get_account_by_upn_raw(app, login_hint);
	if (!account_json) {
		return NULL;
	}

	JsonArray *scopes_array = mib_scopes_to_json(scopes);
	JsonObject *pop_params = auth_scheme ? mib_pop_params_to_json(auth_scheme) :
										   NULL;

	/* first try silent, on error try interactive */
	if (!mib_client_app_get_enforce_interactive(app)) {
		token_json =
			mib_acquire_token_silent_raw(app, account_json, scopes_array,
										 claims_challenge, pop_params, NULL);
	}
	if (token_json) {
		token = mib_prt_from_json(token_json);
		if (!token)
			json_object_unref(token_json);
	}
	if (!token) {
		token_json = mib_acquire_token_interactive_raw(
			app, scopes_array, prompt, account_json, domain_hint,
			claims_challenge, pop_params, NULL);
		token = mib_prt_from_json(token_json);
	}
	json_object_unref(account_json);
	json_array_unref(scopes_array);
	if (pop_params) {
		json_object_unref(pop_params);
	}
	if (!token_json) {
		return NULL;
	}
	json_object_unref(token_json);
	return token;
}

static JsonObject *prepare_prt_sso_request_data(JsonObject *account,
												JsonObject *auth_params,
												const gchar *sso_url)
{
	// {
	//  'account': account,
	//  'authParameters': params,
	//  'ssoUrl': sso_url
	// }
	JsonObject *params_obj = json_object_new();
	JsonNode *account_node = json_node_new(JSON_NODE_OBJECT);
	json_node_set_object(account_node, account);
	JsonNode *auth_params_node = json_node_new(JSON_NODE_OBJECT);
	json_node_set_object(auth_params_node, auth_params);
	JsonNode *sso_url_node = json_node_new(JSON_NODE_VALUE);
	json_node_set_string(sso_url_node, sso_url);

	json_object_set_member(params_obj, "account", account_node);
	json_object_set_member(params_obj, "authParameters", auth_params_node);
	json_object_set_member(params_obj, "ssoUrl", sso_url_node);
	return params_obj;
}

static JsonObject *mib_acquire_prt_sso_cookie_raw(MIBClientApp *app,
												  JsonObject *account,
												  const gchar *sso_url,
												  JsonArray *scopes)
{
	JsonObject *cookie;
	gchar *data;
	GError *error = NULL;
	gchar *response;
	gboolean ok;

	JsonObject *auth_params = prepare_prt_auth_params(
		app, account, scopes, NULL, NULL, NULL, NULL, sso_url);
	JsonObject *params =
		prepare_prt_sso_request_data(account, auth_params, sso_url);
	debug_print_json_object("mib_acquire_prt_sso_cookie_raw", "request",
							params);
	data = json_object_to_string(params);
	json_object_unref(params);
	json_object_unref(auth_params);

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
	cookie = json_object_from_string(response);
	debug_print_json_object("mib_acquire_prt_sso_cookie_raw", "response",
							cookie);
	g_free(response);
	return cookie;
}

MIBPrtSsoCookie *mib_client_app_acquire_prt_sso_cookie(MIBClientApp *app,
													   MIBAccount *account,
													   const gchar *sso_url,
													   GSList *scopes)
{
	g_assert(app);
	g_assert(account);
	g_assert(sso_url);
	g_assert(scopes);

	JsonObject *account_json = mib_account_to_json(account);
	JsonArray *scopes_array = mib_scopes_to_json(scopes);
	JsonObject *cookie_json = mib_acquire_prt_sso_cookie_raw(
		app, account_json, sso_url, scopes_array);
	json_object_unref(account_json);
	json_array_unref(scopes_array);
	if (!cookie_json) {
		return NULL;
	}
	MIBPrtSsoCookie *cookie = mib_prt_sso_cookie_from_json(cookie_json);
	json_object_unref(cookie_json);
	return cookie;
}

static JsonObject *mib_generate_signed_http_request_raw(
	MIBClientApp *app, const gchar *home_account_id, JsonObject *pop_params)
{
	GError *error = NULL;
	gboolean ok;
	gchar *response;
	JsonObject *params = json_object_new();
	json_object_set_string_member(params, "clientId",
								  mib_client_app_get_client_id(app));
	json_object_set_string_member(pop_params, "homeAccountId", home_account_id);
	json_object_ref(pop_params);
	json_object_set_object_member(params, "popParams", pop_params);
	debug_print_json_object("mib_generate_signed_http_request_raw", "request",
							params);
	gchar *params_data = json_object_to_string(params);
	json_object_unref(params);

	ok = mib_dbus_identity_broker1_call_generate_signed_http_request_sync(
		mib_client_app_get_broker(app), MIB_REQUIRED_BROKER_PROTOCOL_VERSION,
		mib_client_app_get_correlation_id(app), params_data, &response,
		mib_client_app_get_cancellable(app), &error);

	g_free(params_data);
	if (!ok) {
		g_warning("could not generate signed HTTP request: %s", error->message);
		g_error_free(error);
		return NULL;
	}
	JsonObject *token = json_object_from_string(response);
	debug_print_json_object("mib_generate_signed_http_request_raw", "response",
							token);
	g_free(response);
	return token;
}

gchar *mib_client_app_generate_signed_http_request(MIBClientApp *app,
												   MIBAccount *account,
												   MIBPopParams *pop_params)
{
	JsonObject *params_json;
	gchar *access_token = NULL;

	g_assert(app);
	g_assert(account);

	if (pop_params) {
		params_json = mib_pop_params_to_json(pop_params);
	} else {
		params_json = json_object_new();
	}
	JsonObject *token = mib_generate_signed_http_request_raw(
		app, mib_account_get_home_account_id(account), params_json);
	json_object_unref(params_json);
	if (!token) {
		return NULL;
	}
	if (!json_object_has_member(token, "signedHttpRequest")) {
		g_warning("response json is missing 'signedHttpRequest'");
		goto err;
	}
	access_token =
		g_strdup(json_object_get_string_member(token, "signedHttpRequest"));
err:
	json_object_unref(token);
	return access_token;
}

static int mib_remove_account_raw(MIBClientApp *app, JsonObject *account)
{
	GError *error = NULL;
	gboolean ok;
	gchar *response = NULL;

	JsonObject *params = json_object_new();
	json_object_set_string_member(params, "clientId", app->client_id);
	json_object_set_object_member(params, "account", json_object_ref(account));

	debug_print_json_object("mib_remove_account_raw", "request", params);

	gchar *data = json_object_to_string(params);
	json_object_unref(params);
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
	JsonObject *resp_json = json_object_from_string(response);
	g_free(response);
	debug_print_json_object("mib_remove_account_raw", "response", resp_json);
	json_object_unref(resp_json);
	return 0;
}

int mib_client_app_remove_account(MIBClientApp *app, MIBAccount *account)
{
	g_assert(app);
	g_assert(account);
	int ret = 0;

	JsonObject *account_json = mib_account_to_json(account);
	ret = mib_remove_account_raw(app, account_json);

	json_object_unref(account_json);
	return ret;
}
