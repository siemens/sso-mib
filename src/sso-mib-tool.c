/*
 * SPDX-FileCopyrightText: (C) 2025 Siemens AG
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <libgen.h>
#include <signal.h>
#include <sys/time.h>
#include <json-glib/json-glib.h>
#ifdef WITH_LIBJWT
#include <jwt.h>
#endif

#include "sso-mib.h"

// Microsoft Edge on Linux ID
#define CLIENT_ID_DEFAULT "d7b530a4-7680-4c23-a8bf-c52c121d2e87"
// Fake MSAL CPP version
#define MSAL_CPP_VERSION "1.28.0"

#define FORMAT_JSON "json"
#define FORMAT_TEXT "text"

static GCancellable *cancellable = NULL;

static void sig_handler(int signo)
{
	if (signo == SIGINT) {
		if (cancellable) {
			g_print("Interrupted. Cancel in-flight operations.\n");
			g_cancellable_cancel(cancellable);
		}
	}
}

#ifdef WITH_LIBJWT
#if LIBJWT_VERSION_MAJOR == 1 || LIBJWT_VERSION_MAJOR == 2
static int decode_headers_and_claims(const gchar *token, char **grants,
									 char **hdrs)
{
	jwt_t *jwt = NULL;
	int ret = jwt_decode(&jwt, token, NULL, 0);
	if (ret != 0)
		return ret;
	*hdrs = jwt_get_headers_json(jwt, NULL);
	*grants = jwt_get_grants_json(jwt, NULL);
	jwt_free(jwt);
	return 0;
}
#else
struct jwt_cb_ctx {
	char **grants;
	char **hdrs;
};

static int on_check_cb(jwt_t *jwt, jwt_config_t *config)
{
	jwt_value_t header_val;
	jwt_value_t claims_val;
	struct jwt_cb_ctx *ctx = config->ctx;

	jwt_set_GET_JSON(&header_val, NULL);
	if (jwt_header_get(jwt, &header_val) == JWT_VALUE_ERR_NONE) {
		*ctx->hdrs = header_val.json_val;
	}
	jwt_set_GET_JSON(&claims_val, NULL);
	if (jwt_claim_get(jwt, &claims_val) == JWT_VALUE_ERR_NONE)
		*ctx->grants = claims_val.json_val;
	return 0;
}

static int decode_headers_and_claims(const gchar *token, char **grants,
									 char **hdrs)
{
	struct jwt_cb_ctx ctx = { .grants = grants, .hdrs = hdrs };
	jwt_checker_t *checker = jwt_checker_new();
	jwt_checker_setcb(checker, on_check_cb, &ctx);
	jwt_checker_verify(checker, token);
	jwt_checker_free(checker);
	return 0;
}
#endif

static void print_decoded_jwt(const gchar *token)
{
	char *grants = NULL;
	char *hdrs = NULL;
	if (decode_headers_and_claims(token, &grants, &hdrs) != 0) {
		g_print("Error: Failed to decode JWT\n");
		return;
	}
	g_print("%s\n", hdrs);
	g_print("%s\n", grants);
	free(hdrs);
	free(grants);
}
#else
static void print_decoded_jwt(const gchar *token)
{
	g_printerr("token decoding requires libjwt (dependency missing)\n");
}
#endif

static void print_json_builder(JsonBuilder *builder)
{
	JsonGenerator *generator = json_generator_new();
	JsonNode *root = json_builder_get_root(builder);
	json_generator_set_root(generator, root);

	gchar *buf = json_generator_to_data(generator, NULL);
	g_print("%s\n", buf);
	g_free(buf);

	json_node_free(root);
	g_object_unref(generator);
}

static void json_builder_add_jwt_token(JsonBuilder *builder, const gchar *token)
{
	char *grants = NULL;
	char *hdrs = NULL;
	if (decode_headers_and_claims(token, &grants, &hdrs) != 0) {
		g_print("Error: Failed to decode JWT\n");
		return;
	}

	json_builder_begin_object(builder);

	GError *error = NULL;
	JsonParser *parser = json_parser_new();
	if (json_parser_load_from_data(parser, hdrs, -1, &error)) {
		JsonNode *node = json_parser_get_root(parser);
		json_builder_set_member_name(builder, "headers");
		JsonNode *copied = json_node_copy(node);
		json_builder_add_value(builder, copied);
	} else {
		g_printerr("Error parsing JSON string: %s\n", error->message);
	}
	g_clear_error(&error);

	if (json_parser_load_from_data(parser, grants, -1, &error)) {
		JsonNode *node = json_parser_get_root(parser);
		json_builder_set_member_name(builder, "grants");
		JsonNode *copied = json_node_copy(node);
		json_builder_add_value(builder, copied);
	} else {
		g_printerr("Error parsing JSON string: %s\n", error->message);
	}
	g_clear_error(&error);

	g_object_unref(parser);
	free(hdrs);
	free(grants);
	json_builder_end_object(builder);
}

static void print_prt_sso_cookie(MIBPrtSsoCookie *cookie, int decode)
{
	const gchar *name = mib_prt_sso_cookie_get_name(cookie);
	const gchar *content = mib_prt_sso_cookie_get_content(cookie);
	if (decode) {
		g_print("# cookie-name: %s\n", name);
		g_print("# cookie-content\n");
		print_decoded_jwt(content);
	} else {
		g_print("cookie-name: %s\n", name);
		g_print("cookie-content: %s\n", content);
	}
}

static void json_print_prt_sso_cookie(MIBPrtSsoCookie *cookie, int decode)
{
	JsonBuilder *builder = json_builder_new();
	json_builder_begin_object(builder);

	json_builder_set_member_name(builder, "cookie_name");
	json_builder_add_string_value(builder, mib_prt_sso_cookie_get_name(cookie));

	json_builder_set_member_name(builder, "cookie_content");
	const gchar *content = mib_prt_sso_cookie_get_content(cookie);
	if (decode) {
		json_builder_add_jwt_token(builder, content);
	} else {
		json_builder_add_string_value(builder, content);
	}

	json_builder_end_object(builder);
	print_json_builder(builder);
	g_object_unref(builder);
}

static void print_account(MIBAccount *account, gchar *prefix)
{
	char realm_str[37];
	uuid_t realm;
	mib_account_get_realm(account, realm);
	uuid_unparse(realm, realm_str);
	g_print("%sclient-info: %s\n", prefix,
			mib_account_get_client_info(account));
	g_print("%senvironment: %s\n", prefix,
			mib_account_get_environment(account));
	g_print("%sfamily-name: %s\n", prefix,
			mib_account_get_family_name(account));
	g_print("%sgiven-name: %s\n", prefix, mib_account_get_given_name(account));
	g_print("%shome-account-id: %s\n", prefix,
			mib_account_get_home_account_id(account));
	g_print("%slocal-account-id: %s\n", prefix,
			mib_account_get_local_account_id(account));
	g_print("%sname: %s\n", prefix, mib_account_get_name(account));
	g_print("%spassword-expiry: %ld\n", prefix,
			mib_account_get_password_expiry(account));
	g_print("%srealm: %s\n", prefix, realm_str);
	g_print("%susername: %s\n", prefix, mib_account_get_username(account));
}

static void json_builder_add_account(JsonBuilder *builder, MIBAccount *account)
{
	char realm_str[37];
	uuid_t realm;
	mib_account_get_realm(account, realm);
	uuid_unparse(realm, realm_str);

	json_builder_set_member_name(builder, "client_info");
	json_builder_add_string_value(builder,
								  mib_account_get_client_info(account));

	json_builder_set_member_name(builder, "environment");
	json_builder_add_string_value(builder,
								  mib_account_get_environment(account));

	json_builder_set_member_name(builder, "family_name");
	json_builder_add_string_value(builder,
								  mib_account_get_family_name(account));

	json_builder_set_member_name(builder, "given_name");
	json_builder_add_string_value(builder, mib_account_get_given_name(account));

	json_builder_set_member_name(builder, "home_account_id");
	json_builder_add_string_value(builder,
								  mib_account_get_home_account_id(account));

	json_builder_set_member_name(builder, "local_account_id");
	json_builder_add_string_value(builder,
								  mib_account_get_local_account_id(account));

	json_builder_set_member_name(builder, "name");
	json_builder_add_string_value(builder, mib_account_get_name(account));

	json_builder_set_member_name(builder, "password_expiry");
	json_builder_add_int_value(builder,
							   mib_account_get_password_expiry(account));

	json_builder_set_member_name(builder, "realm");
	json_builder_add_string_value(builder, realm_str);

	json_builder_set_member_name(builder, "username");
	json_builder_add_string_value(builder, mib_account_get_username(account));
}

static const char *auth_scheme_to_str(enum MIB_AUTH_SCHEME scheme)
{
	if (scheme == MIB_AUTH_SCHEME_POP) {
		return "pop";
	} else {
		return "bearer";
	}
}

static void print_prt_token(MIBPrt *token, int decode)
{
	char buffer[32];
	struct tm *tm_info;
	struct timeval tv;
	const char *token_type =
		auth_scheme_to_str(mib_prt_get_access_token_type(token));
	if (decode) {
		g_print("# access token\n");
		print_decoded_jwt(mib_prt_get_access_token(token));
		g_print("# id token\n");
		print_decoded_jwt(mib_prt_get_id_token(token));
	} else {
		g_print("access-token: %s\n", mib_prt_get_access_token(token));
		g_print("id-token: %s\n", mib_prt_get_id_token(token));
	}

	const gchar *p = decode ? "# " : "";
	g_print("%saccess-token type: %s\n", p, token_type);
	g_print("%sclient-info: %s\n", p, mib_prt_get_client_info(token));
	g_print("%sgranted-scopes:", p);
	gchar *const *scopes = mib_prt_get_granted_scopes(token);
	for (int i = 0; scopes[i]; i++) {
		g_print(" %s", scopes[i]);
	}
	g_print("\n");
	tv.tv_sec = mib_prt_get_expires_on(token);
	tm_info = localtime(&tv.tv_sec);
	strftime(buffer, sizeof(buffer) - 1, "%Y-%m-%d %H:%M:%S", tm_info);
	g_print("%sexpires-on: %s\n", p, buffer);
	g_print("%saccount:\n", p);
	print_account(mib_prt_get_account(token), "# ");
}

static void json_print_prt_token(MIBPrt *token, int decode)
{
	JsonBuilder *builder = json_builder_new();
	json_builder_begin_object(builder);
	if (decode) {
		json_builder_set_member_name(builder, "access_token");
		json_builder_add_jwt_token(builder, mib_prt_get_access_token(token));
		json_builder_set_member_name(builder, "id_token");
		json_builder_add_jwt_token(builder, mib_prt_get_id_token(token));
	} else {
		json_builder_set_member_name(builder, "access_token");
		json_builder_add_string_value(builder, mib_prt_get_access_token(token));
		json_builder_set_member_name(builder, "id_token");
		json_builder_add_string_value(builder, mib_prt_get_id_token(token));
	}

	json_builder_set_member_name(builder, "access_token_type");
	json_builder_add_string_value(
		builder, auth_scheme_to_str(mib_prt_get_access_token_type(token)));

	json_builder_set_member_name(builder, "client_info");
	json_builder_add_string_value(builder, mib_prt_get_client_info(token));

	json_builder_set_member_name(builder, "granted_scopes");
	gchar *const *scopes = mib_prt_get_granted_scopes(token);
	json_builder_begin_array(builder);
	for (int i = 0; scopes[i]; i++) {
		json_builder_add_string_value(builder, scopes[i]);
	}
	json_builder_end_array(builder);

	struct timeval tv;
	tv.tv_sec = mib_prt_get_expires_on(token);
	struct tm *tm_info = localtime(&tv.tv_sec);
	char buffer[32];
	strftime(buffer, sizeof(buffer) - 1, "%Y-%m-%d %H:%M:%S", tm_info);
	json_builder_set_member_name(builder, "expires_on");
	json_builder_add_string_value(builder, buffer);

	json_builder_set_member_name(builder, "account");
	json_builder_begin_object(builder);
	json_builder_add_account(builder, mib_prt_get_account(token));
	json_builder_end_object(builder);

	// finish builder
	json_builder_end_object(builder);

	print_json_builder(builder);
	g_object_unref(builder);
}

static JsonObject *parse_to_json_object(const gchar *data)
{
	JsonParser *parser = json_parser_new();
	gboolean ok = json_parser_load_from_data(parser, data, -1, NULL);
	if (!ok) {
		g_object_unref(parser);
		return NULL;
	}
	JsonObject *object = json_node_get_object(json_parser_get_root(parser));
	json_object_ref(object);
	g_object_unref(parser);
	return object;
}

/**
 * We use the documented keys from msal-js / access-token-proof-of-possession.md
 * which are different from the ones that are communicated to the broker.
 */
static MIBPopParams *mib_pop_params_from_json(JsonObject *params_json)
{
	if (!json_object_has_member(params_json, "authenticationScheme") ||
		!json_object_has_member(params_json, "resourceRequestMethod") ||
		!json_object_has_member(params_json, "resourceRequestUri")) {
		return NULL;
	}
	MIBPopParams *params = NULL;
	enum MIB_AUTH_SCHEME auth_scheme;
	enum MIB_REQUEST_METHOD req_method;

	const char *auth_scheme_str =
		json_object_get_string_member(params_json, "authenticationScheme");
	if (g_strcmp0(auth_scheme_str, "PoP") == 0) {
		auth_scheme = MIB_AUTH_SCHEME_POP;
	} else if (g_strcmp0(auth_scheme_str, "Bearer") == 0) {
		auth_scheme = MIB_AUTH_SCHEME_BEARER;
	} else {
		g_printerr("invalid authentication scheme: %s", auth_scheme_str);
		goto err;
	}
	const char *req_method_str =
		json_object_get_string_member(params_json, "resourceRequestMethod");
	if (g_strcmp0(req_method_str, "GET") == 0) {
		req_method = MIB_REQUEST_METHOD_GET;
	} else if (g_strcmp0(req_method_str, "POST") == 0) {
		req_method = MIB_REQUEST_METHOD_POST;
	} else if (g_strcmp0(req_method_str, "PUT") == 0) {
		req_method = MIB_REQUEST_METHOD_PUT;
	} else {
		g_printerr("invalid request method: %s", req_method_str);
		goto err;
	}
	const gchar *req_uri =
		json_object_get_string_member(params_json, "resourceRequestUri");
	params = mib_pop_params_new(auth_scheme, req_method, req_uri);
	if (!params) {
		return NULL;
	}
	if (json_object_has_member(params_json, "shrClaims")) {
		mib_pop_params_set_shr_claims(
			params, json_object_get_string_member(params_json, "shrClaims"));
	}
	if (json_object_has_member(params_json, "shrNonce")) {
		mib_pop_params_set_shr_nonce(
			params,
			g_strdup(json_object_get_string_member(params_json, "shrNonce")));
	}
	return params;
err:
	g_object_unref(params);
	return NULL;
}

GSList *default_scope_if_empty(GSList *scopes)
{
	if (!scopes) {
		scopes = g_slist_append(scopes, g_strdup(MIB_SCOPE_GRAPH_DEFAULT));
	}
	return scopes;
}

static void print_help(char *name)
{
	g_print("Usage: %s COMMAND [OPTION]...\n", basename(name));
	g_print("Commands:\n");
	g_print(
		"  getAccounts, removeAccount, acquirePrtSsoCookie, acquireTokenSilent,\n"
		"  acquireTokenInteractive, getLinuxBrokerVersion, generateSignedHttpRequest\n");
	g_print("Options:\n");
	g_print("  -a <account>  Account index (default: 0)\n");
	g_print("  -A <upn>      Select account by User Principal Name\n");
	g_print("  -d            Decode JWT\n");
	g_print("  -f <format>   Set output format: %s, %s (default: %s)\n",
			FORMAT_TEXT, FORMAT_JSON, FORMAT_TEXT);
	g_print("  -h            Print this help message\n");
	g_print("  -I            Enforce interactive token acquire\n");
	g_print("  -P            Proof-of-Possession parameters\n");
	g_print("  -r <uri>      OIDC redirect URI\n");
	g_print("  -s <client_id> Azure client application ID (default: %s)\n",
			CLIENT_ID_DEFAULT);
	g_print("  -S <scope>    OIDC scope (repeatable)\n");
	g_print("  -t <token>    Renew token\n");
	g_print("  -x <authority> Entra ID authority (default: %s)\n",
			MIB_AUTHORITY_COMMON);
}

int main(int argc, char **argv)
{
	int account_idx = 0;
	char *account_hint = NULL;
	const gchar *authority = MIB_AUTHORITY_COMMON;
	char *command = NULL;
	gchar *client_id = CLIENT_ID_DEFAULT;
	gchar *pop_params = NULL;
	JsonObject *pop_params_json = NULL;
	MIBPopParams *auth_params = NULL;
	gchar *redirect_uri = NULL;
	GSList *scopes = NULL;
	char *renew_token = NULL;
	int decode = 0;
	int enforce_interactive = 0;
	gchar *format = FORMAT_TEXT;
	int c;
	if (argc < 2) {
		print_help(argv[0]);
		return 1;
	}
	command = argv[1];
	if (strcmp(command, "-h") == 0) {
		print_help(argv[0]);
		return 0;
	}
	while ((c = getopt(argc - 1, argv + 1, "a:A:df:hIP:r:s:S:t:x:")) != -1)
		switch (c) {
		case 'a':
			account_idx = atoi(optarg);
			break;
		case 'A':
			g_clear_pointer(&account_hint, g_free);
			account_hint = g_strdup(optarg);
			break;
		case 'd':
			decode = 1;
			break;
		case 'f':
			format = optarg;
			break;
		case 'h':
			print_help(argv[0]);
			return 0;
		case 'I':
			enforce_interactive = 1;
			break;
		case 'P':
			pop_params = optarg;
			break;
		case 'r':
			g_clear_pointer(&redirect_uri, g_free);
			redirect_uri = g_strdup(optarg);
			break;
		case 's':
			client_id = optarg;
			break;
		case 'S':
			scopes = g_slist_append(scopes, g_strdup(optarg));
			break;
		case 't':
			renew_token = optarg;
			break;
		case 'x':
			authority = optarg;
			break;
		case '?':
			print_help(argv[0]);
			return 1;
		default:
			abort();
		}
	if (!command) {
		g_print("Error: -c <command> is required\n");
		return 1;
	}
	if (scopes && (strncmp(command, "acquire", strlen("acquire")) != 0)) {
		g_slist_free_full(scopes, g_free);
		g_printerr(
			"Warning: scopes must only be provided on acquire* commands. Ignoring\n");
	}

	cancellable = g_cancellable_new();
	MIBClientApp *app =
		mib_public_client_app_new(client_id, authority, cancellable, NULL);
	if (!app) {
		g_print("Error: Failed to start app\n");
		return 1;
	}
	mib_client_app_set_enforce_interactive(app, enforce_interactive);
	if (redirect_uri) {
		mib_client_app_set_redirect_uri(app, redirect_uri);
		g_clear_pointer(&redirect_uri, g_free);
	}

	// register cancellation handler
	signal(SIGINT, sig_handler);

	if (pop_params) {
		pop_params_json = parse_to_json_object(pop_params);
		if (!pop_params_json) {
			g_print("Error: Failed to parse PoP parameters\n");
			g_object_unref(app);
			g_object_unref(cancellable);
			return 1;
		}
		auth_params = mib_pop_params_from_json(pop_params_json);
		json_object_unref(pop_params_json);
	}

	if (strcmp(command, "getAccounts") == 0 && account_hint) {
		MIBAccount *account = NULL;
		account = mib_client_app_get_account_by_upn(app, account_hint);
		g_free(account_hint);
		if (!account) {
			g_print("Error[getAccounts]: No accounts found\n");
			g_object_unref(app);
			g_object_unref(cancellable);
			return 1;
		}
		print_account(account, "  ");
		g_object_unref(account);
	} else if (strcmp(command, "getAccounts") == 0) {
		GSList *accounts = mib_client_app_get_accounts(app);
		if (!accounts) {
			g_print("Error[getAccounts]: No accounts found\n");
			g_object_unref(app);
			g_object_unref(cancellable);
			return 1;
		}
		for (GSList *iter = accounts; iter; iter = g_slist_next(iter)) {
			g_print("# Account %d\n", account_idx++);
			MIBAccount *account = (MIBAccount *)iter->data;
			print_account(account, "  ");
		}
		g_slist_free_full(accounts, (GDestroyNotify)g_object_unref);
	} else if (strcmp(command, "removeAccount") == 0) {
		GSList *accounts = mib_client_app_get_accounts(app);
		if (!accounts) {
			g_print("No accounts registered\n");
			g_object_unref(app);
			g_object_unref(cancellable);
			return 0;
		}
		MIBAccount *account = g_slist_nth_data(accounts, account_idx);
		g_print("Selected account: %s\n", mib_account_get_username(account));
		int ret = mib_client_app_remove_account(app, account);
		g_slist_free_full(accounts, (GDestroyNotify)g_object_unref);
		if (ret == 0) {
			g_print("removed account\n");
		} else {
			g_print("failed to remove account\n");
			g_object_unref(app);
			g_object_unref(cancellable);
			return 1;
		}
	} else if (strcmp(command, "acquirePrtSsoCookie") == 0) {
		scopes = default_scope_if_empty(scopes);
		GSList *accounts = mib_client_app_get_accounts(app);
		if (!accounts) {
			g_print("Error[acquirePrtSsoCookie]: No accounts found\n");
			g_slist_free_full(scopes, g_free);
			g_object_unref(app);
			g_object_unref(cancellable);
			return 1;
		}
		MIBAccount *account = g_slist_nth_data(accounts, account_idx);
		MIBPrtSsoCookie *prt_cookie = mib_client_app_acquire_prt_sso_cookie(
			app, account, MIB_SSO_URL_DEFAULT, scopes);
		g_slist_free_full(scopes, g_free);
		g_slist_free_full(accounts, (GDestroyNotify)g_object_unref);
		if (!prt_cookie) {
			g_print(
				"Error[acquirePrtSsoCookie]: Failed to acquire PRT SSO cookie\n");
			g_object_unref(app);
			g_object_unref(cancellable);
			return 1;
		}
		if (g_ascii_strcasecmp(format, FORMAT_TEXT) == 0) {
			print_prt_sso_cookie(prt_cookie, decode);
		} else if (g_ascii_strcasecmp(format, FORMAT_JSON) == 0) {
			json_print_prt_sso_cookie(prt_cookie, decode);
		} else {
			g_print(
				"Error[acquirePrtSsoCookie]: Unsupported output format: %s\n",
				format);
		}
		g_object_unref(prt_cookie);
	} else if (strcmp(command, "acquireTokenSilent") == 0) {
		scopes = default_scope_if_empty(scopes);
		GSList *accounts = mib_client_app_get_accounts(app);
		if (!accounts) {
			g_print("Error[acquireTokenSilent]: No accounts found\n");
			g_slist_free_full(scopes, g_free);
			g_object_unref(app);
			g_object_unref(cancellable);
			return 1;
		}
		MIBAccount *account = g_slist_nth_data(accounts, account_idx);
		MIBPrt *prt_token = mib_client_app_acquire_token_silent(
			app, account, scopes, NULL, auth_params, renew_token);
		g_slist_free_full(scopes, g_free);
		g_slist_free_full(accounts, (GDestroyNotify)g_object_unref);
		if (auth_params)
			g_object_unref(auth_params);
		if (!prt_token) {
			g_print("Error[acquireTokenSilent]: Failed to acquire token\n");
			g_object_unref(app);
			g_object_unref(cancellable);
			return 1;
		}
		if (g_ascii_strcasecmp(format, FORMAT_TEXT) == 0) {
			print_prt_token(prt_token, decode);
		} else if (g_ascii_strcasecmp(format, FORMAT_JSON) == 0) {
			json_print_prt_token(prt_token, decode);
		} else {
			g_print(
				"Error[acquireTokenSilent]: Unsupported output format: %s\n",
				format);
		}
		g_object_unref(prt_token);
	} else if (strcmp(command, "acquireTokenInteractive") == 0) {
		scopes = default_scope_if_empty(scopes);
		MIBPrt *prt_token = mib_client_app_acquire_token_interactive(
			app, scopes, MIB_PROMPT_CONSENT, NULL, NULL, NULL, auth_params);
		g_slist_free_full(scopes, g_free);
		if (auth_params)
			g_object_unref(auth_params);
		if (!prt_token) {
			g_print(
				"Error[acquireTokenInteractive]: Failed to acquire token\n");
			g_object_unref(app);
			g_object_unref(cancellable);
			return 1;
		}
		if (g_ascii_strcasecmp(format, FORMAT_TEXT) == 0) {
			print_prt_token(prt_token, decode);
		} else if (g_ascii_strcasecmp(format, FORMAT_JSON) == 0) {
			json_print_prt_token(prt_token, decode);
		} else {
			g_print(
				"Error[acquireTokenInteractive]: Unsupported output format: %s\n",
				format);
		}
		g_object_unref(prt_token);
	} else if (strcmp(command, "getLinuxBrokerVersion") == 0) {
		gchar *version =
			mib_client_app_get_linux_broker_version(app, MSAL_CPP_VERSION);
		if (version) {
			g_print("Linux broker version: %s\n", version);
			g_free(version);
		} else {
			g_print("Error[getLinuxBrokerVersion]: Failed to get version\n");
			return 1;
		}
	} else if (strcmp(command, "generateSignedHttpRequest") == 0) {
		GSList *accounts = mib_client_app_get_accounts(app);
		if (!accounts) {
			g_print("Error[generateSignedHttpRequest]: No accounts found\n");
			g_object_unref(app);
			g_object_unref(cancellable);
			return 1;
		}
		if (!auth_params) {
			g_print(
				"Error[generateSignedHttpRequest]: PoP parameters are required\n");
			g_print(
				"Example: -P "
				"'{\"authenticationScheme\":\"PoP\",\"resourceRequestMethod\":"
				"\"POST\",\"resourceRequestUri\":\"https://example.com/\"}'\n");
			g_slist_free_full(accounts, (GDestroyNotify)g_object_unref);
			g_object_unref(app);
			g_object_unref(cancellable);
			return 1;
		}
		MIBAccount *account = g_slist_nth_data(accounts, account_idx);
		gchar *token = mib_client_app_generate_signed_http_request(app, account,
																   auth_params);
		g_object_unref(auth_params);
		g_slist_free_full(accounts, (GDestroyNotify)g_object_unref);
		if (token) {
			if (g_ascii_strcasecmp(format, FORMAT_TEXT) == 0) {
				if (decode) {
					print_decoded_jwt(token);
				} else {
					g_print("HTTP request token: %s\n", token);
				}
			} else if (g_ascii_strcasecmp(format, FORMAT_JSON) == 0) {
				JsonBuilder *builder = json_builder_new();
				json_builder_begin_object(builder);
				json_builder_set_member_name(builder, "token");
				if (decode) {
					json_builder_add_jwt_token(builder, token);
				} else {
					json_builder_add_string_value(builder, token);
				}
				json_builder_end_object(builder);
				print_json_builder(builder);
				g_object_unref(builder);
			} else {
				g_print(
					"Error[generateSignedHttpRequest]: Unsupported output format: %s\n",
					format);
			}
			g_free(token);
		} else {
			g_print(
				"Error[generateSignedHttpRequest]: Failed to generate signed "
				"HTTP request\n");
			g_object_unref(app);
			g_object_unref(cancellable);
			return 1;
		}
	} else {
		g_print("Unknown command: %s\n", command);
		g_object_unref(app);
		g_object_unref(cancellable);
		return 1;
	}
	g_object_unref(app);
	g_object_unref(cancellable);
	return 0;
}
