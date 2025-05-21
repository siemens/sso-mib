/*
 * SPDX-FileCopyrightText: (C) 2025 Siemens AG
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <libgen.h>
#include <stdio.h>
#include <signal.h>
#include <sys/time.h>
#include <json-glib/json-glib.h>

#include "sso-mib.h"
#include "base64.h"

// Microsoft Edge on Linux ID
#define CLIENT_ID_DEFAULT "d7b530a4-7680-4c23-a8bf-c52c121d2e87"
// Fake MSAL CPP version
#define MSAL_CPP_VERSION "1.28.0"

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

static void print_decoded_jwt(const gchar *jwt)
{
	gchar **parts;
	unsigned char *decoded = NULL;
	gsize len;
	gchar *suffix = "";
	parts = g_strsplit(jwt, ".", 3);
	for (int i = 0; i < 2; ++i) {
		const size_t inlen = strlen(parts[i]);
		decoded = malloc(BASE64_DECODE_OUT_SIZE(inlen));
		len = base64_decode(parts[i], inlen, decoded);
		if (!len) {
			g_print("Error: Failed to decode JWT\n");
			free(decoded);
			return;
		}
		g_print("%.*s%s\n", (int)len, decoded, suffix);
		free(decoded);
	}
	g_strfreev(parts);
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
	strftime(buffer, 32, "%Y-%m-%d %H:%M:%S", tm_info);
	g_print("%sexpires-on: %s\n", p, buffer);
	g_print("%saccount:\n", p);
	print_account(mib_prt_get_account(token), "# ");
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

static void print_help(char *name)
{
	g_print("Usage: %s COMMAND [OPTION]...\n", basename(name));
	g_print("Commands:\n");
	g_print(
		"  getAccounts, acquirePrtSsoCookie, acquireTokenSilent, acquireTokenInteractive, "
		"getLinuxBrokerVersion, generateSignedHttpRequest)\n");
	g_print("Options:\n");
	g_print("  -a <account>  Account index (default: 0)\n");
	g_print("  -A <upn>      Select account by User Principal Name\n");
	g_print("  -d            Decode JWT\n");
	g_print("  -h            Print this help message\n");
	g_print("  -I            Enforce interactive token acquire\n");
	g_print("  -P            Proof-of-Possession parameters\n");
	g_print("  -s <client_id> Azure client application ID (default: %s)\n",
			CLIENT_ID_DEFAULT);
	g_print("  -t <token>    Renew token\n");
}

int main(int argc, char **argv)
{
	int account_idx = 0;
	char *account_hint = NULL;
	char *command = NULL;
	gchar *client_id = CLIENT_ID_DEFAULT;
	gchar *pop_params = NULL;
	JsonObject *pop_params_json = NULL;
	MIBPopParams *auth_params = NULL;
	char *renew_token = NULL;
	int decode = 0;
	int enforce_interactive = 0;
	int c;
	if (argc < 2) {
		print_help(argv[0]);
		return 1;
	}
	command = argv[1];
	while ((c = getopt(argc - 1, argv + 1, "a:A:dhIP:s:t:")) != -1)
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
		case 'h':
			print_help(argv[0]);
			return 0;
		case 'I':
			enforce_interactive = 1;
			break;
		case 'P':
			pop_params = optarg;
			break;
		case 's':
			client_id = optarg;
			break;
		case 't':
			renew_token = optarg;
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

	const gchar *authority = MIB_AUTHORITY_COMMON;
	cancellable = g_cancellable_new();
	MIBClientApp *app =
		mib_public_client_app_new(client_id, authority, cancellable, NULL);
	if (!app) {
		g_print("Error: Failed to start app\n");
		return 1;
	}
	mib_client_app_set_enforce_interactive(app, enforce_interactive);

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
	} else if (strcmp(command, "acquirePrtSsoCookie") == 0) {
		GSList *scopes = NULL;
		scopes = g_slist_append(scopes, g_strdup(MIB_SCOPE_GRAPH_DEFAULT));
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
		print_prt_sso_cookie(prt_cookie, decode);
		g_object_unref(prt_cookie);
	} else if (strcmp(command, "acquireTokenSilent") == 0) {
		GSList *scopes = NULL;
		scopes = g_slist_append(scopes, g_strdup(MIB_SCOPE_GRAPH_DEFAULT));
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
		if (auth_params)
			g_object_unref(auth_params);
		if (prt_token) {
			print_prt_token(prt_token, decode);
			g_object_unref(prt_token);
		}
		g_slist_free_full(scopes, g_free);
		g_slist_free_full(accounts, (GDestroyNotify)g_object_unref);
	} else if (strcmp(command, "acquireTokenInteractive") == 0) {
		GSList *scopes = NULL;
		scopes = g_slist_append(scopes, g_strdup(MIB_SCOPE_GRAPH_DEFAULT));
		MIBPrt *prt_token = mib_client_app_acquire_token_interactive(
			app, scopes, MIB_PROMPT_CONSENT, NULL, NULL, NULL, auth_params);
		if (auth_params)
			g_object_unref(auth_params);
		if (prt_token) {
			print_prt_token(prt_token, decode);
			g_object_unref(prt_token);
		}
		g_slist_free_full(scopes, g_free);
	} else if (strcmp(command, "getLinuxBrokerVersion") == 0) {
		gchar *version =
			mib_client_app_get_linux_broker_version(app, MSAL_CPP_VERSION);
		if (version) {
			g_print("Linux broker version: %s\n", version);
			g_free(version);
		} else {
			g_print("Error[getLinuxBrokerVersion]: Failed to get version\n");
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
		if (token) {
			if (decode) {
				print_decoded_jwt(token);
			} else {
				g_print("HTTP request token: %s\n", token);
			}
			g_free(token);
		} else {
			g_print(
				"Error[generateSignedHttpRequest]: Failed to generate signed "
				"HTTP request\n");
		}
		g_slist_free_full(accounts, (GDestroyNotify)g_object_unref);
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
