/*
 * SPDX-FileCopyrightText: (C) 2025 Siemens
 * SPDX-License-Identifier: MIT
 */

#include <sso-mib.h>
#include "mock-broker.h"

#define TEST_CLIENT_ID "00000000-1111-2222-3333-444444444444"
#define TEST_TENANT_ID "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

static MockBroker *broker = NULL;

/* JSON response snippets */

#define ACCOUNT_JSON                                 \
	"{"                                              \
	"\"environment\":\"login.microsoftonline.com\"," \
	"\"givenName\":\"Test\","                        \
	"\"homeAccountId\":\"home-account-id-1\","       \
	"\"localAccountId\":\"local-account-id-1\","     \
	"\"name\":\"Test User\","                        \
	"\"passwordExpiry\":0,"                          \
	"\"realm\":\"" TEST_TENANT_ID "\","              \
	"\"username\":\"testuser@example.com\""          \
	"}"

#define GET_ACCOUNTS_RESPONSE "{\"accounts\":[" ACCOUNT_JSON "]}"

#define GET_ACCOUNTS_EMPTY_RESPONSE "{\"accounts\":[]}"

#define TOKEN_RESPONSE                                               \
	"{\"brokerTokenResponse\":{"                                     \
	"\"accessToken\":\"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.test\"," \
	"\"accessTokenType\":0,"                                         \
	"\"account\":" ACCOUNT_JSON ","                                  \
	"\"clientInfo\":\"client-info-value\","                          \
	"\"expiresOn\":1700000000000,"                                   \
	"\"grantedScopes\":\"https://graph.microsoft.com/.default\","    \
	"\"idToken\":\"id-token-value\""                                 \
	"}}"

#define PRT_SSO_COOKIE_RESPONSE                        \
	"{\"cookieName\":\"x-ms-RefreshTokenCredential\"," \
	"\"cookieContent\":\"cookie-content-value\"}"

#define SIGNED_HTTP_REQUEST_RESPONSE \
	"{\"signedHttpRequest\":\"signed-request-token-value\"}"

#define BROKER_VERSION_RESPONSE "{\"linuxBrokerVersion\":\"2.1.0\"}"

/* --- Test: create client app --- */

static void test_client_app_new(void)
{
	GError *error = NULL;
	MIBClientApp *app = mib_public_client_app_new(
		TEST_CLIENT_ID, MIB_AUTHORITY_COMMON, NULL, &error);

	g_assert_no_error(error);
	g_assert_nonnull(app);
	g_assert_cmpstr(mib_client_app_get_client_id(app), ==, TEST_CLIENT_ID);
	g_assert_cmpstr(mib_client_app_get_authority(app), ==,
					MIB_AUTHORITY_COMMON);
	g_assert_nonnull(mib_client_app_get_correlation_id(app));

	g_object_unref(app);
}

static void test_client_app_new_invalid_id(void)
{
	g_test_expect_message("ssomib", G_LOG_LEVEL_WARNING,
						  "*client id is not a UUID*");
	MIBClientApp *app = mib_public_client_app_new(
		"not-a-uuid", MIB_AUTHORITY_COMMON, NULL, NULL);
	g_assert_null(app);
	g_test_assert_expected_messages();
}

/* --- Test: get accounts --- */

static void test_get_accounts(void)
{
	GError *error = NULL;
	mock_broker_set_get_accounts_response(broker, GET_ACCOUNTS_RESPONSE);

	MIBClientApp *app = mib_public_client_app_new(
		TEST_CLIENT_ID, MIB_AUTHORITY_COMMON, NULL, &error);
	g_assert_no_error(error);
	g_assert_nonnull(app);

	GSList *accounts = mib_client_app_get_accounts(app);
	g_assert_nonnull(accounts);
	g_assert_cmpuint(g_slist_length(accounts), ==, 1);

	MIBAccount *account = accounts->data;
	g_assert_cmpstr(mib_account_get_username(account), ==,
					"testuser@example.com");
	g_assert_cmpstr(mib_account_get_environment(account), ==,
					"login.microsoftonline.com");
	g_assert_cmpstr(mib_account_get_home_account_id(account), ==,
					"home-account-id-1");
	g_assert_cmpstr(mib_account_get_local_account_id(account), ==,
					"local-account-id-1");
	g_assert_cmpstr(mib_account_get_name(account), ==, "Test User");
	g_assert_cmpstr(mib_account_get_given_name(account), ==, "Test");

	g_slist_free_full(accounts, (GDestroyNotify)g_object_unref);
	g_object_unref(app);
}

static void test_get_accounts_empty(void)
{
	GError *error = NULL;
	mock_broker_set_get_accounts_response(broker, GET_ACCOUNTS_EMPTY_RESPONSE);

	MIBClientApp *app = mib_public_client_app_new(
		TEST_CLIENT_ID, MIB_AUTHORITY_COMMON, NULL, &error);
	g_assert_no_error(error);

	GSList *accounts = mib_client_app_get_accounts(app);
	g_assert_null(accounts);

	g_object_unref(app);
}

/* --- Test: get accounts async --- */

static void get_accounts_async_cb(GObject *source_object, GAsyncResult *res,
								  gpointer user_data)
{
	GMainLoop *loop = user_data;
	MIBClientApp *app = MIB_CLIENT_APP(source_object);
	GError *error = NULL;

	GSList *accounts = mib_client_app_get_accounts_finish(app, res, &error);
	g_assert_no_error(error);
	g_assert_nonnull(accounts);
	g_assert_cmpuint(g_slist_length(accounts), ==, 1);

	MIBAccount *account = accounts->data;
	g_assert_cmpstr(mib_account_get_username(account), ==,
					"testuser@example.com");

	g_slist_free_full(accounts, (GDestroyNotify)g_object_unref);
	g_main_loop_quit(loop);
}

static void test_get_accounts_async(void)
{
	GError *error = NULL;
	mock_broker_set_get_accounts_response(broker, GET_ACCOUNTS_RESPONSE);

	MIBClientApp *app = mib_public_client_app_new(
		TEST_CLIENT_ID, MIB_AUTHORITY_COMMON, NULL, &error);
	g_assert_no_error(error);

	GMainLoop *loop = g_main_loop_new(NULL, FALSE);
	mib_client_app_get_accounts_async(app, get_accounts_async_cb, loop);
	g_main_loop_run(loop);

	g_main_loop_unref(loop);
	g_object_unref(app);
}

/* --- Test: get account by UPN --- */

static void test_get_account_by_upn(void)
{
	GError *error = NULL;
	mock_broker_set_get_accounts_response(broker, GET_ACCOUNTS_RESPONSE);

	MIBClientApp *app = mib_public_client_app_new(
		TEST_CLIENT_ID, MIB_AUTHORITY_COMMON, NULL, &error);
	g_assert_no_error(error);

	MIBAccount *account =
		mib_client_app_get_account_by_upn(app, "testuser@example.com");
	g_assert_nonnull(account);
	g_assert_cmpstr(mib_account_get_username(account), ==,
					"testuser@example.com");

	g_object_unref(account);
	g_object_unref(app);
}

static void test_get_account_by_upn_not_found(void)
{
	GError *error = NULL;
	mock_broker_set_get_accounts_response(broker, GET_ACCOUNTS_RESPONSE);

	MIBClientApp *app = mib_public_client_app_new(
		TEST_CLIENT_ID, MIB_AUTHORITY_COMMON, NULL, &error);
	g_assert_no_error(error);

	MIBAccount *account =
		mib_client_app_get_account_by_upn(app, "nobody@example.com");
	g_assert_null(account);

	g_object_unref(app);
}

static void test_get_account_by_upn_null(void)
{
	GError *error = NULL;
	mock_broker_set_get_accounts_response(broker, GET_ACCOUNTS_RESPONSE);

	MIBClientApp *app = mib_public_client_app_new(
		TEST_CLIENT_ID, MIB_AUTHORITY_COMMON, NULL, &error);
	g_assert_no_error(error);

	/* NULL upn returns first account */
	MIBAccount *account = mib_client_app_get_account_by_upn(app, NULL);
	g_assert_nonnull(account);
	g_assert_cmpstr(mib_account_get_username(account), ==,
					"testuser@example.com");

	g_object_unref(account);
	g_object_unref(app);
}

/* --- Test: acquire token silent --- */

static void test_acquire_token_silent(void)
{
	GError *error = NULL;
	mock_broker_set_get_accounts_response(broker, GET_ACCOUNTS_RESPONSE);
	mock_broker_set_acquire_token_silently_response(broker, TOKEN_RESPONSE);

	MIBClientApp *app = mib_public_client_app_new(
		TEST_CLIENT_ID, MIB_AUTHORITY_COMMON, NULL, &error);
	g_assert_no_error(error);

	MIBAccount *account =
		mib_client_app_get_account_by_upn(app, "testuser@example.com");
	g_assert_nonnull(account);

	GSList *scopes = g_slist_append(NULL, (gpointer)MIB_SCOPE_GRAPH_DEFAULT);
	MIBPrt *token = mib_client_app_acquire_token_silent(app, account, scopes,
														NULL, NULL, NULL);
	g_assert_nonnull(token);

	g_assert_cmpstr(mib_prt_get_access_token(token), ==,
					"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.test");
	g_assert_cmpint(mib_prt_get_access_token_type(token), ==,
					MIB_AUTH_SCHEME_BEARER);
	g_assert_cmpstr(mib_prt_get_client_info(token), ==, "client-info-value");
	g_assert_cmpstr(mib_prt_get_id_token(token), ==, "id-token-value");
	g_assert_cmpint(mib_prt_get_expires_on(token), ==, 1700000000);

	gchar *const *granted = mib_prt_get_granted_scopes(token);
	g_assert_nonnull(granted);
	g_assert_cmpstr(granted[0], ==, "https://graph.microsoft.com/.default");

	g_slist_free(scopes);
	g_object_unref(token);
	g_object_unref(account);
	g_object_unref(app);
}

static void test_acquire_token_silent_bad_response(void)
{
	GError *error = NULL;
	mock_broker_set_get_accounts_response(broker, GET_ACCOUNTS_RESPONSE);
	mock_broker_set_acquire_token_silently_response(
		broker, "{\"error\":\"something\"}");

	MIBClientApp *app = mib_public_client_app_new(
		TEST_CLIENT_ID, MIB_AUTHORITY_COMMON, NULL, &error);
	g_assert_no_error(error);

	MIBAccount *account =
		mib_client_app_get_account_by_upn(app, "testuser@example.com");
	g_assert_nonnull(account);

	GSList *scopes = g_slist_append(NULL, (gpointer)MIB_SCOPE_GRAPH_DEFAULT);
	MIBPrt *token = mib_client_app_acquire_token_silent(app, account, scopes,
														NULL, NULL, NULL);
	g_assert_null(token);

	g_slist_free(scopes);
	g_object_unref(account);
	g_object_unref(app);
}

/* --- Test: acquire token silent async --- */

static void acquire_token_silent_async_cb(GObject *source_object,
										  GAsyncResult *res, gpointer user_data)
{
	GMainLoop *loop = user_data;
	MIBClientApp *app = MIB_CLIENT_APP(source_object);
	GError *error = NULL;

	MIBPrt *token =
		mib_client_app_acquire_token_silent_finish(app, res, &error);
	g_assert_no_error(error);
	g_assert_nonnull(token);

	g_object_unref(token);
	g_main_loop_quit(loop);
}

static void test_acquire_token_silent_async(void)
{
	GError *error = NULL;
	mock_broker_set_get_accounts_response(broker, GET_ACCOUNTS_RESPONSE);
	mock_broker_set_acquire_token_silently_response(broker, TOKEN_RESPONSE);

	MIBClientApp *app = mib_public_client_app_new(
		TEST_CLIENT_ID, MIB_AUTHORITY_COMMON, NULL, &error);
	g_assert_no_error(error);

	MIBAccount *account =
		mib_client_app_get_account_by_upn(app, "testuser@example.com");
	g_assert_nonnull(account);

	GSList *scopes = g_slist_append(NULL, (gpointer)MIB_SCOPE_GRAPH_DEFAULT);

	GMainLoop *loop = g_main_loop_new(NULL, FALSE);
	mib_client_app_acquire_token_silent_async(app, account, scopes, NULL, NULL,
											  NULL,
											  acquire_token_silent_async_cb,
											  loop);
	g_main_loop_run(loop);

	g_main_loop_unref(loop);
	g_slist_free(scopes);
	g_object_unref(account);
	g_object_unref(app);
}

/* --- Test: acquire token interactive async --- */

static void acquire_token_interactive_async_cb(GObject *source_object,
											   GAsyncResult *res,
											   gpointer user_data)
{
	GMainLoop *loop = user_data;
	MIBClientApp *app = MIB_CLIENT_APP(source_object);
	GError *error = NULL;

	MIBPrt *token =
		mib_client_app_acquire_token_interactive_finish(app, res, &error);
	g_assert_no_error(error);
	g_assert_nonnull(token);

	g_assert_cmpstr(mib_prt_get_access_token(token), ==,
					"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.test");

	g_object_unref(token);
	g_main_loop_quit(loop);
}

static void test_acquire_token_interactive_async(void)
{
	GError *error = NULL;
	mock_broker_set_get_accounts_response(broker, GET_ACCOUNTS_RESPONSE);
	mock_broker_set_acquire_token_silently_response(broker, TOKEN_RESPONSE);

	MIBClientApp *app = mib_public_client_app_new(
		TEST_CLIENT_ID, MIB_AUTHORITY_COMMON, NULL, &error);
	g_assert_no_error(error);

	GSList *scopes = g_slist_append(NULL, (gpointer)MIB_SCOPE_GRAPH_DEFAULT);

	GMainLoop *loop = g_main_loop_new(NULL, FALSE);
	mib_client_app_acquire_token_interactive_async(
		app, scopes, MIB_PROMPT_UNSET, "testuser@example.com", NULL, NULL, NULL,
		acquire_token_interactive_async_cb, loop);
	g_main_loop_run(loop);

	g_main_loop_unref(loop);
	g_slist_free(scopes);
	g_object_unref(app);
}

static void acquire_token_interactive_enforce_async_cb(GObject *source_object,
													   GAsyncResult *res,
													   gpointer user_data)
{
	GMainLoop *loop = user_data;
	MIBClientApp *app = MIB_CLIENT_APP(source_object);
	GError *error = NULL;

	MIBPrt *token =
		mib_client_app_acquire_token_interactive_finish(app, res, &error);
	g_assert_no_error(error);
	g_assert_nonnull(token);

	g_assert_cmpstr(mib_prt_get_access_token(token), ==,
					"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.test");

	g_object_unref(token);
	g_main_loop_quit(loop);
}

static void test_acquire_token_interactive_async_enforce(void)
{
	GError *error = NULL;
	mock_broker_set_get_accounts_response(broker, GET_ACCOUNTS_RESPONSE);
	mock_broker_set_acquire_token_interactively_response(broker,
														 TOKEN_RESPONSE);

	MIBClientApp *app = mib_public_client_app_new(
		TEST_CLIENT_ID, MIB_AUTHORITY_COMMON, NULL, &error);
	g_assert_no_error(error);

	mib_client_app_set_enforce_interactive(app, 1);

	GSList *scopes = g_slist_append(NULL, (gpointer)MIB_SCOPE_GRAPH_DEFAULT);

	GMainLoop *loop = g_main_loop_new(NULL, FALSE);
	mib_client_app_acquire_token_interactive_async(
		app, scopes, MIB_PROMPT_UNSET, "testuser@example.com", NULL, NULL, NULL,
		acquire_token_interactive_enforce_async_cb, loop);
	g_main_loop_run(loop);

	g_main_loop_unref(loop);
	g_slist_free(scopes);
	g_object_unref(app);
}

/* --- Test: acquire PRT SSO cookie --- */

static void test_acquire_prt_sso_cookie(void)
{
	GError *error = NULL;
	mock_broker_set_get_accounts_response(broker, GET_ACCOUNTS_RESPONSE);
	mock_broker_set_acquire_prt_sso_cookie_response(broker,
													PRT_SSO_COOKIE_RESPONSE);

	MIBClientApp *app = mib_public_client_app_new(
		TEST_CLIENT_ID, MIB_AUTHORITY_COMMON, NULL, &error);
	g_assert_no_error(error);

	MIBAccount *account =
		mib_client_app_get_account_by_upn(app, "testuser@example.com");
	g_assert_nonnull(account);

	GSList *scopes = g_slist_append(NULL, (gpointer)MIB_SCOPE_GRAPH_DEFAULT);
	MIBPrtSsoCookie *cookie = mib_client_app_acquire_prt_sso_cookie(
		app, account, MIB_SSO_URL_DEFAULT, scopes);
	g_assert_nonnull(cookie);

	g_assert_cmpstr(mib_prt_sso_cookie_get_name(cookie), ==,
					"x-ms-RefreshTokenCredential");
	g_assert_cmpstr(mib_prt_sso_cookie_get_content(cookie), ==,
					"cookie-content-value");

	g_slist_free(scopes);
	g_object_unref(cookie);
	g_object_unref(account);
	g_object_unref(app);
}

/* --- Test: acquire PRT SSO cookie async --- */

static void acquire_prt_sso_cookie_async_cb(GObject *source_object,
											GAsyncResult *res,
											gpointer user_data)
{
	GMainLoop *loop = user_data;
	MIBClientApp *app = MIB_CLIENT_APP(source_object);
	GError *error = NULL;

	MIBPrtSsoCookie *cookie =
		mib_client_app_acquire_prt_sso_cookie_finish(app, res, &error);
	g_assert_no_error(error);
	g_assert_nonnull(cookie);

	g_assert_cmpstr(mib_prt_sso_cookie_get_name(cookie), ==,
					"x-ms-RefreshTokenCredential");
	g_assert_cmpstr(mib_prt_sso_cookie_get_content(cookie), ==,
					"cookie-content-value");

	g_object_unref(cookie);
	g_main_loop_quit(loop);
}

static void test_acquire_prt_sso_cookie_async(void)
{
	GError *error = NULL;
	mock_broker_set_get_accounts_response(broker, GET_ACCOUNTS_RESPONSE);
	mock_broker_set_acquire_prt_sso_cookie_response(broker,
													PRT_SSO_COOKIE_RESPONSE);

	MIBClientApp *app = mib_public_client_app_new(
		TEST_CLIENT_ID, MIB_AUTHORITY_COMMON, NULL, &error);
	g_assert_no_error(error);

	MIBAccount *account =
		mib_client_app_get_account_by_upn(app, "testuser@example.com");
	g_assert_nonnull(account);

	GSList *scopes = g_slist_append(NULL, (gpointer)MIB_SCOPE_GRAPH_DEFAULT);

	GMainLoop *loop = g_main_loop_new(NULL, FALSE);
	mib_client_app_acquire_prt_sso_cookie_async(app, account,
												MIB_SSO_URL_DEFAULT, scopes,
												acquire_prt_sso_cookie_async_cb,
												loop);
	g_main_loop_run(loop);

	g_main_loop_unref(loop);
	g_slist_free(scopes);
	g_object_unref(account);
	g_object_unref(app);
}

/* --- Test: generate signed HTTP request --- */

static void test_generate_signed_http_request(void)
{
	GError *error = NULL;
	mock_broker_set_get_accounts_response(broker, GET_ACCOUNTS_RESPONSE);
	mock_broker_set_generate_signed_http_request_response(
		broker, SIGNED_HTTP_REQUEST_RESPONSE);

	MIBClientApp *app = mib_public_client_app_new(
		TEST_CLIENT_ID, MIB_AUTHORITY_COMMON, NULL, &error);
	g_assert_no_error(error);

	MIBAccount *account =
		mib_client_app_get_account_by_upn(app, "testuser@example.com");
	g_assert_nonnull(account);

	gchar *signed_req =
		mib_client_app_generate_signed_http_request(app, account, NULL);
	g_assert_nonnull(signed_req);
	g_assert_cmpstr(signed_req, ==, "signed-request-token-value");

	g_free(signed_req);
	g_object_unref(account);
	g_object_unref(app);
}

/* --- Test: generate signed HTTP request async --- */

static void generate_signed_http_request_async_cb(GObject *source_object,
												  GAsyncResult *res,
												  gpointer user_data)
{
	GMainLoop *loop = user_data;
	MIBClientApp *app = MIB_CLIENT_APP(source_object);
	GError *error = NULL;

	gchar *signed_req =
		mib_client_app_generate_signed_http_request_finish(app, res, &error);
	g_assert_no_error(error);
	g_assert_nonnull(signed_req);
	g_assert_cmpstr(signed_req, ==, "signed-request-token-value");

	g_free(signed_req);
	g_main_loop_quit(loop);
}

static void test_generate_signed_http_request_async(void)
{
	GError *error = NULL;
	mock_broker_set_get_accounts_response(broker, GET_ACCOUNTS_RESPONSE);
	mock_broker_set_generate_signed_http_request_response(
		broker, SIGNED_HTTP_REQUEST_RESPONSE);

	MIBClientApp *app = mib_public_client_app_new(
		TEST_CLIENT_ID, MIB_AUTHORITY_COMMON, NULL, &error);
	g_assert_no_error(error);

	MIBAccount *account =
		mib_client_app_get_account_by_upn(app, "testuser@example.com");
	g_assert_nonnull(account);

	GMainLoop *loop = g_main_loop_new(NULL, FALSE);
	mib_client_app_generate_signed_http_request_async(
		app, account, NULL, generate_signed_http_request_async_cb, loop);
	g_main_loop_run(loop);

	g_main_loop_unref(loop);
	g_object_unref(account);
	g_object_unref(app);
}

/* --- Test: remove account --- */

static void test_remove_account(void)
{
	GError *error = NULL;
	mock_broker_set_get_accounts_response(broker, GET_ACCOUNTS_RESPONSE);
	mock_broker_set_remove_account_response(broker, "{}");

	MIBClientApp *app = mib_public_client_app_new(
		TEST_CLIENT_ID, MIB_AUTHORITY_COMMON, NULL, &error);
	g_assert_no_error(error);

	MIBAccount *account =
		mib_client_app_get_account_by_upn(app, "testuser@example.com");
	g_assert_nonnull(account);

	int ret = mib_client_app_remove_account(app, account);
	g_assert_cmpint(ret, ==, 0);

	g_object_unref(account);
	g_object_unref(app);
}

/* --- Test: remove account async --- */

static void remove_account_async_cb(GObject *source_object, GAsyncResult *res,
									gpointer user_data)
{
	GMainLoop *loop = user_data;
	MIBClientApp *app = MIB_CLIENT_APP(source_object);
	GError *error = NULL;

	int ret = mib_client_app_remove_account_finish(app, res, &error);
	g_assert_no_error(error);
	g_assert_cmpint(ret, ==, 0);

	g_main_loop_quit(loop);
}

static void test_remove_account_async(void)
{
	GError *error = NULL;
	mock_broker_set_get_accounts_response(broker, GET_ACCOUNTS_RESPONSE);
	mock_broker_set_remove_account_response(broker, "{}");

	MIBClientApp *app = mib_public_client_app_new(
		TEST_CLIENT_ID, MIB_AUTHORITY_COMMON, NULL, &error);
	g_assert_no_error(error);

	MIBAccount *account =
		mib_client_app_get_account_by_upn(app, "testuser@example.com");
	g_assert_nonnull(account);

	GMainLoop *loop = g_main_loop_new(NULL, FALSE);
	mib_client_app_remove_account_async(app, account, remove_account_async_cb,
										loop);
	g_main_loop_run(loop);

	g_main_loop_unref(loop);
	g_object_unref(account);
	g_object_unref(app);
}

/* --- Test: get Linux broker version --- */

static void test_get_linux_broker_version(void)
{
	GError *error = NULL;
	mock_broker_set_get_linux_broker_version_response(broker,
													  BROKER_VERSION_RESPONSE);

	MIBClientApp *app = mib_public_client_app_new(
		TEST_CLIENT_ID, MIB_AUTHORITY_COMMON, NULL, &error);
	g_assert_no_error(error);

	gchar *version = mib_client_app_get_linux_broker_version(app, "1.28.0");
	g_assert_nonnull(version);
	g_assert_cmpstr(version, ==, "2.1.0");

	g_free(version);
	g_object_unref(app);
}

/* --- Test: get Linux broker version async --- */

static void get_linux_broker_version_async_cb(GObject *source_object,
											  GAsyncResult *res,
											  gpointer user_data)
{
	GMainLoop *loop = user_data;
	MIBClientApp *app = MIB_CLIENT_APP(source_object);
	GError *error = NULL;

	gchar *version =
		mib_client_app_get_linux_broker_version_finish(app, res, &error);
	g_assert_no_error(error);
	g_assert_nonnull(version);
	g_assert_cmpstr(version, ==, "2.1.0");

	g_free(version);
	g_main_loop_quit(loop);
}

static void test_get_linux_broker_version_async(void)
{
	GError *error = NULL;
	mock_broker_set_get_linux_broker_version_response(broker,
													  BROKER_VERSION_RESPONSE);

	MIBClientApp *app = mib_public_client_app_new(
		TEST_CLIENT_ID, MIB_AUTHORITY_COMMON, NULL, &error);
	g_assert_no_error(error);

	GMainLoop *loop = g_main_loop_new(NULL, FALSE);
	mib_client_app_get_linux_broker_version_async(
		app, "1.28.0", get_linux_broker_version_async_cb, loop);
	g_main_loop_run(loop);

	g_main_loop_unref(loop);
	g_object_unref(app);
}

/* --- Test: enforce interactive flag --- */

static void test_enforce_interactive(void)
{
	GError *error = NULL;
	MIBClientApp *app = mib_public_client_app_new(
		TEST_CLIENT_ID, MIB_AUTHORITY_COMMON, NULL, &error);
	g_assert_no_error(error);

	g_assert_cmpint(mib_client_app_get_enforce_interactive(app), ==, 0);
	mib_client_app_set_enforce_interactive(app, 1);
	g_assert_cmpint(mib_client_app_get_enforce_interactive(app), ==, 1);

	g_object_unref(app);
}

/* --- Test: redirect URI --- */

static void test_redirect_uri(void)
{
	GError *error = NULL;
	MIBClientApp *app = mib_public_client_app_new(
		TEST_CLIENT_ID, MIB_AUTHORITY_COMMON, NULL, &error);
	g_assert_no_error(error);

	gchar *default_uri = mib_client_app_get_broker_redirect_uri(app);
	g_assert_nonnull(default_uri);
	g_free(default_uri);

	mib_client_app_set_redirect_uri(app, "https://custom.redirect/uri");

	/* Verify by doing a get_accounts call and checking the request JSON
	 * contains the custom URI */
	mock_broker_set_get_accounts_response(broker, GET_ACCOUNTS_EMPTY_RESPONSE);
	mib_client_app_get_accounts(app);

	const gchar *last_req = mock_broker_get_last_request(broker, "getAccounts");
	g_assert_nonnull(last_req);
	g_assert_nonnull(g_strstr_len(last_req, -1, "https://custom.redirect/uri"));

	g_object_unref(app);
}

int main(int argc, char *argv[])
{
	g_test_init(&argc, &argv, NULL);

	broker = mock_broker_new();

	g_test_add_func("/client-app/new", test_client_app_new);
	g_test_add_func("/client-app/new-invalid-id",
					test_client_app_new_invalid_id);
	g_test_add_func("/client-app/get-accounts", test_get_accounts);
	g_test_add_func("/client-app/get-accounts-empty", test_get_accounts_empty);
	g_test_add_func("/client-app/get-accounts-async", test_get_accounts_async);
	g_test_add_func("/client-app/get-account-by-upn", test_get_account_by_upn);
	g_test_add_func("/client-app/get-account-by-upn-not-found",
					test_get_account_by_upn_not_found);
	g_test_add_func("/client-app/get-account-by-upn-null",
					test_get_account_by_upn_null);
	g_test_add_func("/client-app/acquire-token-silent",
					test_acquire_token_silent);
	g_test_add_func("/client-app/acquire-token-silent-bad-response",
					test_acquire_token_silent_bad_response);
	g_test_add_func("/client-app/acquire-token-silent-async",
					test_acquire_token_silent_async);
	g_test_add_func("/client-app/acquire-token-interactive-async",
					test_acquire_token_interactive_async);
	g_test_add_func("/client-app/acquire-token-interactive-async-enforce",
					test_acquire_token_interactive_async_enforce);
	g_test_add_func("/client-app/acquire-prt-sso-cookie",
					test_acquire_prt_sso_cookie);
	g_test_add_func("/client-app/acquire-prt-sso-cookie-async",
					test_acquire_prt_sso_cookie_async);
	g_test_add_func("/client-app/generate-signed-http-request",
					test_generate_signed_http_request);
	g_test_add_func("/client-app/generate-signed-http-request-async",
					test_generate_signed_http_request_async);
	g_test_add_func("/client-app/remove-account", test_remove_account);
	g_test_add_func("/client-app/remove-account-async",
					test_remove_account_async);
	g_test_add_func("/client-app/get-linux-broker-version",
					test_get_linux_broker_version);
	g_test_add_func("/client-app/get-linux-broker-version-async",
					test_get_linux_broker_version_async);
	g_test_add_func("/client-app/enforce-interactive",
					test_enforce_interactive);
	g_test_add_func("/client-app/redirect-uri", test_redirect_uri);

	int ret = g_test_run();

	mock_broker_free(broker);
	return ret;
}
