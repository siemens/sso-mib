/*
 * SPDX-FileCopyrightText: (C) 2025 Siemens
 * SPDX-License-Identifier: MIT
 */

#include "mock-broker.h"
#include "identity-broker.h"

struct _MockBroker {
	GTestDBus *dbus;
	GDBusConnection *conn;
	mibdbusIdentityBroker1 *skeleton;
	guint name_id;

	/* Dedicated thread and context for processing skeleton method calls */
	GMainContext *context;
	GMainLoop *loop;
	GThread *thread;

	gchar *get_accounts_response;
	gchar *acquire_token_silently_response;
	gchar *acquire_token_interactively_response;
	gchar *acquire_prt_sso_cookie_response;
	gchar *generate_signed_http_request_response;
	gchar *remove_account_response;
	gchar *get_linux_broker_version_response;

	GHashTable *last_requests; /* method_name -> last request JSON */
};

static void store_request(MockBroker *self, const gchar *method,
						  const gchar *request)
{
	g_hash_table_replace(self->last_requests, g_strdup(method),
						 g_strdup(request));
}

static gboolean on_handle_get_accounts(mibdbusIdentityBroker1 *skeleton,
									   GDBusMethodInvocation *invocation,
									   const gchar *protocol_version,
									   const gchar *correlation_id,
									   const gchar *request, gpointer user_data)
{
	MockBroker *self = user_data;
	store_request(self, "getAccounts", request);
	mib_dbus_identity_broker1_complete_get_accounts(
		skeleton, invocation,
		self->get_accounts_response ? self->get_accounts_response : "{}");
	return TRUE;
}

static gboolean on_handle_acquire_token_silently(
	mibdbusIdentityBroker1 *skeleton, GDBusMethodInvocation *invocation,
	const gchar *protocol_version, const gchar *correlation_id,
	const gchar *request, gpointer user_data)
{
	MockBroker *self = user_data;
	store_request(self, "acquireTokenSilently", request);
	mib_dbus_identity_broker1_complete_acquire_token_silently(
		skeleton, invocation,
		self->acquire_token_silently_response ?
			self->acquire_token_silently_response :
			"{}");
	return TRUE;
}

static gboolean on_handle_acquire_token_interactively(
	mibdbusIdentityBroker1 *skeleton, GDBusMethodInvocation *invocation,
	const gchar *protocol_version, const gchar *correlation_id,
	const gchar *request, gpointer user_data)
{
	MockBroker *self = user_data;
	store_request(self, "acquireTokenInteractively", request);
	mib_dbus_identity_broker1_complete_acquire_token_interactively(
		skeleton, invocation,
		self->acquire_token_interactively_response ?
			self->acquire_token_interactively_response :
			"{}");
	return TRUE;
}

static gboolean on_handle_acquire_prt_sso_cookie(
	mibdbusIdentityBroker1 *skeleton, GDBusMethodInvocation *invocation,
	const gchar *protocol_version, const gchar *correlation_id,
	const gchar *request, gpointer user_data)
{
	MockBroker *self = user_data;
	store_request(self, "acquirePrtSsoCookie", request);
	mib_dbus_identity_broker1_complete_acquire_prt_sso_cookie(
		skeleton, invocation,
		self->acquire_prt_sso_cookie_response ?
			self->acquire_prt_sso_cookie_response :
			"{}");
	return TRUE;
}

static gboolean on_handle_generate_signed_http_request(
	mibdbusIdentityBroker1 *skeleton, GDBusMethodInvocation *invocation,
	const gchar *protocol_version, const gchar *correlation_id,
	const gchar *request, gpointer user_data)
{
	MockBroker *self = user_data;
	store_request(self, "generateSignedHttpRequest", request);
	mib_dbus_identity_broker1_complete_generate_signed_http_request(
		skeleton, invocation,
		self->generate_signed_http_request_response ?
			self->generate_signed_http_request_response :
			"{}");
	return TRUE;
}

static gboolean on_handle_remove_account(mibdbusIdentityBroker1 *skeleton,
										 GDBusMethodInvocation *invocation,
										 const gchar *protocol_version,
										 const gchar *correlation_id,
										 const gchar *request,
										 gpointer user_data)
{
	MockBroker *self = user_data;
	store_request(self, "removeAccount", request);
	mib_dbus_identity_broker1_complete_remove_account(
		skeleton, invocation,
		self->remove_account_response ? self->remove_account_response : "{}");
	return TRUE;
}

static gboolean on_handle_get_linux_broker_version(
	mibdbusIdentityBroker1 *skeleton, GDBusMethodInvocation *invocation,
	const gchar *protocol_version, const gchar *correlation_id,
	const gchar *request, gpointer user_data)
{
	MockBroker *self = user_data;
	store_request(self, "getLinuxBrokerVersion", request);
	mib_dbus_identity_broker1_complete_get_linux_broker_version(
		skeleton, invocation,
		self->get_linux_broker_version_response ?
			self->get_linux_broker_version_response :
			"{}");
	return TRUE;
}

static gpointer mock_broker_thread_func(gpointer data)
{
	MockBroker *self = data;
	g_main_loop_run(self->loop);
	return NULL;
}

MockBroker *mock_broker_new(void)
{
	MockBroker *self = g_new0(MockBroker, 1);
	GError *error = NULL;

	self->last_requests =
		g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);

	/* Create a dedicated context for the broker thread */
	self->context = g_main_context_new();
	self->loop = g_main_loop_new(self->context, FALSE);

	/* Start an isolated session bus */
	self->dbus = g_test_dbus_new(G_TEST_DBUS_NONE);
	g_test_dbus_up(self->dbus);

	/* Get a private connection for the skeleton.
	 * Push our context so the connection dispatches on it. */
	g_main_context_push_thread_default(self->context);

	self->conn = g_dbus_connection_new_for_address_sync(
		g_test_dbus_get_bus_address(self->dbus),
		G_DBUS_CONNECTION_FLAGS_AUTHENTICATION_CLIENT |
			G_DBUS_CONNECTION_FLAGS_MESSAGE_BUS_CONNECTION,
		NULL, NULL, &error);
	g_assert_no_error(error);

	/* Create and export skeleton */
	self->skeleton = mib_dbus_identity_broker1_skeleton_new();

	g_signal_connect(self->skeleton, "handle-get-accounts",
					 G_CALLBACK(on_handle_get_accounts), self);
	g_signal_connect(self->skeleton, "handle-acquire-token-silently",
					 G_CALLBACK(on_handle_acquire_token_silently), self);
	g_signal_connect(self->skeleton, "handle-acquire-token-interactively",
					 G_CALLBACK(on_handle_acquire_token_interactively), self);
	g_signal_connect(self->skeleton, "handle-acquire-prt-sso-cookie",
					 G_CALLBACK(on_handle_acquire_prt_sso_cookie), self);
	g_signal_connect(self->skeleton, "handle-generate-signed-http-request",
					 G_CALLBACK(on_handle_generate_signed_http_request), self);
	g_signal_connect(self->skeleton, "handle-remove-account",
					 G_CALLBACK(on_handle_remove_account), self);
	g_signal_connect(self->skeleton, "handle-get-linux-broker-version",
					 G_CALLBACK(on_handle_get_linux_broker_version), self);

	gboolean exported = g_dbus_interface_skeleton_export(
		G_DBUS_INTERFACE_SKELETON(self->skeleton), self->conn,
		"/com/microsoft/identity/broker1", &error);
	g_assert_no_error(error);
	g_assert_true(exported);

	/* Own the well-known name */
	self->name_id = g_bus_own_name_on_connection(
		self->conn, "com.microsoft.identity.broker1",
		G_BUS_NAME_OWNER_FLAGS_NONE, NULL, NULL, NULL, NULL);

	g_main_context_pop_thread_default(self->context);

	/* Start the broker thread to handle incoming method calls */
	self->thread = g_thread_new("mock-broker", mock_broker_thread_func, self);

	/* Give the thread a moment to start and own the name */
	g_usleep(100 * 1000);

	return self;
}

void mock_broker_free(MockBroker *self)
{
	if (!self)
		return;

	/* Stop the broker thread */
	g_main_loop_quit(self->loop);
	g_thread_join(self->thread);

	g_bus_unown_name(self->name_id);
	g_dbus_interface_skeleton_unexport(
		G_DBUS_INTERFACE_SKELETON(self->skeleton));
	g_clear_object(&self->skeleton);
	g_clear_object(&self->conn);
	g_test_dbus_down(self->dbus);
	g_clear_object(&self->dbus);

	g_main_loop_unref(self->loop);
	g_main_context_unref(self->context);

	g_free(self->get_accounts_response);
	g_free(self->acquire_token_silently_response);
	g_free(self->acquire_token_interactively_response);
	g_free(self->acquire_prt_sso_cookie_response);
	g_free(self->generate_signed_http_request_response);
	g_free(self->remove_account_response);
	g_free(self->get_linux_broker_version_response);

	g_hash_table_unref(self->last_requests);
	g_free(self);
}

void mock_broker_set_get_accounts_response(MockBroker *self, const gchar *json)
{
	g_free(self->get_accounts_response);
	self->get_accounts_response = g_strdup(json);
}

void mock_broker_set_acquire_token_silently_response(MockBroker *self,
													 const gchar *json)
{
	g_free(self->acquire_token_silently_response);
	self->acquire_token_silently_response = g_strdup(json);
}

void mock_broker_set_acquire_token_interactively_response(MockBroker *self,
														  const gchar *json)
{
	g_free(self->acquire_token_interactively_response);
	self->acquire_token_interactively_response = g_strdup(json);
}

void mock_broker_set_acquire_prt_sso_cookie_response(MockBroker *self,
													 const gchar *json)
{
	g_free(self->acquire_prt_sso_cookie_response);
	self->acquire_prt_sso_cookie_response = g_strdup(json);
}

void mock_broker_set_generate_signed_http_request_response(MockBroker *self,
														   const gchar *json)
{
	g_free(self->generate_signed_http_request_response);
	self->generate_signed_http_request_response = g_strdup(json);
}

void mock_broker_set_remove_account_response(MockBroker *self,
											 const gchar *json)
{
	g_free(self->remove_account_response);
	self->remove_account_response = g_strdup(json);
}

void mock_broker_set_get_linux_broker_version_response(MockBroker *self,
													   const gchar *json)
{
	g_free(self->get_linux_broker_version_response);
	self->get_linux_broker_version_response = g_strdup(json);
}

const gchar *mock_broker_get_last_request(MockBroker *self,
										  const gchar *method_name)
{
	return g_hash_table_lookup(self->last_requests, method_name);
}
