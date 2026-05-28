/*
 * SPDX-FileCopyrightText: (C) 2026 Siemens
 * SPDX-License-Identifier: MIT
 *
 * This example demonstrates how to acquire a token asynchronously using
 * the GAsyncReadyCallback pattern with chained async operations.
 * A periodic GSource prints progress dots on the default main context
 * while the request is in-flight.
 */

#include "sso-mib.h"
#include <stdio.h>

#define EDGE_BROWSER_CLIENT_ID "d7b530a4-7680-4c23-a8bf-c52c121d2e87"

typedef struct {
	GSList *scopes;
	gboolean done;
} AsyncContext;

static gboolean print_dot(gpointer user_data)
{
	AsyncContext *ctx = user_data;
	if (ctx->done)
		return G_SOURCE_REMOVE;
	g_print(".");
	fflush(stdout);
	return G_SOURCE_CONTINUE;
}

static void on_token_acquired(GObject *source_object, GAsyncResult *res,
							  gpointer user_data)
{
	AsyncContext *ctx = user_data;
	MIBClientApp *app = MIB_CLIENT_APP(source_object);
	GError *error = NULL;

	MIBPrt *prt = mib_client_app_acquire_token_silent_finish(app, res, &error);
	if (!prt) {
		g_printerr("Failed to acquire token: %s\n", error->message);
		g_error_free(error);
	} else {
		g_print("Access token: %s\n", mib_prt_get_access_token(prt));
		g_object_unref(prt);
	}

	ctx->done = TRUE;
}

static void on_accounts_ready(GObject *source_object, GAsyncResult *res,
							  gpointer user_data)
{
	AsyncContext *ctx = user_data;
	MIBClientApp *app = MIB_CLIENT_APP(source_object);
	GError *error = NULL;

	GSList *accounts = mib_client_app_get_accounts_finish(app, res, &error);
	if (!accounts) {
		g_printerr("Failed to get accounts: %s\n",
				   error ? error->message : "no accounts registered");
		g_clear_error(&error);
		ctx->done = TRUE;
		return;
	}

	MIBAccount *account = g_slist_nth_data(accounts, 0);
	if (!account) {
		g_printerr("No account is registered\n");
		g_slist_free_full(accounts, (GDestroyNotify)g_object_unref);
		ctx->done = TRUE;
		return;
	}

	/* chain: acquire token asynchronously */
	mib_client_app_acquire_token_silent_async(
		app, account, ctx->scopes, NULL, NULL, NULL, on_token_acquired, ctx);
	g_slist_free_full(accounts, (GDestroyNotify)g_object_unref);
}

int main(void)
{
	const gchar *authority = MIB_AUTHORITY_COMMON;
	AsyncContext ctx = { .scopes = NULL, .done = FALSE };

	MIBClientApp *app = mib_public_client_app_new(EDGE_BROWSER_CLIENT_ID,
												  authority, NULL, NULL);
	if (!app) {
		g_printerr("Failed to create client app\n");
		return -1;
	}

	ctx.scopes = g_slist_append(NULL, g_strdup("User.Read"));

	/* start the async chain: get accounts, then acquire token */
	mib_client_app_get_accounts_async(app, on_accounts_ready, &ctx);

	/* print dots while the request is in-flight */
	g_timeout_add(50, print_dot, &ctx);

	/* iterate the main context until all async work completes */
	while (!ctx.done)
		g_main_context_iteration(NULL, TRUE);

	g_slist_free_full(ctx.scopes, g_free);
	g_object_unref(app);
	return 0;
}
