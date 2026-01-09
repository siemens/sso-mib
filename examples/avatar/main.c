/*
 * SPDX-FileCopyrightText: (C) 2025 Siemens
 * SPDX-License-Identifier: MIT
 * 
 * This example demonstrates how to get an access token from the broker and use
 * that to get the avatar picture of the calling user from the MS Graph API.
 */

#include "sso-mib.h"

#include <stdio.h>
#include <curl/curl.h>

#define EDGE_BROWSER_CLIENT_ID "d7b530a4-7680-4c23-a8bf-c52c121d2e87"
#define AVATAR_URL "https://graph.microsoft.com/v1.0/me/photo/$value"

static void fetch_avatar(const char *bearer, FILE *outfile)
{
	struct curl_slist *headers = NULL;
	CURLcode ret;
	long http_code = 0L;

	curl_global_init(CURL_GLOBAL_DEFAULT);
	CURL *curl = curl_easy_init();
	if (!curl) {
		g_printerr("could not initialize CURL\n");
		curl_global_cleanup();
		return;
	}

	headers = curl_slist_append(headers, "Accept: image/jpeg");
	curl_easy_setopt(curl, CURLOPT_URL, AVATAR_URL);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, outfile);
	curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BEARER);
	curl_easy_setopt(curl, CURLOPT_XOAUTH2_BEARER, bearer);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

	g_print("Fetch avatar\n");
	ret = curl_easy_perform(curl);
	if (ret != CURLE_OK) {
		g_printerr("error performing request\n");
	} else {
		curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
		g_print("HTTP Response Code: %ld\n", http_code);
	}

	curl_slist_free_all(headers);
	curl_easy_cleanup(curl);
	curl_global_cleanup();
}

int main()
{
	const gchar *client_id = EDGE_BROWSER_CLIENT_ID;
	const gchar *authority = MIB_AUTHORITY_COMMON;
	int ret = 0;

	MIBClientApp *app =
		mib_public_client_app_new(client_id, authority, NULL, NULL);
	GSList *scopes = NULL;

	/* get all registered accounts, select first one */
	GSList *accounts = mib_client_app_get_accounts(app);
	MIBAccount *account = g_slist_nth_data(accounts, 0);
	if (!account) {
		g_printerr("no account is registered\n");
		g_object_unref(app);
		return -1;
	}

	FILE *f = fopen("avatar.jpg", "w");
	if (!f) {
		g_printerr("could not open file\n");
		ret = -1;
		goto cleanup;
	}

	printf("Acquire Bearer token\n");
	scopes = g_slist_append(scopes, g_strdup(MIB_SCOPE_GRAPH_DEFAULT));
	MIBPrt *prt =
		mib_client_app_acquire_token_silent(app, account, scopes, NULL, NULL, NULL);
	if (!prt) {
		printf("Failed to get Graph API token\n");
		ret = -1;
		goto cleanup;
	}

	const char *token = mib_prt_get_access_token(prt);
	fetch_avatar(token, f);
	printf("Successfully stored avatar picture in 'avatar.jpg'\n");

cleanup:
	fclose(f);
	g_slist_free_full(scopes, (GDestroyNotify)g_free);
	g_slist_free_full(accounts, (GDestroyNotify)g_object_unref);
	g_clear_object(&prt);
	g_object_unref(app);
	return ret;
}
