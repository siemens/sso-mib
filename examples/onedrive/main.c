/*
 * SPDX-FileCopyrightText: (C) 2025 Siemens
 * SPDX-License-Identifier: MIT
 * 
 * This example demonstrates how to get an access token from the broker and use
 * that to list the top-level files in the users OneDrive.
 */

#include "sso-mib.h"
#include <curl/curl.h>
#include <json-glib/json-glib.h>

/* OneDrive Client for Linux */
#define CLIENT_ID "d50ca740-c83f-4d1b-b616-12c519384f0c"
/* reduce the set of properties we fetch to "name" */
#define ONEDRIVE_LIST_FILES_URL \
	"https://graph.microsoft.com/v1.0/me/drive/root/children?$select=name"

/* the default application requires a non-broker redirect URI */
#define APP_REDIRECT_URI \
	"https://login.microsoftonline.com/common/oauth2/nativeclient"

struct memory {
	char *response;
	size_t size;
};

/* It would be more efficient to directly stream into the parser,
 * but for that we would have to implement an adapter to a GInputStream.
 * Instead, we just write the data to a buffer and parse this.
 */
static size_t cb(char *data, size_t size, size_t nmemb, void *clientp)
{
	size_t realsize = size * nmemb;
	struct memory *mem = (struct memory *)clientp;

	char *ptr = realloc(mem->response, mem->size + realsize + 1);
	if (!ptr)
		return 0;

	mem->response = ptr;
	memcpy(&(mem->response[mem->size]), data, realsize);
	mem->size += realsize;
	mem->response[mem->size] = 0;

	return realsize;
}

/**
 * Print a list of top-level items in the users OneDrive
 */
static void parse_response(char *data, size_t size)
{
	JsonParser *parser = NULL;
	JsonNode *root = NULL;
	GError *error = NULL;
	gboolean parse_ok = 0;
	JsonObject *rootobj = NULL, *entry = NULL;
	JsonArray *items = NULL;

	parser = json_parser_new();
	parse_ok = json_parser_load_from_data(parser, data, size, &error);
	if (!parse_ok) {
		g_warning("could not parse JSON: %s", error->message);
		g_warning("data: %s", data);
		goto cleanup;
	}
	/* for simplicity reasons, we only parse expected data */
	root = json_parser_get_root(parser);
	rootobj = json_node_get_object(root);
	items = json_object_get_array_member(rootobj, "value");
	g_print("OneDrive elements\n");
	for (guint i = 0; i < json_array_get_length(items); i++) {
		entry = json_array_get_object_element(items, i);
		const gchar *name = json_object_get_string_member(entry, "name");
		g_print("\t%s\n", name);
	}

cleanup:
	g_clear_error(&error);
	g_object_unref(parser);
}

static void list_top_level(const char *bearer)
{
	struct curl_slist *headers = NULL;
	CURLcode ret;
	long http_code = 0L;
	struct memory chunk = { 0 };

	curl_global_init(CURL_GLOBAL_DEFAULT);
	CURL *curl = curl_easy_init();
	if (!curl) {
		g_printerr("could not initialize CURL\n");
		curl_global_cleanup();
		return;
	}

	headers = curl_slist_append(headers, "Accept: application/json");
	curl_easy_setopt(curl, CURLOPT_URL, ONEDRIVE_LIST_FILES_URL);
	curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BEARER);
	curl_easy_setopt(curl, CURLOPT_XOAUTH2_BEARER, bearer);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, cb);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

	g_print("Fetch list of files\n");
	ret = curl_easy_perform(curl);
	if (ret != CURLE_OK) {
		g_printerr("error performing request\n");
	} else {
		curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
		if (http_code == 200) {
			parse_response(chunk.response, chunk.size);
		}
	}

	free(chunk.response);
	curl_slist_free_all(headers);
	curl_easy_cleanup(curl);
	curl_global_cleanup();
}

int main()
{
	MIBClientApp *app = NULL;
	GSList *scopes = NULL;
	char *const *granted_scopes = NULL;
	/* if NULL, it is auto-resolved. Could also come from a config */
	const gchar *upn_hint = NULL;
	MIBPrt *token = NULL;

	app =
		mib_public_client_app_new(CLIENT_ID, MIB_AUTHORITY_COMMON, NULL, NULL);
	if (!app)
		goto cleanup;

	mib_client_app_set_redirect_uri(app, APP_REDIRECT_URI);
	scopes = g_slist_append(scopes, "Files.Read");

	token = mib_client_app_acquire_token_interactive(
		app, scopes, MIB_PROMPT_UNSET, upn_hint, NULL, NULL, NULL);
	if (!token) {
		g_printerr("could not get token\n");
		goto cleanup;
	}

	/* check which scopes were granted */
	g_print("granted scopes:\n");
	granted_scopes = mib_prt_get_granted_scopes(token);
	while (*granted_scopes) {
		g_print("\t%s\n", *granted_scopes++);
	}

	list_top_level(mib_prt_get_access_token(token));

cleanup:
	g_clear_object(&token);
	g_slist_free(scopes);
	g_clear_object(&app);
}
