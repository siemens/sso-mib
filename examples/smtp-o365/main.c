/*
 * SPDX-FileCopyrightText: (C) 2025 Siemens
 * SPDX-License-Identifier: MIT
 * 
 * This example showcases a fully-functional git credential helper to
 * authenticate git send-email on Office365 using tokens from the broker.
 * 
 * The following data needs to be set via environment variables:
 *  - MIB_GCH_SMTP_AUTHORITY : authority to run OAUTH2 against
 *  - MIB_GCH_SMTP_CLIENT_ID : client-id of the application
 * 
 * Example entry in .gitconfig
 * [credential "smtp://"]
 * helper = !sso-mib-gch-smtp-o365
 */

#include "sso-mib.h"
#include <stdio.h>

#define MAX_LINE 512
#define MAX_VAL 256

#define APP_REDIRECT_URI \
	"https://login.microsoftonline.com/common/oauth2/nativeclient"

typedef struct {
	char username[MAX_VAL];
	char protocol[MAX_VAL];
} GitCredInput;

void parse_git_cred_input(GitCredInput *out)
{
	char line[MAX_LINE];

	while (fgets(line, sizeof(line), stdin)) {
		char *eq, *key, *val;

		line[strcspn(line, "\r\n")] = '\0';
		if ((eq = strchr(line, '=')) == NULL)
			continue;

		*eq = '\0';
		key = line;
		val = eq + 1;

		if (strcmp(key, "username") == 0) {
			strncpy(out->username, val, sizeof(out->username) - 1);
			out->username[sizeof(out->username) - 1] = '\0';
		} else if (strcmp(key, "protocol") == 0) {
			strncpy(out->protocol, val, sizeof(out->protocol) - 1);
			out->protocol[sizeof(out->protocol) - 1] = '\0';
		}
	}
}

int main()
{
	MIBClientApp *app = NULL;
	GSList *scopes = NULL;
	MIBPrt *token = NULL;
	MIBAccount *account = NULL;
	GitCredInput input = { .username = "", .protocol = "" };
	const gchar *authority = getenv("MIB_GCH_SMTP_AUTHORITY");
	const gchar *client_id = getenv("MIB_GCH_SMTP_CLIENT_ID");

	if (!authority) {
		printf("missing authority, set via env-var 'MIB_GCH_SMTP_AUTHORITY'\n");
		return 1;
	}
	if (!client_id) {
		printf("missing client-id, set via env-var 'MIB_GCH_SMTP_CLIENT_ID'\n");
		return 1;
	}

	parse_git_cred_input(&input);
	// helper called for wrong protocol
	if (strcmp(input.protocol, "smtp") != 0)
		goto cleanup;

	app = mib_public_client_app_new(client_id, authority, NULL, NULL);
	if (!app)
		goto cleanup;

	mib_client_app_set_redirect_uri(app, APP_REDIRECT_URI);
	scopes = g_slist_append(scopes, "offline_access");
	scopes = g_slist_append(scopes, "https://outlook.office365.com/SMTP.Send");

	token = mib_client_app_acquire_token_interactive(
		app, scopes, MIB_PROMPT_NONE, input.username, NULL, NULL, NULL);
	if (!token) {
		g_printerr("could not get token\n");
		goto cleanup;
	}
	account = mib_prt_get_account(token);
	g_print("username=%s\n", mib_account_get_username(account));
	g_print("password=%s\n", mib_prt_get_access_token(token));
	g_print("password_expiry_utc=%jd\n", mib_prt_get_expires_on(token));
	g_print("authtype=bearer\n");

cleanup:
	g_clear_object(&token);
	g_slist_free(scopes);
	g_clear_object(&app);

	return 0;
}
