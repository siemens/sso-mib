/*
 * SPDX-FileCopyrightText: (C) 2025 Siemens
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include "mib-utils.h"
#include "mib-account.h"
#include "mib-account-impl.h"

struct _MIBPrt {
	GObject parent_instance;

	gchar *access_token;
	enum MIB_AUTH_SCHEME access_token_type;
	MIBAccount *account;
	gchar *client_info;
	/// Expiry time in seconds since epoch
	time_t expires_on;
	/// Allocated array of strings, null terminated
	gchar **granted_scopes;
	gchar *id_token;
	gchar *refresh_token;
};
G_DEFINE_TYPE(MIBPrt, mib_prt, G_TYPE_OBJECT)

static void mib_prt_finalize(GObject *gobject)
{
	MIBPrt *self = mib_prt_get_instance_private(MIB_PRT(gobject));
	g_clear_pointer(&self->access_token, g_free);
	g_clear_object(&self->account);
	g_clear_pointer(&self->client_info, g_free);
	g_clear_pointer(&self->granted_scopes, g_strfreev);
	g_clear_pointer(&self->id_token, g_free);
	g_clear_pointer(&self->refresh_token, g_free);
	G_OBJECT_CLASS(mib_prt_parent_class)->finalize(gobject);
}

static void mib_prt_class_init(MIBPrtClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS(klass);
	object_class->finalize = mib_prt_finalize;
}

static void mib_prt_init(MIB_ARG_UNUSED MIBPrt *self)
{
}

/* Convert undocumented external token number to our types */
static int mib_prt_token_type_from_ext(int ext_token_type)
{
	switch (ext_token_type) {
	case 0:
		return MIB_AUTH_SCHEME_BEARER;
	case 1:
		return MIB_AUTH_SCHEME_POP;
	default:
		g_warning("unknown token type %d\n", ext_token_type);
	}
	return MIB_AUTH_SCHEME_BEARER;
}

MIBPrt *mib_prt_from_json(JsonObject *token_json)
{
	MIBAccount *account = NULL;
	JsonObject *account_json = NULL;
	MIBPrt *token = NULL;
	const char *members[] = { "accessToken",  "accessTokenType", "account",
							  "clientInfo",	  "expiresOn",		 "idToken",
							  "grantedScopes" };

	if (!json_object_has_member(token_json, "brokerTokenResponse"))
		return NULL;

	JsonObject *broker_resp =
		json_object_get_object_member(token_json, "brokerTokenResponse");

	for (size_t i = 0; i < sizeof(members) / sizeof(members[0]); i++) {
		if (!json_object_has_member(broker_resp, members[i]))
			return NULL;
	}

	token = g_object_new(MIB_TYPE_PRT, NULL);
	token->access_token =
		g_strdup(json_object_get_string_member(broker_resp, "accessToken"));
	token->access_token_type = mib_prt_token_type_from_ext(
		json_object_get_int_member(broker_resp, "accessTokenType"));
	account_json = json_object_get_object_member(broker_resp, "account");
	account = mib_account_from_json(account_json);
	if (!account) {
		g_warning("account data is not valid");
		g_object_unref(token);
		return NULL;
	}
	token->account = account;
	token->client_info =
		g_strdup(json_object_get_string_member(broker_resp, "clientInfo"));
	token->expires_on =
		json_object_get_int_member(broker_resp, "expiresOn") / 1000;
	token->id_token =
		g_strdup(json_object_get_string_member(broker_resp, "idToken"));

	if (json_object_has_member(broker_resp, "refreshToken")) {
		token->refresh_token = g_strdup(
			json_object_get_string_member(broker_resp, "refreshToken"));
	}

	const gchar *granted_scopes =
		json_object_get_string_member(broker_resp, "grantedScopes");
	token->granted_scopes = g_strsplit(granted_scopes, " ", -1);
	return token;
}

const gchar *mib_prt_get_access_token(MIBPrt *self)
{
	g_assert(self);
	return self->access_token;
}
enum MIB_AUTH_SCHEME mib_prt_get_access_token_type(MIBPrt *self)
{
	g_assert(self);
	return self->access_token_type;
}
MIBAccount *mib_prt_get_account(MIBPrt *self)
{
	g_assert(self);
	return self->account;
}
const gchar *mib_prt_get_client_info(MIBPrt *self)
{
	g_assert(self);
	return self->client_info;
}
time_t mib_prt_get_expires_on(MIBPrt *self)
{
	g_assert(self);
	return self->expires_on;
}
gchar *const *mib_prt_get_granted_scopes(MIBPrt *self)
{
	g_assert(self);
	return self->granted_scopes;
}
const gchar *mib_prt_get_id_token(MIBPrt *self)
{
	g_assert(self);
	return self->id_token;
}

const gchar *mib_prt_get_refresh_token(MIBPrt *self)
{
	g_assert(self);
	return self->refresh_token;
}
