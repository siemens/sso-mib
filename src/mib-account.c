/*
 * SPDX-FileCopyrightText: (C) 2025 Siemens
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include "mib-utils.h"
#include "mib-account.h"

struct _MIBAccount {
	GObject parent_instance;

	gchar *client_info;
	gchar *environment;
	gchar *family_name;
	gchar *given_name;
	gchar *home_account_id;
	gchar *local_account_id;
	gchar *name;
	time_t password_expiry;
	uuid_t realm;
	gchar *username;
};
G_DEFINE_TYPE(MIBAccount, mib_account, G_TYPE_OBJECT)

static void mib_account_finalize(GObject *gobject)
{
	MIBAccount *self = mib_account_get_instance_private(MIB_ACCOUNT(gobject));
	g_clear_pointer(&self->client_info, g_free);
	g_clear_pointer(&self->environment, g_free);
	g_clear_pointer(&self->family_name, g_free);
	g_clear_pointer(&self->given_name, g_free);
	g_clear_pointer(&self->home_account_id, g_free);
	g_clear_pointer(&self->local_account_id, g_free);
	g_clear_pointer(&self->name, g_free);
	g_clear_pointer(&self->username, g_free);
	G_OBJECT_CLASS(mib_account_parent_class)->finalize(gobject);
}

static void mib_account_class_init(MIBAccountClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS(klass);
	object_class->finalize = mib_account_finalize;
}

static void mib_account_init(MIB_ARG_UNUSED MIBAccount *self)
{
}

MIBAccount *mib_account_from_json(JsonObject *account_json)
{
	const char *members[] = { "environment",	"givenName", "homeAccountId",
							  "localAccountId", "name",		 "passwordExpiry",
							  "realm",			"username" };
	int ret = 0;
	for (size_t i = 0; i < sizeof(members) / sizeof(members[0]); i++) {
		if (!json_object_has_member(account_json, members[i]))
			return NULL;
	}

	MIBAccount *account = g_object_new(MIB_TYPE_ACCOUNT, NULL);
	account->environment =
		g_strdup(json_object_get_string_member(account_json, "environment"));
	account->given_name =
		g_strdup(json_object_get_string_member(account_json, "givenName"));
	account->home_account_id =
		g_strdup(json_object_get_string_member(account_json, "homeAccountId"));
	account->local_account_id =
		g_strdup(json_object_get_string_member(account_json, "localAccountId"));
	account->name =
		g_strdup(json_object_get_string_member(account_json, "name"));
	account->password_expiry =
		json_object_get_int_member(account_json, "passwordExpiry");
	ret = uuid_parse(json_object_get_string_member(account_json, "realm"),
					 account->realm);
	if (ret < 0) {
		g_object_unref(account);
		return NULL;
	}
	account->username =
		g_strdup(json_object_get_string_member(account_json, "username"));
	// optional fields
	if (json_object_has_member(account_json, "familyName")) {
		account->family_name =
			g_strdup(json_object_get_string_member(account_json, "familyName"));
	}
	if (json_object_has_member(account_json, "clientInfo")) {
		account->client_info =
			g_strdup(json_object_get_string_member(account_json, "clientInfo"));
	}
	return account;
}

JsonObject *mib_account_to_json(const MIBAccount *account)
{
	JsonBuilder *builder = json_builder_new();
	json_builder_begin_object(builder);
	if (account->client_info) {
		json_builder_set_member_name(builder, "clientInfo");
		json_builder_add_string_value(builder, account->client_info);
	}
	json_builder_set_member_name(builder, "environment");
	json_builder_add_string_value(builder, account->environment);
	json_builder_set_member_name(builder, "familyName");
	json_builder_add_string_value(builder, account->family_name);
	json_builder_set_member_name(builder, "givenName");
	json_builder_add_string_value(builder, account->given_name);
	json_builder_set_member_name(builder, "homeAccountId");
	json_builder_add_string_value(builder, account->home_account_id);
	json_builder_set_member_name(builder, "localAccountId");
	json_builder_add_string_value(builder, account->local_account_id);
	json_builder_set_member_name(builder, "name");
	json_builder_add_string_value(builder, account->name);
	json_builder_set_member_name(builder, "passwordExpiry");
	json_builder_add_int_value(builder, account->password_expiry);
	gchar realm_str[UUID_STR_LEN];
	uuid_unparse_lower(account->realm, realm_str);
	json_builder_set_member_name(builder, "realm");
	json_builder_add_string_value(builder, realm_str);
	json_builder_set_member_name(builder, "username");
	json_builder_add_string_value(builder, account->username);
	json_builder_end_object(builder);
	JsonNode *root = json_builder_get_root(builder);
	JsonObject *account_json = json_node_get_object(root);
	json_object_ref(account_json);
	json_node_unref(root);
	g_object_unref(builder);
	return account_json;
}

const gchar *mib_account_get_client_info(MIBAccount *account)
{
	g_assert(account);
	return account->client_info;
}
const gchar *mib_account_get_environment(MIBAccount *account)
{
	g_assert(account);
	return account->environment;
}
const gchar *mib_account_get_family_name(MIBAccount *account)
{
	g_assert(account);
	return account->family_name;
}
const gchar *mib_account_get_given_name(MIBAccount *account)
{
	g_assert(account);
	return account->given_name;
}
const gchar *mib_account_get_home_account_id(MIBAccount *account)
{
	g_assert(account);
	return account->home_account_id;
}
const gchar *mib_account_get_local_account_id(MIBAccount *account)
{
	g_assert(account);
	return account->local_account_id;
}
const gchar *mib_account_get_name(MIBAccount *account)
{
	g_assert(account);
	return account->name;
}
const gchar *mib_account_get_username(MIBAccount *account)
{
	g_assert(account);
	return account->username;
}
time_t mib_account_get_password_expiry(MIBAccount *account)
{
	g_assert(account);
	return account->password_expiry;
}
void mib_account_get_realm(MIBAccount *account, uuid_t realm)
{
	g_assert(account && realm);
	memcpy(realm, account->realm, sizeof(uuid_t));
}
