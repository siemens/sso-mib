/*
 * SPDX-FileCopyrightText: (C) 2026 Siemens
 * SPDX-License-Identifier: MIT
 *
 * JSON (de)serialization helpers for the linux-entra-sso host.
 */

#include "json-processing.h"
#include "native-messaging.h"

#include <uuid/uuid.h>

JsonNode *make_string_node(const gchar *value)
{
	JsonNode *node = json_node_alloc();
	json_node_init_string(node, value);
	return node;
}

void respond_error(const gchar *command, const gchar *message)
{
	JsonBuilder *builder = json_builder_new();
	json_builder_begin_object(builder);
	json_builder_set_member_name(builder, "error");
	json_builder_add_string_value(builder, message);
	json_builder_end_object(builder);
	JsonNode *node = json_builder_get_root(builder);
	g_object_unref(builder);
	nm_send(command, node);
}

void add_optional_string(JsonBuilder *builder, const gchar *name,
						 const gchar *value)
{
	if (!value)
		return;
	json_builder_set_member_name(builder, name);
	json_builder_add_string_value(builder, value);
}

void account_build(JsonBuilder *builder, MIBAccount *account)
{
	uuid_t realm;
	gchar realm_str[UUID_STR_LEN];

	json_builder_begin_object(builder);
	add_optional_string(builder, "clientInfo",
						mib_account_get_client_info(account));
	add_optional_string(builder, "environment",
						mib_account_get_environment(account));
	add_optional_string(builder, "familyName",
						mib_account_get_family_name(account));
	add_optional_string(builder, "givenName",
						mib_account_get_given_name(account));
	add_optional_string(builder, "homeAccountId",
						mib_account_get_home_account_id(account));
	add_optional_string(builder, "localAccountId",
						mib_account_get_local_account_id(account));
	add_optional_string(builder, "name", mib_account_get_name(account));
	json_builder_set_member_name(builder, "passwordExpiry");
	json_builder_add_int_value(builder,
							   mib_account_get_password_expiry(account));
	mib_account_get_realm(account, realm);
	uuid_unparse_lower(realm, realm_str);
	json_builder_set_member_name(builder, "realm");
	json_builder_add_string_value(builder, realm_str);
	add_optional_string(builder, "username",
						mib_account_get_username(account));
	json_builder_end_object(builder);
}

const gchar *received_username(JsonObject *request)
{
	JsonObject *account;

	if (!json_object_has_member(request, "account"))
		return NULL;
	account = json_object_get_object_member(request, "account");
	if (!account || !json_object_has_member(account, "username"))
		return NULL;
	return json_object_get_string_member(account, "username");
}

GSList *build_scopes(JsonObject *request)
{
	GSList *scopes = NULL;

	if (request && json_object_has_member(request, "scopes")) {
		JsonNode *node = json_object_get_member(request, "scopes");
		if (JSON_NODE_HOLDS_ARRAY(node)) {
			JsonArray *arr = json_node_get_array(node);
			guint n = json_array_get_length(arr);
			for (guint i = 0; i < n; i++) {
				const gchar *scope =
					json_array_get_string_element(arr, i);
				if (scope)
					scopes = g_slist_append(scopes, (gpointer)scope);
			}
		}
	}
	if (!scopes)
		scopes = g_slist_append(scopes, (gpointer)MIB_SCOPE_GRAPH_DEFAULT);
	return scopes;
}
