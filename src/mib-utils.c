/*
 * SPDX-FileCopyrightText: (C) 2025 Siemens
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include "mib-utils.h"

gchar *json_object_to_string(JsonObject *object)
{
	JsonGenerator *gen = json_generator_new();
	JsonNode *root = json_node_new(JSON_NODE_OBJECT);
	json_node_set_object(root, object);
	json_generator_set_root(gen, root);
	gchar *buffer = json_generator_to_data(gen, NULL);
	json_node_unref(root);
	g_object_unref(gen);
	return buffer;
}

static void print_json_object(JsonObject *object)
{
	JsonGenerator *gen = json_generator_new();
	JsonNode *root = json_node_new(JSON_NODE_OBJECT);
	json_node_set_object(root, object);
	json_generator_set_root(gen, root);
	json_generator_set_pretty(gen, TRUE);
	gchar *buffer = json_generator_to_data(gen, NULL);
	g_debug("%s", buffer);
	g_free(buffer);
	json_node_unref(root);
	g_object_unref(gen);
}

void debug_print_json_object(gchar *func, gchar *scope, JsonObject *object)
{
	g_debug("json-object from %s,%s", func, scope);
	print_json_object(object);
}

JsonObject *json_object_from_string(const gchar *data)
{
	JsonParser *parser = json_parser_new();
	JsonNode *root;
	GError *error = NULL;
	gboolean parse_ok = json_parser_load_from_data(parser, data, -1, &error);
	if (!parse_ok) {
		g_warning("could not parse JSON: %s", error->message);
		g_warning("data: %s", data);
		g_error_free(error);
		g_object_unref(parser);
		return NULL;
	}
	root = json_parser_get_root(parser);
	if (json_node_get_value_type(root) != JSON_TYPE_OBJECT) {
		g_warning("could not parse JSON: root is not an object");
		g_object_unref(parser);
		return NULL;
	}
	JsonObject *object = json_node_get_object(root);
	json_object_ref(object);
	g_object_unref(parser);
	return object;
}

JsonArray *mib_scopes_to_json(GSList *scopes)
{
	JsonArray *scopes_array = json_array_new();
	for (GSList *iter = scopes; iter; iter = g_slist_next(iter)) {
		json_array_add_string_element(scopes_array, iter->data);
	}
	return scopes_array;
}
