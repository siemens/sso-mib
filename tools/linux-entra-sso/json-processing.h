/*
 * SPDX-FileCopyrightText: (C) 2026 Siemens
 * SPDX-License-Identifier: MIT
 *
 * JSON (de)serialization helpers for the linux-entra-sso host.
 */

#ifndef LINUX_ENTRA_SSO_JSON_PROCESSING_H
#define LINUX_ENTRA_SSO_JSON_PROCESSING_H

#include "sso-mib.h"

#include <glib.h>
#include <json-glib/json-glib.h>

/* Allocate a JSON string node holding value. */
JsonNode *make_string_node(const gchar *value);

/* Build and send an { error } response for command. */
void respond_error(const gchar *command, const gchar *message);

/* Add a string member to builder, skipping it when value is NULL. */
void add_optional_string(JsonBuilder *builder, const gchar *name,
						 const gchar *value);

/* Serialize account into the object currently being built. */
void account_build(JsonBuilder *builder, MIBAccount *account);

/* Return the username from request->account, or NULL if absent. */
const gchar *received_username(JsonObject *request);

/*
 * Build the requested scopes, falling back to the graph default scope.
 * The returned list borrows the strings and must be freed with g_slist_free.
 */
GSList *build_scopes(JsonObject *request);

#endif /* LINUX_ENTRA_SSO_JSON_PROCESSING_H */
