/*
 * SPDX-FileCopyrightText: (C) 2025 Siemens
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#pragma once

#if (__GNUC__ > 2) || (__GNUC__ == 2 && __GNUC_MINOR__ > 4)
#define MIB_ARG_UNUSED __attribute__((__unused__))
#else
#define MIB_ARG_UNUSED
#endif

#include <glib-2.0/glib.h>
#include <json-glib/json-glib.h>

typedef struct _MIBAccount MIBAccount;

gchar *json_object_to_string(JsonObject *object);
JsonObject *json_object_from_string(const gchar *data);
void debug_print_json_object(const gchar *func, const gchar *scope,
							 JsonObject *object);
JsonArray *mib_scopes_to_json(GSList *scopes);

/**
 * Helper to deep copy strings in a GSList.
 */
gpointer copy_string(gconstpointer src, MIB_ARG_UNUSED gpointer data);

/**
 * Find an account matching @upn in a list.
 * Returns a new reference or NULL.
 */
MIBAccount *find_account_by_upn(GSList *accounts, const gchar *upn);
