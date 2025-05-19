/*
 * SPDX-FileCopyrightText: (C) 2025 Siemens
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#pragma once

#include <json-glib/json-glib.h>
#include "mib-prt.h"

gchar *json_object_to_string(JsonObject *object);
MIBPrt *mib_prt_from_json(JsonObject *token_json);
