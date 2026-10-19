/*
 * SPDX-FileCopyrightText: (C) 2025 Siemens
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#pragma once

#include <json-glib/json-glib.h>
#include "mib-prt-sso-cookie.h"

/**
 * Create a MIBPrtSsoCookie object from a JSON representation of a cookie.
 *
 * For security reasons, this is a destructive operation: the JSON string
 * containing sensitive cookie information may be cleared from memory.
 */
MIBPrtSsoCookie *mib_prt_sso_cookie_from_json(JsonObject *cookie_json);
