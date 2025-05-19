/*
 * SPDX-FileCopyrightText: (C) 2025 Siemens
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#pragma once

#include <json-glib/json-glib.h>
#include "mib-prt-sso-cookie.h"

MIBPrtSsoCookie *mib_prt_sso_cookie_from_json(JsonObject *cookie_json);
