/*
 * SPDX-FileCopyrightText: (C) 2025 Siemens
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#pragma once

#include <glib-2.0/glib.h>
#include <json-glib/json-glib.h>
#include "mib-account.h"
#include "mib-client-app.h"

MIBAccount *mib_account_from_json(JsonObject *account_json);
JsonObject *mib_account_to_json(const MIBAccount *account);
