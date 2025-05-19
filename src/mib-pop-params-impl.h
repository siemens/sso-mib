/*
 * SPDX-FileCopyrightText: (C) 2025 Siemens
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#pragma once

#include <json-glib/json-glib.h>
#include "mib-pop-params.h"

JsonObject *mib_pop_params_to_json(MIBPopParams *self);
