/*
 * SPDX-FileCopyrightText: (C) 2025 Siemens
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#pragma once

#include <glib-2.0/glib.h>
#include "identity-broker.h"
#include "mib-client-app.h"

GCancellable *mib_client_app_get_cancellable(MIBClientApp *self);
mibdbusIdentityBroker1 *mib_client_app_get_broker(MIBClientApp *self);
