/*
 * SPDX-FileCopyrightText: (C) 2026 Siemens
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#pragma once

#if !defined(_SSO_MIB_INSIDE_) && !defined(SSO_MIB_COMPILATION)
#error "Only <sso-mib.h> can be included directly."
#endif

#include <glib-object.h>

#include "mib-exports.h"

/**
 * \defgroup mib_utils MIB Utilities
 * \brief Utility functions for MIB library
 *
 * \addtogroup mib_utils
 *  @{
 */

G_BEGIN_DECLS

/**
 * Securely wipe and free a sensitive string returned by this library.
 *
 * The string may be NULL.
 */
PUBLIC_API void mib_secure_free_string(gchar *string);

G_END_DECLS

/** @} */
