/*
 * SPDX-FileCopyrightText: (C) 2025 Siemens
 * SPDX-License-Identifier: LGPL-2.1-only
 * 
 */

#pragma once

#if !defined(_SSO_MIB_INSIDE_) && !defined(SSO_MIB_COMPILATION)
#error "Only <sso-mib.h> can be included directly."
#endif

#include <glib-object.h>

#include "mib-exports.h"

/**
 * \defgroup prtssocookie PRT SSO Cookie
 * \brief PRT SSO Cookie (MS-OAPXBC OAuth2 extension)
 *
 * \note The cookie content is securely wiped from memory when the object is destroyed.
 * Use the pointer returned when accessing the content directly, without making a
 * copy. This avoids duplicating the sensitive content in memory and ensures it is
 * wiped when the cookie object is destroyed.
 *
 * \addtogroup prtssocookie
 *  @{
 */

G_BEGIN_DECLS

#ifndef DOXYGEN
#define MIB_TYPE_PRT_SSO_COOKIE mib_prt_sso_cookie_get_type()
G_DECLARE_FINAL_TYPE(MIBPrtSsoCookie, mib_prt_sso_cookie, MIB, PRT_SSO_COOKIE,
					 GObject)
PUBLIC_API GType mib_prt_sso_cookie_get_type(void);
#else
typedef void* MIBPrtSsoCookie;
#endif

PUBLIC_API const gchar *mib_prt_sso_cookie_get_name(MIBPrtSsoCookie *self);
PUBLIC_API const gchar *mib_prt_sso_cookie_get_content(MIBPrtSsoCookie *self);

G_END_DECLS

/** @} */
