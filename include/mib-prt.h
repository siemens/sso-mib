/*
 * SPDX-FileCopyrightText: (C) 2025 Siemens
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#pragma once

#if !defined(_SSO_MIB_INSIDE_) && !defined(SSO_MIB_COMPILATION)
#error "Only <sso-mib.h> can be included directly."
#endif

#include <glib-object.h>

#include "mib-exports.h"
#include "mib-prt.h"
#include "mib-pop-params.h"

/**
 * \defgroup prt Primary Refresh Token
 * \brief Primary Refresh Token
 * \addtogroup prt
 *  @{
 */

G_BEGIN_DECLS

#ifndef DOXYGEN
#define MIB_TYPE_PRT mib_prt_get_type()
G_DECLARE_FINAL_TYPE(MIBPrt, mib_prt, MIB, PRT, GObject)
#else
typedef void* MIBPrt;
#endif

PUBLIC_API const gchar *mib_prt_get_access_token(MIBPrt *self);
PUBLIC_API enum MIB_AUTH_SCHEME mib_prt_get_access_token_type(MIBPrt *self);
PUBLIC_API MIBAccount *mib_prt_get_account(MIBPrt *self);
PUBLIC_API const gchar *mib_prt_get_client_info(MIBPrt *self);
PUBLIC_API time_t mib_prt_get_expires_on(MIBPrt *self);
PUBLIC_API gchar *const *mib_prt_get_granted_scopes(MIBPrt *self);
PUBLIC_API const gchar *mib_prt_get_id_token(MIBPrt *self);
PUBLIC_API const gchar *mib_prt_get_refresh_token(MIBPrt *self);

G_END_DECLS

/** @} */
