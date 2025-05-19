/*
 * SPDX-FileCopyrightText: (C) 2025 Siemens
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#pragma once

#if !defined(_SSO_MIB_INSIDE_) && !defined(SSO_MIB_COMPILATION)
#error "Only <sso-mib.h> can be included directly."
#endif

#include <glib-object.h>
#include <uuid/uuid.h>

#include "mib-exports.h"

/**
 * \defgroup account Account
 * \brief Account object as returned by \ref mib_client_app_get_accounts
 * \addtogroup account
 *  @{
 */

G_BEGIN_DECLS

#ifndef DOXYGEN
#define MIB_TYPE_ACCOUNT mib_account_get_type()
G_DECLARE_FINAL_TYPE(MIBAccount, mib_account, MIB, ACCOUNT, GObject)
#else
typedef void* MIBAccount;
#endif

PUBLIC_API const gchar *mib_account_get_client_info(MIBAccount *self);
PUBLIC_API const gchar *mib_account_get_environment(MIBAccount *self);
PUBLIC_API const gchar *mib_account_get_family_name(MIBAccount *self);
PUBLIC_API const gchar *mib_account_get_given_name(MIBAccount *self);
PUBLIC_API const gchar *mib_account_get_home_account_id(MIBAccount *self);
PUBLIC_API const gchar *mib_account_get_local_account_id(MIBAccount *self);
PUBLIC_API const gchar *mib_account_get_name(MIBAccount *self);
PUBLIC_API const gchar *mib_account_get_username(MIBAccount *self);
PUBLIC_API time_t mib_account_get_password_expiry(MIBAccount *self);
PUBLIC_API void mib_account_get_realm(MIBAccount *self, uuid_t realm);

G_END_DECLS

/** @}*/
