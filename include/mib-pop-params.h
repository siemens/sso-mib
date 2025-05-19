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

/**
 * \defgroup popparams PoP Parameters
 * \brief Proof-of-Possession Parameters
 * \addtogroup popparams
 *  @{
 */

/**
 * \brief Authentication schemes
 */
enum MIB_AUTH_SCHEME {
    MIB_AUTH_SCHEME_BEARER = 1,
    MIB_AUTH_SCHEME_POP = 2
};

/**
 * \brief Request methods
 */
enum MIB_REQUEST_METHOD {
    MIB_REQUEST_METHOD_GET = 1,
    MIB_REQUEST_METHOD_POST = 2,
    MIB_REQUEST_METHOD_PUT = 3
};

#ifndef DOXYGEN
#define MIB_TYPE_POP_PARAMS mib_pop_params_get_type()
G_DECLARE_FINAL_TYPE(MIBPopParams, mib_pop_params, MIB, POP_PARAMS, GObject)
#else
typedef void* MIBPopParams;
#endif

/**
 * \brief Create new Proof-of-Possession parameters object
 * 
 * The caller is responsible for freeing the returned object with \c g_object_unref .
 * 
 * \param auth_scheme Indicates whether a bearer or pop token is requested
 * \param method The HTTP method of the request that will use the signed token
 * \param uri The URL of the protected resource for which the access token is being issued
 * \return The PoP parameters object
 */
PUBLIC_API MIBPopParams* mib_pop_params_new(enum MIB_AUTH_SCHEME auth_scheme, enum MIB_REQUEST_METHOD method, const gchar* uri);
PUBLIC_API void mib_pop_params_set_shr_claims(MIBPopParams *self, const gchar *claims);
PUBLIC_API void mib_pop_params_set_shr_nonce(MIBPopParams *self, const gchar* nonce);

/**
 * \brief Set the decoded "kid" part from a "req_cnf"
 * 
 * A RFC9201 \c req_cnf is an OAuth2 parameter allowing clients to request a
 * specific PoP key in an access token from a token endpoint. This value is
 * a base64 encoded string with key \c kid and a value. This value needs to
 * be provided here.
 */
PUBLIC_API void mib_pop_params_set_kid(MIBPopParams *self, const gchar* kid);

/** @} */
