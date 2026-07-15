/*
 * SPDX-FileCopyrightText: (C) 2025 Siemens
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#pragma once

#if !defined(_SSO_MIB_INSIDE_) && !defined(SSO_MIB_COMPILATION)
#error "Only <sso-mib.h> can be included directly."
#endif

#include <gio/gio.h>

#include "mib-client-app.h"
#include "mib-account.h"
#include "mib-exports.h"
#include "mib-pop-params.h"
#include "mib-prt-sso-cookie.h"
#include "mib-prt.h"

/**
 * \defgroup clientapp Client App
 * \brief OAuth2 Client Application
 * \addtogroup clientapp
 *  @{
 */

/**
 * \brief Common authority for all tenants
 */
#define MIB_AUTHORITY_COMMON "https://login.microsoftonline.com/common"

/**
 * \brief Default SSO URL
 */
#define MIB_SSO_URL_DEFAULT "https://login.microsoftonline.com/"

/**
 * \brief Default scope for graph API
 */
#define MIB_SCOPE_GRAPH_DEFAULT "https://graph.microsoft.com/.default"

G_BEGIN_DECLS

enum MIB_PROMPT {
	MIB_PROMPT_UNSET = 0,
	MIB_PROMPT_NONE = 1 << 0,
	MIB_PROMPT_SELECT_ACCOUNT = 1 << 1,
	MIB_PROMPT_CONSENT = 1 << 2,
	MIB_PROMPT_LOGIN = 1 << 3
};

#ifndef DOXYGEN
#define MIB_TYPE_CLIENT_APP mib_client_app_get_type()
G_DECLARE_FINAL_TYPE(MIBClientApp, mib_client_app, MIB, CLIENT_APP, GObject)
PUBLIC_API GType mib_client_app_get_type(void);
#else
typedef void *MIBClientApp;
#endif

/**
 * \brief Start a new session
 *
 * This function creates a new session for the given client_id.
 * The user is responsible for freeing the object with \c g_object_unref .
 *
 * Since version \c 0.10.1 , this function no longer triggers a DBus
 * activation of the broker service. Instead, the service is activated
 * on demand by the individual method calls. As a result, a
 * \c MIBClientApp object can be long-lived and remains valid across
 * broker restarts.
 *
 * \param client_id Azure client application ID
 * \param authority Azure authority URL (e.g. value from MIB_AUTHORITY_COMMON)
 * \param cancellable Cancellable object or NULL
 * \param error GError object or NULL
 * \return opaque client app object
 */
PUBLIC_API MIBClientApp *mib_public_client_app_new(const gchar *client_id,
												   const gchar *authority,
												   GCancellable *cancellable,
												   GError **error);

PUBLIC_API const gchar *mib_client_app_get_client_id(const MIBClientApp *self);
PUBLIC_API const gchar *
mib_client_app_get_correlation_id(const MIBClientApp *self);
PUBLIC_API const gchar *mib_client_app_get_authority(const MIBClientApp *self);
PUBLIC_API int mib_client_app_get_enforce_interactive(const MIBClientApp *self);

/**
 * \brief do not try silent mode first on interactive
 * 
 * When requesting a token via \ref mib_client_app_acquire_token_interactive,
 * internally a non-interactive token acquire is tried first. Only if that fails,
 * the interactive acquire is performed. If set to \c true, this non-interactive
 * part is skipped.
 */
PUBLIC_API void mib_client_app_set_enforce_interactive(MIBClientApp *self,
													   int enforce);

/**
 * Returns the client-id specific redirect URI for broker clients, according to
 * https://msal-python.readthedocs.io/en/latest/#publicclientapplication
 * 
 * The caller is responsible for freeing the returned string.
 */
PUBLIC_API gchar *
mib_client_app_get_broker_redirect_uri(const MIBClientApp *self);

/**
 * \brief Override the address to return to upon receiving a response from the authority.
 *
 * If this method is not called, the broker redirect URI (returned by
 * \ref mib_client_app_get_broker_redirect_uri ) is used.
 *
 * \note The redirect URI must be in the list of allowed redirect URIs for
 *       the target application. Otherwise, the token acquisition will not work.
 */
PUBLIC_API void mib_client_app_set_redirect_uri(MIBClientApp *self,
												const gchar *uri);

/**
 * \brief Get the version of the Linux broker
 *
 * \dbuscall{getLinuxBrokerVersion}
 *
 * \param app client app object
 * \param msal_cpp_version MSAL CPP version (non-empty string, e.g. 1.28.0)
 * \return broker version (or null on error, must be freed with g_free())
 */
PUBLIC_API gchar *
mib_client_app_get_linux_broker_version(MIBClientApp *app,
										const gchar *msal_cpp_version);

/**
 * \brief Get the version of the Linux broker (async)
 *
 * Asynchronous variant of \ref mib_client_app_get_linux_broker_version.
 *
 * \dbusacall{getLinuxBrokerVersion}
 *
 * \param app client app object
 * \param msal_cpp_version MSAL CPP version (non-empty string, e.g. 1.28.0)
 * \param callback a GAsyncReadyCallback to call when the request is done
 * \param user_data user data to pass to the callback
 */
PUBLIC_API void mib_client_app_get_linux_broker_version_async(
	MIBClientApp *app, const gchar *msal_cpp_version,
	GAsyncReadyCallback callback, gpointer user_data);

/**
 * \brief Finish an async get Linux broker version operation
 *
 * \param app client app object
 * \param result the GAsyncResult passed to the callback
 * \param error return location for a GError or NULL
 * \return broker version (or null on error, must be freed with g_free())
 */
PUBLIC_API gchar *mib_client_app_get_linux_broker_version_finish(
	MIBClientApp *app, GAsyncResult *result, GError **error);

/**
 * \brief Get the accounts associated with the session
 *
 * Returns a list of \ref MIBAccount entries associated with the application.
 * Which accounts are returned depends on the apps client_id.
 * 
 * The user is responsible for freeing the list, e.g. with
 * \c g_slist_free_full(accounts,(GDestroyNotify)g_object_unref)
 *
 * \dbuscall{getAccounts}
 *
 * \param app client app object
 * \return list of \ref MIBAccount*
 */
PUBLIC_API GSList *mib_client_app_get_accounts(MIBClientApp *app);

/**
 * \brief Get the accounts associated with the session (async)
 *
 * Asynchronous variant of \ref mib_client_app_get_accounts.
 * When the operation is finished, \p callback will be called.
 * You can then call \ref mib_client_app_get_accounts_finish to get
 * the result.
 *
 * \dbusacall{getAccounts}
 *
 * \param app client app object
 * \param callback a GAsyncReadyCallback to call when the request is done
 * \param user_data user data to pass to the callback
 */
PUBLIC_API void mib_client_app_get_accounts_async(MIBClientApp *app,
												  GAsyncReadyCallback callback,
												  gpointer user_data);

/**
 * \brief Finish an async get accounts operation
 *
 * Finishes an operation started with \ref mib_client_app_get_accounts_async.
 *
 * The user is responsible for freeing the list, e.g. with
 * \c g_slist_free_full(accounts,(GDestroyNotify)g_object_unref)
 *
 * \param app client app object
 * \param result the GAsyncResult passed to the callback
 * \param error return location for a GError or NULL
 * \return list of \ref MIBAccount* or NULL on error
 */
PUBLIC_API GSList *mib_client_app_get_accounts_finish(MIBClientApp *app,
													  GAsyncResult *result,
													  GError **error);

/**
 * \brief Filter the registered accounts by UPN and return the first match
 * 
 * Returns the first registered account that matches the provided
 * "User Principal Name" (upn). If \c upn is \c NULL , the first account
 * is returned.
 *
 * \dbuscall{getAccounts}
 *
 * \param app client app object
 * \param upn User Principal Name
 * \return first matching account
 */
PUBLIC_API MIBAccount *mib_client_app_get_account_by_upn(MIBClientApp *app,
														 const gchar *upn);

/**
 * \brief Acquire a token without user interaction
 *
 * This function acquires a token for the given account and requested scopes.
 * 
 * The user is responsible for freeing the object with \c g_object_unref .
 *
 * \dbuscall{acquireTokenSilently}
 *
 * \param app client app object
 * \param account mib account reference
 * \param scopes list of scopes (\c gchar* entries)
 * \param claims_challenge string of a JSON object which contains lists of
 *                         claims being requested from these locations or NULL.
 * \param auth_scheme PoP parameters or NULL
 * \param id_token ID token (NULL to request a fresh one) \return PRT token
 * struct
 */
PUBLIC_API MIBPrt *mib_client_app_acquire_token_silent(
	MIBClientApp *app, MIBAccount *account, GSList *scopes,
	const gchar *claims_challenge, MIBPopParams *auth_scheme,
	const gchar *id_token);

/**
 * \brief Acquire a token without user interaction (async)
 *
 * Asynchronous variant of \ref mib_client_app_acquire_token_silent.
 *
 * \dbusacall{acquireTokenSilently}
 *
 * \param app client app object
 * \param account mib account reference
 * \param scopes list of scopes (\c gchar* entries)
 * \param claims_challenge claims challenge or NULL
 * \param auth_scheme PoP parameters or NULL
 * \param id_token ID token or NULL
 * \param callback a GAsyncReadyCallback to call when the request is done
 * \param user_data user data to pass to the callback
 */
PUBLIC_API void mib_client_app_acquire_token_silent_async(
	MIBClientApp *app, MIBAccount *account, GSList *scopes,
	const gchar *claims_challenge, MIBPopParams *auth_scheme,
	const gchar *id_token, GAsyncReadyCallback callback, gpointer user_data);

/**
 * \brief Finish an async silent token acquisition
 *
 * The user is responsible for freeing the object with \c g_object_unref .
 *
 * \param app client app object
 * \param result the GAsyncResult passed to the callback
 * \param error return location for a GError or NULL
 * \return PRT token struct or NULL on error
 */
PUBLIC_API MIBPrt *mib_client_app_acquire_token_silent_finish(
	MIBClientApp *app, GAsyncResult *result, GError **error);

/**
 * \brief Acquire a token without with user interaction (if needed)
 *
 * This function acquires a token and asks the user for the needed data.
 * Note, that (similar to MSAL's implementation), internally a silent token acquire
 * is performed first. In case that fails, the interactive version is performed.
 * 
 * The user is responsible for freeing the object with \c g_object_unref .
 *
 * \dbuscall{acquireTokenInteractively}
 *
 * \param app client app object
 * \param scopes list of scopes (\c gchar* entries)
 * \param prompt what the user should be asked
 * \param login_hint Identifier of the user. Generally a User Principal Name (UPN) (or NULL)
 * \param domain_hint Not Implemented (yet). Set to NULL
 * \param claims_challenge string of a JSON object which contains lists of
 *                         claims being requested from these locations or NULL.
 * \param auth_scheme PoP parameters or NULL
 */
PUBLIC_API MIBPrt *mib_client_app_acquire_token_interactive(
	MIBClientApp *app, GSList *scopes, enum MIB_PROMPT prompt,
	const gchar *login_hint, const gchar *domain_hint,
	const gchar *claims_challenge, MIBPopParams *auth_scheme);

/**
 * \brief Acquire a token with user interaction (async)
 *
 * Asynchronous variant of \ref mib_client_app_acquire_token_interactive.
 * Internally, a silent token acquire is attempted first (unless
 * \ref mib_client_app_set_enforce_interactive is set). If that fails,
 * the interactive acquire is performed.
 *
 * \dbusacall{acquireTokenInteractively}
 * \dbusacall{getAccounts}
 * \dbusacall{acquireTokenSilently} (if interactive is not enforced)
 *
 * \param app client app object
 * \param scopes list of scopes (\c gchar* entries)
 * \param prompt what the user should be asked
 * \param login_hint Identifier of the user. Generally a User Principal Name (UPN) (or NULL)
 * \param domain_hint Not Implemented (yet). Set to NULL
 * \param claims_challenge claims challenge or NULL
 * \param auth_scheme PoP parameters or NULL
 * \param callback a GAsyncReadyCallback to call when the request is done
 * \param user_data user data to pass to the callback
 */
PUBLIC_API void mib_client_app_acquire_token_interactive_async(
	MIBClientApp *app, GSList *scopes, enum MIB_PROMPT prompt,
	const gchar *login_hint, const gchar *domain_hint,
	const gchar *claims_challenge, MIBPopParams *auth_scheme,
	GAsyncReadyCallback callback, gpointer user_data);

/**
 * \brief Finish an async interactive token acquisition
 *
 * The user is responsible for freeing the object with \c g_object_unref .
 *
 * \param app client app object
 * \param result the GAsyncResult passed to the callback
 * \param error return location for a GError or NULL
 * \return PRT token struct or NULL on error
 */
PUBLIC_API MIBPrt *mib_client_app_acquire_token_interactive_finish(
	MIBClientApp *app, GAsyncResult *result, GError **error);

/**
 * \brief Acquire a PRT SSO cookie
 *
 * This function acquires a PRT SSO cookie for the given account, SSO URL and
 * requested scopes.
 * 
 * The user is responsible for freeing the object with \c g_object_unref .
 *
 * \dbuscall{acquirePrtSsoCookie}
 *
 * \param app client app object
 * \param account mib account reference
 * \param sso_url SSO URL
 * \param scopes list of scopes
 * \return PRT SSO cookie struct
 */
PUBLIC_API MIBPrtSsoCookie *
mib_client_app_acquire_prt_sso_cookie(MIBClientApp *app, MIBAccount *account,
									  const gchar *sso_url, GSList *scopes);

/**
 * \brief Acquire a PRT SSO cookie (async)
 *
 * Asynchronous variant of \ref mib_client_app_acquire_prt_sso_cookie.
 *
 * \dbusacall{acquirePrtSsoCookie}
 *
 * \param app client app object
 * \param account mib account reference
 * \param sso_url SSO URL
 * \param scopes list of scopes
 * \param callback a GAsyncReadyCallback to call when the request is done
 * \param user_data user data to pass to the callback
 */
PUBLIC_API void mib_client_app_acquire_prt_sso_cookie_async(
	MIBClientApp *app, MIBAccount *account, const gchar *sso_url,
	GSList *scopes, GAsyncReadyCallback callback, gpointer user_data);

/**
 * \brief Finish an async PRT SSO cookie acquisition
 *
 * The user is responsible for freeing the object with \c g_object_unref .
 *
 * \param app client app object
 * \param result the GAsyncResult passed to the callback
 * \param error return location for a GError or NULL
 * \return PRT SSO cookie struct or NULL on error
 */
PUBLIC_API MIBPrtSsoCookie *mib_client_app_acquire_prt_sso_cookie_finish(
	MIBClientApp *app, GAsyncResult *result, GError **error);

/**
 * \brief Generate a signed HTTP request
 *
 * This function implements the Acquiring Access Tokens Protected with
 * Proof-of-Possession (PoP) specification.
 * 
 * The user is responsible for freeing the string with \c g_free .
 *
 * \dbuscall{generateSignedHttpRequest}
 *
 * \param app client app object
 * \param account mib account reference
 * \param pop_params PoP parameters
 * \return access token (must be freed with g_free())
 */
PUBLIC_API gchar *mib_client_app_generate_signed_http_request(
	MIBClientApp *app, MIBAccount *account, MIBPopParams *pop_params);

/**
 * \brief Generate a signed HTTP request (async)
 *
 * Asynchronous variant of \ref mib_client_app_generate_signed_http_request.
 *
 * \dbusacall{generateSignedHttpRequest}
 *
 * \param app client app object
 * \param account mib account reference
 * \param pop_params PoP parameters
 * \param callback a GAsyncReadyCallback to call when the request is done
 * \param user_data user data to pass to the callback
 */
PUBLIC_API void mib_client_app_generate_signed_http_request_async(
	MIBClientApp *app, MIBAccount *account, MIBPopParams *pop_params,
	GAsyncReadyCallback callback, gpointer user_data);

/**
 * \brief Finish an async signed HTTP request generation
 *
 * The user is responsible for freeing the string with \c g_free .
 *
 * \param app client app object
 * \param result the GAsyncResult passed to the callback
 * \param error return location for a GError or NULL
 * \return access token (must be freed with g_free()) or NULL on error
 */
PUBLIC_API gchar *mib_client_app_generate_signed_http_request_finish(
	MIBClientApp *app, GAsyncResult *result, GError **error);

/**
 * \brief Signout the account and clear linked token cache
 *
 * \dbuscall{removeAccount}
 *
 * \param app client app object
 * \param account mib account reference
 * \return 0 on success, -1 on error
 */
PUBLIC_API int mib_client_app_remove_account(MIBClientApp *app,
											 MIBAccount *account);

/**
 * \brief Signout the account and clear linked token cache (async)
 *
 * Asynchronous variant of \ref mib_client_app_remove_account.
 *
 * \dbusacall{removeAccount}
 *
 * \param app client app object
 * \param account mib account reference
 * \param callback a GAsyncReadyCallback to call when the request is done
 * \param user_data user data to pass to the callback
 */
PUBLIC_API void
mib_client_app_remove_account_async(MIBClientApp *app, MIBAccount *account,
									GAsyncReadyCallback callback,
									gpointer user_data);

/**
 * \brief Finish an async remove account operation
 *
 * \param app client app object
 * \param result the GAsyncResult passed to the callback
 * \param error return location for a GError or NULL
 * \return 0 on success, -1 on error
 */
PUBLIC_API int mib_client_app_remove_account_finish(MIBClientApp *app,
													GAsyncResult *result,
													GError **error);

G_END_DECLS

/** @} */
