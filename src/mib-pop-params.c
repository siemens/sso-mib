/*
 * SPDX-FileCopyrightText: (C) 2025 Siemens
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#include "mib-utils.h"
#include "mib-pop-params.h"

struct _MIBPopParams {
	GObject parent_instance;

	enum MIB_AUTH_SCHEME auth_scheme;
	enum MIB_REQUEST_METHOD resource_req_method;
	gchar *resource_req_uri;
	gchar *shr_claims;
	gchar *shr_nonce;
	gchar *kid;
};
G_DEFINE_TYPE(MIBPopParams, mib_pop_params, G_TYPE_OBJECT)

static void mib_pop_params_finalize(GObject *gobject)
{
	MIBPopParams *priv =
		mib_pop_params_get_instance_private(MIB_POP_PARAMS(gobject));
	g_clear_pointer(&priv->resource_req_uri, g_free);
	g_clear_pointer(&priv->shr_claims, g_free);
	g_clear_pointer(&priv->shr_nonce, g_free);
	g_clear_pointer(&priv->kid, g_free);
	G_OBJECT_CLASS(mib_pop_params_parent_class)->finalize(gobject);
}

static void mib_pop_params_class_init(MIBPopParamsClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS(klass);
	object_class->finalize = mib_pop_params_finalize;
}

static void mib_pop_params_init(MIBPopParams *self)
{
	self->auth_scheme = MIB_AUTH_SCHEME_BEARER;
	self->resource_req_method = MIB_REQUEST_METHOD_POST;
}

MIBPopParams *mib_pop_params_new(enum MIB_AUTH_SCHEME auth_scheme,
								 enum MIB_REQUEST_METHOD method,
								 const gchar *uri)
{
	g_assert(uri);

	MIBPopParams *self = g_object_new(MIB_TYPE_POP_PARAMS, NULL);
	self->auth_scheme = auth_scheme;
	self->resource_req_method = method;
	self->resource_req_uri = g_strdup(uri);
	return self;
}

JsonObject *mib_pop_params_to_json(MIBPopParams *self)
{
	const char *auth_scheme_str;
	const char *req_method_str;
	if (self->auth_scheme == MIB_AUTH_SCHEME_POP) {
		auth_scheme_str = "pop";
	} else {
		auth_scheme_str = "bearer";
	}
	if (self->resource_req_method == MIB_REQUEST_METHOD_GET) {
		req_method_str = "GET";
	} else if (self->resource_req_method == MIB_REQUEST_METHOD_PUT) {
		req_method_str = "PUT";
	} else {
		req_method_str = "POST";
	}

	JsonObject *params_json = json_object_new();
	json_object_set_string_member(params_json, "authenticationScheme",
								  auth_scheme_str);
	/* TODO: to clarify how to split URI into host an path */
	json_object_set_string_member(params_json, "uriHost",
								  self->resource_req_uri);
	json_object_set_string_member(params_json, "httpMethod", req_method_str);
	/* optional parameters */
	if (self->shr_claims) {
		json_object_set_string_member(params_json, "clientClaims",
									  self->shr_claims);
	}
	if (self->shr_nonce) {
		json_object_set_string_member(params_json, "nonce", self->shr_nonce);
	}
	if (self->kid) {
		json_object_set_string_member(params_json, "kid", self->kid);
	}
	return params_json;
}

void mib_pop_params_set_shr_claims(MIBPopParams *self, const gchar *claims)
{
	g_assert(self);
	g_assert(claims);
	self->shr_claims = g_strdup(claims);
}

void mib_pop_params_set_shr_nonce(MIBPopParams *self, const gchar *nonce)
{
	g_assert(self);
	g_assert(nonce);
	self->shr_nonce = g_strdup(nonce);
}

void mib_pop_params_set_kid(MIBPopParams *self, const gchar *kid)
{
	g_assert(self);
	g_assert(kid);
	self->kid = g_strdup(kid);
}
