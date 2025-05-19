/*
 * SPDX-FileCopyrightText: (C) 2025 Siemens
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include "mib-utils.h"
#include "mib-prt-sso-cookie-impl.h"

/**
 * \brief Parsed PRT SSO cookie
 */
struct _MIBPrtSsoCookie {
	GObject parent_instance;

	gchar *name;
	gchar *content;
};
G_DEFINE_TYPE(MIBPrtSsoCookie, mib_prt_sso_cookie, G_TYPE_OBJECT)

static void mib_prt_sso_cookie_finalize(GObject *gobject)
{
	MIBPrtSsoCookie *priv =
		mib_prt_sso_cookie_get_instance_private(MIB_PRT_SSO_COOKIE(gobject));
	g_clear_pointer(&priv->name, g_free);
	g_clear_pointer(&priv->content, g_free);
	G_OBJECT_CLASS(mib_prt_sso_cookie_parent_class)->finalize(gobject);
}

static void mib_prt_sso_cookie_class_init(MIBPrtSsoCookieClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS(klass);
	object_class->finalize = mib_prt_sso_cookie_finalize;
}

static void mib_prt_sso_cookie_init(MIB_ARG_UNUSED MIBPrtSsoCookie *self)
{
}

MIBPrtSsoCookie *mib_prt_sso_cookie_from_json(JsonObject *cookie_json)
{
	MIBPrtSsoCookie *cookie;
	if (!json_object_has_member(cookie_json, "cookieName") ||
		!json_object_has_member(cookie_json, "cookieContent")) {
		g_warning("invalid cookie data");
		return NULL;
	}
	cookie = g_object_new(MIB_TYPE_PRT_SSO_COOKIE, NULL);
	cookie->name =
		g_strdup(json_object_get_string_member(cookie_json, "cookieName"));
	cookie->content =
		g_strdup(json_object_get_string_member(cookie_json, "cookieContent"));
	return cookie;
}

const gchar *mib_prt_sso_cookie_get_name(MIBPrtSsoCookie *self)
{
	g_assert(self);
	return self->name;
}
const gchar *mib_prt_sso_cookie_get_content(MIBPrtSsoCookie *self)
{
	g_assert(self);
	return self->content;
}
