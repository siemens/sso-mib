# SPDX-FileCopyrightText: (C) 2024 Siemens AG
# SPDX-License-Identifier: LGPL-2.1-only
project(
  'sso-mib',
  'c',
  version : '0.5.0',
  default_options : ['c_std=c11', 'warning_level=3'],
)
project_description = 'Library to interact with the Microsoft Device Broker for SSO'

libsso_mib_hdrs = [
  'include/sso-mib.h',
  'include/mib-account.h',
  'include/mib-client-app.h',
  'include/mib-exports.h',
  'include/mib-prt-sso-cookie.h',
  'include/mib-prt.h',
  'include/mib-pop-params.h'
]
libsso_mib_src = [
  'src/mib-utils.h',
  'src/mib-utils.c',
  'src/mib-account-impl.h',
  'src/mib-account.c',
  'src/mib-client-app.c',
  'src/mib-client-app-impl.h',
  'src/mib-pop-params.c',
  'src/mib-pop-params-impl.h',
  'src/mib-prt-sso-cookie-impl.h',
  'src/mib-prt-sso-cookie.c',
  'src/mib-prt.c',
]
public_headers = include_directories('include')

gnome = import('gnome')

glibdep = dependency('glib-2.0')
giodep = dependency('gio-2.0')
jsondep = dependency('json-glib-1.0')
uuiddep = dependency('uuid')

identity_broker = gnome.gdbus_codegen('identity-broker',
  sources: 'dbus/spec/com.microsoft.identity.broker1.xml',
  interface_prefix : 'com.microsoft.',
  namespace : 'mib_dbus',
)

libsso_mib = shared_library(
  meson.project_name(),
  libsso_mib_src, identity_broker,
  install : true,
  c_args : ['-DBUILDING_SSO_MIB=1',
            '-DSSO_MIB_COMPILATION=1',
            '-DG_LOG_DOMAIN="ssomib"'],
  gnu_symbol_visibility : 'hidden',
  include_directories : public_headers,
  dependencies : [giodep, glibdep, jsondep, uuiddep],
  version : meson.project_version(),
  soversion : '0',
)
install_headers(libsso_mib_hdrs, subdir : meson.project_name())

pkg_mod = import('pkgconfig')
pkg_mod.generate(
  name : meson.project_name(),
  filebase : meson.project_name(),
  description : project_description,
  libraries : libsso_mib,
  requires: ['glib-2.0', 'gio-2.0', 'uuid']
)

sso_mib_tool = executable(
  'sso-mib-tool',
  'src/sso-mib-tool.c',
  install : true,
  include_directories : public_headers,
  link_with : [libsso_mib],
  dependencies: [glibdep, giodep, jsondep, uuiddep]
)

if get_option('documentation')
  subdir('docs')
endif

if get_option('examples')
  subdir('examples')
endif
