# SPDX-FileCopyrightText: (C) 2024 Siemens AG
# SPDX-License-Identifier: LGPL-2.1-only
project(
  'sso-mib',
  'c',
  version : '0.10.2',
  default_options : ['c_std=gnu11', 'warning_level=3'],
  license : 'GPL-2.0-only OR LGPL-2.1-only OR MIT',
  license_files : [
    'LICENSES/GPL-2.0-only.txt',
    'LICENSES/LGPL-2.1-only.txt',
    'LICENSES/MIT.txt'
  ]
)
project_description = 'Library to interact with the Microsoft Device Broker for SSO'
project_authors = [
  'Felix Moessbauer <felix.moessbauer@siemens.com>',
  'Andreas Ziegler <ziegler.andreas@siemens.com>',
]
add_project_arguments('-Wno-unused-parameter', language : 'c')

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
jwtdep = dependency('libjwt', required: get_option('libjwt'))

summary({'libjwt (sso-mib-tool)': jwtdep.found()}, bool_yn: true, section: 'Misc dependencies')

identity_broker = gnome.gdbus_codegen('identity-broker',
  sources: 'dbus/spec/com.microsoft.identity.broker1.xml',
  interface_prefix : 'com.microsoft.',
  namespace : 'mib_dbus',
)
identity_broker_obj = static_library(
  'identity_broker_obj',
  identity_broker,
  c_args : ['-Wno-pedantic'],
  gnu_symbol_visibility : 'hidden',
  dependencies : [giodep],
  install : false)

libsso_mib = shared_library(
  meson.project_name(),
  libsso_mib_src, identity_broker[1],
  install : true,
  c_args : ['-DBUILDING_SSO_MIB=1',
            '-DSSO_MIB_COMPILATION=1',
            '-DG_LOG_DOMAIN="ssomib"'],
  gnu_symbol_visibility : 'hidden',
  include_directories : public_headers,
  dependencies : [giodep, glibdep, jsondep, uuiddep],
  link_with : [identity_broker_obj],
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

sso_mib_tool_cargs_extra = []
if jwtdep.found()
  jwtdep_version = jwtdep.version().split('.')
  sso_mib_tool_cargs_extra += [
    '-DWITH_LIBJWT',
    '-DLIBJWT_VERSION_MAJOR=' + jwtdep_version[0],
    '-DLIBJWT_VERSION_MINOR=' + jwtdep_version[1],
  ]
endif

sso_mib_tool = executable(
  'sso-mib-tool',
  [
    'src/sso-mib-tool.c',
  ],
  install : true,
  include_directories : public_headers,
  link_with : [libsso_mib],
  c_args: sso_mib_tool_cargs_extra,
  dependencies: [glibdep, giodep, jsondep, uuiddep, jwtdep],
  install_tag : 'tool'
)

gch_smtp_office365 = executable(
  'sso-mib-gch-smtp-o365',
  'examples/smtp-o365/main.c',
  install : true,
  include_directories : public_headers,
  link_with : [libsso_mib],
  dependencies: [glibdep, giodep],
  install_tag : 'git-cred-helper'
)

man_config = configuration_data()
man_config.set('PACKAGE_NAME', meson.project_name())
man_config.set('PACKAGE_VERSION', meson.project_version())
man_config.set('PACKAGE_AUTHORS', '\n.br\n'.join(project_authors))

configure_file(input : 'man/sso-mib-tool.1.in',
               output : 'sso-mib-tool.1',
               configuration : man_config,
               install : true,
               install_dir : join_paths(get_option('mandir'), 'man1'),
               install_tag : 'tool')

configure_file(input : 'man/sso-mib-gch-smtp-o365.1.in',
               output : 'sso-mib-gch-smtp-o365.1',
               configuration : man_config,
               install : true,
               install_dir : join_paths(get_option('mandir'), 'man1'),
               install_tag : 'git-cred-helper')

if get_option('documentation')
  subdir('docs')
endif

if get_option('examples')
  subdir('examples')
endif

if get_option('tests')
  subdir('tests')
endif
