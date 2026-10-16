# SPDX-FileCopyrightText: (C) 2026 Siemens AG
# SPDX-License-Identifier: LGPL-2.1-only

gch_smtp_office365 = executable(
  'sso-mib-gch-smtp-o365',
  'smtp-o365/main.c',
  install : true,
  include_directories : public_headers,
  link_with : [libsso_mib],
  dependencies: [glibdep, giodep],
  install_tag : 'git-cred-helper'
)

sso_mib_tool = executable(
  'sso-mib-tool',
  [
    'sso-mib-tool/main.c',
  ],
  install : true,
  include_directories : public_headers,
  link_with : [libsso_mib],
  c_args: sso_mib_tool_cargs_extra,
  dependencies: [glibdep, giodep, jsondep, uuiddep, jwtdep],
  install_tag : 'tool'
)

sasldep = dependency('libsasl2', required: get_option('libsasl2'))
if sasldep.found()
  shared_module(
    'sso-mib-sasl-xoauth2',
    'sasl-xoauth2/xoauth2.c',
    install : true,
    install_dir : join_paths(get_option('libdir'), 'sasl2'),
    install_tag : 'sasl',
    include_directories : public_headers,
    link_with : [libsso_mib],
    dependencies : [glibdep, giodep, uuiddep,
                    sasldep.partial_dependency(compile_args : true, includes : true)]
  )

  configure_file(input : '../man/sso-mib-sasl-xoauth2.7.in',
                 output : 'sso-mib-sasl-xoauth2.7',
                 configuration : man_config,
                 install : true,
                 install_dir : join_paths(get_option('mandir'), 'man7'),
                 install_tag : 'sasl')
endif
