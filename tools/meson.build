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
