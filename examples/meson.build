# SPDX-FileCopyrightText: (C) 2025 Siemens AG
# SPDX-License-Identifier: MIT

curldep = dependency('libcurl')

example_avatar = executable(
  'mib-example-avatar',
  'avatar/main.c',
  install : false,
  include_directories : public_headers,
  link_with : [libsso_mib],
  dependencies: [glibdep, giodep, uuiddep, curldep]
)
