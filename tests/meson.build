# SPDX-FileCopyrightText: (C) 2026 Siemens
# SPDX-License-Identifier: LGPL-2.1-only

test_deps = [glibdep, giodep, jsondep, uuiddep]

# Build a static test-only version of the library that includes both
# the library sources and the identity-broker generated code in one unit,
# avoiding duplicate GType registrations.
test_lib_src = []
foreach src : libsso_mib_src
  test_lib_src += files('../' + src)
endforeach

libsso_mib_test = static_library('sso-mib-test',
  test_lib_src, identity_broker,
  c_args : ['-DBUILDING_SSO_MIB=1',
            '-DSSO_MIB_COMPILATION=1',
            '-DG_LOG_DOMAIN="ssomib"',
            '-Wno-pedantic'],
  include_directories : public_headers,
  dependencies : [giodep, glibdep, jsondep, uuiddep],
)

test_client_app = executable('test-client-app',
  'test-client-app.c', 'mock-broker.c', identity_broker[1],
  c_args : ['-Wno-pedantic'],
  include_directories : public_headers,
  link_with : [libsso_mib_test],
  dependencies : test_deps,
)

test('client-app', test_client_app)
