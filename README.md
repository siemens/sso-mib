[![API Docs](https://img.shields.io/badge/API-documented-blue)](https://siemens.github.io/sso-mib/)

# Single-Sign-On using Microsoft Identity Broker (SSO-MIB)

This project implements a C library to interact with a locally running microsoft-identity-broker to get various authentication tokens via DBus.
By that, it implements support for the OIDC extension [MS-OAPXBC], sections [3.1.5.1.2 Request for Primary Refresh Token](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-oapxbc/d32d5cd0-05d4-4ec2-8bcc-ac29ce711c23), [3.1.5.1.3 Exchange Primary Refresh Token for Access Token](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-oapxbc/06e2bf0d-8cea-4b11-ad78-d212330ebda9)
and can be used to obtain Proof-of-Possession tokens for RDP [[MS-RDPBCGR](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/e967ebeb-9e9f-443e-857a-5208802943c2)].

## Dependencies

- Gio2.0
- JSON-Glib
- libdbus
- libuuid
- libjwt (only for sso-mib-tool)

## Interface

The interface of the library is defined in `<sso-mib/sso-mib.h>`. Only this file must be included.
The semantics follow roughly the [MSAL Python](https://msal-python.readthedocs.io/en/latest/) library.

### Logging

We integrate with the GLib message logging system and use the domain `ssomib`.
To debug the input and output parameters of the DBus calls, set the environment variable `G_MESSAGES_DEBUG=ssomib`.

We try to keep the interface both API and ABI compatible, however this is not guaranteed prior to version 1.0.

### How do I use this library

Note: for simplicity, this code does not have error handling and cleanup logic.

```c
#include <sso-mib/sso-mib.h>

const gchar *client_id = "<my-client-uuid>";
const gchar *authority = MIB_AUTHORITY_COMMON;

MIBClientApp *app = mib_public_client_app_new(client_id, authority, NULL, NULL);
GSList *scopes = NULL;
scopes = g_slist_append(scopes, g_strdup(MIB_SCOPE_GRAPH_DEFAULT));

/// get default / first known account
MIBAccount *account = mib_client_app_get_account_by_upn(app, NULL);

/// get a fresh token pair (access, refresh)
MIBPrt *prt = mib_client_app_acquire_token_silent(app, account, scopes, NULL, NULL, NULL);

/// get a PRT SSO Cookie
MIBPrtSsoCookie *prt_cookie =
    mib_client_app_acquire_prt_sso_cookie(app, account, MIB_SSO_URL_DEFAULT, scopes);

const char *name = mib_prt_sso_cookie_get_name(cookie);
const char *value = mib_prt_sso_cookie_get_content(cookie);
```

Further examples are provided in `examples`.

## Frontend

The `sso-mib-tool` provides a simple frontend to interact with the library.

## Maintainers

- Felix Moessbauer <felix.moessbauer@siemens.com>
- Andreas Ziegler <ziegler.andreas@siemens.com>

## Code Integrity

Since version `v0.5`, git release tags are signed with one of the following maintainer GPG keys:

- `AF73F6EF5A53CFE304569F50E648A311F67A50FC` (Felix Moessbauer)

## License

The library is licensed according to the terms of the GNU Lesser General Public License v2.1.
The tooling is licensed according to the terms of the GNU Public License v2.0.
The examples are licensed according to the terms of the MIT License.
