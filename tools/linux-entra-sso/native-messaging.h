/*
 * SPDX-FileCopyrightText: (C) 2026 Siemens
 * SPDX-License-Identifier: MIT
 *
 * WebExtension native messaging protocol framing on stdin/stdout.
 */

#ifndef LINUX_ENTRA_SSO_NATIVE_MESSAGING_H
#define LINUX_ENTRA_SSO_NATIVE_MESSAGING_H

#include <glib.h>
#include <json-glib/json-glib.h>

/* refuse messages larger than this to guard against bogus length prefixes */
#define NM_MAX_MESSAGE_SIZE (16 * 1024 * 1024)

/*
 * Read a single native messaging frame from fd. On success stores a
 * newly-allocated message buffer in *out_data and its length in *out_len
 * (caller frees with g_free). Returns FALSE on EOF, IO error or an invalid
 * length prefix.
 */
gboolean nm_read_message(int fd, gchar **out_data, gsize *out_len);

/*
 * Wrap message in the { command, message } envelope and write it to stdout.
 * Takes ownership of message.
 */
void nm_send(const gchar *command, JsonNode *message);

#endif /* LINUX_ENTRA_SSO_NATIVE_MESSAGING_H */
