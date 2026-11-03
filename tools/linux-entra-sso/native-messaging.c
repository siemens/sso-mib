/*
 * SPDX-FileCopyrightText: (C) 2026 Siemens
 * SPDX-License-Identifier: MIT
 *
 * WebExtension native messaging protocol framing on stdin/stdout.
 */

#include "native-messaging.h"

#include <stdio.h>
#include <unistd.h>

static gboolean read_exact(int fd, void *buf, size_t len)
{
	guint8 *p = buf;
	while (len > 0) {
		ssize_t r = read(fd, p, len);
		if (r <= 0)
			return FALSE;
		p += (size_t)r;
		len -= (size_t)r;
	}
	return TRUE;
}

gboolean nm_read_message(int fd, gchar **out_data, gsize *out_len)
{
	guint32 msg_len = 0;

	if (!read_exact(fd, &msg_len, sizeof(msg_len)))
		return FALSE;
	if (msg_len == 0 || msg_len > NM_MAX_MESSAGE_SIZE) {
		g_printerr("invalid message length: %u\n", msg_len);
		return FALSE;
	}

	gchar *buffer = g_malloc(msg_len);
	if (!read_exact(fd, buffer, msg_len)) {
		g_free(buffer);
		return FALSE;
	}

	*out_data = buffer;
	*out_len = msg_len;
	return TRUE;
}

void nm_send(const gchar *command, JsonNode *message)
{
	JsonBuilder *builder = json_builder_new();
	json_builder_begin_object(builder);
	json_builder_set_member_name(builder, "command");
	json_builder_add_string_value(builder, command);
	json_builder_set_member_name(builder, "message");
	json_builder_add_value(builder, message);
	json_builder_end_object(builder);

	JsonNode *root = json_builder_get_root(builder);
	JsonGenerator *gen = json_generator_new();
	json_generator_set_root(gen, root);

	gsize len = 0;
	gchar *data = json_generator_to_data(gen, &len);
	guint32 prefix = (guint32)len;
	fwrite(&prefix, sizeof(prefix), 1, stdout);
	fwrite(data, 1, len, stdout);
	fflush(stdout);

	g_free(data);
	g_object_unref(gen);
	json_node_unref(root);
	g_object_unref(builder);
}
