/*
 * SPDX-FileCopyrightText: (C) 2025 Siemens
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include <gio/gio.h>

typedef struct _MockBroker MockBroker;

MockBroker *mock_broker_new(void);
void mock_broker_free(MockBroker *self);

/* Configure canned responses (the mock returns these verbatim) */
void mock_broker_set_get_accounts_response(MockBroker *self, const gchar *json);
void mock_broker_set_acquire_token_silently_response(MockBroker *self,
													 const gchar *json);
void mock_broker_set_acquire_token_interactively_response(MockBroker *self,
														  const gchar *json);
void mock_broker_set_acquire_prt_sso_cookie_response(MockBroker *self,
													 const gchar *json);
void mock_broker_set_generate_signed_http_request_response(MockBroker *self,
														   const gchar *json);
void mock_broker_set_remove_account_response(MockBroker *self,
											 const gchar *json);
void mock_broker_set_get_linux_broker_version_response(MockBroker *self,
													   const gchar *json);

/* Retrieve the last request JSON received by each method */
const gchar *mock_broker_get_last_request(MockBroker *self,
										  const gchar *method_name);
