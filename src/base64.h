/* 
 * SPDX-FileCopyrightText: WEI Zhicheng
 * SPDX-License-Identifier: MIT
 * 
 * This is derived from a public domain base64 implementation written by WEI Zhicheng.
 */
#pragma once

#define BASE64_DECODE_OUT_SIZE(s) ((unsigned int)(((s) / 4) * 3))

unsigned int base64_decode(const char *in, unsigned int inlen,
						   unsigned char *out);
