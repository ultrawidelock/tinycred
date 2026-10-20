/* SPDX-FileCopyrightText: 2026 Aseem Chopra */
/* SPDX-License-Identifier: Apache-2.0 */

/* The slice of tinypsa's backend contract tinycred uses, for the host build. The target
 * includes tinypsa's own header. */
#ifndef TINYPSA_BACKEND_H
#define TINYPSA_BACKEND_H

#include <stddef.h>
#include <stdint.h>

void tp_be_sha256_init(void *ctx);
void tp_be_sha256_update(void *ctx, const uint8_t *in, size_t len);
void tp_be_sha256_final(void *ctx, uint8_t out[32]);
void tp_be_hmac_sha256_init(void *ctx, const uint8_t *key, size_t key_len);
void tp_be_hmac_sha256_update(void *ctx, const uint8_t *in, size_t len);
void tp_be_hmac_sha256_final(void *ctx, uint8_t out[32]);
void tp_be_ctx_free(void *ctx, size_t size);

#endif
