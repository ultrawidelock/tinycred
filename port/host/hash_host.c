/* SPDX-FileCopyrightText: 2026 Aseem Chopra */
/* SPDX-License-Identifier: Apache-2.0 */

/*
 * Portable SHA-256 + HMAC/HKDF/X9.63-KDF. See tc_hash.h.
 */
#include <tinypsa/backend.h>
#include <tinypsa_backend_ctx.h>
#include <stddef.h>
#include <stdint.h>

#include <string.h>

// Rotate a 32-bit word right by n bits.
static uint32_t ror32(uint32_t x, unsigned n)
{
	return (x >> n) | (x << (32 - n));
}

static const uint32_t K[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
	0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
	0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
	0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
	0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
	0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
	0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
	0xc67178f2,
};

// Compresses one 64-byte message block into the running SHA-256 state h, per FIPS 180-4.
// h: 8-word running hash state, updated in place.
// p: 64-byte input block.
static void sha256_block(uint32_t h[8], const uint8_t p[64])
{
	uint32_t w[64];

	/* size_t index so i * 4 is computed at pointer width rather than in int
	 * and widened afterwards. No behavioural change at these bounds; it keeps
	 * the offset arithmetic honest for the analyser. */
	for (size_t i = 0; i < 16; i++) {
		w[i] = (uint32_t)p[i * 4] << 24 | (uint32_t)p[i * 4 + 1] << 16 |
		       (uint32_t)p[i * 4 + 2] << 8 | (uint32_t)p[i * 4 + 3];
	}
	for (int i = 16; i < 64; i++) {
		uint32_t s0 = ror32(w[i - 15], 7) ^ ror32(w[i - 15], 18) ^ (w[i - 15] >> 3);
		uint32_t s1 = ror32(w[i - 2], 17) ^ ror32(w[i - 2], 19) ^ (w[i - 2] >> 10);

		w[i] = w[i - 16] + s0 + w[i - 7] + s1;
	}

	uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
	uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];

	for (int i = 0; i < 64; i++) {
		uint32_t S1 = ror32(e, 6) ^ ror32(e, 11) ^ ror32(e, 25);
		uint32_t ch = (e & f) ^ (~e & g);
		uint32_t t1 = hh + S1 + ch + K[i] + w[i];
		uint32_t S0 = ror32(a, 2) ^ ror32(a, 13) ^ ror32(a, 22);
		uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
		uint32_t t2 = S0 + maj;

		hh = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
	}

	h[0] += a;
	h[1] += b;
	h[2] += c;
	h[3] += d;
	h[4] += e;
	h[5] += f;
	h[6] += g;
	h[7] += hh;
}

// Initialize a streaming SHA-256 context with the FIPS 180-4 initial hash values.
// Resets total byte count and internal buffer length to zero; must be called before feeding data.

struct sha256_host {
	uint32_t h[8];
	uint64_t total;
	uint8_t buf[64];
	size_t buflen;
};

struct hmac_host {
	struct sha256_host inner;
	uint8_t opad[64];
};

_Static_assert(sizeof(struct sha256_host) <= TINYPSA_SHA256_CTX_SIZE, "SHA-256 context");
_Static_assert(sizeof(struct hmac_host) <= TINYPSA_HMAC_SHA256_CTX_SIZE, "HMAC context");

void tp_be_sha256_init(void *ctx)
{
	struct sha256_host *s = ctx;

	s->h[0] = 0x6a09e667;
	s->h[1] = 0xbb67ae85;
	s->h[2] = 0x3c6ef372;
	s->h[3] = 0xa54ff53a;
	s->h[4] = 0x510e527f;
	s->h[5] = 0x9b05688c;
	s->h[6] = 0x1f83d9ab;
	s->h[7] = 0x5be0cd19;
	s->total = 0;
	s->buflen = 0;
}

void tp_be_sha256_update(void *ctx, const uint8_t *p, size_t len)
{
	struct sha256_host *s = ctx;

	s->total += len;
	if (s->buflen) {
		size_t n = 64 - s->buflen;

		if (n > len) {
			n = len;
		}
		memcpy(s->buf + s->buflen, p, n);
		s->buflen += n;
		p += n;
		len -= n;
		if (s->buflen == 64) {
			sha256_block(s->h, s->buf);
			s->buflen = 0;
		}
	}
	while (len >= 64) {
		sha256_block(s->h, p);
		p += 64;
		len -= 64;
	}
	if (len) {
		memcpy(s->buf, p, len);
		s->buflen = len;
	}
}

void tp_be_sha256_final(void *ctx, uint8_t out[32])
{
	struct sha256_host *s = ctx;
	uint64_t bits = s->total * 8;
	uint8_t pad = 0x80;
	uint8_t lenbe[8];

	tp_be_sha256_update(s, &pad, 1);
	pad = 0;
	while (s->buflen != 56) {
		tp_be_sha256_update(s, &pad, 1);
	}
	for (int i = 0; i < 8; i++) {
		lenbe[i] = (uint8_t)(bits >> (56 - i * 8));
	}
	tp_be_sha256_update(s, lenbe, 8);
	for (size_t i = 0; i < 8; i++) {
		out[i * 4] = (uint8_t)(s->h[i] >> 24);
		out[i * 4 + 1] = (uint8_t)(s->h[i] >> 16);
		out[i * 4 + 2] = (uint8_t)(s->h[i] >> 8);
		out[i * 4 + 3] = (uint8_t)s->h[i];
	}
}

void tp_be_hmac_sha256_init(void *ctx, const uint8_t *key, size_t key_len)
{
	struct hmac_host *h = ctx;
	uint8_t k[64] = {0};
	uint8_t ipad[64];

	if (key_len > 64) {
		struct sha256_host t;

		tp_be_sha256_init(&t);
		tp_be_sha256_update(&t, key, key_len);
		tp_be_sha256_final(&t, k);
	} else if (key_len) {
		memcpy(k, key, key_len);
	}
	for (size_t i = 0; i < 64; i++) {
		ipad[i] = k[i] ^ 0x36;
		h->opad[i] = k[i] ^ 0x5c;
	}
	tp_be_sha256_init(&h->inner);
	tp_be_sha256_update(&h->inner, ipad, sizeof(ipad));
}

void tp_be_hmac_sha256_update(void *ctx, const uint8_t *in, size_t len)
{
	struct hmac_host *h = ctx;

	tp_be_sha256_update(&h->inner, in, len);
}

void tp_be_hmac_sha256_final(void *ctx, uint8_t out[32])
{
	struct hmac_host *h = ctx;
	struct sha256_host outer;
	uint8_t inner[32];

	tp_be_sha256_final(&h->inner, inner);
	tp_be_sha256_init(&outer);
	tp_be_sha256_update(&outer, h->opad, sizeof(h->opad));
	tp_be_sha256_update(&outer, inner, sizeof(inner));
	tp_be_sha256_final(&outer, out);
}

void tp_be_ctx_free(void *ctx, size_t size)
{
	memset(ctx, 0, size);
}
