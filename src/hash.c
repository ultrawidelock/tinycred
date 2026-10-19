/** @file hash.c — the KDFs of tinycred/hash.h on tinypsa's SHA-256 and HMAC. */

#include "tinycred/hash.h"

#include <string.h>

#include <tinypsa/backend.h>

void tc_sha256_init(struct tc_sha256 *s)
{
	tp_be_sha256_init(s->ctx);
}

void tc_sha256_update(struct tc_sha256 *s, const void *data, size_t len)
{
	tp_be_sha256_update(s->ctx, (const uint8_t *)data, len);
}

void tc_sha256_final(struct tc_sha256 *s, uint8_t out[TC_SHA256_LEN])
{
	tp_be_sha256_final(s->ctx, out);
}

void tc_sha256(const void *data, size_t len, uint8_t out[TC_SHA256_LEN])
{
	struct tc_sha256 s;

	tc_sha256_init(&s);
	tc_sha256_update(&s, data, len);
	tc_sha256_final(&s, out);
}

void tc_hmac_sha256(const uint8_t *key, size_t key_len, const void *msg, size_t msg_len,
		    uint8_t out[TC_SHA256_LEN])
{
	uint8_t ctx[TINYPSA_HMAC_SHA256_CTX_SIZE];

	tp_be_hmac_sha256_init(ctx, key, key_len);
	tp_be_hmac_sha256_update(ctx, (const uint8_t *)msg, msg_len);
	tp_be_hmac_sha256_final(ctx, out);
	tp_be_ctx_free(ctx, sizeof(ctx));
}

void tc_hkdf_extract(const uint8_t *salt, size_t salt_len, const uint8_t *ikm, size_t ikm_len,
		     uint8_t prk[TC_SHA256_LEN])
{
	uint8_t zero[TC_SHA256_LEN] = {0};

	if (salt == NULL || salt_len == 0) {
		salt = zero;
		salt_len = sizeof(zero);
	}
	tc_hmac_sha256(salt, salt_len, ikm, ikm_len, prk);
}

int tc_hkdf_expand(const uint8_t prk[TC_SHA256_LEN], const uint8_t *info, size_t info_len,
		   uint8_t *out, size_t out_len)
{
	uint8_t t[TC_SHA256_LEN];
	size_t tlen = 0;
	uint8_t counter = 1;
	size_t done = 0;

	if (out_len > (size_t)255u * TC_SHA256_LEN) {
		return -1;
	}
	while (done < out_len) {
		uint8_t ctx[TINYPSA_HMAC_SHA256_CTX_SIZE];
		size_t n = out_len - done;

		/* T(n) = HMAC(prk, T(n-1) | info | counter) */
		tp_be_hmac_sha256_init(ctx, prk, TC_SHA256_LEN);
		tp_be_hmac_sha256_update(ctx, t, tlen);
		tp_be_hmac_sha256_update(ctx, info, info_len);
		tp_be_hmac_sha256_update(ctx, &counter, 1);
		tp_be_hmac_sha256_final(ctx, t);
		tp_be_ctx_free(ctx, sizeof(ctx));
		tlen = TC_SHA256_LEN;
		if (n > TC_SHA256_LEN) {
			n = TC_SHA256_LEN;
		}
		memcpy(out + done, t, n);
		done += n;
		counter++;
	}
	return 0;
}

int tc_hkdf(const uint8_t *salt, size_t salt_len, const uint8_t *ikm, size_t ikm_len,
	    const uint8_t *info, size_t info_len, uint8_t *out, size_t out_len)
{
	uint8_t prk[TC_SHA256_LEN];

	tc_hkdf_extract(salt, salt_len, ikm, ikm_len, prk);
	return tc_hkdf_expand(prk, info, info_len, out, out_len);
}

int tc_x963_kdf(const uint8_t *z, size_t z_len, const uint8_t *info, size_t info_len,
		uint8_t *out, size_t out_len)
{
	uint32_t counter = 1;
	size_t done = 0;

	if (out_len > 0xffffffffu - TC_SHA256_LEN) {
		return -1;
	}
	while (done < out_len) {
		struct tc_sha256 s;
		uint8_t cbe[4];
		uint8_t digest[TC_SHA256_LEN];
		size_t n = out_len - done;

		cbe[0] = (uint8_t)(counter >> 24);
		cbe[1] = (uint8_t)(counter >> 16);
		cbe[2] = (uint8_t)(counter >> 8);
		cbe[3] = (uint8_t)counter;
		tc_sha256_init(&s);
		tc_sha256_update(&s, z, z_len);
		tc_sha256_update(&s, cbe, sizeof(cbe));
		if (info && info_len) {
			tc_sha256_update(&s, info, info_len);
		}
		tc_sha256_final(&s, digest);
		if (n > TC_SHA256_LEN) {
			n = TC_SHA256_LEN;
		}
		memcpy(out + done, digest, n);
		done += n;
		counter++;
	}
	return 0;
}
