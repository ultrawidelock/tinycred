/** @file hash.h — SHA-256, HMAC-SHA-256, HKDF (RFC 5869) and the ANSI X9.63 KDF, the
 * key-schedule primitives of the credential transaction. The hash and the HMAC are
 * tinypsa's backend (tp_be_sha256_*, tp_be_hmac_sha256_*); the two KDFs are built on them
 * here. On the host port/host/hash_host.c supplies the backend functions.
 */

#ifndef TINYCRED_HASH_H
#define TINYCRED_HASH_H

#include <stddef.h>
#include <stdint.h>

#include <tinypsa_backend_ctx.h>

#define TC_SHA256_BLOCK 64u
#define TC_SHA256_LEN   32u

struct tc_sha256 {
	uint8_t ctx[TINYPSA_SHA256_CTX_SIZE];
};

void tc_sha256_init(struct tc_sha256 *s);
void tc_sha256_update(struct tc_sha256 *s, const void *data, size_t len);
void tc_sha256_final(struct tc_sha256 *s, uint8_t out[TC_SHA256_LEN]);
void tc_sha256(const void *data, size_t len, uint8_t out[TC_SHA256_LEN]);

void tc_hmac_sha256(const uint8_t *key, size_t key_len, const void *msg, size_t msg_len,
		    uint8_t out[TC_SHA256_LEN]);

/* HKDF-SHA256: a NULL or empty salt is the RFC's HashLen zero octets. expand takes at most
 * 255 x 32 octets and returns -1 beyond that. */
void tc_hkdf_extract(const uint8_t *salt, size_t salt_len, const uint8_t *ikm, size_t ikm_len,
		     uint8_t prk[TC_SHA256_LEN]);
int tc_hkdf_expand(const uint8_t prk[TC_SHA256_LEN], const uint8_t *info, size_t info_len,
		   uint8_t *out, size_t out_len);
int tc_hkdf(const uint8_t *salt, size_t salt_len, const uint8_t *ikm, size_t ikm_len,
	    const uint8_t *info, size_t info_len, uint8_t *out, size_t out_len);

/* ANSI X9.63 KDF with SHA-256: out = Hash(z || counter_be32 || info) per 32-octet block,
 * the counter starting at 1. */
int tc_x963_kdf(const uint8_t *z, size_t z_len, const uint8_t *info, size_t info_len,
		uint8_t *out, size_t out_len);

#endif /* TINYCRED_HASH_H */
