/* SPDX-FileCopyrightText: 2026 Aseem Chopra */
/* SPDX-License-Identifier: Apache-2.0 */

/*
 * tc_prim — the symmetric-crypto + elliptic-curve + RNG primitive
 * interface used by the portable modules. Target builds use
 * tc_prim_psa.c over their platform's PSA provider; host tests use a
 * recording or reference double.
 *
 * Hashing/KDF is NOT here; that is the portable tc_hash.c, shared by both.
 * All returns: 0 on success, negative on failure (AEAD decrypt returns <0 on a
 * tag mismatch and must be treated as a hard auth failure).
 */
#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TC_P256_SCALAR 32u /* private scalar / coordinate */
#define TC_P256_POINT  65u /* uncompressed point: 0x04 | X32 | Y32 */
#define TC_P256_SIG    64u /* raw ECDSA r|s */
#define TC_GCM_TAG     16u
#define TC_CCM_TAG     16u /* maximum; the sealed link uses 8 */

/* Initialise the backend (idempotent). Call once before any other call. */
int tc_prim_init(void);

/* CSPRNG. */
int tc_random(uint8_t *out, size_t len);

/* AES-256-GCM. tag_len must be <= 16. Decrypt verifies the tag, and may decrypt
 * in place: pt may start at or below ct in the same buffer (never above it). */
int tc_aes256_gcm_encrypt(const uint8_t key[32], const uint8_t *nonce, size_t nonce_len,
			     const uint8_t *aad, size_t aad_len, const uint8_t *pt, size_t pt_len,
			     uint8_t *ct, uint8_t *tag, size_t tag_len);
int tc_aes256_gcm_decrypt(const uint8_t key[32], const uint8_t *nonce, size_t nonce_len,
			     const uint8_t *aad, size_t aad_len, const uint8_t *ct, size_t ct_len,
			     const uint8_t *tag, size_t tag_len, uint8_t *pt);

/*
 * AES-ECB, one block. key_bits must be 128 or 256. This is the primitive
 * beneath the CCC key ladder, Matter CCM, and the advertisement Dynamic Tag.
 */
int tc_aes_ecb_encrypt(const uint8_t *key, size_t key_bits,
				  const uint8_t in[16], uint8_t out[16]);

/* Stable AES-128 convenience ABI used by the advertisement Dynamic Tag. */
int tc_aes128_ecb_encrypt(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]);

/*
 * AES-128-CCM, one shot, no AAD (the sealed link between the lock and its
 * satellites and witnesses). Output is ciphertext ‖ tag, which is what goes on
 * the wire; the GCM pair above hands the tag back separately because it streams
 * a message that does not fit in RAM, and these messages are tens of bytes.
 *
 * No AAD parameter because nothing has one: everything the seal authenticates
 * is inside the plaintext, and the nonce carries the sender and counter. Add it
 * when a caller needs it, not before.
 *
 * tag_len must be <= TC_CCM_TAG. *out_len is what the backend wrote.
 * Decrypt verifies the tag and returns <0 on a mismatch: a hard auth failure,
 * never a retry.
 */
int tc_aes128_ccm_encrypt(const uint8_t key[16], const uint8_t *nonce, size_t nonce_len,
				     const uint8_t *pt, size_t pt_len, size_t tag_len, uint8_t *out,
				     size_t out_cap, size_t *out_len);
int tc_aes128_ccm_decrypt(const uint8_t key[16], const uint8_t *nonce, size_t nonce_len,
				     const uint8_t *in, size_t in_len, size_t tag_len, uint8_t *out,
				     size_t out_cap, size_t *out_len);

/* P-256 ephemeral key pair: priv = 32-byte scalar, pub = 65-byte point. */
int tc_ec_p256_keygen(uint8_t priv[TC_P256_SCALAR],
				 uint8_t pub[TC_P256_POINT]);

/* Derive the 65-byte uncompressed public key from a 32-byte P-256 private
 * scalar (used to recover the reader group key X from the provisioned
 * signingKey; verificationKey = pub(signingKey)). */
int tc_ec_p256_pub_from_priv(const uint8_t priv[TC_P256_SCALAR],
				uint8_t pub[TC_P256_POINT]);

/* ECDH: shared_x = X coordinate (32 bytes) of priv * peer_pub. */
int tc_ecdh_p256(const uint8_t priv[TC_P256_SCALAR],
			    const uint8_t peer_pub[TC_P256_POINT],
			    uint8_t shared_x[TC_P256_SCALAR]);

/* ECDSA-P256-SHA256 over the raw message (hashing is internal). sig = r|s. */
int tc_ecdsa_p256_sign(const uint8_t priv[TC_P256_SCALAR], const uint8_t *msg,
				  size_t msg_len, uint8_t sig[TC_P256_SIG]);
/* ECDSA-P256 over an already computed SHA-256 digest. sig = r|s. */
int tc_ecdsa_p256_sign_hash(const uint8_t priv[TC_P256_SCALAR],
				       const uint8_t hash[32], uint8_t sig[TC_P256_SIG]);
int tc_ecdsa_p256_verify(const uint8_t pub[TC_P256_POINT], const uint8_t *msg,
				    size_t msg_len, const uint8_t sig[TC_P256_SIG]);
/* The same check over an already computed SHA-256 digest. */
int tc_ecdsa_p256_verify_hash(const uint8_t pub[TC_P256_POINT],
					 const uint8_t hash[32],
					 const uint8_t sig[TC_P256_SIG]);

#ifdef __cplusplus
}
#endif
