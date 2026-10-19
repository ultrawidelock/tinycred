/** @file prim_tinypsa.c — tinycred/prim.h on tinypsa's backend: no PSA key objects, the
 * key bytes go straight to the primitive. Points cross the seam uncompressed (0x04 x y, 65
 * octets); tinypsa takes x || y (64 octets).
 */

#include "tinycred/prim.h"

#include <string.h>

#include <tinypsa/prim.h>

#include "tinycred/hash.h"

int tc_prim_init(void)
{
	return 0; /* psa_crypto_init() ran at boot; tinypsa's DRBG is seeded by it */
}

int tc_random(uint8_t *out, size_t len)
{
	return tinypsa_random(out, len) == 0 ? 0 : -1;
}

/* ── AES ─────────────────────────────────────────────────────────────────── */

int tc_aes256_gcm_encrypt(const uint8_t key[32], const uint8_t *nonce, size_t nonce_len,
			  const uint8_t *aad, size_t aad_len, const uint8_t *pt, size_t pt_len,
			  uint8_t *ct, uint8_t *tag, size_t tag_len)
{
	uint8_t ctx[TINYPSA_GCM_CTX_SIZE];

	if (tag_len != TC_GCM_TAG) {
		return -1;
	}
	tp_be_gcm_key(ctx, key, 32u);
	tp_be_gcm_start(ctx, 1, nonce, nonce_len);
	if (aad_len != 0u) {
		tp_be_gcm_update_ad(ctx, aad, aad_len);
	}
	if (pt_len != 0u) {
		tp_be_gcm_update(ctx, 1, ct, pt, pt_len);
	}
	tp_be_gcm_final_enc(ctx, tag, tag_len);
	tp_be_ctx_free(ctx, sizeof(ctx));
	return 0;
}

int tc_aes256_gcm_decrypt(const uint8_t key[32], const uint8_t *nonce, size_t nonce_len,
			  const uint8_t *aad, size_t aad_len, const uint8_t *ct, size_t ct_len,
			  const uint8_t *tag, size_t tag_len, uint8_t *pt)
{
	uint8_t ctx[TINYPSA_GCM_CTX_SIZE];
	int rc;

	if (tag_len != TC_GCM_TAG) {
		return -1;
	}
	tp_be_gcm_key(ctx, key, 32u);
	tp_be_gcm_start(ctx, 0, nonce, nonce_len);
	if (aad_len != 0u) {
		tp_be_gcm_update_ad(ctx, aad, aad_len);
	}
	if (ct_len != 0u) {
		tp_be_gcm_update(ctx, 0, pt, ct, ct_len);
	}
	rc = tp_be_gcm_final_dec(ctx, tag, tag_len);
	tp_be_ctx_free(ctx, sizeof(ctx));
	if (rc != 0) {
		memset(pt, 0, ct_len); /* never hand out an unauthenticated plaintext */
		return -1;
	}
	return 0;
}

int tc_aes_ecb_encrypt(const uint8_t *key, size_t key_bits, const uint8_t in[16],
		       uint8_t out[16])
{
	uint8_t ctx[TINYPSA_AES_CTX_SIZE];

	if (key_bits != 128u && key_bits != 256u) {
		return -1;
	}
	tp_be_aes_init(ctx, key, key_bits / 8u);
	tp_be_aes_encrypt(ctx, out, in, 16u);
	tp_be_ctx_free(ctx, sizeof(ctx));
	return 0;
}

int tc_aes128_ecb_encrypt(const uint8_t key[16], const uint8_t in[16], uint8_t out[16])
{
	return tc_aes_ecb_encrypt(key, 128u, in, out);
}

int tc_aes128_ccm_encrypt(const uint8_t key[16], const uint8_t *nonce, size_t nonce_len,
			  const uint8_t *pt, size_t pt_len, size_t tag_len, uint8_t *out,
			  size_t out_cap, size_t *out_len)
{
	uint8_t ctx[TINYPSA_CCM_CTX_SIZE];

	if (out_cap < pt_len + tag_len) {
		return -1;
	}
	tp_be_ccm_key(ctx, key, 16u);
	tp_be_ccm_start(ctx, 1, 16u, nonce, nonce_len, tag_len, pt_len, 0u);
	if (pt_len != 0u) {
		tp_be_ccm_update(ctx, 1, out, pt, pt_len);
	}
	tp_be_ccm_final_enc(ctx, out + pt_len, tag_len);
	tp_be_ctx_free(ctx, sizeof(ctx));
	*out_len = pt_len + tag_len;
	return 0;
}

int tc_aes128_ccm_decrypt(const uint8_t key[16], const uint8_t *nonce, size_t nonce_len,
			  const uint8_t *in, size_t in_len, size_t tag_len, uint8_t *out,
			  size_t out_cap, size_t *out_len)
{
	uint8_t ctx[TINYPSA_CCM_CTX_SIZE];
	size_t pt_len;
	int rc;

	if (in_len < tag_len || out_cap < in_len - tag_len) {
		return -1;
	}
	pt_len = in_len - tag_len;
	tp_be_ccm_key(ctx, key, 16u);
	tp_be_ccm_start(ctx, 0, 16u, nonce, nonce_len, tag_len, pt_len, 0u);
	if (pt_len != 0u) {
		tp_be_ccm_update(ctx, 0, out, in, pt_len);
	}
	rc = tp_be_ccm_final_dec(ctx, in + pt_len, tag_len);
	tp_be_ctx_free(ctx, sizeof(ctx));
	if (rc != 0) {
		memset(out, 0, pt_len);
		return -1;
	}
	*out_len = pt_len;
	return 0;
}

/* ── P-256 ───────────────────────────────────────────────────────────────── */

static void point_out(uint8_t pub[TC_P256_POINT], const uint8_t xy[64])
{
	pub[0] = 0x04u;
	memcpy(pub + 1, xy, 64u);
}

static int point_in(const uint8_t pub[TC_P256_POINT], uint8_t xy[64])
{
	if (pub[0] != 0x04u) {
		return -1;
	}
	memcpy(xy, pub + 1, 64u);
	return tp_be_p256_pk_check(xy);
}

int tc_ec_p256_keygen(uint8_t priv[TC_P256_SCALAR], uint8_t pub[TC_P256_POINT])
{
	uint8_t xy[64];

	if (tinypsa_p256_keygen(priv, xy) != 0) {
		return -1;
	}
	point_out(pub, xy);
	return 0;
}

int tc_ec_p256_pub_from_priv(const uint8_t priv[TC_P256_SCALAR], uint8_t pub[TC_P256_POINT])
{
	uint8_t xy[64];

	if (tp_be_p256_public_key(xy, priv) != 0) {
		return -1;
	}
	point_out(pub, xy);
	return 0;
}

int tc_ecdh_p256(const uint8_t priv[TC_P256_SCALAR], const uint8_t peer_pub[TC_P256_POINT],
		 uint8_t shared_x[TC_P256_SCALAR])
{
	uint8_t xy[64];

	if (point_in(peer_pub, xy) != 0) {
		return -1;
	}
	return tp_be_p256_ecdh(shared_x, priv, xy) == 0 ? 0 : -1;
}

int tc_ecdsa_p256_sign_hash(const uint8_t priv[TC_P256_SCALAR], const uint8_t hash[32],
			    uint8_t sig[TC_P256_SIG])
{
	return tinypsa_p256_sign_hash(sig, hash, priv) == 0 ? 0 : -1;
}

int tc_ecdsa_p256_sign(const uint8_t priv[TC_P256_SCALAR], const uint8_t *msg, size_t msg_len,
		       uint8_t sig[TC_P256_SIG])
{
	uint8_t hash[32];

	tc_sha256(msg, msg_len, hash);
	return tc_ecdsa_p256_sign_hash(priv, hash, sig);
}

int tc_ecdsa_p256_verify_hash(const uint8_t pub[TC_P256_POINT], const uint8_t hash[32],
			      const uint8_t sig[TC_P256_SIG])
{
	uint8_t xy[64];

	if (point_in(pub, xy) != 0) {
		return -1;
	}
	return tp_be_p256_verify_hash(sig, hash, xy) == 0 ? 0 : -1;
}

int tc_ecdsa_p256_verify(const uint8_t pub[TC_P256_POINT], const uint8_t *msg, size_t msg_len,
			 const uint8_t sig[TC_P256_SIG])
{
	uint8_t hash[32];

	tc_sha256(msg, msg_len, hash);
	return tc_ecdsa_p256_verify_hash(pub, hash, sig);
}
