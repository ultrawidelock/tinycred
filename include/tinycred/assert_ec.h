/*
 * tc_assert_ec — binds the tc_assert P-256 seam to tc_prim.
 *
 * tc_assert.c stays free of any crypto backend so it can remain portable
 * C11. This is the other half: the two-function shim that hands the seam
 * whatever P-256 the platform already provides, so nothing else has to know the
 * seam exists.
 *
 * Split into its own translation unit rather than #ifdef'd into tc_assert.c
 * because it is the only part with a dependency: a build that has no PSA simply
 * does not compile this file.
 */
#pragma once

#include <stdint.h>

#include "tinycred/assert.h"
#include "tinycred/prim.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Key material the two binders expect as their ctx. Pass a pointer to one of
 * these as the void *ctx argument of tc_assert_build_p256 / _verify_p256. */
struct tc_assert_ec_priv {
	uint8_t d[TC_P256_SCALAR]; /* P-256 private scalar */
};

/**
 * Uncompressed ECDSA-P256 public key point: 0x04 || X || Y (65 bytes).
 */
struct tc_assert_ec_pub {
	uint8_t q[TC_ASSERT_PUB_LEN]; /* uncompressed point, 0x04 || X || Y */
};

/* tc_assert_sign_fn over tc_ecdsa_p256_sign. ctx is a
 * struct tc_assert_ec_priv *. Returns 0 on success. */
int tc_assert_ec_sign(void *ctx, const uint8_t *msg, size_t msg_len,
			 uint8_t sig[TC_ASSERT_SIG_LEN]);

/* tc_assert_verify_fn over tc_ecdsa_p256_verify. ctx is a
 * struct tc_assert_ec_pub *. Returns 0 when the signature is valid. */
int tc_assert_ec_verify(void *ctx, const uint8_t *msg, size_t msg_len,
			   const uint8_t sig[TC_ASSERT_SIG_LEN]);

#ifdef __cplusplus
}
#endif
