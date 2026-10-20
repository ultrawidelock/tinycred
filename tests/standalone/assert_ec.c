/* SPDX-FileCopyrightText: 2026 Aseem Chopra */
/* SPDX-License-Identifier: Apache-2.0 */

/** @file test_assert_ec.c — the P-256 binder between tc_assert and
 * tc_prim.
 *
 * tc_assert.c is backend-free by design, so the main host suite exercises its
 * P-256 path against a local double. That leaves one thing untested: the shim
 * that actually wires the seam to tc_prim, where a swapped key argument or a
 * mis-sized buffer would be invisible to both sides. This links the real
 * tc_assert_ec.c against the host prim double (tc_prim_host.c, a
 * documented fake curve -- so this proves wiring, never curve arithmetic).
 *
 * What it pins: a frame signed through the binder verifies through the binder,
 * the wrong public key is rejected, tampering is rejected, and NULL key material
 * fails loudly rather than dereferencing.
 */
#include <stdio.h>
#include <string.h>

#include "tinycred/assert.h"
#include "tinycred/assert_ec.h"
#include "tinycred/prim.h"

static int fails;
static int total;

static void check(const char *name, int ok)
{
	total++;
	if (!ok) {
		printf("  FAIL %s\n", name);
		fails++;
	}
}

int main(void)
{
	struct tc_assert_ec_priv priv;
	struct tc_assert_ec_pub pub;
	uint8_t p[TC_P256_SCALAR];
	uint8_t q[TC_P256_POINT];

	check("prim_init", tc_prim_init() == 0);
	check("keygen", tc_ec_p256_keygen(p, q) == 0);
	memcpy(priv.d, p, sizeof(p));
	memcpy(pub.q, q, sizeof(q));

	struct tc_assert a;

	memset(&a, 0, sizeof(a));
	a.status = TC_PRESENCE_PRESENT;
	memset(a.nonce, 0x5A, sizeof(a.nonce));
	a.distance_cm = 42;
	/* A defended range: without the evidence the verifier below refuses the
	 * frame on policy and this binder test would never reach the curve. */
	a.range_flags = TC_ASSERT_RANGE_STS_OK;
	a.sts_quality = 120;
	a.trust_level = 3;
	a.uptime_ms = 123456;
	a.unix_ms = 1785000000000ULL;

	uint8_t wire[TC_ASSERT_WIRE_P256];
	size_t wlen = 0;

	check("build", tc_assert_build_p256(tc_assert_ec_sign, &priv, &a,
						       wire, sizeof(wire), &wlen) == 0);
	check("build.len", wlen == TC_ASSERT_WIRE_P256);
	check("build.alg", wire[3] == TC_ASSERT_ALG_ECDSA_P256);

	struct tc_assert out;

	check("verify", tc_assert_verify_p256(tc_assert_ec_verify, &pub, wire,
							 wlen, a.nonce, a.cred_id, 100, 0,
							 &out) == TC_ASSERT_OK);
	check("verify.dist", out.distance_cm == 42);
	check("verify.unix", out.unix_ms == 1785000000000ULL);

	/* A different key pair must not verify this frame: catches a binder that
	 * ignores its ctx, which would otherwise pass every test above.
	 * Deliberately NOT a second keygen call -- tc_random in the host double
	 * is a deterministic filler, so keygen hands back the same pair every time
	 * and the "other" key would be byte-identical to the first. */
	struct tc_assert_ec_pub other;
	uint8_t p2[TC_P256_SCALAR];
	uint8_t q2[TC_P256_POINT];

	memcpy(p2, p, sizeof(p2));
	p2[0] ^= 0xFF;
	check("pub_from_priv2", tc_ec_p256_pub_from_priv(p2, q2) == 0);
	check("keys_differ", memcmp(q2, q, sizeof(q2)) != 0);
	memcpy(other.q, q2, sizeof(q2));
	check("verify.wrong_key",
	      tc_assert_verify_p256(tc_assert_ec_verify, &other, wire, wlen,
					       a.nonce, a.cred_id, 100, 0,
					       &out) == TC_ASSERT_E_MAC);

	/* Tamper the signed prefix. */
	uint8_t tam[TC_ASSERT_WIRE_P256];

	memcpy(tam, wire, sizeof(tam));
	tam[30] ^= 0x01; /* distance_cm low byte */
	check("verify.tampered",
	      tc_assert_verify_p256(tc_assert_ec_verify, &pub, tam,
					       sizeof(tam), a.nonce, a.cred_id, 100, 0,
					       &out) == TC_ASSERT_E_MAC);

	/* NULL key material is a wiring bug: fail, do not dereference. */
	check("sign.null_ctx", tc_assert_ec_sign(NULL, wire, 8, tam) != 0);
	check("verify.null_ctx", tc_assert_ec_verify(NULL, wire, 8, tam) != 0);
	check("build.null_key",
	      tc_assert_build_p256(tc_assert_ec_sign, NULL, &a, wire,
					      sizeof(wire), &wlen) == -1);

	printf("  tc_assert_ec: %d checks, %d failed\n", total, fails);
	return fails == 0 ? 0 : 1;
}
