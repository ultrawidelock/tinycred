/* SPDX-FileCopyrightText: 2026 Aseem Chopra */
/* SPDX-License-Identifier: Apache-2.0 */

/*
 * tc_assert — the presence-assertion protocol for the non-door primitive.
 *
 * A presence dongle answers a challenge with an ECDSA-P256-signed statement:
 * "a provisioned credential is within N cm right now, for THIS nonce." One
 * fresh CSPRNG nonce per challenge, one response accepted, so replays fail; a
 * strictly-increasing dongle uptime is an optional second guard. unix_ms is
 * the attested wall clock (TC_ASSERT_TIME_NONE without trusted time).
 * The signed prefix carries the range-integrity evidence (STS ok, quality,
 * consensus blocks) so a verifier can tell a defended 19 cm from an attack's
 * 19 cm; a frame that does not claim a good STS is rejected outright.
 *
 * Wire codec + verifier only, portable C11 (SHA-256 via tc_hash.c); the
 * dongle firmware fills the fields, the host maps the verdict. trust_level is
 * reported, not thresholded -- the policy layer owns any floor. Wire version 3;
 * v1/v2 frames are rejected, no decoder kept.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TC_ASSERT_NONCE_LEN  16u
#define TC_ASSERT_CREDID_LEN 8u  /* first 8 bytes of SHA-256(credential pub) */
#define TC_ASSERT_SIG_LEN    64u /* ECDSA-P256 signature, r||s, 32 bytes each */
#define TC_ASSERT_PUB_LEN    65u /* uncompressed P-256 point, 0x04 || X || Y */

/* The signed prefix; only the trailing signature follows it. */
#define TC_ASSERT_SIGNED_LEN 51u
#define TC_ASSERT_WIRE_P256                                                             \
	(TC_ASSERT_SIGNED_LEN + TC_ASSERT_SIG_LEN) /* 115 */
#define TC_ASSERT_WIRE_MAX                                                              \
	TC_ASSERT_WIRE_P256 /* size any receive buffer by this */

#define TC_ASSERT_DIST_NONE 0xFFFFu /* distance_cm sentinel: no valid range */
#define TC_ASSERT_TIME_NONE 0u      /* unix_ms sentinel: no trusted wall clock */

/*
 * range_flags — what the ranging layer can vouch for about distance_cm.
 *
 * STS_OK means every block in the agreeing run behind this distance correlated
 * its scrambled timestamp sequence well enough to trust. A spoofed early first
 * path cannot reproduce that sequence, so its STS quality collapses; the bit is
 * therefore the difference between a measured distance and a claimed one.
 *
 * Bits outside FLAGS_KNOWN must be zero. An unknown bit means the frame asserts
 * a property this verifier cannot evaluate, and a security field that cannot be
 * read has to fail closed rather than be ignored. Adding a bit later costs a
 * version bump, which is the intended price.
 */
#define TC_ASSERT_RANGE_STS_OK      0x01u /* STS held for every block in the run */
#define TC_ASSERT_RANGE_FLAGS_KNOWN 0x01u /* every bit this wire version defines */

/* Authentication algorithm, carried in the frame so the verifier never has to
 * guess and so a frame can never be verified under the algorithm it was not
 * built for. Values are wire-visible; do not renumber. */
enum tc_assert_alg {
	/* 1 was HMAC-SHA256, retired with the paired-host PAM path it existed for.
	 * Deliberately not reused: a v1 frame must reject as unknown-alg rather
	 * than be reinterpreted under a scheme it was never signed with. */
	TC_ASSERT_ALG_ECDSA_P256 = 2,
};

/* Presence status the dongle reports from the ranging round. */
enum tc_assert_status {
	TC_PRESENCE_ABSENT = 0,  /* no provisioned credential answered the round */
	TC_PRESENCE_PRESENT = 1, /* a trusted credential transacted + ranged */
};

/*
 * The assertion fields. Wire layout (big-endian multi-byte), the tag covers
 * every byte before it:
 *   magic(2)=A1 50 | version(1)=03 | alg(1) | status(1) | nonce(16) |
 *   cred_id(8) | distance_cm(2) | range_flags(1) | sts_quality(2) |
 *   trust_level(1) | uptime_ms(8) | unix_ms(8) | sig(64)
 * = 115 bytes.
 *
 * The three integrity fields sit next to distance_cm because they qualify it:
 * reading the distance without them is reading a number with its provenance
 * stripped off.
 */
struct tc_assert {
	uint8_t status;                           /* enum tc_assert_status */
	uint8_t nonce[TC_ASSERT_NONCE_LEN];    /* echoed from the challenge */
	uint8_t cred_id[TC_ASSERT_CREDID_LEN]; /* which credential answered */
	uint16_t distance_cm;                     /* TC_ASSERT_DIST_NONE if none */
	uint8_t range_flags;                      /* TC_ASSERT_RANGE_* evidence bits */
	int16_t sts_quality;                      /* STS quality index, worst block in the run */
	uint8_t trust_level;                      /* agreeing blocks behind the distance */
	uint64_t uptime_ms;                       /* dongle monotonic ms at build */
	uint64_t unix_ms;                         /* attested wall clock, or TIME_NONE */
};

/* Verdict / reason codes from tc_assert_verify. 0 = presence confirmed;
 * every negative value is a distinct reject reason (for logging + tests). */
enum tc_assert_verdict {
	TC_ASSERT_OK = 0,
	TC_ASSERT_E_MALFORMED = -1,  /* bad length, magic, or version */
	TC_ASSERT_E_MAC = -2,        /* tag mismatch: wrong key or tampered */
	TC_ASSERT_E_NONCE = -3,      /* nonce != challenge: replay / mismatch */
	TC_ASSERT_E_STALE = -4,      /* uptime_ms <= min_uptime_ms */
	TC_ASSERT_E_ABSENT = -5,     /* status != PRESENT */
	TC_ASSERT_E_RANGE = -6,      /* distance_cm > threshold, or no range */
	TC_ASSERT_E_ALG = -7,        /* unknown alg, or not the one being verified */
	TC_ASSERT_E_CREDENTIAL = -8, /* cred_id != enrolled credential */
	/* Distance not backed by a good STS, or unknown range_flags bits. */
	TC_ASSERT_E_INTEGRITY = -9,
};

/* Frame length for an algorithm, or 0 if the algorithm is unknown. The alg byte
 * sits at a fixed offset inside the signed prefix, so a stream scanner can read
 * it at a candidate offset and learn how long the frame is before validating. */
size_t tc_assert_wire_len(uint8_t alg);

/* Reads the alg byte of a candidate frame. buf must hold at least
 * TC_ASSERT_SIGNED_LEN bytes; returns 0 (an invalid alg) otherwise. */
uint8_t tc_assert_peek_alg(const uint8_t *buf, size_t len);

/* cred_id = first 8 bytes of SHA-256(cred_pub[65]). Stable id for a credential
 * public key so the verifier can bind presence to a specific enrolled
 * credential. */
void tc_assert_cred_id(const uint8_t cred_pub[TC_ASSERT_PUB_LEN],
			  uint8_t cred_id[TC_ASSERT_CREDID_LEN]);

/*
 * Signing seam for the ECDSA-P256 mode.
 *
 * The curve arithmetic deliberately does NOT live in this module. Keeping the
 * codec free of any crypto-backend dependency is what lets it stay portable
 * C11, and it lets each caller bind whatever P-256 it already has -- on target
 * that is tc_ecdsa_p256_sign/verify from
 * tc_prim.h, in tests it is a double that can assert exactly which bytes
 * were presented for signature.
 *
 * Both take the signed prefix as msg (never a pre-hash: the backend hashes
 * internally, matching tc_prim's ECDSA-P256-SHA256 contract) and return 0
 * on success, non-zero on failure. sig is r||s, 32 bytes each.
 */
typedef int (*tc_assert_sign_fn)(void *ctx, const uint8_t *msg, size_t msg_len,
				    uint8_t sig[TC_ASSERT_SIG_LEN]);
typedef int (*tc_assert_verify_fn)(void *ctx, const uint8_t *msg, size_t msg_len,
				      const uint8_t sig[TC_ASSERT_SIG_LEN]);

/* Serialise an assertion and have sign() sign it, producing an
 * TC_ASSERT_WIRE_P256-byte frame. Returns 0 and sets *wire_len; -1 if
 * wire_cap is too small, sign is NULL, or sign() fails. */
int tc_assert_build_p256(tc_assert_sign_fn sign, void *ctx,
				    const struct tc_assert *a, uint8_t *wire,
				    size_t wire_cap, size_t *wire_len);

/*
 * Parse + fully verify a frame, delegating authentication to verify(). Checks,
 * in order: length/magic/version, alg == ECDSA-P256, signature, nonce echo,
 * enrolled credential id, forward-progress (uptime_ms > min_uptime_ms; pass 0
 * to skip), status == PRESENT, distance_cm <= threshold_cm, then range
 * integrity (known flag bits only, and STS_OK set).
 *
 * The integrity check is not optional and takes no parameter. A caller cannot
 * ask for a distance whose measurement was never vouched for, because there is
 * no threat model in which that answer is useful: the whole value of the
 * assertion is that the number was measured rather than asserted.
 *
 * Returns TC_ASSERT_OK (0) only when all pass; otherwise the first failing
 * reason. A failed signature reports TC_ASSERT_E_MAC, whatever the backend's
 * own reason was: from the caller's side they all mean "not authentic".
 *
 * *out, when non-NULL, is populated with whatever parsed AFTER the signature
 * check passed (for logging / cred-allowlist); it is left untouched if the
 * signature or framing is bad, and must never be trusted for an unlock on a
 * non-zero return. threshold_cm is inclusive.
 */
int tc_assert_verify_p256(
	tc_assert_verify_fn verify, void *ctx, const uint8_t *wire, size_t wire_len,
	const uint8_t expected_nonce[TC_ASSERT_NONCE_LEN],
	const uint8_t expected_cred_id[TC_ASSERT_CREDID_LEN], uint16_t threshold_cm,
	uint64_t min_uptime_ms, struct tc_assert *out);

#ifdef __cplusplus
}
#endif
