/* SPDX-FileCopyrightText: 2026 Aseem Chopra */
/* SPDX-License-Identifier: Apache-2.0 */

// Presence-assertion wire codec + verifier (see tc_assert.h). Serialises a
// dongle's "credential present within N cm for this nonce" statement and verifies
// an ECDSA-P256 frame against a challenge nonce, enrolled credential and distance
// threshold. Portable C11; no UWB/BLE/platform dependencies.
#include <string.h>

#include "tinycred/assert.h"
#include "tinycred/hash.h"

/* Frame layout (see the header). OFF_TAG == TC_ASSERT_SIGNED_LEN == the
 * number of signed bytes. */
#define OFF_MAGIC       0u
#define OFF_VERSION     2u
#define OFF_ALG         3u
#define OFF_STATUS      4u
#define OFF_NONCE       5u
#define OFF_CREDID      21u
#define OFF_DISTANCE    29u
#define OFF_RANGE_FLAGS 31u
#define OFF_STS_QUALITY 32u
#define OFF_TRUST       34u
#define OFF_UPTIME      35u
#define OFF_UNIX        43u
#define OFF_TAG         TC_ASSERT_SIGNED_LEN /* == number of signed bytes */

#define ASSERT_MAGIC0  0xA1u
#define ASSERT_MAGIC1  0x50u
#define ASSERT_VERSION 0x03u

// Writes v as 2 big-endian bytes to p.
static void put_be16(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)(v >> 8);
	p[1] = (uint8_t)v;
}

// Reads 2 big-endian bytes from p.
static uint16_t get_be16(const uint8_t *p)
{
	return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

// Reads 2 big-endian bytes from p as a signed value. Goes through uint16_t and
// an explicit two's-complement fold rather than casting, so the result does not
// depend on the implementation-defined narrowing of an out-of-range cast.
static int16_t get_be16_signed(const uint8_t *p)
{
	uint16_t raw = get_be16(p);

	return (raw & 0x8000u) ? (int16_t)((int32_t)raw - 65536) : (int16_t)raw;
}

// Writes v as 8 big-endian bytes to p.
static void put_be64(uint8_t *p, uint64_t v)
{
	for (int i = 7; i >= 0; i--) {
		p[i] = (uint8_t)v;
		v >>= 8;
	}
}

// Reads 8 big-endian bytes from p.
static uint64_t get_be64(const uint8_t *p)
{
	uint64_t v = 0;

	for (unsigned i = 0; i < 8u; i++) {
		v = (v << 8) | p[i];
	}
	return v;
}

// Constant-time equality of two n-byte buffers: 1 if equal, 0 otherwise. Timing
// is independent of where the first differing byte is, so a MAC check does not
// leak how much of a forged tag was correct.
static int ct_equal(const uint8_t *a, const uint8_t *b, size_t n)
{
	uint8_t diff = 0;

	for (size_t i = 0; i < n; i++) {
		diff |= (uint8_t)(a[i] ^ b[i]);
	}
	return diff == 0;
}

/**
 * Return the wire frame length for a given algorithm byte, or 0 if the algorithm is unrecognized.
 */
size_t tc_assert_wire_len(uint8_t alg)
{
	switch (alg) {
	case TC_ASSERT_ALG_ECDSA_P256:
		return TC_ASSERT_WIRE_P256;
	default:
		return 0u;
	}
}

/**
 * Extract and return the algorithm byte from a wire-encoded attestation frame; return 0 if the
 * buffer is NULL or shorter than TC_ASSERT_SIGNED_LEN.
 */
uint8_t tc_assert_peek_alg(const uint8_t *buf, size_t len)
{
	if (buf == NULL || len < TC_ASSERT_SIGNED_LEN) {
		return 0u;
	}
	return buf[OFF_ALG];
}

/**
 * Derive a credential ID by hashing the 65-byte P-256 public key and truncating to
 * TC_ASSERT_CREDID_LEN bytes.
 */
void tc_assert_cred_id(const uint8_t cred_pub[TC_ASSERT_PUB_LEN],
			  uint8_t cred_id[TC_ASSERT_CREDID_LEN])
{
	uint8_t digest[TC_SHA256_LEN];

	tc_sha256(cred_pub, TC_ASSERT_PUB_LEN, digest);
	memcpy(cred_id, digest, TC_ASSERT_CREDID_LEN);
}

// Writes the signed prefix (everything before the signature).
static void put_prefix(uint8_t *wire, uint8_t alg, const struct tc_assert *a)
{
	wire[OFF_MAGIC] = ASSERT_MAGIC0;
	wire[OFF_MAGIC + 1u] = ASSERT_MAGIC1;
	wire[OFF_VERSION] = ASSERT_VERSION;
	wire[OFF_ALG] = alg;
	wire[OFF_STATUS] = a->status;
	memcpy(wire + OFF_NONCE, a->nonce, TC_ASSERT_NONCE_LEN);
	memcpy(wire + OFF_CREDID, a->cred_id, TC_ASSERT_CREDID_LEN);
	put_be16(wire + OFF_DISTANCE, a->distance_cm);
	wire[OFF_RANGE_FLAGS] = a->range_flags;
	put_be16(wire + OFF_STS_QUALITY, (uint16_t)a->sts_quality);
	wire[OFF_TRUST] = a->trust_level;
	put_be64(wire + OFF_UPTIME, a->uptime_ms);
	put_be64(wire + OFF_UNIX, a->unix_ms);
}

/*
 * Framing checks: length for the algorithm named in the frame, magic, version,
 * and that the algorithm is the one this verifier implements.
 */
static int check_framing(const uint8_t *wire, size_t wire_len, uint8_t want_alg)
{
	/* Enough bytes to hold the header fields this function reads. */
	if (wire == NULL || wire_len < TC_ASSERT_SIGNED_LEN) {
		return TC_ASSERT_E_MALFORMED;
	}
	if (wire[OFF_MAGIC] != ASSERT_MAGIC0 || wire[OFF_MAGIC + 1u] != ASSERT_MAGIC1 ||
	    wire[OFF_VERSION] != ASSERT_VERSION) {
		return TC_ASSERT_E_MALFORMED;
	}
	/* Algorithm before length, deliberately. A well-formed frame for the other
	 * algorithm should be reported as the wrong ALGORITHM whatever its length,
	 * rather than as generic malformed framing -- the two have very different
	 * causes and only one of them means "your peer is misconfigured". */
	if (wire[OFF_ALG] != want_alg) {
		return TC_ASSERT_E_ALG;
	}
	if (wire_len != tc_assert_wire_len(want_alg)) {
		return TC_ASSERT_E_MALFORMED;
	}
	return TC_ASSERT_OK;
}

/*
 * Everything after authentication: parse the fields, hand them to the caller
 * for logging even on a semantic reject, then apply the policy checks in a
 * fixed order.
 */
static int parse_and_check(const uint8_t *wire, const uint8_t *expected_nonce,
			   const uint8_t *expected_cred_id, uint16_t threshold_cm,
			   uint64_t min_uptime_ms, struct tc_assert *out)
{
	struct tc_assert a;

	a.status = wire[OFF_STATUS];
	memcpy(a.nonce, wire + OFF_NONCE, TC_ASSERT_NONCE_LEN);
	memcpy(a.cred_id, wire + OFF_CREDID, TC_ASSERT_CREDID_LEN);
	a.distance_cm = get_be16(wire + OFF_DISTANCE);
	a.range_flags = wire[OFF_RANGE_FLAGS];
	a.sts_quality = get_be16_signed(wire + OFF_STS_QUALITY);
	a.trust_level = wire[OFF_TRUST];
	a.uptime_ms = get_be64(wire + OFF_UPTIME);
	a.unix_ms = get_be64(wire + OFF_UNIX);
	if (out != NULL) {
		*out = a;
	}

	if (expected_nonce == NULL || !ct_equal(a.nonce, expected_nonce, TC_ASSERT_NONCE_LEN)) {
		return TC_ASSERT_E_NONCE;
	}
	if (expected_cred_id == NULL ||
	    !ct_equal(a.cred_id, expected_cred_id, TC_ASSERT_CREDID_LEN)) {
		return TC_ASSERT_E_CREDENTIAL;
	}
	if (min_uptime_ms != 0u && a.uptime_ms <= min_uptime_ms) {
		return TC_ASSERT_E_STALE;
	}
	if (a.status != TC_PRESENCE_PRESENT) {
		return TC_ASSERT_E_ABSENT;
	}
	if (a.distance_cm == TC_ASSERT_DIST_NONE || a.distance_cm > threshold_cm) {
		return TC_ASSERT_E_RANGE;
	}
	/* Last, because it is the most specific complaint about the distance: the
	 * number is in bounds but its measurement was never vouched for. An unknown
	 * flag bit lands here too -- this verifier cannot evaluate what the frame is
	 * claiming, and an unreadable security field must fail closed. */
	if ((a.range_flags & ~(uint8_t)TC_ASSERT_RANGE_FLAGS_KNOWN) != 0u ||
	    (a.range_flags & (uint8_t)TC_ASSERT_RANGE_STS_OK) == 0u) {
		return TC_ASSERT_E_INTEGRITY;
	}
	return TC_ASSERT_OK;
}

/**
 * Encode a credential attestation into a wire frame with a P-256 signature, signing all bytes
 * before the tag; return 0 on success, -1 if any argument is NULL or wire_cap is too small.
 */
int tc_assert_build_p256(tc_assert_sign_fn sign, void *ctx,
				    const struct tc_assert *a, uint8_t *wire,
				    size_t wire_cap, size_t *wire_len)
{
	if (sign == NULL || wire == NULL || a == NULL || wire_cap < TC_ASSERT_WIRE_P256) {
		return -1;
	}

	put_prefix(wire, TC_ASSERT_ALG_ECDSA_P256, a);

	/* Sign every byte before the tag: magic, version, alg and all the claimed
	 * facts, so none of them can be edited without breaking the signature. */
	if (sign(ctx, wire, OFF_TAG, wire + OFF_TAG) != 0) {
		return -1;
	}

	if (wire_len != NULL) {
		*wire_len = TC_ASSERT_WIRE_P256;
	}
	return 0;
}

/**
 * Verify and parse a P-256-signed wire frame after authenticating the signature, checking framing,
 * algorithm, magic, and version; parse fields and validate against expected nonce, credential ID,
 * distance threshold, and minimum uptime; return TC_ASSERT_OK on success or a specific
 * error code (TC_ASSERT_E_MALFORMED, TC_ASSERT_E_MAC, etc.).
 */
int tc_assert_verify_p256(
	tc_assert_verify_fn verify, void *ctx, const uint8_t *wire, size_t wire_len,
	const uint8_t expected_nonce[TC_ASSERT_NONCE_LEN],
	const uint8_t expected_cred_id[TC_ASSERT_CREDID_LEN], uint16_t threshold_cm,
	uint64_t min_uptime_ms, struct tc_assert *out)
{
	if (verify == NULL) {
		return TC_ASSERT_E_MALFORMED;
	}

	int fr = check_framing(wire, wire_len, TC_ASSERT_ALG_ECDSA_P256);

	if (fr != TC_ASSERT_OK) {
		return fr;
	}

	/* Authenticate before interpreting any field. A backend that fails for any
	 * reason -- bad signature, malformed point, backend error -- is a frame we
	 * cannot trust, so all of it collapses to one verdict. */
	if (verify(ctx, wire, OFF_TAG, wire + OFF_TAG) != 0) {
		return TC_ASSERT_E_MAC;
	}

	return parse_and_check(wire, expected_nonce, expected_cred_id, threshold_cm, min_uptime_ms,
			       out);
}
