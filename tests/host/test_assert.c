/** @file test_assert.c — presence-assertion codec + verifier.
 *
 * The security core of the non-door primitive: a spoofed USB device must not be
 * able to assert presence. Covers the happy path and every distinct reject:
 * forged or tampered signature, replayed/other nonce, stale uptime, absent
 * status, out-of-range distance, and malformed framing.
 */
#include <string.h>

#include "tinycred/assert.h"
#include "tinycred/hash.h"
#include "test.h"

/*
 * Stand-in for the P-256 backend.
 *
 * This is NOT ECDSA and proves nothing about curve arithmetic -- the host suite
 * has no real P-256 (the PSA seam is a recording fake), and real signature
 * validation belongs in an on-target test. What it does prove is everything the
 * codec is actually responsible for: that the bytes handed to the backend are
 * exactly the signed prefix, that a tampered frame fails authentication, and
 * that authentication happens before any field is trusted. sig is a
 * deterministic function of the message, so tampering anywhere in the prefix
 * changes it.
 */
struct fake_ec {
	unsigned sign_calls;
	unsigned verify_calls;
	size_t last_msg_len;
	uint8_t last_msg[TC_ASSERT_WIRE_MAX];
	int force_fail;
};

static void fake_ec_tag(const uint8_t *msg, size_t msg_len,
			uint8_t sig[TC_ASSERT_SIG_LEN])
{
	uint8_t d[TC_SHA256_LEN];

	tc_sha256(msg, msg_len, d);
	memcpy(sig, d, TC_SHA256_LEN);
	tc_sha256(d, sizeof(d), sig + TC_SHA256_LEN);
}

static int fake_ec_sign(void *ctx, const uint8_t *msg, size_t msg_len,
			uint8_t sig[TC_ASSERT_SIG_LEN])
{
	struct fake_ec *f = ctx;

	f->sign_calls++;
	f->last_msg_len = msg_len;
	memcpy(f->last_msg, msg, msg_len);
	if (f->force_fail) {
		return -1;
	}
	fake_ec_tag(msg, msg_len, sig);
	return 0;
}

static int fake_ec_verify(void *ctx, const uint8_t *msg, size_t msg_len,
			  const uint8_t sig[TC_ASSERT_SIG_LEN])
{
	struct fake_ec *f = ctx;
	uint8_t want[TC_ASSERT_SIG_LEN];

	f->verify_calls++;
	f->last_msg_len = msg_len;
	memcpy(f->last_msg, msg, msg_len);
	if (f->force_fail) {
		return -1;
	}
	fake_ec_tag(msg, msg_len, want);
	return memcmp(want, sig, sizeof(want)) == 0 ? 0 : -1;
}

/* A fixed challenge nonce + a built assertion the tests mutate. */
static const uint8_t k_nonce[TC_ASSERT_NONCE_LEN] = {
	0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04,
	0xa5, 0xa5, 0x5a, 0x5a, 0x10, 0x20, 0x30, 0x40,
};

static void base_assertion(struct tc_assert *a)
{
	memset(a, 0, sizeof(*a));
	a->status = TC_PRESENCE_PRESENT;
	memcpy(a->nonce, k_nonce, TC_ASSERT_NONCE_LEN);
	for (unsigned i = 0; i < TC_ASSERT_CREDID_LEN; i++) {
		a->cred_id[i] = (uint8_t)(0xC0u + i);
	}
	a->distance_cm = 25;
	/* A defended measurement: STS held, and a distinctive positive quality so
	 * the byte-exact vector below pins where the field sits and how wide it is. */
	a->range_flags = TC_ASSERT_RANGE_STS_OK;
	a->sts_quality = 300;
	a->trust_level = 3;
	a->uptime_ms = 1000000;
	/* Non-zero so the byte-exact vector below actually pins where unix_ms
	 * sits; all-zero would pass even if the field were misplaced. */
	a->unix_ms = 1785000000000ULL;
}

void test_assert(void)
{
	struct fake_ec fec;
	memset(&fec, 0, sizeof(fec));
	struct tc_assert a;
	base_assertion(&a);
	uint8_t wire[TC_ASSERT_WIRE_P256];
	size_t wlen = 0;

	t_group("build");
	T_EQ("build.rc",
	     tc_assert_build_p256(fake_ec_sign, &fec, &a, wire, sizeof(wire), &wlen), 0);
	T_EQ("build.len", (long)wlen, TC_ASSERT_WIRE_P256);
	T_EQ("build.magic0", wire[0], 0xA1);
	T_EQ("build.magic1", wire[1], 0x50);
	T_EQ("build.version", wire[2], 0x03);
	T_EQ("build.alg", wire[3], TC_ASSERT_ALG_ECDSA_P256);
	uint8_t tiny[8];
	T_EQ("build.too_small",
	     tc_assert_build_p256(fake_ec_sign, &fec, &a, tiny, sizeof(tiny), &wlen), -1);
	/* Lock the 51-byte signed prefix so the wire layout cannot drift. Derived
	 * independently (Python struct) before being pinned here. The signature is
	 * not pinned: it comes from the test double, so it would pin the double
	 * rather than the format.
	 * magic|ver=03|alg=02|status|nonce|cred_id|dist=0019(25)|flags=01|
	 * sts=012c(300)|trust=03|uptime=0f4240(1e6)|unix=019f9a4a7a00. */
	t_vec("build.prefix", wire, TC_ASSERT_SIGNED_LEN,
	      "a150030201deadbeef01020304a5a55a5a10203040c0c1c2c3c4c5c6c700190101"
	      "2c0300000000000f42400000019f9a4a7a00");
	/* The backend must be handed the signed prefix -- all of it, and nothing
	 * but it. A backend fed the wrong span would still round-trip against
	 * itself, so this is checked directly rather than inferred. */
	T_EQ("build.signed_len", (long)fec.last_msg_len, TC_ASSERT_SIGNED_LEN);
	T_OK("build.signed_bytes", memcmp(fec.last_msg, wire, TC_ASSERT_SIGNED_LEN) == 0);

	t_group("verify OK");
	struct tc_assert out;
	memset(&out, 0, sizeof(out));
	T_EQ("ok", tc_assert_verify_p256(fake_ec_verify, &fec, wire, wlen, k_nonce, a.cred_id,
					    40, 0, &out),
	     TC_ASSERT_OK);
	T_EQ("ok.dist", out.distance_cm, 25);
	T_EQ("ok.status", out.status, TC_PRESENCE_PRESENT);
	T_OK("ok.credid", memcmp(out.cred_id, a.cred_id, TC_ASSERT_CREDID_LEN) == 0);
	/* Decode side of the two 64-bit clocks: the prefix KAT above pins how they
	 * are written, this pins that verify hands them back. */
	T_OK("ok.uptime", out.uptime_ms == 1000000ULL);
	T_OK("ok.unix", out.unix_ms == 1785000000000ULL);
	/* The integrity evidence reaches the caller, not just the verdict: a policy
	 * layer above this one tightens the quality floor by reading these. */
	T_EQ("ok.range_flags", out.range_flags, TC_ASSERT_RANGE_STS_OK);
	T_EQ("ok.sts_quality", out.sts_quality, 300);
	T_EQ("ok.trust_level", out.trust_level, 3);
	/* Threshold is inclusive: exactly at the boundary passes. */
	T_EQ("ok.boundary",
	     tc_assert_verify_p256(fake_ec_verify, &fec, wire, wlen, k_nonce, a.cred_id, 25, 0,
				      &out),
	     TC_ASSERT_OK);
	/* Forward-progress guard: uptime strictly greater than the floor passes. */
	T_EQ("ok.fresh",
	     tc_assert_verify_p256(fake_ec_verify, &fec, wire, wlen, k_nonce, a.cred_id, 40,
				      999999, &out),
	     TC_ASSERT_OK);

	t_group("reject: tampered / unauthentic");
	/* Any single-bit tamper of the signed region fails authentication. */
	uint8_t tampered[TC_ASSERT_WIRE_P256];
	memcpy(tampered, wire, sizeof(tampered));
	tampered[29] ^= 0x08; /* flip distance high byte: claim a different distance */
	T_EQ("tamper.prefix",
	     tc_assert_verify_p256(fake_ec_verify, &fec, tampered, sizeof(tampered), k_nonce,
				      a.cred_id, 40, 0, &out),
	     TC_ASSERT_E_MAC);
	/* The integrity evidence must be inside the signed span too. If it were not,
	 * an attacker could clear STS_OK on a real frame -- or set it on a suspect
	 * one -- without touching the distance, which is the entire attack this
	 * field exists to stop. */
	memcpy(tampered, wire, sizeof(tampered));
	tampered[31] ^= 0x01; /* flip range_flags: claim the STS held when it did not */
	T_EQ("tamper.range_flags",
	     tc_assert_verify_p256(fake_ec_verify, &fec, tampered, sizeof(tampered), k_nonce,
				      a.cred_id, 40, 0, &out),
	     TC_ASSERT_E_MAC);
	memcpy(tampered, wire, sizeof(tampered));
	tampered[TC_ASSERT_SIGNED_LEN] ^= 0x01; /* tamper the signature itself */
	T_EQ("tamper.sig",
	     tc_assert_verify_p256(fake_ec_verify, &fec, tampered, sizeof(tampered), k_nonce,
				      a.cred_id, 40, 0, &out),
	     TC_ASSERT_E_MAC);
	/* Backend failures propagate as not-authentic, never as a silently accepted
	 * frame -- a backend error must not read as a pass. */
	fec.force_fail = 1;
	T_EQ("backend_fails",
	     tc_assert_verify_p256(fake_ec_verify, &fec, wire, wlen, k_nonce, a.cred_id, 40, 0,
				      &out),
	     TC_ASSERT_E_MAC);
	T_EQ("sign_fails",
	     tc_assert_build_p256(fake_ec_sign, &fec, &a, tampered, sizeof(tampered),
					     NULL),
	     -1);
	fec.force_fail = 0;

	t_group("reject: replay / nonce mismatch");
	uint8_t other_nonce[TC_ASSERT_NONCE_LEN];
	memcpy(other_nonce, k_nonce, sizeof(other_nonce));
	other_nonce[15] ^= 0xFF;
	T_EQ("nonce",
	     tc_assert_verify_p256(fake_ec_verify, &fec, wire, wlen, other_nonce, a.cred_id, 40,
				      0, &out),
	     TC_ASSERT_E_NONCE);

	t_group("reject: credential mismatch");
	uint8_t other_cred_id[TC_ASSERT_CREDID_LEN];
	memcpy(other_cred_id, a.cred_id, sizeof(other_cred_id));
	other_cred_id[0] ^= 0xFF;
	T_EQ("credential",
	     tc_assert_verify_p256(fake_ec_verify, &fec, wire, wlen, k_nonce, other_cred_id, 40,
				      0, &out),
	     TC_ASSERT_E_CREDENTIAL);

	t_group("reject: stale (uptime not advancing)");
	/* uptime_ms == min is stale; a replayed frame at the same uptime is rejected. */
	T_EQ("stale.eq",
	     tc_assert_verify_p256(fake_ec_verify, &fec, wire, wlen, k_nonce, a.cred_id, 40,
				      1000000, &out),
	     TC_ASSERT_E_STALE);
	T_EQ("stale.lt",
	     tc_assert_verify_p256(fake_ec_verify, &fec, wire, wlen, k_nonce, a.cred_id, 40,
				      1000001, &out),
	     TC_ASSERT_E_STALE);

	t_group("reject: absent status");
	struct tc_assert absent = a;
	absent.status = TC_PRESENCE_ABSENT;
	uint8_t awire[TC_ASSERT_WIRE_P256];
	tc_assert_build_p256(fake_ec_sign, &fec, &absent, awire, sizeof(awire), NULL);
	T_EQ("absent",
	     tc_assert_verify_p256(fake_ec_verify, &fec, awire, sizeof(awire), k_nonce,
				      a.cred_id, 40, 0, &out),
	     TC_ASSERT_E_ABSENT);

	t_group("reject: out of range / no range");
	struct tc_assert far = a;
	far.distance_cm = 41;
	uint8_t fwire[TC_ASSERT_WIRE_P256];
	tc_assert_build_p256(fake_ec_sign, &fec, &far, fwire, sizeof(fwire), NULL);
	T_EQ("far",
	     tc_assert_verify_p256(fake_ec_verify, &fec, fwire, sizeof(fwire), k_nonce,
				      a.cred_id, 40, 0, &out),
	     TC_ASSERT_E_RANGE);
	struct tc_assert norange = a;
	norange.distance_cm = TC_ASSERT_DIST_NONE;
	uint8_t nwire[TC_ASSERT_WIRE_P256];
	tc_assert_build_p256(fake_ec_sign, &fec, &norange, nwire, sizeof(nwire), NULL);
	T_EQ("no_range",
	     tc_assert_verify_p256(fake_ec_verify, &fec, nwire, sizeof(nwire), k_nonce,
				      a.cred_id, 0xFFFE, 0, &out),
	     TC_ASSERT_E_RANGE);

	t_group("reject: range integrity");
	/* An in-threshold distance whose STS did not correlate. This is the frame a
	 * distance-reduction attack wants accepted: the number looks perfect, and
	 * only the evidence beside it says the timestamp was never measured. */
	struct tc_assert suspect = a;
	suspect.range_flags = 0u;
	uint8_t swire[TC_ASSERT_WIRE_P256];
	tc_assert_build_p256(fake_ec_sign, &fec, &suspect, swire, sizeof(swire), NULL);
	T_EQ("sts_not_ok",
	     tc_assert_verify_p256(fake_ec_verify, &fec, swire, sizeof(swire), k_nonce,
					      a.cred_id, 40, 0, &out),
	     TC_ASSERT_E_INTEGRITY);
	/* Distance is checked first, so a frame that is both far AND suspect is
	 * reported as far: the order is pinned, not incidental. */
	struct tc_assert farsus = a;
	farsus.distance_cm = 41;
	farsus.range_flags = 0u;
	uint8_t fswire[TC_ASSERT_WIRE_P256];
	tc_assert_build_p256(fake_ec_sign, &fec, &farsus, fswire, sizeof(fswire), NULL);
	T_EQ("far_beats_suspect",
	     tc_assert_verify_p256(fake_ec_verify, &fec, fswire, sizeof(fswire), k_nonce,
				      a.cred_id, 40, 0, &out),
	     TC_ASSERT_E_RANGE);
	/* A bit this version does not define means the producer is claiming
	 * something the verifier cannot evaluate. Fail closed rather than mask it
	 * off and accept the rest. */
	struct tc_assert unknown = a;
	unknown.range_flags = (uint8_t)(TC_ASSERT_RANGE_STS_OK | 0x80u);
	uint8_t uwire[TC_ASSERT_WIRE_P256];
	tc_assert_build_p256(fake_ec_sign, &fec, &unknown, uwire, sizeof(uwire), NULL);
	T_EQ("unknown_flag_bit",
	     tc_assert_verify_p256(fake_ec_verify, &fec, uwire, sizeof(uwire), k_nonce,
					      a.cred_id, 40, 0, &out),
	     TC_ASSERT_E_INTEGRITY);
	/* The evidence fields survive the round trip, including a negative quality
	 * index -- the codec must not mangle the sign on the way back. */
	struct tc_assert negq = a;
	negq.sts_quality = -1234;
	negq.trust_level = 2;
	uint8_t nqwire[TC_ASSERT_WIRE_P256];
	tc_assert_build_p256(fake_ec_sign, &fec, &negq, nqwire, sizeof(nqwire), NULL);
	memset(&out, 0, sizeof(out));
	T_EQ("neg_quality.verdict",
	     tc_assert_verify_p256(fake_ec_verify, &fec, nqwire, sizeof(nqwire), k_nonce,
				      a.cred_id, 40, 0, &out),
	     TC_ASSERT_OK);
	T_EQ("neg_quality.roundtrip", out.sts_quality, -1234);
	T_EQ("neg_quality.trust", out.trust_level, 2);

	t_group("reject: malformed framing");
	T_EQ("short_len",
	     tc_assert_verify_p256(fake_ec_verify, &fec, wire, wlen - 1u, k_nonce,
					      a.cred_id, 40, 0, &out),
	     TC_ASSERT_E_MALFORMED);
	uint8_t bad[TC_ASSERT_WIRE_P256];
	memcpy(bad, wire, sizeof(bad));
	bad[0] = 0x00; /* bad magic */
	T_EQ("bad_magic",
	     tc_assert_verify_p256(fake_ec_verify, &fec, bad, sizeof(bad), k_nonce,
					      a.cred_id, 40, 0, &out),
	     TC_ASSERT_E_MALFORMED);
	memcpy(bad, wire, sizeof(bad));
	/* v2 specifically: it is the version that shipped to a bench board and whose
	 * frames carry no range-integrity evidence. Reinterpreting one under v3
	 * would read the flags byte out of the top half of its uptime field, so it
	 * has to be refused at the version check, not deeper. */
	bad[2] = 0x02;
	T_EQ("bad_version",
	     tc_assert_verify_p256(fake_ec_verify, &fec, bad, sizeof(bad), k_nonce,
					      a.cred_id, 40, 0, &out),
	     TC_ASSERT_E_MALFORMED);
	/* A frame naming an algorithm this verifier does not implement must be
	 * refused as a wrong ALGORITHM, not mislabelled as a bad signature. Alg 1 is
	 * the retired HMAC mode: a v1 frame must reject here rather than be
	 * reinterpreted. Rejected before the signature is even checked. */
	memcpy(bad, wire, sizeof(bad));
	bad[3] = 0x01;
	T_EQ("retired_alg",
	     tc_assert_verify_p256(fake_ec_verify, &fec, bad, sizeof(bad), k_nonce,
					      a.cred_id, 40, 0, &out),
	     TC_ASSERT_E_ALG);
	memcpy(bad, wire, sizeof(bad));
	bad[3] = 0x7F; /* unknown algorithm */
	T_EQ("unknown_alg",
	     tc_assert_verify_p256(fake_ec_verify, &fec, bad, sizeof(bad), k_nonce,
					      a.cred_id, 40, 0, &out),
	     TC_ASSERT_E_ALG);

	t_group("wire length by algorithm");
	T_EQ("len.p256", (long)tc_assert_wire_len(TC_ASSERT_ALG_ECDSA_P256),
	     TC_ASSERT_WIRE_P256);
	/* The retired HMAC value has no length: a scanner must not size a buffer
	 * from it, and the value stays reserved rather than being reassigned. */
	T_EQ("len.retired", (long)tc_assert_wire_len(0x01), 0);
	T_EQ("len.unknown", (long)tc_assert_wire_len(0x7F), 0);
	T_EQ("peek.alg", tc_assert_peek_alg(wire, sizeof(wire)),
	     TC_ASSERT_ALG_ECDSA_P256);
	/* Too short to contain the alg byte's own prefix: report invalid, not a
	 * read past the end of the caller's buffer. */
	T_EQ("peek.short", tc_assert_peek_alg(wire, TC_ASSERT_SIGNED_LEN - 1u), 0);

	/* NULL arguments are caller bugs, but they must fail loudly at the guard
	 * rather than dereference: these are the paths a wrong integration hits. */
	t_group("misuse: NULL arguments");
	T_EQ("null.build_assert",
	     tc_assert_build_p256(fake_ec_sign, &fec, NULL, wire, sizeof(wire), &wlen), -1);
	T_EQ("null.build_wire",
	     tc_assert_build_p256(fake_ec_sign, &fec, &a, NULL,
					     TC_ASSERT_WIRE_P256, &wlen),
	     -1);
	T_EQ("null.build_sign",
	     tc_assert_build_p256(NULL, &fec, &a, wire, sizeof(wire), &wlen), -1);
	T_EQ("null.build_small",
	     tc_assert_build_p256(fake_ec_sign, &fec, &a, wire,
					     TC_ASSERT_WIRE_P256 - 1u, &wlen),
	     -1);
	T_EQ("null.verify_wire",
	     tc_assert_verify_p256(fake_ec_verify, &fec, NULL,
					      TC_ASSERT_WIRE_P256, k_nonce, a.cred_id,
					      40, 0, &out),
	     TC_ASSERT_E_MALFORMED);
	T_EQ("null.verify_fn",
	     tc_assert_verify_p256(NULL, &fec, wire, TC_ASSERT_WIRE_P256,
					      k_nonce, a.cred_id, 40, 0, &out),
	     TC_ASSERT_E_MALFORMED);
	T_EQ("null.peek", tc_assert_peek_alg(NULL, TC_ASSERT_WIRE_MAX), 0);

	t_group("cred_id derivation");
	uint8_t pub[65];
	memset(pub, 0, sizeof(pub));
	pub[0] = 0x04;
	pub[1] = 0xAB;
	uint8_t cid[TC_ASSERT_CREDID_LEN];
	tc_assert_cred_id(pub, cid);
	/* Stable: first 8 bytes of SHA-256(pub). Locked value. */
	t_vec("cred_id", cid, sizeof(cid), "279125357c1cad0f");
}
