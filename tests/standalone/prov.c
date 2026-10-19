/*
 * Host KAT for the reader provisioning core (tc_prov.c): the dev identity,
 * blob (de)serialisation round-trip + malformed-blob rejection, and the trust
 * store (check / add / dedup / full / bad-point). Pure host build; the NVS
 * backend (tc_prov_nvs.c) is target-only and not linked here.
 */
#include <stdio.h>
#include <string.h>

#include "tinycred/prov.h"

static int fails;

static void okc(const char *name, int cond)
{
	if (!cond) {
		printf("  FAIL %s\n", name);
		fails++;
	} else {
		printf("  ok   %s\n", name);
	}
}

/* An uncompressed-point-shaped key filled from a seed byte. */
static void mkpub(uint8_t pub[TC_CRED_PUB_LEN], uint8_t seed)
{
	pub[0] = 0x04;
	for (unsigned i = 1; i < TC_CRED_PUB_LEN; i++) {
		pub[i] = (uint8_t)(seed + i);
	}
}

int main(void)
{
	struct tc_reader_identity id, id2;
	struct tc_trust_store ts, ts2;

	printf("== dev default ==\n");
	tc_prov_dev_default(&id, &ts);
	okc("dev.is_dev", id.is_dev);
	okc("dev.trust_empty", ts.count == 0);
	/* reader_id = dev signing pub X (first bytes 11 3b 1a 9e ...). */
	okc("dev.reader_id0", id.reader_id[0] == 0x11 && id.reader_id[1] == 0x3b &&
			      id.reader_id[2] == 0x1a && id.reader_id[3] == 0x9e);
	okc("dev.sign_priv0", id.sign_priv[0] == 0x4d && id.sign_priv[1] == 0x33);
	/* dev identity is stable: two loads are byte-identical. */
	tc_prov_dev_default(&id2, &ts2);
	okc("dev.stable", memcmp(&id, &id2, sizeof(id)) == 0);

	printf("\n== serialize / deserialize round-trip ==\n");
	uint8_t blob[TC_PROV_BLOB_MAX];
	size_t n = 0;

	/* A provisioned (non-dev) identity + a 2-key trust store. */
	for (unsigned i = 0; i < TC_READER_ID_LEN; i++) {
		id.reader_id[i] = (uint8_t)(0xA0 + i);
	}
	for (unsigned i = 0; i < TC_READER_PRIV_LEN; i++) {
		id.sign_priv[i] = (uint8_t)(0x50 + i);
	}
	for (unsigned i = 0; i < TC_GRK_LEN; i++) {
		id.grk[i] = (uint8_t)(0x30 + i);
	}
	id.is_dev = false;
	memset(&ts, 0, sizeof(ts));
	uint8_t k0[TC_CRED_PUB_LEN], k1[TC_CRED_PUB_LEN];

	mkpub(k0, 0x10);
	mkpub(k1, 0x60);
	okc("add.k0", tc_prov_trust_add(&ts, k0) == 0);
	okc("add.k1", tc_prov_trust_add(&ts, k1) == 0);
	okc("trust.count2", ts.count == 2);

	okc("ser.ok", tc_prov_serialize(&id, &ts, blob, sizeof(blob), &n) == 0);
	/* v4 adds a 5-byte (type, credential index, user index) binding per anchor;
	 * v5 a 1-byte issuer binding per anchor, then the issuer count (0 here). */
	okc("ser.len", n == TC_PROV_BLOB_HDR + TC_READER_ID_LEN +
			   TC_READER_PRIV_LEN + TC_GRK_LEN + 1u +
			   2u * TC_CRED_PUB_LEN + 1u + 2u * TC_KPERSISTENT_LEN + 2u * 5u +
			   2u * 1u + 1u);
	okc("ser.magic", blob[0] == 'A' && blob[1] == 'P' && blob[2] == 'R' &&
			 blob[3] == 'V');

	okc("de.ok", tc_prov_deserialize(blob, n, &id2, &ts2) == 0);
	okc("de.is_dev", id2.is_dev == false);
	okc("de.reader_id", memcmp(id2.reader_id, id.reader_id, TC_READER_ID_LEN) == 0);
	okc("de.sign_priv", memcmp(id2.sign_priv, id.sign_priv, TC_READER_PRIV_LEN) == 0);
	okc("de.grk", memcmp(id2.grk, id.grk, TC_GRK_LEN) == 0);
	okc("de.count", ts2.count == 2);
	okc("de.k0", memcmp(ts2.cred_pub[0], k0, TC_CRED_PUB_LEN) == 0);
	okc("de.k1", memcmp(ts2.cred_pub[1], k1, TC_CRED_PUB_LEN) == 0);

	/* is_dev flag survives the round-trip. */
	tc_prov_dev_default(&id, &ts);
	okc("ser.dev.ok", tc_prov_serialize(&id, &ts, blob, sizeof(blob), &n) == 0);
	okc("ser.dev.len", n == TC_PROV_BLOB_HDR + TC_READER_ID_LEN +
			       TC_READER_PRIV_LEN + TC_GRK_LEN + 1u + 1u + 1u);
	okc("de.dev.ok", tc_prov_deserialize(blob, n, &id2, &ts2) == 0);
	okc("de.dev.flag", id2.is_dev == true);
	okc("de.dev.count", ts2.count == 0);

	printf("\n== serialize overflow ==\n");
	okc("ser.overflow", tc_prov_serialize(&id, &ts, blob, 10, &n) == -1);

	printf("\n== malformed-blob rejection ==\n");
	/* Rebuild a valid 1-key blob, then corrupt copies of it. */
	memset(&ts, 0, sizeof(ts));
	tc_prov_trust_add(&ts, k0);
	tc_prov_dev_default(&id, NULL);
	tc_prov_serialize(&id, &ts, blob, sizeof(blob), &n);

	uint8_t bad[TC_PROV_BLOB_MAX];

	okc("de.tooshort", tc_prov_deserialize(blob, TC_PROV_BLOB_HDR + 1,
							  &id2, &ts2) == -1);

	memcpy(bad, blob, n);
	bad[0] = 'X';
	okc("de.badmagic", tc_prov_deserialize(bad, n, &id2, &ts2) == -1);

	memcpy(bad, blob, n);
	bad[4] = 0xFF; /* unknown version (0x01..0x04 are valid) */
	okc("de.badver", tc_prov_deserialize(bad, n, &id2, &ts2) == -1);

	memcpy(bad, blob, n);
	bad[TC_PROV_BLOB_HDR + TC_READER_ID_LEN +
	    TC_READER_PRIV_LEN + TC_GRK_LEN] = TC_TRUST_MAX + 1;
	okc("de.badcount", tc_prov_deserialize(bad, n, &id2, &ts2) == -1);

	/* count says 1 but the buffer is truncated by a byte. */
	okc("de.lenmismatch", tc_prov_deserialize(blob, n - 1, &id2, &ts2) == -1);

	printf("\n== Kpersistent bind / v3 round-trip / v2 compat ==\n");
	memset(&ts, 0, sizeof(ts));
	mkpub(k0, 0x10);
	mkpub(k1, 0x60);
	tc_prov_trust_add(&ts, k0);
	tc_prov_trust_add(&ts, k1);
	uint8_t kp[TC_KPERSISTENT_LEN], kmiss[TC_CRED_PUB_LEN];

	for (unsigned i = 0; i < TC_KPERSISTENT_LEN; i++) {
		kp[i] = (uint8_t)(0xD0 + i);
	}
	mkpub(kmiss, 0xF0);
	okc("find.k1", tc_prov_trust_find(&ts, k1) == 1);
	okc("find.miss", tc_prov_trust_find(&ts, kmiss) == -1);
	okc("kp.set", tc_prov_kpersistent_set(&ts, 1, kp) == 0);
	okc("kp.mask", ts.kp_valid == 0x02);
	okc("kp.set-oob", tc_prov_kpersistent_set(&ts, 2, kp) == -1);
	okc("kp.set-neg", tc_prov_kpersistent_set(&ts, -1, kp) == -1);

	tc_prov_dev_default(&id, NULL);
	okc("kp.ser", tc_prov_serialize(&id, &ts, blob, sizeof(blob), &n) == 0);
	okc("kp.de", tc_prov_deserialize(blob, n, &id2, &ts2) == 0);
	okc("kp.de-mask", ts2.kp_valid == 0x02);
	okc("kp.de-key", memcmp(ts2.kpersistent[1], kp, TC_KPERSISTENT_LEN) == 0);
	uint8_t zeros[TC_KPERSISTENT_LEN] = { 0 };

	okc("kp.de-unset-zero",
	    memcmp(ts2.kpersistent[0], zeros, TC_KPERSISTENT_LEN) == 0);

	/* a v2 blob (no kpersistent tail, no index tail, no issuer tail) still
	 * parses, with no Kpersistent -- the three tails are dropped from the v5
	 * blob's length (the v5 tail here is two anchor bindings + the count) */
	memcpy(bad, blob, n);
	bad[4] = 0x02; /* TC_PROV_VERSION_2 */
	okc("kp.v2-compat",
	    tc_prov_deserialize(
		    bad, n - 1u - 2u * TC_KPERSISTENT_LEN - 2u * 5u - 3u, &id2, &ts2) == 0);
	okc("kp.v2-no-kp", ts2.kp_valid == 0 && ts2.count == 2 &&
				   memcmp(ts2.cred_pub[1], k1, TC_CRED_PUB_LEN) == 0);

	/* a v3 blob (kpersistent tail, no index tail): what every board
	 * provisioned before revocation is carrying */
	memcpy(bad, blob, n);
	bad[4] = 0x03; /* TC_PROV_VERSION_3 */
	okc("kp.v3-compat", tc_prov_deserialize(bad, n - 2u * 5u - 3u, &id2, &ts2) == 0);
	okc("kp.v3-keeps-kp", ts2.kp_valid == 0x02 && ts2.count == 2);
	okc("kp.v3-no-index", ts2.cred_index[0] == TC_CRED_INDEX_NONE &&
				      ts2.cred_index[1] == TC_CRED_INDEX_NONE);

	/* trust_add must not inherit a stale bit for the slot it fills */
	memset(&ts, 0, sizeof(ts));
	tc_prov_trust_add(&ts, k0);
	ts.kp_valid = 0x03; /* stale bit for the not-yet-used slot 1 */
	memcpy(ts.kpersistent[1], kp, TC_KPERSISTENT_LEN); /* stale bytes */
	okc("add.clears-slot",
	    tc_prov_trust_add(&ts, k1) == 0 && ts.kp_valid == 0x01 &&
		    memcmp(ts.kpersistent[1], zeros, TC_KPERSISTENT_LEN) == 0);

	printf("\n== trust check / add / dedup / full ==\n");
	memset(&ts, 0, sizeof(ts));
	uint8_t kx[TC_CRED_PUB_LEN];

	mkpub(kx, 0xAA);
	okc("check.empty", tc_prov_trust_check(&ts, kx) == 1);
	okc("add.first", tc_prov_trust_add(&ts, kx) == 0);
	okc("check.hit", tc_prov_trust_check(&ts, kx) == 0);
	mkpub(k0, 0x01);
	okc("check.miss", tc_prov_trust_check(&ts, k0) == -1);
	okc("add.dedup", tc_prov_trust_add(&ts, kx) == 1);
	okc("dedup.count", ts.count == 1);

	uint8_t badpt[TC_CRED_PUB_LEN];

	mkpub(badpt, 0x33);
	badpt[0] = 0x02; /* not an uncompressed point */
	okc("add.badpoint", tc_prov_trust_add(&ts, badpt) == -1);

	/* Fill to capacity, then one more must fail. */
	memset(&ts, 0, sizeof(ts));
	for (unsigned i = 0; i < TC_TRUST_MAX; i++) {
		uint8_t kk[TC_CRED_PUB_LEN];

		mkpub(kk, (uint8_t)(0x70 + i * 8));
		okc("fill.add", tc_prov_trust_add(&ts, kk) == 0);
	}
	okc("fill.count", ts.count == TC_TRUST_MAX);
	uint8_t over[TC_CRED_PUB_LEN];

	mkpub(over, 0xF0);
	/*
	 * A FULL STORE EVICTS, it does not refuse. Refusing locked a re-paired
	 * reader out permanently: anchors accumulate two per pairing, nothing
	 * removed them, and once full the key the phone actually presents could
	 * never be added -- the unlock failing one step after the signature
	 * verified, with no way back on a board that has no console.
	 * 2 = added, and something was dropped to make room.
	 */
	okc("fill.overflow_evicts", tc_prov_trust_add(&ts, over) == 2);
	okc("fill.still_full", ts.count == TC_TRUST_MAX);
	okc("fill.newest_kept", tc_prov_trust_check(&ts, over) == 0);

	printf("\n== issuer keys / learned anchors / v5 round-trip / v4 compat ==\n");
	{
		/*
		 * The issuer key (Matter SetCredential type 6) is the trust root the
		 * Access Document is signed under. An endpoint key the reader LEARNS
		 * from a document is an anchor bound to that issuer, so revoking the
		 * issuer revokes every key it vouched for and nothing else.
		 */
		uint8_t i0[TC_CRED_PUB_LEN], i1[TC_CRED_PUB_LEN];
		uint8_t a0[TC_CRED_PUB_LEN], a1[TC_CRED_PUB_LEN],
			a2[TC_CRED_PUB_LEN];

		memset(&ts, 0, sizeof(ts));
		mkpub(i0, 0x11);
		mkpub(i1, 0x22);
		okc("iss.empty_find", tc_prov_issuer_find(&ts, i0) == -1);
		okc("iss.add0", tc_prov_issuer_add(&ts, i0, 1u, 1u) == 0);
		okc("iss.find0", tc_prov_issuer_find(&ts, i0) == 0);
		okc("iss.find_index0", tc_prov_issuer_find_index(&ts, 1u) == 0);
		okc("iss.none_never_matches",
		    tc_prov_issuer_find_index(&ts, TC_CRED_INDEX_NONE) == -1);
		okc("iss.dedup", tc_prov_issuer_add(&ts, i0, 1u, 1u) == 1);
		/* Apple re-installs a key under a fresh index when a user is re-added. */
		okc("iss.rebind", tc_prov_issuer_add(&ts, i0, 3u, 2u) == 1);
		okc("iss.rebound", ts.issuer_cred_index[0] == 3u && ts.issuer_user_index[0] == 2u);
		okc("iss.add1", tc_prov_issuer_add(&ts, i1, 2u, 2u) == 0);
		okc("iss.count2", ts.issuer_count == 2u);
		badpt[0] = 0x02;
		okc("iss.badpoint", tc_prov_issuer_add(&ts, badpt, 4u, 1u) == -1);

		/* Anchors: a0 learned under i0, a1 learned under i1, a2 installed by
		 * the admin (no issuer). */
		mkpub(a0, 0x40);
		mkpub(a1, 0x50);
		mkpub(a2, 0x60);
		okc("iss.anchor_a0", tc_prov_trust_add(&ts, a0) == 0);
		okc("iss.anchor_a1", tc_prov_trust_add(&ts, a1) == 0);
		okc("iss.anchor_a2", tc_prov_trust_add(&ts, a2) == 0);
		okc("iss.bind_a0", tc_prov_anchor_issuer_set(&ts, 0, 0) == 0);
		okc("iss.bind_a1", tc_prov_anchor_issuer_set(&ts, 1, 1) == 0);
		okc("iss.bind_bad_slot", tc_prov_anchor_issuer_set(&ts, 2, 5) == -1);
		okc("iss.bind_bad_anchor", tc_prov_anchor_issuer_set(&ts, 7, 0) == -1);
		okc("iss.a2_unbound", tc_prov_anchor_issuer(&ts, 2) == -1);
		okc("iss.a1_bound", tc_prov_anchor_issuer(&ts, 1) == 1);
		/* A learned key takes the lowest free index of ITS type: the admin's
		 * evictable key sits at 1, so the reader's first learned key is 2. */
		(void)tc_prov_cred_bind_set(&ts, 2, 7u, 1u, 1u);
		okc("iss.free_index_type7", tc_prov_free_cred_index(&ts, 7u) == 2);
		okc("iss.free_index_type8", tc_prov_free_cred_index(&ts, 8u) == 1);

		/* v5 round trip carries every issuer and every binding. */
		okc("v5.ser", tc_prov_serialize(&id, &ts, blob, sizeof(blob), &n) == 0);
		okc("v5.fits_blob_max", n <= TC_PROV_BLOB_MAX);
		okc("v5.version", blob[4] == 0x05);
		memset(&ts2, 0xEE, sizeof(ts2));
		okc("v5.de", tc_prov_deserialize(blob, n, &id2, &ts2) == 0);
		okc("v5.same", memcmp(&ts, &ts2, sizeof(ts)) == 0);

		/* Revoking i0 drops a0 (learned under it), keeps a1 and re-points it at
		 * the issuer that slid into slot 0, and leaves the admin's a2 alone. */
		okc("iss.remove0", tc_prov_issuer_remove_at(&ts, 0) == 1);
		okc("iss.count1", ts.issuer_count == 1u &&
					  tc_prov_issuer_find(&ts, i1) == 0);
		okc("iss.a0_gone", tc_prov_trust_check(&ts, a0) == -1);
		okc("iss.a1_kept", tc_prov_trust_find(&ts, a1) == 0 &&
					   tc_prov_anchor_issuer(&ts, 0) == 0);
		okc("iss.a2_kept", tc_prov_trust_find(&ts, a2) == 1 &&
					   tc_prov_anchor_issuer(&ts, 1) == -1);
		okc("iss.remove_bad", tc_prov_issuer_remove_at(&ts, 3) == -1);

		/* Issuers never evict: a controller installed them and the cap it was
		 * told (NumberOfAliroCredentialIssuerKeysSupported) is this one. */
		memset(&ts, 0, sizeof(ts));
		for (unsigned i = 0; i < TC_ISSUER_MAX; i++) {
			uint8_t kk[TC_CRED_PUB_LEN];

			mkpub(kk, (uint8_t)(0x80 + i * 4));
			okc("iss.fill", tc_prov_issuer_add(&ts, kk, (uint16_t)(i + 1u), 1u) == 0);
		}
		okc("iss.full_refuses", tc_prov_issuer_add(&ts, over, 9u, 1u) == -1);
		okc("iss.full_count", ts.issuer_count == TC_ISSUER_MAX);

		/* A v4 blob (this store, before issuers existed) still loads, with no
		 * issuer and every anchor unbound. With no anchors and no issuers a v5
		 * blob is a v4 blob plus the one issuer-count byte. */
		memset(&ts, 0, sizeof(ts));
		okc("v4.ser_v5", tc_prov_serialize(&id, &ts, blob, sizeof(blob), &n) == 0);
		blob[4] = 0x04;
		memset(&ts2, 0xEE, sizeof(ts2));
		okc("v4.parse", tc_prov_deserialize(blob, n - 1u, &id2, &ts2) == 0);
		okc("v4.no_issuers", ts2.issuer_count == 0u);
		okc("v4.rejects_v5_tail", tc_prov_deserialize(blob, n, &id2, &ts2) == -1);
	}

	printf("\n== corrupt count / v1 compat / NULL store ==\n");
	{
		/* a count beyond the store capacity must refuse to serialize */
		struct tc_trust_store tsbad;

		memset(&tsbad, 0, sizeof(tsbad));
		tsbad.count = TC_TRUST_MAX + 1;
		okc("ser.countoverflow",
		    tc_prov_serialize(&id, &tsbad, blob, sizeof(blob), &n) == -1);
	}
	{
		/* hand-built v1 blob: hdr + reader_id + sign_priv + count(0) — no grk
		 * field, no kpersistent tail. The parse must zero the grk. */
		uint8_t v1[TC_PROV_BLOB_HDR + TC_READER_ID_LEN +
			   TC_READER_PRIV_LEN + 1u];
		uint8_t zgrk[TC_GRK_LEN] = { 0 };

		tc_prov_dev_default(&id, NULL);
		v1[0] = 'A';
		v1[1] = 'P';
		v1[2] = 'R';
		v1[3] = 'V';
		v1[4] = 0x01; /* TC_PROV_VERSION_1 */
		v1[5] = 0x01; /* dev flag */
		memcpy(v1 + TC_PROV_BLOB_HDR, id.reader_id, TC_READER_ID_LEN);
		memcpy(v1 + TC_PROV_BLOB_HDR + TC_READER_ID_LEN, id.sign_priv,
		       TC_READER_PRIV_LEN);
		v1[sizeof(v1) - 1u] = 0; /* no trust anchors */
		memset(id2.grk, 0xEE, TC_GRK_LEN); /* stale bytes the parse must clear */
		okc("v1.parse", tc_prov_deserialize(v1, sizeof(v1), &id2, &ts2) == 0);
		okc("v1.grk-zeroed", memcmp(id2.grk, zgrk, TC_GRK_LEN) == 0);
		okc("v1.dev-flag", id2.is_dev == true);
		okc("v1.count", ts2.count == 0);
	}
	okc("find.null-store", tc_prov_trust_find(NULL, k0) == -1);

	printf("\nRESULT: %s\n", fails == 0 ? "PASS" : "FAIL");
	return fails == 0 ? 0 : 1;
}
