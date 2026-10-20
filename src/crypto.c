/* SPDX-FileCopyrightText: 2026 Aseem Chopra */
/* SPDX-License-Identifier: Apache-2.0 */

// credential cryptographic primitives: key derivation (KDF/HKDF), key-block splitting, AES-GCM
// secure channels, and wire message framing built on a pluggable crypto backend
// (tc_prim_*). Implements the credential key-derivation chain (ECDH shared secret -> z
// -> 160-byte key block -> split session keys / URSK / BLE ranging keys), per-direction AES-256-GCM
// secure channels with monotonic message counters, and the seal/open framing used to carry engine
// plaintext over the wire.
/*
 * tc_crypto — credential-auth key schedule. See tc_crypto.h.
 *
 * The KDF chain (ECDH/Kpersistent -> 160-byte block -> URSK + secure-channel
 * keys) is built on the portable SHA-256/HKDF/X9.63 core (tc_hash.c) and the
 * AEAD/EC primitives (tc_prim.h). The transcript inputs and labels follow
 * Aliro §8.1.1.2 and §8.3.1; the tests pin them to the §14 worked examples.
 */
#include "tinycred/crypto.h"

#include <string.h>

#include "tinycred/hash.h"
#include "tinycred/prim.h"

// Initializes the credential crypto backend's underlying primitive library.
// Must be called once before any other tc_crypto function. Returns the underlying
// tc_prim_init() status code.
int tc_crypto_init(void)
{
	return tc_prim_init();
}

// Extracts the URSK from a derived 160-byte key block at its fixed offset.
// Does not perform any derivation; block must already be the HKDF output of
// tc_crypto_derive_block.
void tc_crypto_ursk_from_block(const uint8_t block[TC_KEY_BLOCK_LEN],
				  uint8_t ursk[TC_URSK_LEN])
{
	memcpy(ursk, block + TC_URSK_OFFSET, TC_URSK_LEN);
}

/* ---- key schedule ---- */

// Derives the 32-byte KDF intermediate z from the ECDH shared secret and transaction ID via
// single-block ANSI X9.63 KDF: SHA-256(shared_secret || 00000001 || txid). z is the input consumed
// by tc_crypto_derive_block and tc_crypto_derive_key32.
void tc_crypto_derive_z(const uint8_t shared_secret[TC_SHARED_SECRET_LEN],
			   const uint8_t txid[TC_TXID_LEN], uint8_t z[32])
{
	/* Single-block X9.63: SHA-256( shared_secret | 00000001 | txid ). */
	tc_x963_kdf(shared_secret, TC_SHARED_SECRET_LEN, txid,
			       TC_TXID_LEN, z, 32);
}

// Derives the 160-byte credential key block via HKDF-SHA256(salt, IKM=z, info=device_pub_x, L=160).
// z is the 32-byte KDF intermediate (tc_crypto_derive_z output); device_pub_x is the
// peer device's ephemeral public-key X coordinate. Returns 0 on success, nonzero on HKDF failure.
int tc_crypto_derive_block(const uint8_t z[32], const uint8_t *salt, size_t salt_len,
			      const uint8_t device_pub_x[TC_EC_PUBX_LEN],
			      uint8_t block[TC_KEY_BLOCK_LEN])
{
	/* HKDF-SHA256(salt, IKM=z, info=device_pub_x, L=160). */
	return tc_hkdf(salt, salt_len, z, 32, device_pub_x, TC_EC_PUBX_LEN, block,
			  TC_KEY_BLOCK_LEN);
}

// Derives a standalone 32-byte key via HKDF-SHA256(salt, IKM=z, info=device_pub_x, L=32),
// independent of the standard 160-byte key block layout. Returns 0 on success, nonzero on HKDF
// failure.
int tc_crypto_derive_key32(const uint8_t z[32], const uint8_t *salt, size_t salt_len,
			      const uint8_t device_pub_x[TC_EC_PUBX_LEN], uint8_t out[32])
{
	return tc_hkdf(salt, salt_len, z, 32, device_pub_x, TC_EC_PUBX_LEN, out, 32);
}

// Splits a derived 160-byte key block into the directional session keys and URSK.
// with_c selects which pair of 32-byte segments become enc_key/dec_key: nonzero uses segments S0/S1
// (base offset 0), zero uses S1/S2 (base offset 32); this corresponds to the "derive shared key C"
// config flag. ursk is always taken from the fixed S4 segment (offset 128) regardless of with_c.
void tc_crypto_split(const uint8_t block[TC_KEY_BLOCK_LEN], int with_c,
			uint8_t enc_key[TC_SESSION_KEY_LEN],
			uint8_t dec_key[TC_SESSION_KEY_LEN], uint8_t ursk[TC_URSK_LEN])
{
	/* Five 32-byte segments S0..S4. The config flag "derive shared key C"
	 * shifts the base of the two directional keys: with C -> S0/S1, without
	 * C -> S1/S2. URSK is S4 (offset 128) unconditionally. The fast block uses
	 * the without-C layout (CryptogramSK is S0, ExpeditedSKReader/Device are
	 * S1/S2), so tc_crypto_split(block, 0, ...) extracts the fast channel
	 * keys too. */
	size_t base = with_c ? 0u : 32u;

	memcpy(enc_key, block + base, TC_SESSION_KEY_LEN);
	memcpy(dec_key, block + base + 32u, TC_SESSION_KEY_LEN);
	memcpy(ursk, block + TC_URSK_OFFSET, TC_URSK_LEN);
}

// Verify an AUTH0 fast-phase cryptogram (Aliro §8.3.1.11): AES-256-GCM open of the
// encrypted_payload || 16-byte tag under CryptogramSK with a 12-byte zero IV and no AAD.
// Returns 0 (and writes cryptogram_len-16 plaintext bytes) on a tag match; <0 on a mismatch
// (short input, or the tag does not verify under this CryptogramSK).
int tc_crypto_verify_cryptogram(
	const uint8_t cryptogram_sk[TC_SESSION_KEY_LEN], const uint8_t *cryptogram,
	size_t cryptogram_len, uint8_t *plain_payload)
{
	/* §8.3.1.10/.11 fix IV = 0x00 * 12 and no AAD for the cryptogram AEAD. */
	static const uint8_t zero_iv[TC_GCM_NONCE_LEN] = {0};

	if (cryptogram == NULL || cryptogram_len < TC_GCM_TAG_LEN) {
		return -1;
	}

	size_t ct_len = cryptogram_len - TC_GCM_TAG_LEN;

	return tc_aes256_gcm_decrypt(cryptogram_sk, zero_iv, TC_GCM_NONCE_LEN,
						NULL, 0, cryptogram, ct_len, cryptogram + ct_len,
						TC_GCM_TAG_LEN, plain_payload);
}

/* ---- secure channel ---- */

// Initializes a secure channel with the given per-direction encrypt/decrypt keys and sets both
// message counters to 1. Per Aliro §8.3.1 both enc_ctr and dec_ctr start at 1, not 0 (unlike the
// HomeKey channel), so the first inbound decrypt must use device_counter=1.
void tc_secchan_init(struct tc_secchan *sc,
				const uint8_t enc_key[TC_SESSION_KEY_LEN],
				const uint8_t dec_key[TC_SESSION_KEY_LEN])
{
	memcpy(sc->enc_key, enc_key, TC_SESSION_KEY_LEN);
	memcpy(sc->dec_key, dec_key, TC_SESSION_KEY_LEN);
	/* Aliro §8.3.1 initialises both per-direction counters to 1 (NOT 0 like the
	 * HomeKey channel). The first inbound decrypt therefore uses device_counter=1. */
	sc->enc_ctr = 1;
	sc->dec_ctr = 1;
}

// Builds a 12-byte AES-GCM nonce as an 8-byte big-endian direction value followed by a 4-byte
// big-endian counter. direction distinguishes the two traffic directions of a secure channel;
// counter is the per-message sequence number that must be incremented by the caller between
// messages to avoid nonce reuse.
void tc_crypto_gcm_nonce(uint64_t direction, uint32_t counter,
			    uint8_t nonce[TC_GCM_NONCE_LEN])
{
	/* 8-byte BE direction || 4-byte BE counter. */
	for (int i = 0; i < 8; i++) {
		nonce[i] = (uint8_t)(direction >> (56 - i * 8));
	}
	nonce[8] = (uint8_t)(counter >> 24);
	nonce[9] = (uint8_t)(counter >> 16);
	nonce[10] = (uint8_t)(counter >> 8);
	nonce[11] = (uint8_t)counter;
}

// Encrypt and authenticate plaintext with the secure channel's outbound (enc) key and counter.
// Builds the nonce from direction 0 and the current enc_ctr, writes ciphertext to ct and the GCM
// tag to tag, and advances enc_ctr only on success. Returns -1 without encrypting if enc_ctr has
// reached 0xffffffff (counter exhausted, no wraparound), or if encryption fails; returns 0 on
// success.
int tc_secchan_seal(struct tc_secchan *sc, const uint8_t *aad, size_t aad_len,
		       const uint8_t *pt, size_t pt_len, uint8_t *ct,
		       uint8_t tag[TC_GCM_TAG_LEN])
{
	uint8_t nonce[TC_GCM_NONCE_LEN];
	int rc;

	if (sc->enc_ctr == 0xffffffffu) {
		return -1; /* counter exhausted: no wrap */
	}
	tc_crypto_gcm_nonce(0, sc->enc_ctr, nonce);
	rc = tc_aes256_gcm_encrypt(sc->enc_key, nonce, sizeof(nonce), aad, aad_len, pt, pt_len,
				      ct, tag, TC_GCM_TAG_LEN);
	if (rc == 0) {
		sc->enc_ctr++;
	}
	return rc;
}

// Decrypt and authenticate a ciphertext with the secure channel's inbound (dec) key and counter.
// Builds the nonce from direction 1 and the current dec_ctr, verifies tag against aad/ct, and
// writes the plaintext to pt on success. Advances dec_ctr only on successful authentication.
// Returns -1 without decrypting if dec_ctr has reached 0xffffffff (counter exhausted, no
// wraparound), or if decryption/authentication fails; returns 0 on success.
int tc_secchan_open(struct tc_secchan *sc, const uint8_t *aad, size_t aad_len,
		       const uint8_t *ct, size_t ct_len, const uint8_t tag[TC_GCM_TAG_LEN],
		       uint8_t *pt)
{
	uint8_t nonce[TC_GCM_NONCE_LEN];
	int rc;

	if (sc->dec_ctr == 0xffffffffu) {
		return -1;
	}
	tc_crypto_gcm_nonce(1, sc->dec_ctr, nonce);
	rc = tc_aes256_gcm_decrypt(sc->dec_key, nonce, sizeof(nonce), aad, aad_len, ct, ct_len,
				      tag, TC_GCM_TAG_LEN, pt);
	if (rc == 0) {
		sc->dec_ctr++;
	}
	return rc;
}

/* ---- credential message security (§11.8): ranging/notification SDUs ---- */

// Derives the two directional BLE ranging-channel session keys (BleSKReader, BleSKDevice) from the
// BleSK segment of a derived key block via HKDF. salt/salt_len is the caller-built ranging-channel
// salt (protocol versions + selected version); ble_sk is read from a fixed offset within block.
// Returns 0 on success, or the first nonzero HKDF return code (ble_reader is left populated even if
// the second derivation for ble_device fails).
int tc_crypto_derive_ble_keys(const uint8_t block[TC_KEY_BLOCK_LEN],
					 const uint8_t *salt, size_t salt_len,
					 uint8_t ble_reader[TC_SESSION_KEY_LEN],
					 uint8_t ble_device[TC_SESSION_KEY_LEN])
{
	const uint8_t *ble_sk = block + TC_BLESK_OFFSET;
	int rc;

	rc = tc_hkdf(salt, salt_len, ble_sk, 32, (const uint8_t *)"BleSKReader", 11, ble_reader,
			TC_SESSION_KEY_LEN);
	if (rc != 0) {
		return rc;
	}
	return tc_hkdf(salt, salt_len, ble_sk, 32, (const uint8_t *)"BleSKDevice", 11,
			  ble_device, TC_SESSION_KEY_LEN);
}

// Seal an engine-plaintext message (4-byte header + payload) into a framed, encrypted wire SDU.
// The header's 2-byte big-endian length field (plain[2..3]) must equal the payload length
// (plain_len - 4); mismatches are rejected. Copies the header's first two bytes unchanged into the
// wire frame, rewrites the length field as payload_len + GCM tag length, then seals the payload
// using the original 4-byte plaintext header as AAD. Requires plain_len >= 4 and wire_cap large
// enough for the framed output (4 + payload_len + GCM tag length); returns -1 on either violation
// or if the underlying seal fails, 0 on success with *wire_len set.
int tc_msg_seal(struct tc_secchan *sc, const uint8_t *plain, size_t plain_len,
			   uint8_t *wire, size_t wire_cap, size_t *wire_len)
{
	if (plain_len < 4u) {
		return -1;
	}
	size_t len_plain = plain_len - 4u;

	if ((((size_t)plain[2] << 8) | plain[3]) != len_plain) {
		return -1; /* header length must equal the actual payload length */
	}
	size_t wl = 4u + len_plain + TC_GCM_TAG_LEN;

	if (wl > wire_cap) {
		return -1;
	}
	uint16_t wlen = (uint16_t)(len_plain + TC_GCM_TAG_LEN);

	wire[0] = plain[0];
	wire[1] = plain[1];
	wire[2] = (uint8_t)(wlen >> 8);
	wire[3] = (uint8_t)(wlen & 0xffu);
	/* AAD = the 4-byte header carrying the PLAINTEXT length (= plain[0..4]). */
	if (tc_secchan_seal(sc, plain, 4u, plain + 4u, len_plain, wire + 4u,
			       wire + 4u + len_plain) != 0) {
		return -1;
	}
	*wire_len = wl;
	return 0;
}

// Represents a secure credential communication channel: a pair of AES-GCM session keys and
// per-direction message counters, used to seal/open messages exchanged with the device.
int tc_msg_open(struct tc_secchan *sc, const uint8_t *wire, size_t wire_len,
			   uint8_t *plain, size_t plain_cap, size_t *plain_len)
{
	if (wire_len < 4u + TC_GCM_TAG_LEN) {
		return -1;
	}
	size_t len_wire = ((size_t)wire[2] << 8) | wire[3];

	if (len_wire + 4u != wire_len || len_wire < TC_GCM_TAG_LEN) {
		return -1;
	}
	size_t len_plain = len_wire - TC_GCM_TAG_LEN;

	if (4u + len_plain > plain_cap) {
		return -1;
	}
	/* AAD = [proto][id][len_plain BE] — the plaintext length, not the wire length. */
	uint8_t aad[4] = {wire[0], wire[1], (uint8_t)(len_plain >> 8),
			  (uint8_t)(len_plain & 0xffu)};

	if (tc_secchan_open(sc, aad, 4u, wire + 4u, len_plain, wire + 4u + len_plain,
			       plain + 4u) != 0) {
		return -1;
	}
	memcpy(plain, aad, 4u);
	*plain_len = 4u + len_plain;
	return 0;
}

/* ---- CreateSalt transcript (provisional layout — see header) ---- */

/* 36-byte domain label, sliced into three 12-byte labels by salt type. The
 * trailing NUL (index 36) is never read: slices span index 0..35. */
static const char k_salt_label[] = "VolatileFastVolatile\x2a\x2a\x2a\x2aPersistent\x2a\x2a";
static const uint8_t k_salt_const[2] = {0x5c, 0x02};

// Appends n bytes from src into out at *pos, bounds-checked against cap.
// Returns 0 on success and advances *pos by n; returns -1 without writing or advancing *pos if the
// append would exceed cap.
static int append(uint8_t *out, size_t *pos, size_t cap, const void *src, size_t n)
{
	if (*pos + n > cap) {
		return -1;
	}
	memcpy(out + *pos, src, n);
	*pos += n;
	return 0;
}

// Build the Aliro §8.3.1.13 salt_volatile byte string for HKDF derivation from its component
// fields. Appends, in fixed order: span_s1, a type-specific 12-byte label, reader_id, the interface
// byte (0xC3 BLE / 0x5E NFC), a fixed salt constant, the big-endian protocol version, reader_value,
// txid, and the (exp_phase_type, user_auth_policy) flag pair. If a5_tlv is non-null and non-empty,
// appends the 0xA5 SELECT-response proprietary-information TLV. If type is not
// TC_SALT_SESSION and s3opt is non-null, appends s3opt last. Writes into out (capacity
// TC_SALT_MAX) and sets *out_len. Returns 0 on success, -1 if any append exceeds
// TC_SALT_MAX.
int tc_salt_build(enum tc_salt_type type,
			     const uint8_t txid[TC_TXID_LEN],
			     const uint8_t span_s1[TC_EC_PUBX_LEN],
			     const uint8_t reader_value[TC_EC_PUBX_LEN],
			     const uint8_t reader_id[32], uint8_t interface_byte,
			     uint16_t proto_version, uint8_t exp_phase_type,
			     uint8_t user_auth_policy,
			     const uint8_t s3opt[TC_EC_PUBX_LEN], const uint8_t *a5_tlv,
			     size_t a5_tlv_len, uint8_t *out, size_t *out_len)
{
	size_t pos = 0;
	uint8_t ver[2] = {(uint8_t)(proto_version >> 8), (uint8_t)proto_version};
	uint8_t policy[2] = {exp_phase_type, user_auth_policy};
	int rc = 0;

	/* Aliro §8.3.1.13 salt_volatile append order. Item 4 = the interface_byte
	 * (0xC3 BLE / 0x5E NFC); item 6 = the protocol version (big-endian); item 9
	 * = the flag (command_parameters || authentication_policy); item 10 = the
	 * 0xA5 SELECT-response proprietary-information TLV (Table 10-2). */
	rc |= append(out, &pos, TC_SALT_MAX, span_s1, TC_EC_PUBX_LEN); /* 1 */
	rc |= append(out, &pos, TC_SALT_MAX, k_salt_label + (size_t)type * 12u, 12); /* 2 */
	rc |= append(out, &pos, TC_SALT_MAX, reader_id, 32);                         /* 3 */
	rc |= append(out, &pos, TC_SALT_MAX, &interface_byte, 1);                    /* 4 */
	rc |= append(out, &pos, TC_SALT_MAX, k_salt_const, sizeof(k_salt_const));    /* 5 */
	rc |= append(out, &pos, TC_SALT_MAX, ver, sizeof(ver));                      /* 6 */
	rc |= append(out, &pos, TC_SALT_MAX, reader_value,
		     TC_EC_PUBX_LEN);                                       /* 7 */
	rc |= append(out, &pos, TC_SALT_MAX, txid, TC_TXID_LEN); /* 8 */
	rc |= append(out, &pos, TC_SALT_MAX, policy, sizeof(policy));                /* 9 */
	if (a5_tlv != NULL && a5_tlv_len > 0) {                                         /* 10 */
		rc |= append(out, &pos, TC_SALT_MAX, a5_tlv, a5_tlv_len);
	}
	if (type != TC_SALT_SESSION && s3opt != NULL) { /* 11 */
		rc |= append(out, &pos, TC_SALT_MAX, s3opt, TC_EC_PUBX_LEN);
	}
	if (rc != 0) {
		return -1;
	}
	*out_len = pos;
	return 0;
}
