/* SPDX-FileCopyrightText: 2026 Aseem Chopra */
/* SPDX-License-Identifier: Apache-2.0 */

// credential crypto public API: key derivation, AES-GCM secure channels, and wire message
// seal/open framing shared by the reader and device sides of a credential session.
/*
 * tc_crypto — the credential-auth cryptography for the credential reader: the
 * P-256 / AES-256-GCM / SHA-256 suite and the key-derivation schedule that
 * turns a passed credential authentication into the 32-byte URSK (the UWB
 * ranging root) plus the secure-channel keys.
 *
 * This is Phase 3.1: the primitives and the key schedule. The transaction state
 * machine that drives it (AUTH0/AUTH1, EXCHANGE) is 3.2; the handoff of the URSK
 * into tc_uwb_start_cred(cfg) is 3.3.
 */
#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TC_URSK_LEN          32u
#define TC_KEY_BLOCK_LEN     160u /* full derived block */
#define TC_URSK_OFFSET       128u /* URSK = block[128 .. 159] */
#define TC_SESSION_KEY_LEN   32u
#define TC_SHARED_SECRET_LEN 32u /* ECDH X coordinate */
#define TC_TXID_LEN          16u
#define TC_EC_PUBX_LEN       32u /* an EC point's X coordinate */
#define TC_GCM_NONCE_LEN     12u
#define TC_GCM_TAG_LEN       16u

/* interface_byte for the salt transcript (Aliro §8.3.1.13): the transport the
 * transaction runs on. BLE for the reader's live path; NFC for the §14 example. */
#define TC_IFACE_NFC 0x5Eu
#define TC_IFACE_BLE 0xC3u

/* Initialise the crypto backend (idempotent). 0 on success, negative on fail. */
int tc_crypto_init(void);

/* Extract the 32-byte URSK from the derived 160-byte key block. */
void tc_crypto_ursk_from_block(const uint8_t block[TC_KEY_BLOCK_LEN],
				  uint8_t ursk[TC_URSK_LEN]);

/*
 * ---- Credential-auth key schedule (standard/ECDH path) -------------------
 *
 * Stage 1: Z = SHA-256( shared_secret(32) | 0x00000001 | txid(16) ), the
 * single-block ANSI-X9.63 concat KDF over the raw ECDH shared secret. Z is the
 * IKM for every stage-2 HKDF.
 */
void tc_crypto_derive_z(const uint8_t shared_secret[TC_SHARED_SECRET_LEN],
			   const uint8_t txid[TC_TXID_LEN], uint8_t z[32]);

/*
 * Stage 2: block = HKDF-SHA256(salt, IKM=z, info=device_pub_x(32), L=160). The
 * salt is the CreateSalt transcript (tc_salt_build). Returns 0 on success.
 */
int tc_crypto_derive_block(const uint8_t z[32], const uint8_t *salt, size_t salt_len,
			      const uint8_t device_pub_x[TC_EC_PUBX_LEN],
			      uint8_t block[TC_KEY_BLOCK_LEN]);

/*
 * Single 32-byte keyed derivation off z: Kpersistent (salt type 2) and the
 * Auth1 cryptogram key (salt type 0) both use this, differing only in the salt.
 * block = HKDF-SHA256(salt, IKM=z, info=device_pub_x, L=32). Returns 0 on ok.
 */
int tc_crypto_derive_key32(const uint8_t z[32], const uint8_t *salt, size_t salt_len,
			      const uint8_t device_pub_x[TC_EC_PUBX_LEN], uint8_t out[32]);

/*
 * Split the 160-byte block into the two directional session keys + URSK. The
 * reference derives up to two optional "shared" keys (C/D) alongside; a config
 * flag shifts which segments are the symmetric keys. with_c=1: enc=S0, dec=S1;
 * with_c=0: enc=S1, dec=S2 (S0 unused). URSK = S4 (offset 128) either way.
 */
void tc_crypto_split(const uint8_t block[TC_KEY_BLOCK_LEN], int with_c,
			uint8_t enc_key[TC_SESSION_KEY_LEN],
			uint8_t dec_key[TC_SESSION_KEY_LEN], uint8_t ursk[TC_URSK_LEN]);

/*
 * ---- Expedited-fast phase (§8.1.1.2, §8.3.1.10/.11/.12) ------------------
 *
 * The fast phase skips ECDH and the two signatures: the User Device proves it
 * holds a Kpersistent (agreed during an earlier expedited-standard phase) by
 * returning a cryptogram the Reader verifies by trial against each stored
 * Kpersistent. No new derivation code is needed — the fast key material reuses
 * the standard primitives with different inputs:
 *
 *   Kpersistent (during the standard phase, per §8.3.1.13):
 *     tc_crypto_derive_key32(IKM = Kdh, salt = salt_persistent, info =
 *     credential_ephemeral_pub_x) -> 32 bytes. salt_persistent is tc_salt_build
 *     type TC_SALT_KPERSISTENT, which appends the Access Credential public-key X.
 *
 *   Fast block (per §8.3.1.12):
 *     tc_crypto_derive_block(IKM = Kpersistent, salt = salt_fast, info =
 *     credential_ephemeral_pub_x) -> 160 bytes. salt_fast is tc_salt_build type
 *     TC_SALT_CRYPTOGRAM ("VolatileFast"), also appending the credential pub-key X.
 *
 * The fast block's layout differs from the standard block only in the first 96
 * bytes: CryptogramSK@0, ExpeditedSKReader@32, ExpeditedSKDevice@64, BleSK@96,
 * URSK@128. So BleSK (tc_crypto_derive_ble_keys) and URSK (offset 128) come
 * out exactly as in the standard block, and tc_crypto_split(block, 0, ...)
 * yields ExpeditedSKReader (enc) / ExpeditedSKDevice (dec). CryptogramSK is the
 * leading 32 bytes.
 */
#define TC_CRYPTOGRAM_SK_OFFSET 0u  /* CryptogramSK = fast_block[0 .. 31] */
#define TC_CRYPTOGRAM_LEN 64u /* AUTH0 response tag 0x9D: enc_payload(48) || tag(16) */

/* Verify an AUTH0 fast-phase cryptogram (§8.3.1.11): AES-256-GCM open of
 * cryptogram = encrypted_payload || 16-byte tag under CryptogramSK, with a
 * 12-byte all-zero IV and no AAD. On a tag match, writes (cryptogram_len - 16)
 * plaintext bytes to plain_payload and returns 0; returns <0 on a mismatch,
 * meaning this Kpersistent is not the one (the caller tries the next). The
 * caller must size plain_payload to at least cryptogram_len - 16 bytes. */
int tc_crypto_verify_cryptogram(
	const uint8_t cryptogram_sk[TC_SESSION_KEY_LEN], const uint8_t *cryptogram,
	size_t cryptogram_len, uint8_t *plain_payload);

/*
 * ---- Secure channel (AES-256-GCM, directional per-message counters) ------
 *
 * Nonce = 8-byte big-endian direction (0 outbound/seal, 1 inbound/open) followed
 * by a 4-byte big-endian per-direction counter. Separate seal/open counters,
 * start at 0, no wrap. SessionCrypto sends no AAD; the BLE channel authenticates
 * a 4-byte AAD (caller-supplied here).
 */
struct tc_secchan {
	uint8_t enc_key[TC_SESSION_KEY_LEN];
	uint8_t dec_key[TC_SESSION_KEY_LEN];
	uint32_t enc_ctr;
	uint32_t dec_ctr;
};

void tc_secchan_init(struct tc_secchan *sc,
				const uint8_t enc_key[TC_SESSION_KEY_LEN],
				const uint8_t dec_key[TC_SESSION_KEY_LEN]);
void tc_crypto_gcm_nonce(uint64_t direction, uint32_t counter,
			    uint8_t nonce[TC_GCM_NONCE_LEN]);
/* Seal/open advance the matching counter on success. Return 0 on success;
 * open returns <0 on a tag mismatch (hard auth failure) — never trust the
 * plaintext then. */
int tc_secchan_seal(struct tc_secchan *sc, const uint8_t *aad, size_t aad_len,
		       const uint8_t *pt, size_t pt_len, uint8_t *ct,
		       uint8_t tag[TC_GCM_TAG_LEN]);
int tc_secchan_open(struct tc_secchan *sc, const uint8_t *aad, size_t aad_len,
		       const uint8_t *ct, size_t ct_len, const uint8_t tag[TC_GCM_TAG_LEN],
		       uint8_t *pt);

/*
 * ---- credential message security (§11.8): ranging/notification SDUs -----------
 *
 * Proto-1/2/3 SDUs (UWB Ranging Service M1-M4, Notification, Supplementary) ride
 * a SEPARATE AES-256-GCM channel from the AP secure channel: BleSKReader/
 * BleSKDevice keys (HKDF off BleSK = block offset 96), fresh per-direction
 * counters starting at 1, and the 4-byte header (with the PLAINTEXT payload
 * length) as AAD. Wire form: [proto][id][len_be16][encrypted_payload||16B tag],
 * where len_be16 = plaintext length + 16. Reuse struct tc_secchan for it
 * (enc=BleSKReader, dec=BleSKDevice; tc_secchan_init sets both counters to 1).
 */
#define TC_BLESK_OFFSET 96u /* BleSK = block[96 .. 127] (§8.3.1.12/.13) */

/* Derive BleSKReader + BleSKDevice from the 160-byte block per §11.8.1:
 * HKDF-SHA256(ikm=BleSK, info="BleSKReader"/"BleSKDevice", L=32,
 * salt = reader_supported_versions || user_device_selected_version). 0 on ok. */
int tc_crypto_derive_ble_keys(const uint8_t block[TC_KEY_BLOCK_LEN],
					 const uint8_t *salt, size_t salt_len,
					 uint8_t ble_reader[TC_SESSION_KEY_LEN],
					 uint8_t ble_device[TC_SESSION_KEY_LEN]);

/* Seal an engine plaintext message [proto][id][len_plain_be16][payload] into the
 * on-wire [proto][id][(len_plain+16)_be16][ct||tag], sealed under sc with the
 * 4-byte plaintext-length header as AAD (§11.8.2). *wire_len set on 0-return. */
int tc_msg_seal(struct tc_secchan *sc, const uint8_t *plain, size_t plain_len,
			   uint8_t *wire, size_t wire_cap, size_t *wire_len);

/* Inverse of tc_msg_seal: open a wire SDU into the engine plaintext form,
 * verifying the tag. Returns <0 on a tag mismatch (drop the connection then). */
int tc_msg_open(struct tc_secchan *sc, const uint8_t *wire, size_t wire_len,
			   uint8_t *plain, size_t plain_cap, size_t *plain_len);

/*
 * ---- CreateSalt transcript builder --------------------------------------
 *
 * Builds the stage-2 HKDF salt byte-exact to Aliro §8.3.1.13 (salt_volatile for
 * the SESSION/standard type):
 *   span_s1(reader_group_identifier_key.x, 32) || label(12) || reader_id(32) ||
 *   interface_byte(1) || 0x5C || 0x02 || protocol_version(2) ||
 *   reader_value(reader ephemeral pub X, 32) || txid(16) ||
 *   flag(exp_phase_type||user_auth_policy, 2) || a5_tlv(0xA5 proprietary info).
 * For the fast/persistent types a trailing s3opt (Access Credential public key X)
 * follows the a5_tlv. Returns 0 on success and the assembled length in *out_len.
 */
enum tc_salt_type {
	TC_SALT_CRYPTOGRAM = 0, /* label "VolatileFast" */
	TC_SALT_SESSION = 1,    /* label "Volatile****" */
	TC_SALT_KPERSISTENT = 2 /* label "Persistent**" */
};

#define TC_SALT_MAX 256u

int tc_salt_build(enum tc_salt_type type,
			     const uint8_t txid[TC_TXID_LEN],
			     const uint8_t span_s1[TC_EC_PUBX_LEN],
			     const uint8_t reader_value[TC_EC_PUBX_LEN],
			     const uint8_t reader_id[32], uint8_t interface_byte,
			     uint16_t proto_version, uint8_t exp_phase_type,
			     uint8_t user_auth_policy,
			     const uint8_t s3opt[TC_EC_PUBX_LEN] /* NULL for type 1 */,
			     const uint8_t *a5_tlv, size_t a5_tlv_len, uint8_t *out,
			     size_t *out_len);

#ifdef __cplusplus
}
#endif
