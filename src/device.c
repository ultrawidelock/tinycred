// credential initiator (User-Device) session machine: the implementation behind
// tc_device.h. Feeds one reader command at a time through
// tc_device_on_command, which parses AUTH0/AUTH1/EXCHANGE with the inverse
// codec, runs the mirror of the reader's key schedule (ephemeral ECDH, the two
// ECDSA transcripts, the session salt) and returns the sealed response. Owns the
// two AES-256-GCM channels the device holds, the Access-Protocol channel and the
// BleSK ranging channel, both split out of the same 160-byte key block, plus the
// standard-path derivation factored EC-free so host tests can drive it with a
// supplied shared secret.
/*
 * credential initiator (User-Device) session layer. See tc_device.h. Mirrors the
 * reader flow in tc_reader.c: the reader builds AUTH0/AUTH1/EXCHANGE commands
 * and verifies the device; here the device parses them and proves itself, running
 * the same §8.3.1.13 key schedule to the same URSK.
 */
#include "tinycred/device.h"

#include <string.h>

/* tc_apdu_build_authdata, TC_AUTH_*, INS/TAG */
#include "tinycred/apdu.h"
#include "tinycred/crypto.h" /* z / salt / block / split / gcm nonce */
#include "tinycred/prim.h"   /* EC + AES-GCM primitives */

/* Protocol v1.0 only, matching the reader's TC_VERSION. Feeds the salt as the
 * protocol_version field (§8.3.1.13), which the reader hardcodes to 0x0100. */
#define TC_DEV_VERSION 0x0100u

/* CSA-app, protocol v1.0-only 0xA5 proprietary-info TLV (Aliro Table 10-2), the
 * salt's trailing field. Identical to the reader's k_a5_csa_v1 fallback; a live
 * device sends its own in the op-0x05 Initiate-Access-Protocol message. */
static const uint8_t k_a5_csa_v1[] = {
	0xa5, 0x08, 0x80, 0x02, 0x00, 0x00, 0x5c, 0x02, 0x01, 0x00,
};

/* ---- device AES-256-GCM channel (mirror direction of tc_secchan) ---- */

/**
 * Initialize a secure channel with two keys and both counters to 1 (per §8.3.1.13).
 */
void tc_dev_secchan_init(struct tc_dev_secchan *sc, const uint8_t s0[32],
			    const uint8_t s1[32])
{
	memcpy(sc->s0, s0, 32);
	memcpy(sc->s1, s1, 32);
	sc->ctr_r2d = 1; /* §8.3.1.13: both directions start at 1 */
	sc->ctr_d2r = 1;
}

/**
 * AES-256-GCM decrypt one reader->device message: derive nonce from counter, decrypt and verify
 * tag, increment counter, return 0 on success or -1 on tag mismatch.
 */
int tc_dev_secchan_open(struct tc_dev_secchan *sc, const uint8_t *ct,
				   size_t ct_len, const uint8_t tag[16], uint8_t *pt)
{
	uint8_t nonce[TC_GCM_NONCE_LEN];

	tc_crypto_gcm_nonce(0, sc->ctr_r2d, nonce); /* direction 0 = reader->device */
	if (tc_aes256_gcm_decrypt(sc->s0, nonce, TC_GCM_NONCE_LEN, NULL, 0,
					     ct, ct_len, tag, TC_GCM_TAG_LEN, pt) != 0) {
		return -1;
	}
	sc->ctr_r2d++;
	return 0;
}

/**
 * AES-256-GCM encrypt one device->reader message: derive nonce from counter, encrypt and compute
 * tag, increment counter, return 0 on success or -1 on error.
 */
int tc_dev_secchan_seal(struct tc_dev_secchan *sc, const uint8_t *pt,
				   size_t pt_len, uint8_t *ct, uint8_t tag[16])
{
	uint8_t nonce[TC_GCM_NONCE_LEN];

	tc_crypto_gcm_nonce(1, sc->ctr_d2r, nonce); /* direction 1 = device->reader */
	if (tc_aes256_gcm_encrypt(sc->s1, nonce, TC_GCM_NONCE_LEN, NULL, 0,
					     pt, pt_len, ct, tag, TC_GCM_TAG_LEN) != 0) {
		return -1;
	}
	sc->ctr_d2r++;
	return 0;
}

/* ---- device BleSK ranging channel (mirror of the reader's sc_ble) ----
 *
 * Same GCM construction as the AP channel, but each SDU carries the reader's
 * tc_msg_seal/open framing: a 4-byte [proto][id][len_be16] header (wire length
 * = payload + 16) authenticated as AAD. s0 = BleSKReader (open, dir 0), s1 =
 * BleSKDevice (seal, dir 1). Byte-for-byte inverse of
 * tc_msg_seal/tc_msg_open.
 */

/**
 * Initialize a BLE secure channel by deriving session keys from a key block and versions salt, then
 * initializing the channel with both keys.
 */
int tc_dev_blesk_init(struct tc_dev_secchan *ch,
				 const uint8_t block[TC_KEY_BLOCK_LEN],
				 const uint8_t *versions_salt, size_t salt_len)
{
	uint8_t ble_reader[TC_SESSION_KEY_LEN], ble_device[TC_SESSION_KEY_LEN];

	if (tc_crypto_derive_ble_keys(block, versions_salt, salt_len, ble_reader, ble_device) !=
	    0) {
		return -1;
	}
	tc_dev_secchan_init(ch, ble_reader, ble_device);
	return 0;
}

/**
 * Decrypt one BLE-SK wire frame (reader->device direction): validate length header, derive nonce,
 * decrypt payload under S0 with AAD, increment counter, copy plaintext and return 0 on success or
 * -1 on length/tag error.
 */
int tc_dev_ble_open(struct tc_dev_secchan *ch, const uint8_t *wire,
			       size_t wire_len, uint8_t *plain, size_t plain_cap, size_t *plain_len)
{
	uint8_t nonce[TC_GCM_NONCE_LEN];

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
	/* AAD = [proto][id][len_plain BE] — the plaintext-length header. */
	uint8_t aad[4] = {wire[0], wire[1], (uint8_t)(len_plain >> 8),
			  (uint8_t)(len_plain & 0xffu)};

	tc_crypto_gcm_nonce(0, ch->ctr_r2d, nonce); /* direction 0 = reader->device */
	if (tc_aes256_gcm_decrypt(ch->s0, nonce, TC_GCM_NONCE_LEN, aad, sizeof(aad),
				     wire + 4u, len_plain, wire + 4u + len_plain, TC_GCM_TAG_LEN,
				     plain + 4u) != 0) {
		return -1;
	}
	memcpy(plain, aad, sizeof(aad));
	*plain_len = 4u + len_plain;
	ch->ctr_r2d++;
	return 0;
}

/**
 * Encrypt one BLE-SK wire frame (device->reader direction): validate plaintext length header,
 * derive nonce, encrypt payload under S1 with AAD, write wire length header, increment counter,
 * return 0 on success or -1 on length/tag error.
 */
int tc_dev_ble_seal(struct tc_dev_secchan *ch, const uint8_t *plain,
			       size_t plain_len, uint8_t *wire, size_t wire_cap, size_t *wire_len)
{
	uint8_t nonce[TC_GCM_NONCE_LEN];

	if (plain_len < 4u) {
		return -1;
	}
	size_t len_plain = plain_len - 4u;

	if ((((size_t)plain[2] << 8) | plain[3]) != len_plain) {
		return -1; /* header length must equal the payload length */
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
	tc_crypto_gcm_nonce(1, ch->ctr_d2r, nonce); /* direction 1 = device->reader */
	if (tc_aes256_gcm_encrypt(
		    ch->s1, nonce, TC_GCM_NONCE_LEN, plain, 4u, plain + 4u, len_plain,
		    wire + 4u, wire + 4u + len_plain, TC_GCM_TAG_LEN) != 0) {
		return -1;
	}
	*wire_len = wl;
	ch->ctr_d2r++;
	return 0;
}

/**
 * AES-256-GCM encrypt with all-zero 12-byte IV and no AAD; plaintext and ciphertext lengths must
 * match.
 */
int tc_dev_seal_cryptogram(const uint8_t cryptogram_sk[32], const uint8_t *plain,
			      size_t plain_len, uint8_t *out)
{
	uint8_t iv[TC_GCM_NONCE_LEN] = {0}; /* §8.3.1.11: 12-byte all-zero IV, no AAD */

	return tc_aes256_gcm_encrypt(cryptogram_sk, iv, TC_GCM_NONCE_LEN,
						NULL, 0, plain, plain_len, out, out + plain_len,
						TC_GCM_TAG_LEN);
}

/**
 * Derive a session key block, URSK, and secure channel from an ECDH shared secret, transaction ID,
 * and reader identity by building a salt, deriving the block, and splitting keys; returns 0 on
 * success.
 */
int tc_device_derive_session(const uint8_t shared_x[32], const uint8_t txid[16],
				const uint8_t reader_group_x[32], const uint8_t reader_eph_x[32],
				const uint8_t reader_id[32], uint8_t exp_phase, const uint8_t *a5,
				size_t a5n, const uint8_t device_eph_x[32],
				struct tc_dev_secchan *sc, uint8_t ursk[32],
				uint8_t block_out[TC_KEY_BLOCK_LEN])
{
	uint8_t z[32], salt[TC_SALT_MAX], block[TC_KEY_BLOCK_LEN];
	uint8_t enc[TC_SESSION_KEY_LEN], dec[TC_SESSION_KEY_LEN];
	size_t slen;

	tc_crypto_derive_z(shared_x, txid, z);
	if (tc_salt_build(TC_SALT_SESSION, txid, reader_group_x, reader_eph_x,
				     reader_id, TC_IFACE_BLE, TC_DEV_VERSION,
				     exp_phase, 0x01u, NULL, a5, a5n, salt, &slen) != 0) {
		return -1;
	}
	if (tc_crypto_derive_block(z, salt, slen, device_eph_x, block) != 0) {
		return -1;
	}
	/* with_c=1: enc=S0 (reader->device), dec=S1 (device->reader), URSK=S4. The
	 * device channel opens on s0 and seals on s1 (mirror of the reader). */
	tc_crypto_split(block, 1, enc, dec, ursk);
	tc_dev_secchan_init(sc, enc, dec);
	if (block_out != NULL) {
		memcpy(block_out, block, TC_KEY_BLOCK_LEN);
	}
	return 0;
}

/* ---- full initiator state machine (EC via tc_prim) ---- */

/**
 * Initialize device with access credential, reader identity and verification key; derive public key
 * from private scalar; set version to v1.0, BLE-SK salt to v1.0 single-version default, and phase
 * to idle. Return 0 on success or -1 if public key derivation fails.
 */
int tc_device_init(struct tc_device *d, const uint8_t cred_priv[32],
		      const uint8_t reader_id[32], const uint8_t reader_verif_pub[65])
{
	memset(d, 0, sizeof(*d));
	memcpy(d->cred_priv, cred_priv, 32);
	if (tc_ec_p256_pub_from_priv(d->cred_priv, d->cred_pub) != 0) {
		return -1;
	}
	memcpy(d->reader_id, reader_id, 32);
	memcpy(d->reader_verif_pub, reader_verif_pub, 65);
	memcpy(d->reader_group_x, reader_verif_pub + 1, 32);
	d->a5 = k_a5_csa_v1;
	d->a5n = sizeof(k_a5_csa_v1);
	d->version = TC_DEV_VERSION;
	/* Default salt for a peer that publishes v1.0 and nothing else: the list half
	 * and the selected half are both TC_DEV_VERSION. Correct against our ESP32
	 * reader, wrong against any multi-version peer — see the struct field. */
	d->blesk_salt[0] = (uint8_t)(TC_DEV_VERSION >> 8);
	d->blesk_salt[1] = (uint8_t)(TC_DEV_VERSION & 0xffu);
	d->blesk_salt[2] = d->blesk_salt[0];
	d->blesk_salt[3] = d->blesk_salt[1];
	d->blesk_salt_len = 4;
	d->phase = TC_DEV_IDLE;
	return 0;
}

/**
 * Set BLE-SK salt from big-endian u16 list; must be even length (at least 4 bytes) and fit in
 * buffer; return 0 on success or -1 if length or format is invalid.
 */
int tc_device_set_blesk_salt(struct tc_device *d, const uint8_t *salt,
					size_t len)
{
	/* Every entry is a big-endian u16 and the selected version is always appended,
	 * so a usable salt is even and holds at least two of them. */
	if (d == NULL || salt == NULL || len < 4u || (len & 1u) != 0u ||
	    len > TC_DEV_BLESK_SALT_MAX) {
		return -1;
	}
	memcpy(d->blesk_salt, salt, len);
	d->blesk_salt_len = len;
	return 0;
}

/**
 * Process an incoming credential APDU command (AUTH0, AUTH1, or EXCHANGE) and generate the
 * response. Validates command structure, reader identity, signatures, and key derivation; returns 0
 * on success and sets device phase accordingly. On any failure sets phase to
 * TC_DEV_FAILED and returns -1.
 */
int tc_device_on_command(struct tc_device *d, const uint8_t *ap_payload,
				    size_t len, uint8_t *resp, size_t cap, size_t *resp_len)
{
	uint8_t ins;
	const uint8_t *data;
	size_t dlen;

	if (tc_apdu_unwrap(ap_payload, len, &ins, &data, &dlen) != 0) {
		goto fail;
	}

	switch (ins) {
	case TC_INS_AUTH0: {
		struct tc_auth0_command c;

		if (tc_dev_parse_auth0_cmd(data, dlen, &c) != 0) {
			goto fail;
		}
		if (memcmp(c.reader_id, d->reader_id, 32) != 0) {
			goto fail; /* not the reader we are provisioned to */
		}
		memcpy(d->reader_eph_pub, c.reader_eph_pub, 65);
		memcpy(d->txid, c.txid, 16);
		d->exp_phase = c.exp_phase;
		if (tc_ec_p256_keygen(d->dev_eph_priv, d->dev_eph_pub) != 0) {
			goto fail;
		}

		size_t n = 0;

		if (tc_dev_build_auth0_resp(d->dev_eph_pub, NULL, resp, cap, &n) != 0 ||
		    tc_apdu_append_sw(resp, &n, cap, 0x9000u) != 0) {
			goto fail;
		}
		*resp_len = n;
		d->phase = TC_DEV_SENT_AUTH0_RESP;
		return 0;
	}
	case TC_INS_AUTH1: {
		struct tc_auth1_command c;
		uint8_t td[160], shared[TC_SHARED_SECRET_LEN], sig[TC_P256_SIG];
		uint8_t plain[160], tag[TC_GCM_TAG_LEN];
		uint8_t block[TC_KEY_BLOCK_LEN];
		size_t tn, pl;

		if (tc_dev_parse_auth1_cmd(data, dlen, &c) != 0) {
			goto fail;
		}
		/* Verify the reader over the reader-usage transcript (device pubX, reader-eph
		 * pubX) with the provisioned reader verification key. */
		if (tc_apdu_build_authdata(TC_AUTH_READER, d->reader_id, d->dev_eph_pub + 1,
					      d->reader_eph_pub + 1, d->txid, td, sizeof(td),
					      &tn) != 0 ||
		    tc_ecdsa_p256_verify(d->reader_verif_pub, td, tn, c.reader_sig) != 0) {
			goto fail;
		}
		/* ECDH + the mirror-image session derivation -> URSK + AP channel. */
		if (tc_ecdh_p256(d->dev_eph_priv, d->reader_eph_pub, shared) != 0 ||
		    tc_device_derive_session(shared, d->txid, d->reader_group_x,
						d->reader_eph_pub + 1, d->reader_id, d->exp_phase,
						d->a5, d->a5n, d->dev_eph_pub + 1, &d->sc, d->ursk,
						block) != 0) {
			goto fail;
		}
		/* Same block feeds the BleSK ranging channel (§11.8.1), which must be up
		 * before the reader's AP-Completed arrives — that SDU is the first thing
		 * sealed under it. Salt = reader_supported_versions || selected_version,
		 * which is the PEER's published list and so cannot be a constant:
		 * tc_device_init defaults it to the v1.0-only 01 00 01 00 and a
		 * transport that read the peer's GATT list overrides it. A zero length
		 * means the struct was cleared behind init's back; fail here rather than
		 * derive a key the peer does not share. */
		if (d->blesk_salt_len == 0u ||
		    tc_dev_blesk_init(&d->sc_ble, block, d->blesk_salt, d->blesk_salt_len) !=
			    0) {
			goto fail;
		}
		/* Sign the device-usage transcript with the credential key, then build +
		 * seal the AUTH1Response (device signature + presented credential key). */
		if (tc_apdu_build_authdata(TC_AUTH_DEVICE, d->reader_id, d->dev_eph_pub + 1,
					      d->reader_eph_pub + 1, d->txid, td, sizeof(td),
					      &tn) != 0 ||
		    tc_ecdsa_p256_sign(d->cred_priv, td, tn, sig) != 0 ||
		    tc_dev_build_auth1_resp(sig, d->cred_pub, plain, sizeof(plain), &pl) != 0) {
			goto fail;
		}
		if (cap < pl + TC_GCM_TAG_LEN + 2u ||
		    tc_dev_secchan_seal(&d->sc, plain, pl, resp, tag) != 0) {
			goto fail;
		}
		memcpy(resp + pl, tag, TC_GCM_TAG_LEN);

		size_t n = pl + TC_GCM_TAG_LEN;

		if (tc_apdu_append_sw(resp, &n, cap, 0x9000u) != 0) {
			goto fail;
		}
		*resp_len = n;
		d->phase = TC_DEV_SENT_AUTH1_RESP;
		return 0;
	}
	case TC_INS_EXCHANGE: {
		uint8_t pt[64], plain[8], tag[TC_GCM_TAG_LEN];
		struct tc_exchange_command ec;
		size_t pl;

		if (dlen < TC_GCM_TAG_LEN) {
			goto fail;
		}

		size_t ctlen = dlen - TC_GCM_TAG_LEN;

		if (ctlen > sizeof(pt) ||
		    tc_dev_secchan_open(&d->sc, data, ctlen, data + ctlen, pt) != 0) {
			goto fail;
		}
		tc_dev_parse_exchange_cmd(pt, ctlen, &ec); /* URSK-ready trigger */

		if (tc_dev_build_exchange_resp(0x0000u, plain, sizeof(plain), &pl) != 0) {
			goto fail;
		}
		if (cap < pl + TC_GCM_TAG_LEN + 2u ||
		    tc_dev_secchan_seal(&d->sc, plain, pl, resp, tag) != 0) {
			goto fail;
		}
		memcpy(resp + pl, tag, TC_GCM_TAG_LEN);

		size_t n = pl + TC_GCM_TAG_LEN;

		if (tc_apdu_append_sw(resp, &n, cap, 0x9000u) != 0) {
			goto fail;
		}
		*resp_len = n;
		d->phase = TC_DEV_ESTABLISHED;
		return 0;
	}
	default:
		break;
	}

fail:
	d->phase = TC_DEV_FAILED;
	return -1;
}
