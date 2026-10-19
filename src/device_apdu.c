// Implementation of the device-side Access-Protocol wire codec declared in
// tc_device_apdu.h: ISO7816 case-4 unwrapping, status-word appending, parsers
// for the reader's AUTH0, AUTH1 and EXCHANGE command TLVs, and builders for the
// three device responses. Every function is bounds-checked byte manipulation over
// caller-owned buffers with no allocation, so it round-trips against the reader's
// own builders and parsers in tc_apdu.c under the host tests.
/*
 * Device-side credential Access-Protocol wire codec. See tc_device_apdu.h.
 */
#include "tinycred/device_apdu.h"

#include <string.h>

/**
 * Extract the instruction byte and data payload from a 5-byte ISO 7816 case-4 short-form APDU with
 * CLA 0x80, returning 0 on success or -1 if the APDU is malformed.
 */
int tc_apdu_unwrap(const uint8_t *apdu, size_t len, uint8_t *ins, const uint8_t **data,
		      size_t *data_len)
{
	/* ISO7816 case-4 short form: CLA INS P1 P2 Lc <data> [Le]. */
	if (apdu == NULL || len < 5u || apdu[0] != 0x80u) {
		return -1;
	}
	size_t lc = apdu[4];

	if (5u + lc > len) {
		return -1; /* Lc runs past the buffer */
	}
	if (ins) {
		*ins = apdu[1];
	}
	*data = apdu + 5;
	*data_len = lc;
	return 0;
}

/**
 * Append a 2-byte big-endian status code to the output buffer and increment its length, returning 0
 * on success or -1 if the buffer is full.
 */
int tc_apdu_append_sw(uint8_t *buf, size_t *len, size_t cap, uint16_t sw)
{
	if (*len + 2u > cap) {
		return -1;
	}
	buf[*len] = (uint8_t)(sw >> 8);
	buf[*len + 1] = (uint8_t)sw;
	*len += 2u;
	return 0;
}

/**
 * Parse the TLV fields of an AUTH0 command into the struct: extract and validate the phase, user
 * policy, version, reader ephemeral public key, transaction ID, and reader ID.
 */
int tc_dev_parse_auth0_cmd(const uint8_t *tlv, size_t len,
				      struct tc_auth0_command *c)
{
	const uint8_t *v;
	size_t vl;

	memset(c, 0, sizeof(*c));

	if (tc_tlv_find(tlv, len, TC_TAG_EXP_PHASE, &v, &vl) != 0 || vl != 1) {
		return -1;
	}
	c->exp_phase = v[0];
	if (tc_tlv_find(tlv, len, TC_TAG_USER_POL, &v, &vl) != 0 || vl != 1) {
		return -1;
	}
	c->user_policy = v[0];
	if (tc_tlv_find(tlv, len, TC_TAG_VERSION, &v, &vl) != 0 || vl != 2) {
		return -1;
	}
	c->version = (uint16_t)((uint16_t)v[0] << 8 | v[1]);
	if (tc_tlv_find(tlv, len, TC_TAG_READER_EPH, &v, &vl) != 0 || vl != 65) {
		return -1;
	}
	memcpy(c->reader_eph_pub, v, 65);
	if (tc_tlv_find(tlv, len, TC_TAG_TXID, &v, &vl) != 0 || vl != 16) {
		return -1;
	}
	memcpy(c->txid, v, 16);
	if (tc_tlv_find(tlv, len, TC_TAG_READER_ID, &v, &vl) != 0 || vl != 32) {
		return -1;
	}
	memcpy(c->reader_id, v, 32);
	return 0;
}

/**
 * Parse the TLV fields of an AUTH1 command into the struct: extract the credential type if present
 * and the mandatory 64-byte reader signature.
 */
int tc_dev_parse_auth1_cmd(const uint8_t *tlv, size_t len,
				      struct tc_auth1_command *c)
{
	const uint8_t *v;
	size_t vl;

	memset(c, 0, sizeof(*c));
	if (tc_tlv_find(tlv, len, TC_TAG_EXP_PHASE, &v, &vl) == 0 && vl == 1) {
		c->cred_type = v[0];
	}
	if (tc_tlv_find(tlv, len, TC_TAG_SIG, &v, &vl) != 0 || vl != 64) {
		return -1; /* reader signature is mandatory, exactly 64 */
	}
	memcpy(c->reader_sig, v, 64);
	return 0;
}

/**
 * Parse optional TLV fields from an EXCHANGE command plaintext: extract reader status and
 * URSK-ready flag if present, leaving unset fields at their default values.
 */
int tc_dev_parse_exchange_cmd(const uint8_t *plain, size_t len,
					 struct tc_exchange_command *c)
{
	const uint8_t *v;
	size_t vl;

	memset(c, 0, sizeof(*c));
	if (tc_tlv_find(plain, len, TC_TAG_STATUS, &v, &vl) == 0 && vl == 2) {
		c->have_status = 1;
		c->reader_status = (uint16_t)((uint16_t)v[0] << 8 | v[1]);
	}
	if (tc_tlv_find(plain, len, TC_TAG_URSK_READY, &v, &vl) == 0) {
		c->ursk_ready = 1;
	}
	return 0;
}

/**
 * Build a TLV-encoded AUTH0 response containing the device ephemeral public key and optionally a
 * 64-byte cryptogram.
 */
int tc_dev_build_auth0_resp(const uint8_t device_eph_pub[65],
				       const uint8_t *cryptogram64, uint8_t *out, size_t cap,
				       size_t *out_len)
{
	struct tc_tlv_w w;

	tc_tlv_w_init(&w, out, cap);
	tc_tlv_put(&w, TC_TAG_DEVICE_PUBX, device_eph_pub, 65);
	if (cryptogram64) {
		tc_tlv_put(&w, 0x9Du, cryptogram64, 64);
	}
	return tc_tlv_w_finish(&w, out_len);
}

/**
 * Build a TLV-encoded AUTH1 response containing the device signature and optionally the device
 * public key.
 */
int tc_dev_build_auth1_resp(const uint8_t device_sig[64], const uint8_t *device_pub65,
			       uint8_t *out, size_t cap, size_t *out_len)
{
	struct tc_tlv_w w;

	tc_tlv_w_init(&w, out, cap);
	tc_tlv_put(&w, TC_TAG_SIG, device_sig, 64);
	if (device_pub65) {
		tc_tlv_put(&w, TC_TAG_DEVICE_PUB, device_pub65, 65);
	}
	return tc_tlv_w_finish(&w, out_len);
}

/**
 * Build a 4-byte EXCHANGE response body with length prefix 0x0002 and the given error code in
 * big-endian format.
 */
int tc_dev_build_exchange_resp(uint16_t error, uint8_t *out, size_t cap, size_t *out_len)
{
	/* Reader gates on body[2]==0 && body[3]==0 (§ on_exchange_response). Success
	 * body = 00 02 00 00: a 2-byte length (0x0002) then the 2-byte error code. */
	if (cap < 4u) {
		return -1;
	}
	out[0] = 0x00u;
	out[1] = 0x02u;
	out[2] = (uint8_t)(error >> 8);
	out[3] = (uint8_t)error;
	*out_len = 4u;
	return 0;
}
