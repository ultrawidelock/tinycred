/* SPDX-FileCopyrightText: 2026 Aseem Chopra */
/* SPDX-License-Identifier: Apache-2.0 */

// Device (User-Device) side of the credential Access-Protocol wire codec: the inverse
// of tc_apdu.c. Where tc_apdu builds reader commands and parses device
// responses, this parses the reader's AUTH0/AUTH1/EXCHANGE commands and builds
// the device's AUTH0/AUTH1/EXCHANGE responses. Pure byte manipulation, no crypto
// and no platform dependency.
/*
 * tc_device_apdu — the initiator half of the credential-auth wire codec.
 * Compiled only by the device build + host tests; the reader firmware never
 * links it, so the reader image is unchanged.
 */
#pragma once

#include <stddef.h>
#include <stdint.h>

#include "tinycred/apdu.h" /* TLV writer/reader, tags, INS bytes, BLE envelope */

#ifdef __cplusplus
extern "C" {
#endif

/* ---- parsed reader commands (device inbound) ---- */

/* Fields parsed from an AUTH0Command TLV. All are mandatory on the wire. */
struct tc_auth0_command {
	uint8_t exp_phase;          /* tag 0x41: ExpeditedPhaseType (0 std, 1 fast-requested) */
	uint8_t user_policy;        /* tag 0x42: UserAuthenticationPolicy */
	uint16_t version;           /* tag 0x5C: protocol version, big-endian */
	uint8_t reader_eph_pub[65]; /* tag 0x87 */
	uint8_t txid[16];           /* tag 0x4C */
	uint8_t reader_id[32];      /* tag 0x4D */
};

/* Fields parsed from an AUTH1Command TLV. */
struct tc_auth1_command {
	uint8_t cred_type;      /* tag 0x41: AccessCredentialType */
	uint8_t reader_sig[64]; /* tag 0x9E: reader ECDSA r|s over the reader-usage transcript */
};

/* Fields parsed from the DECRYPTED EXCHANGE command plaintext. */
struct tc_exchange_command {
	int have_status; /* tag 0x97 present */
	uint16_t reader_status;
	int ursk_ready; /* tag 0x98 present (URSK-ready trigger) */
};

/* Strip an ISO7816 short-form command wrapper "80 <ins> 00 00 Lc <data> [Le]".
 * Sets *ins and points data (with data_len) at the Lc-length command body. A trailing
 * Le byte (the reader always sends 0x00) is tolerated. Returns 0 on success, -1
 * on a malformed/short APDU. */
int tc_apdu_unwrap(const uint8_t *apdu, size_t len, uint8_t *ins, const uint8_t **data,
		      size_t *data_len);

/* Append a 2-byte ISO7816 status word (0x9000 = OK) to a response body in place.
 * Returns 0, or -1 if cap cannot hold the two bytes. */
int tc_apdu_append_sw(uint8_t *buf, size_t *len, size_t cap, uint16_t sw);

/* ---- command parsers (device inbound; input is the raw command TLV) ---- */
int tc_dev_parse_auth0_cmd(const uint8_t *tlv, size_t len,
				      struct tc_auth0_command *c);
int tc_dev_parse_auth1_cmd(const uint8_t *tlv, size_t len,
				      struct tc_auth1_command *c);
int tc_dev_parse_exchange_cmd(const uint8_t *plain, size_t len,
				 struct tc_exchange_command *c);

/* ---- response builders (device outbound; out receives the response TLV,
 *      WITHOUT the status word — the caller seals (AUTH1/EXCHANGE) and/or appends
 *      the SW via tc_apdu_append_sw) ---- */

/* AUTH0Response: device ephemeral pub (tag 0x86, 65) [+ cryptogram tag 0x9D, 64]. */
int tc_dev_build_auth0_resp(const uint8_t device_eph_pub[65],
				       const uint8_t *cryptogram64, uint8_t *out, size_t cap,
				       size_t *out_len);

/* AUTH1Response plaintext: device signature (tag 0x9E, 64) [+ device pub tag 0x5A, 65]. */
int tc_dev_build_auth1_resp(const uint8_t device_sig[64], const uint8_t *device_pub65,
			       uint8_t *out, size_t cap, size_t *out_len);

/* EXCHANGE response plaintext body: [len_be16 = 0x0002][error_be16]. error 0 = URSK
 * armed (the reader gates on body[2]==0 && body[3]==0). */
int tc_dev_build_exchange_resp(uint16_t error, uint8_t *out, size_t cap,
					  size_t *out_len);

#ifdef __cplusplus
}
#endif
