/* SPDX-FileCopyrightText: 2026 Aseem Chopra */
/* SPDX-License-Identifier: Apache-2.0 */

// Crypto-free wire codecs for the credential step-up phase: the mdoc DeviceRequest builders, the
// SessionData {"data": bstr} envelope without the AES-GCM channel (raw wrap/unwrap), the NFC
// DO'53 TLV wrapper, the fragmenting ENVELOPE / extended GET RESPONSE APDU builders, and the
// 61xx GET RESPONSE chaining reassembly. Merged from tc_cred_stack's nfc_step_up.c; this
// unit carries no crypto dependency so transport stacks that encrypt through their own backend
// (session.cpp via Nordic's Interface) link it without tc_crypto.
/*
 * Wire structures from the credential v1.0 spec (§8.4.2, §8.4.4, Table 8-21) and ISO
 * 18013-5 SessionData, over ISO 7816-4 ENVELOPE/GET RESPONSE chaining. The
 * crypto-full SessionData seal/open in tc_stepup.c factor over the raw
 * wrap/unwrap here.
 */
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "cw.h"
#include "tinycred/stepup.h"
#include "tinycred/ber.h"

/* ---- DeviceRequest (Table 8-21) ------------------------------------------ */

/* DeviceRequest = { "1": "1.0", "2": [ { "1": 24(bstr(itemsRequest)) } ] } */
static int wrap_items_request(const uint8_t *items, size_t items_len, uint8_t *out, size_t cap,
			      size_t *out_len)
{
	struct cw w = {out, out + cap, 0};

	cw_map(&w, 2);
	cw_tstr(&w, "1");
	cw_tstr(&w, "1.0");
	cw_tstr(&w, "2");
	cw_arr(&w, 1);
	cw_map(&w, 1);
	cw_tstr(&w, "1");
	cw_tag(&w, 24);
	cw_bstr(&w, items, items_len);
	if (w.err) {
		return TC_STEPUP_BUFFER_TOO_SMALL;
	}
	*out_len = (size_t)(w.p - out);
	return TC_STEPUP_OK;
}

static const char *const k_default_elems[] = {"element2", "element4"};

/**
 * Build a CBOR-encoded Step-Up deviceRequest with itemsRequest containing requested element names
 * (or default AccessCode, AccessLevel if none given) and docType "aliro-a"; return 0 on success or
 * -1 on buffer overflow.
 */
int tc_stepup_build_device_request(const char *const *elems, size_t n_elems,
					      uint8_t *out, size_t cap, size_t *out_len)
{
	if (elems == NULL || n_elems == 0) {
		elems = k_default_elems;
		n_elems = 2;
	}

	/* itemsRequest = { "1": { "aliro-a": { <elem>: true, ... } }, "5": "aliro-a" } */
	uint8_t items[128];
	struct cw iw = {items, items + sizeof(items), 0};

	cw_map(&iw, 2);
	cw_tstr(&iw, "1"); /* nameSpaces */
	cw_map(&iw, 1);
	cw_tstr(&iw, TC_STEPUP_DOCTYPE_ACCESS); /* namespace "aliro-a" */
	cw_map(&iw, n_elems);
	for (size_t i = 0; i < n_elems; i++) {
		cw_tstr(&iw, elems[i]);
		cw_bool(&iw, 1); /* intent to retain */
	}
	cw_tstr(&iw, "5"); /* docType */
	cw_tstr(&iw, TC_STEPUP_DOCTYPE_ACCESS);
	if (iw.err) {
		return -1;
	}
	if (wrap_items_request(items, (size_t)(iw.p - items), out, cap, out_len) != 0) {
		return -1;
	}
	return 0;
}

/**
 * Build the single-element deviceRequest the session layer sends: element identifier supplied as a
 * raw text slice, with the caller's intent-to-retain flag. Same wire shape as
 * tc_stepup_build_device_request. Returns TC_STEPUP_OK, _INVALID_ARGUMENT, or
 * _BUFFER_TOO_SMALL.
 */
int tc_stepup_build_device_request_ex(const uint8_t *element_identifier,
					 size_t element_identifier_length, bool intent_to_store,
					 uint8_t *output, size_t output_capacity,
					 size_t *output_length)
{
	if (element_identifier == NULL || element_identifier_length == 0 || output == NULL ||
	    output_length == NULL) {
		return TC_STEPUP_INVALID_ARGUMENT;
	}
	uint8_t items[512];
	struct cw iw = {items, items + sizeof(items), 0};

	cw_map(&iw, 2);
	cw_tstr(&iw, "1");
	cw_map(&iw, 1);
	cw_tstr(&iw, TC_STEPUP_DOCTYPE_ACCESS);
	cw_map(&iw, 1);
	cw_tstr_n(&iw, element_identifier, element_identifier_length);
	cw_bool(&iw, intent_to_store);
	cw_tstr(&iw, "5");
	cw_tstr(&iw, TC_STEPUP_DOCTYPE_ACCESS);
	if (iw.err) {
		return TC_STEPUP_BUFFER_TOO_SMALL;
	}
	return wrap_items_request(items, (size_t)(iw.p - items), output, output_capacity,
				  output_length);
}

/* ---- SessionData {"data": bstr}, no crypto (§8.4.3) ---------------------- */

int tc_stepup_wrap_sessiondata_raw(const uint8_t *ciphertext, size_t ciphertext_length,
				      uint8_t *output, size_t output_capacity,
				      size_t *output_length)
{
	if ((ciphertext == NULL && ciphertext_length != 0) || output == NULL ||
	    output_length == NULL) {
		return TC_STEPUP_INVALID_ARGUMENT;
	}
	struct cw w = {output, output + output_capacity, 0};

	cw_map(&w, 1);
	cw_tstr(&w, "data");
	cw_bstr(&w, ciphertext, ciphertext_length);
	if (w.err) {
		return TC_STEPUP_BUFFER_TOO_SMALL;
	}
	*output_length = (size_t)(w.p - output);
	return TC_STEPUP_OK;
}

/**
 * Parse a CBOR major type and initial value from an encoded stream. Major type is encoded in the
 * top 3 bits of the first byte; additional info determines whether the value follows. Validates
 * encoding: rejects non-minimal representations (e.g., a 1-byte value encoded with 2 bytes) and
 * returns TC_STEPUP_INVALID_DATA if the major type or additional-info field does not
 * match expectations.
 */
static int cbor_read_head(const uint8_t *data, size_t length, size_t *offset, uint8_t major,
			  size_t *value)
{
	if (*offset >= length) {
		return TC_STEPUP_INVALID_DATA;
	}
	uint8_t b = data[(*offset)++];
	if ((b >> 5) != major) {
		return TC_STEPUP_INVALID_DATA;
	}
	uint8_t ai = b & 31;
	if (ai < 24) {
		*value = ai;
		return 0;
	}
	size_t n = ai == 24 ? 1 : ai == 25 ? 2 : ai == 26 ? 4 : ai == 27 ? 8 : 0;
	if (n == 0 || n > sizeof(size_t) || n > length - *offset) {
		return TC_STEPUP_INVALID_DATA;
	}
	size_t v = 0;
	for (size_t i = 0; i < n; ++i) {
		v = (v << 8) | data[(*offset)++];
	}
	if ((n == 1 && v < 24) || (n == 2 && v <= 0xff) || (n == 4 && v <= 0xffff)) {
		return TC_STEPUP_INVALID_DATA;
	}
	*value = v;
	return 0;
}

/**
 * Unwrap an ISO 18013-5 SessionData envelope (CBOR map with "data" key) to extract the encrypted
 * ciphertext. Validate that SessionData is a map with exactly one entry and return a pointer into
 * the input buffer for the ciphertext bytes and their length. Return 0 on success,
 * TC_STEPUP_INVALID_DATA on format error or invalid argument.
 */
int tc_stepup_unwrap_sessiondata_raw(const uint8_t *session_data,
						size_t session_data_length,
						const uint8_t **ciphertext,
						size_t *ciphertext_length)
{
	if (session_data == NULL || ciphertext == NULL || ciphertext_length == NULL) {
		return TC_STEPUP_INVALID_ARGUMENT;
	}
	size_t off = 0, n;
	if (cbor_read_head(session_data, session_data_length, &off, 5, &n) != 0 || n != 1 ||
	    cbor_read_head(session_data, session_data_length, &off, 3, &n) != 0 || n != 4 ||
	    n > session_data_length - off || memcmp(session_data + off, "data", 4) != 0) {
		return TC_STEPUP_INVALID_DATA;
	}
	off += 4;
	if (cbor_read_head(session_data, session_data_length, &off, 2, &n) != 0 ||
	    n > session_data_length - off || off + n != session_data_length) {
		return TC_STEPUP_INVALID_DATA;
	}
	*ciphertext = session_data + off;
	*ciphertext_length = n;
	return 0;
}

/* ---- NFC Device Engagement DO'53 wrapper --------------------------------- */

int tc_stepup_wrap_do53(const uint8_t *message, size_t message_length, uint8_t *output,
			   size_t output_capacity, size_t *output_length)
{
	if ((message == NULL && message_length != 0) || output == NULL || output_length == NULL) {
		return TC_STEPUP_INVALID_ARGUMENT;
	}
	size_t off = 0;
	if (tc_ber_write(output, output_capacity, &off, 0x53, message, message_length) !=
	    TC_BER_OK) {
		return TC_STEPUP_BUFFER_TOO_SMALL;
	}
	*output_length = off;
	return 0;
}

/**
 * Unwrap a credential DO'53 TLV-encoded message: extract the value of a tag-0x53 object from an
 * encoded buffer. Returns a pointer into the input buffer for the message payload and its length;
 * the pointer is valid only as long as the input buffer is valid.
 */
int tc_stepup_unwrap_do53(const uint8_t *encoded, size_t encoded_length,
				     const uint8_t **message, size_t *message_length)
{
	if (encoded == NULL || message == NULL || message_length == NULL) {
		return TC_STEPUP_INVALID_ARGUMENT;
	}
	struct tc_ber tlv;
	size_t off = 0;
	if (tc_ber_next(encoded, encoded_length, &off, &tlv) != 0 || tlv.tag != 0x53 ||
	    off != encoded_length) {
		return TC_STEPUP_INVALID_DATA;
	}
	*message = tlv.value;
	*message_length = tlv.length;
	return 0;
}

/* ---- fragmenting ENVELOPE / GET RESPONSE APDUs (§8.4.4) ------------------ */

int tc_stepup_build_envelope_ex(const uint8_t *encoded_do53, size_t encoded_length,
				   size_t *offset, size_t max_command_data,
				   size_t max_response_data, bool extended_supported,
				   uint8_t *output, size_t output_capacity, size_t *output_length,
				   bool *last_fragment)
{
	if (encoded_do53 == NULL || offset == NULL || *offset >= encoded_length ||
	    max_command_data == 0 || max_command_data > 65535 || max_response_data == 0 ||
	    max_response_data > 65536 || output == NULL || output_length == NULL ||
	    last_fragment == NULL) {
		return TC_STEPUP_INVALID_ARGUMENT;
	}
	size_t fragment = encoded_length - *offset;
	if (fragment > max_command_data) {
		fragment = max_command_data;
	}
	*last_fragment = *offset + fragment == encoded_length;
	const bool extended = fragment > 255 || (*last_fragment && max_response_data > 256);
	if (extended && !extended_supported) {
		return TC_STEPUP_INVALID_ARGUMENT;
	}
	size_t needed = (extended ? 7 : 5) + fragment + (*last_fragment ? (extended ? 2 : 1) : 0);
	if (needed > output_capacity) {
		return TC_STEPUP_BUFFER_TOO_SMALL;
	}
	size_t o = 0;
	output[o++] = *last_fragment ? 0x00 : 0x10;
	output[o++] = TC_INS_ENVELOPE;
	output[o++] = 0x00;
	output[o++] = 0x00;
	if (extended) {
		output[o++] = 0;
		output[o++] = (uint8_t)(fragment >> 8);
		output[o++] = (uint8_t)fragment;
	} else {
		output[o++] = (uint8_t)fragment;
	}
	memcpy(output + o, encoded_do53 + *offset, fragment);
	o += fragment;
	if (*last_fragment) {
		if (extended) {
			uint16_t le = max_response_data == 65536 ? 0 : (uint16_t)max_response_data;
			output[o++] = (uint8_t)(le >> 8);
			output[o++] = (uint8_t)le;
		} else {
			output[o++] = max_response_data == 256 ? 0 : (uint8_t)max_response_data;
		}
	}
	*offset += fragment;
	*output_length = o;
	return 0;
}

/**
 * Build an ISO 7816 GET RESPONSE command APDU for retrieving data from a previous response chain.
 * For lengths <= 256 bytes, outputs a 5-byte APDU; for lengths > 256, outputs a 7-byte
 * extended-length APDU. Output capacity must be >= 5 or >= 7 bytes respectively. Expected length
 * must be 1–65536.
 */
int tc_stepup_build_get_response_ex(size_t expected_length, uint8_t *output,
				       size_t output_capacity, size_t *output_length)
{
	if (expected_length == 0 || expected_length > 65536 || output == NULL ||
	    output_length == NULL) {
		return TC_STEPUP_INVALID_ARGUMENT;
	}
	if (expected_length <= 256) {
		if (output_capacity < 5) {
			return TC_STEPUP_BUFFER_TOO_SMALL;
		}
		const uint8_t apdu[] = {0x00, TC_INS_GET_RESPONSE, 0x00, 0x00,
					expected_length == 256 ? 0 : (uint8_t)expected_length};
		memcpy(output, apdu, sizeof(apdu));
		*output_length = sizeof(apdu);
	} else {
		if (output_capacity < 7) {
			return TC_STEPUP_BUFFER_TOO_SMALL;
		}
		uint16_t le = expected_length == 65536 ? 0 : (uint16_t)expected_length;
		const uint8_t apdu[] = {0x00, TC_INS_GET_RESPONSE, 0x00, 0x00, 0x00,
					(uint8_t)(le >> 8), (uint8_t)le};
		memcpy(output, apdu, sizeof(apdu));
		*output_length = sizeof(apdu);
	}
	return 0;
}

int tc_stepup_collect_response(const uint8_t *response, size_t response_length,
				  uint8_t *collected, size_t collected_capacity,
				  size_t *collected_length, size_t *next_length)
{
	if (response == NULL || response_length < 2 || collected == NULL ||
	    collected_length == NULL || *collected_length > collected_capacity ||
	    next_length == NULL) {
		return TC_STEPUP_INVALID_ARGUMENT;
	}
	size_t data_length = response_length - 2;
	if (data_length > collected_capacity - *collected_length) {
		return TC_STEPUP_BUFFER_TOO_SMALL;
	}
	uint8_t sw1 = response[data_length], sw2 = response[data_length + 1];
	if (!((sw1 == 0x90 && sw2 == 0) || sw1 == 0x61)) {
		return TC_STEPUP_STATUS_ERROR;
	}
	memcpy(collected + *collected_length, response, data_length);
	*collected_length += data_length;
	if (sw1 == 0x61) {
		*next_length = sw2 == 0 ? 256 : sw2;
		return TC_STEPUP_MORE_RESPONSE;
	}
	*next_length = 0;
	return TC_STEPUP_OK;
}
