/* SPDX-FileCopyrightText: 2026 Aseem Chopra */
/* SPDX-License-Identifier: Apache-2.0 */

/* Minimal strict BER/DER-TLV reader for credential APDU payloads. Promoted from
 * tc_cred_stack (protocol/tlv.h) as the one TLV codec both stacks share. */
#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Parsed TLV (Tag-Length-Value): tag (uint32), value (pointer to payload bytes), length (payload
 * size), encoded_length (total tag+length+value bytes).
 */
struct tc_ber {
	uint32_t tag;
	const uint8_t *value;
	size_t length;
	size_t encoded_length;
};

enum tc_ber_result {
	TC_BER_OK = 0,
	TC_BER_END = 1,
	TC_BER_INVALID = -1,
};

/* Parse one TLV at *offset and advance the offset past it. Indefinite and
 * non-minimal DER lengths are rejected. */
int tc_ber_next(const uint8_t *data, size_t data_length, size_t *offset,
		       struct tc_ber *out);

/* Return the encoded size of a definite-length TLV, or zero when the tag or
 * length cannot be represented by this codec. Tags are supplied in their
 * normal big-endian encoded form (for example 0x7f66). */
size_t tc_ber_encoded_size(uint32_t tag, size_t value_length);

/* Append one definite-length TLV at *offset. */
int tc_ber_write(uint8_t *data, size_t data_capacity, size_t *offset, uint32_t tag,
			const uint8_t *value, size_t value_length);

#ifdef __cplusplus
}
#endif
