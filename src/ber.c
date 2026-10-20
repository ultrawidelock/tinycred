/* SPDX-FileCopyrightText: 2026 Aseem Chopra */
/* SPDX-License-Identifier: Apache-2.0 */

/**
 * @file tc_tlv.c
 * BER-TLV parser and encoder for credential protocol: parse TLVs with definite length and advance
 * offset, compute encoded sizes, and write new TLVs. Promoted verbatim from
 * tc_cred_stack (protocol/tlv.c); full BER incl. multi-byte and high-tag-number tags.
 */
#include "tinycred/ber.h"

#include <string.h>

#include <limits.h>

int tc_ber_next(const uint8_t *data, size_t data_length, size_t *offset,
		       struct tc_ber *out)
{
	if (data == NULL || offset == NULL || out == NULL || *offset > data_length) {
		return TC_BER_INVALID;
	}
	if (*offset == data_length) {
		return TC_BER_END;
	}

	const size_t start = *offset;
	size_t cursor = start;
	uint32_t tag = data[cursor++];
	if ((tag & 0x1fu) == 0x1fu) {
		unsigned int tag_octets = 1;
		uint8_t octet;
		do {
			if (cursor >= data_length || tag_octets == sizeof(tag)) {
				return TC_BER_INVALID;
			}
			octet = data[cursor++];
			/* DER high-tag-number form must not start with a zero group. */
			if (tag_octets == 1 && (octet & 0x7fu) == 0) {
				return TC_BER_INVALID;
			}
			tag = (tag << 8) | octet;
			++tag_octets;
		} while ((octet & 0x80u) != 0);
	}

	if (cursor >= data_length) {
		return TC_BER_INVALID;
	}
	const uint8_t first_length = data[cursor++];
	size_t value_length = 0;
	if ((first_length & 0x80u) == 0) {
		value_length = first_length;
	} else {
		const unsigned int length_octets = first_length & 0x7fu;
		if (length_octets == 0 || length_octets > sizeof(size_t) ||
		    cursor + length_octets > data_length || data[cursor] == 0) {
			return TC_BER_INVALID;
		}
		for (unsigned int i = 0; i < length_octets; ++i) {
			if (value_length > (SIZE_MAX >> 8)) {
				return TC_BER_INVALID;
			}
			value_length = (value_length << 8) | data[cursor++];
		}
		/* DER requires short form for lengths below 128. */
		if (value_length < 128) {
			return TC_BER_INVALID;
		}
	}

	if (value_length > data_length - cursor) {
		return TC_BER_INVALID;
	}
	out->tag = tag;
	out->value = data + cursor;
	out->length = value_length;
	out->encoded_length = cursor + value_length - start;
	*offset = cursor + value_length;
	return TC_BER_OK;
}

/**
 * Compute the BER-TLV tag byte count for a given tag value: 1 byte for 0x00–0xff, 2 for
 * 0x0100–0xffff, 3 for 0x010000–0xffffff, or 0 if tag is unsupported.
 */
static size_t tag_size(uint32_t tag)
{
	if (tag <= 0xff) {
		return 1;
	}
	if (tag <= 0xffff) {
		return 2;
	}
	if (tag <= 0xffffff) {
		return 3;
	}
	return 0;
}

/**
 * Compute the BER-TLV length field byte count for a given value length: 1 byte for 0x00–0x7f, 2 for
 * 0x80–0xff, 3 for 0x0100–0xffff, or 0 if length is unsupported.
 */
static size_t length_size(size_t length)
{
	if (length < 0x80) {
		return 1;
	}
	if (length <= 0xff) {
		return 2;
	}
	if (length <= 0xffff) {
		return 3;
	}
	return 0;
}

size_t tc_ber_encoded_size(uint32_t tag, size_t value_length)
{
	const size_t encoded_tag_size = tag_size(tag);
	const size_t encoded_length_size = length_size(value_length);
	if (encoded_tag_size == 0 || encoded_length_size == 0 ||
	    value_length > SIZE_MAX - encoded_tag_size - encoded_length_size) {
		return 0;
	}
	return encoded_tag_size + encoded_length_size + value_length;
}

int tc_ber_write(uint8_t *data, size_t data_capacity, size_t *offset, uint32_t tag,
			const uint8_t *value, size_t value_length)
{
	if (data == NULL || offset == NULL || (value == NULL && value_length != 0)) {
		return TC_BER_INVALID;
	}
	const size_t total = tc_ber_encoded_size(tag, value_length);
	if (total == 0 || *offset > data_capacity || total > data_capacity - *offset) {
		return TC_BER_INVALID;
	}

	const size_t encoded_tag_size = tag_size(tag);
	for (size_t i = 0; i < encoded_tag_size; ++i) {
		data[(*offset)++] = (uint8_t)(tag >> (8 * (encoded_tag_size - i - 1)));
	}
	if (value_length < 0x80) {
		data[(*offset)++] = (uint8_t)value_length;
	} else if (value_length <= 0xff) {
		data[(*offset)++] = 0x81;
		data[(*offset)++] = (uint8_t)value_length;
	} else {
		data[(*offset)++] = 0x82;
		data[(*offset)++] = (uint8_t)(value_length >> 8);
		data[(*offset)++] = (uint8_t)value_length;
	}
	if (value_length != 0) {
		memcpy(data + *offset, value, value_length);
		*offset += value_length;
	}
	return TC_BER_OK;
}
