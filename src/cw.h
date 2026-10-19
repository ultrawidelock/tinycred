// Tiny definite-length CBOR writer shared by the step-up translation units
// (tc_stepup.c Sig_structure/seal, tc_stepup_wire.c request/SessionData
// codecs). Error-latching: any overflow sets err and later calls no-op.
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/**
 * CBOR writer: tracks output buffer pointer, end, and error state for incremental encoding of
 * BER-TLV and CBOR primitives.
 */
struct cw {
	uint8_t *p;
	uint8_t *end;
	int err;
};

/**
 * Append n bytes from buffer b to the CBOR writer; set error flag and return early if no space
 * remains or writer is already in error state. n==0 is a no-op (b may be NULL).
 */
static inline void cw_raw(struct cw *w, const void *b, size_t n)
{
	if (w->err || (size_t)(w->end - w->p) < n) {
		w->err = 1;
		return;
	}
	if (n != 0) {
		memcpy(w->p, b, n);
		w->p += n;
	}
}

/**
 * Encode a CBOR major type and argument into the writer as 1, 2, 3, or 5 bytes depending on
 * argument magnitude.
 */
static inline void cw_type(struct cw *w, uint8_t major, uint64_t arg)
{
	uint8_t h[9];
	size_t n;

	if (arg < 24u) {
		h[0] = (uint8_t)(major | arg);
		n = 1;
	} else if (arg < 256u) {
		h[0] = (uint8_t)(major | 24u);
		h[1] = (uint8_t)arg;
		n = 2;
	} else if (arg < 65536u) {
		h[0] = (uint8_t)(major | 25u);
		h[1] = (uint8_t)(arg >> 8);
		h[2] = (uint8_t)arg;
		n = 3;
	} else {
		h[0] = (uint8_t)(major | 26u);
		h[1] = (uint8_t)(arg >> 24);
		h[2] = (uint8_t)(arg >> 16);
		h[3] = (uint8_t)(arg >> 8);
		h[4] = (uint8_t)arg;
		n = 5;
	}
	cw_raw(w, h, n);
}

/**
 * Encode a CBOR map header with n key-value pairs.
 */
static inline void cw_map(struct cw *w, uint64_t n)
{
	cw_type(w, 0xa0u, n);
}
/**
 * Encode a CBOR array header with n elements.
 */
static inline void cw_arr(struct cw *w, uint64_t n)
{
	cw_type(w, 0x80u, n);
}
/**
 * Encode a CBOR text string header and payload from a raw byte slice.
 */
static inline void cw_tstr_n(struct cw *w, const uint8_t *s, size_t n)
{
	cw_type(w, 0x60u, n);
	cw_raw(w, s, n);
}
/**
 * Encode a CBOR text string header and payload.
 */
static inline void cw_tstr(struct cw *w, const char *s)
{
	cw_tstr_n(w, (const uint8_t *)s, strlen(s));
}
/**
 * Encode a CBOR byte string header and payload.
 */
static inline void cw_bstr(struct cw *w, const uint8_t *b, size_t n)
{
	cw_type(w, 0x40u, n);
	cw_raw(w, b, n);
}
/**
 * Encode a CBOR semantic tag number.
 */
static inline void cw_tag(struct cw *w, uint64_t t)
{
	cw_type(w, 0xc0u, t);
}
/**
 * Append a CBOR boolean (0xf5 for true, 0xf4 for false) to the writer.
 */
static inline void cw_bool(struct cw *w, int v)
{
	uint8_t b = v ? 0xf5u : 0xf4u;

	cw_raw(w, &b, 1);
}
