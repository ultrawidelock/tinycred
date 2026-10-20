/* SPDX-FileCopyrightText: 2026 Aseem Chopra */
/* SPDX-License-Identifier: Apache-2.0 */

// credential BLE advertisement Dynamic Tag derivation (credential 1.0 section 11.3.1): the 7-byte
// GroupResolvingKey-resolvable tag the phone recomputes to identify a reader of interest.
/*
 * tc_advtag — pure Dynamic Tag derivation, platform-free so the host suite
 * can pin it against the spec's section 20 worked examples. The BLE transport
 * (tc_ble.c) calls this with the live expiry on every (re)advertise.
 */
#pragma once
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TC_ADVTAG_LEN 7u

/* Advertised expiry when the reader has no wall clock (spec section 11.3);
 * phones accept this form but then cannot expiry-filter the tag. */
#define TC_ADVTAG_EXPIRY_UNAVAILABLE 0xFFFFFFFFu

/* Derive the Dynamic Tag: the 7 most significant bytes of
 * AES-128(GRK, 00*6 || AdvA || BE32(expiry)), every field MSB-first.
 * adva_msb is the advertising address in printed order (01:23:45:67:89:ab ->
 * {0x01,..,0xab}); NimBLE's ble_addr_t.val stores it reversed. Returns 0 on
 * success, negative if the AES backend fails. */
int tc_advtag_derive(const uint8_t grk[16], const uint8_t adva_msb[6],
				uint32_t expiry_unix, uint8_t tag[TC_ADVTAG_LEN]);

#ifdef __cplusplus
}
#endif
