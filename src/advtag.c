// credential BLE advertisement Dynamic Tag derivation (credential 1.0 section 11.3.1).
/*
 * plaintextData = Pad_Bytes(6 x 00) || AdvA || Dynamic Tag Expiry Timestamp,
 * all MSB-first; the tag is the 7 most significant bytes of
 * AES-128-ECB(GRK, plaintextData).
 */
#include "tinycred/advtag.h"

#include <string.h>

#include "tinycred/prim.h"

/**
 * Derive a 4-byte advertisement tag from a 16-byte global reader key, 6-byte BLE address MSB, and
 * 32-bit UNIX expiry; tag allows a peer to verify freshness without decryption.
 */
int tc_advtag_derive(const uint8_t grk[16], const uint8_t adva_msb[6],
				uint32_t expiry_unix, uint8_t tag[TC_ADVTAG_LEN])
{
	uint8_t block[16] = {0}; /* [0..5] = Pad_Bytes */
	uint8_t enc[16];

	memcpy(&block[6], adva_msb, 6);
	block[12] = (uint8_t)(expiry_unix >> 24);
	block[13] = (uint8_t)(expiry_unix >> 16);
	block[14] = (uint8_t)(expiry_unix >> 8);
	block[15] = (uint8_t)expiry_unix;

	int rc = tc_aes128_ecb_encrypt(grk, block, enc);

	if (rc != 0) {
		return rc;
	}
	memcpy(tag, enc, TC_ADVTAG_LEN);
	return 0;
}
