/* SPDX-FileCopyrightText: 2026 Aseem Chopra */
/* SPDX-License-Identifier: Apache-2.0 */

/** @file ble_tinyble.h — what the application adds on top of tinycred/ble.h when the
 * transport is tinyble (CONFIG_TINYCRED_TINYBLE). tinyble has one advertiser, shared with
 * the Matter commissioning advertisement, so the application decides which one is on.
 */

#ifndef TINYCRED_BLE_TINYBLE_H
#define TINYCRED_BLE_TINYBLE_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** The reader's advertisement on tinyble's advertiser: flags and the 0xFFF2 service data
 * (resolvable, with the dynamic tag, once tc_ble_set_adv_params() gave a GRK; the bare
 * service UUID before). Off stops advertising; the application then owns the advertiser
 * again (matter_ble_advertise()). Call after tc_reader_start_attached(). */
void tc_ble_tinyble_advertise(bool on);

/** The wall clock, seconds since 1970, for the dynamic tag's expiry. Without one the
 * tag carries the "no clock" expiry, which phones accept but cannot filter on. Rebuilds
 * the advertisement when it is on. */
void tc_ble_tinyble_set_time(uint32_t unix_now);

#ifdef __cplusplus
}
#endif

#endif /* TINYCRED_BLE_TINYBLE_H */
