/* SPDX-FileCopyrightText: 2026 Aseem Chopra */
/* SPDX-License-Identifier: Apache-2.0 */

// BLE-RSSI ranging power gate: decides when the phone is close enough that arming
// UWB ranging is worth the radio's RX power. Pure sample-in/state-out logic (EWMA
// smoothing, open/close hysteresis with a close hold-off, optional rise-rate fast
// open for fast approaches) so it host-tests without a radio; the reader feeds it
// connection RSSI samples and defers Reader-Status-AP-Completed until it opens.
#pragma once
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Tuning knobs. Kconfig supplies the build defaults (TC_RSSI_GATE_CFG_DEFAULT).
 * The thresholds come from a measured curve on one rig; they are per-room and
 * per-handset, so re-run the calibration for a new one. */
struct tc_rssi_gate_cfg {
	int16_t open_dbm;         /* smoothed RSSI at/above this -> open */
	int16_t close_dbm;        /* smoothed RSSI at/below this (sustained) -> close */
	uint16_t close_hold_ms;   /* how long below close_dbm before closing */
	uint8_t ewma_shift;       /* smoothing alpha = 1/2^shift */
	uint8_t slope_open_db;    /* fast-open on this much rise per window; 0 = off */
	uint16_t slope_window_ms; /* rise-rate reference window */
	uint16_t max_hold_ms;     /* longest AP-Completed hold before opening anyway; 0 = off */
};

/* Kconfig-tunable defaults, with host-build fallbacks (no sdkconfig there). */
#ifndef CONFIG_TINYCRED_RSSI_GATE_OPEN_DBM
#define CONFIG_TINYCRED_RSSI_GATE_OPEN_DBM (-55)
#endif
#ifndef CONFIG_TINYCRED_RSSI_GATE_CLOSE_DBM
#define CONFIG_TINYCRED_RSSI_GATE_CLOSE_DBM (-65)
#endif
#ifndef CONFIG_TINYCRED_RSSI_GATE_CLOSE_HOLD_MS
#define CONFIG_TINYCRED_RSSI_GATE_CLOSE_HOLD_MS (3000)
#endif
#ifndef CONFIG_TINYCRED_RSSI_GATE_SLOPE_DB
#define CONFIG_TINYCRED_RSSI_GATE_SLOPE_DB (8)
#endif
#ifndef CONFIG_TINYCRED_RSSI_GATE_MAX_HOLD_MS
#define CONFIG_TINYCRED_RSSI_GATE_MAX_HOLD_MS (0)
#endif

#define TC_RSSI_GATE_CFG_DEFAULT                                                        \
	{                                                                                          \
		.open_dbm = CONFIG_TINYCRED_RSSI_GATE_OPEN_DBM,                                         \
		.close_dbm = CONFIG_TINYCRED_RSSI_GATE_CLOSE_DBM,                                       \
		.close_hold_ms = CONFIG_TINYCRED_RSSI_GATE_CLOSE_HOLD_MS,                               \
		.ewma_shift = 2u,                                                                  \
		.slope_open_db = CONFIG_TINYCRED_RSSI_GATE_SLOPE_DB,                                    \
		.slope_window_ms = 1500u,                                                          \
		.max_hold_ms = CONFIG_TINYCRED_RSSI_GATE_MAX_HOLD_MS,                                   \
	}

/* HCI "RSSI not available" sentinel (Core spec Read RSSI); such samples are ignored. */
#define TC_RSSI_UNAVAILABLE 127

/* Gate state. All-zeroes == reset/closed, so a zeroed session slot needs no init
 * call. Internal values are Q4 fixed point (dBm * 16). */
struct tc_rssi_gate {
	bool primed; /* EWMA seeded by a first sample */
	bool open;
	/* AP-Completed hold, started by tc_rssi_gate_hold_begin. `capped` records
	 * that max_hold_ms opened the gate rather than the level doing it. */
	bool holding;
	bool capped;
	uint32_t hold_since_ms;
	int32_t ewma_q4;
	/* close hold-off tracking */
	bool below;
	uint32_t below_since_ms;
	/* rise-rate reference: `old` is between window/2 and ~window old */
	bool old_valid;
	bool mid_valid;
	int32_t old_q4;
	int32_t mid_q4;
	uint32_t old_ms;
	uint32_t mid_ms;
};

/* Return the gate to its zeroed (closed, unprimed) state. */
void tc_rssi_gate_reset(struct tc_rssi_gate *g);

/* Feed one connection RSSI sample (dBm, TC_RSSI_UNAVAILABLE ignored) stamped
 * with a monotonic ms clock (wrap-safe). Returns the resulting open state. */
bool tc_rssi_gate_feed(struct tc_rssi_gate *g,
				  const struct tc_rssi_gate_cfg *cfg, int8_t rssi_dbm,
				  uint32_t now_ms);

/* Current open state without feeding a sample. */
bool tc_rssi_gate_is_open(const struct tc_rssi_gate *g);

/* Start the AP-Completed hold clock. Called when the reader defers AP-Completed on a
 * closed gate. From here a feed opens the gate once cfg->max_hold_ms has elapsed even
 * if the level never qualifies. Off by default (max_hold_ms 0): the phone stops
 * waiting at around 1.9 s and reconnects, and that reconnect costs one fast re-auth
 * where capping costs seconds of DW3000 RX aimed at a phone still metres away. A
 * capped open is a normal open in every other respect, so the ordinary close path
 * still powers the radio back down when the peer leaves.
 *
 * Only evaluated on a feed, so a cap ends up to one sample period late: budget
 * max_hold_ms + the caller's poll interval against the phone's patience. */
void tc_rssi_gate_hold_begin(struct tc_rssi_gate *g, uint32_t now_ms);

/* True when the gate's current open state came from the hold cap rather than from the
 * level qualifying. Diagnostics only (the power study separates the two). */
bool tc_rssi_gate_was_capped(const struct tc_rssi_gate *g);

/* Smoothed level in whole dBm (truncated), 0 before the first sample. Logging. */
int16_t tc_rssi_gate_level_dbm(const struct tc_rssi_gate *g);

#ifdef __cplusplus
}
#endif
