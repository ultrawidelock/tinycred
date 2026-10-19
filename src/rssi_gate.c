// BLE-RSSI ranging power gate implementation: EWMA smoothing in Q4 fixed point,
// open/close hysteresis with a sustained-below close hold, and an optional
// rise-rate fast open so a fast approach is not penalized by the smoothing lag.
// Pure logic — no radio, clock, or logging dependencies — so the host suite can
// drive it with synthetic approach traces.
#include <string.h>

#include "tinycred/rssi_gate.h"

#define Q4 16 /* Q4 scale; multiply (never shift) — negatives are involved */

/**
 * Reset the RSSI gate to its initial state (all fields zeroed). Gate is not primed and will not
 * filter samples until the first feed.
 */
void tc_rssi_gate_reset(struct tc_rssi_gate *g)
{
	memset(g, 0, sizeof(*g));
}

/**
 * Return true if the RSSI gate is currently open (signal is strong enough to unlock), false
 * otherwise.
 */
bool tc_rssi_gate_is_open(const struct tc_rssi_gate *g)
{
	return g->open;
}

/**
 * Begin a hold period for the RSSI gate, marking the start time. Used by the reader to signal that
 * it is deferring an approach-unlock decision (e.g., awaiting a credential) and will check hold-cap
 * timeout on future samples.
 */
void tc_rssi_gate_hold_begin(struct tc_rssi_gate *g, uint32_t now_ms)
{
	g->holding = true;
	g->capped = false;
	g->hold_since_ms = now_ms;
}

/**
 * Return true if the gate ever hit the hold-cap timeout (max_hold_ms exceeded without qualifying on
 * RSSI level alone), false otherwise. Caller uses this to detect when the reader gave up waiting
 * and opened early.
 */
bool tc_rssi_gate_was_capped(const struct tc_rssi_gate *g)
{
	return g->capped;
}

/**
 * Return the smoothed RSSI level in decibel-milliwatts (dBm). The value is the EWMA average of all
 * samples seen so far.
 */
int16_t tc_rssi_gate_level_dbm(const struct tc_rssi_gate *g)
{
	return (int16_t)(g->ewma_q4 / Q4);
}

/* Advance the rise-rate reference: `mid` follows the newest smoothed value, and
 * once it is window/2 old it becomes `old`, so `old` always lags the present by
 * between window/2 and ~window (given a steady sample interval). */
static void slope_track(struct tc_rssi_gate *g,
			const struct tc_rssi_gate_cfg *cfg, uint32_t now_ms)
{
	uint32_t half = (uint32_t)cfg->slope_window_ms / 2u;

	if (!g->mid_valid) {
		g->mid_q4 = g->ewma_q4;
		g->mid_ms = now_ms;
		g->mid_valid = true;
		return;
	}
	if (now_ms - g->mid_ms >= half) {
		g->old_q4 = g->mid_q4;
		g->old_ms = g->mid_ms;
		g->old_valid = true;
		g->mid_q4 = g->ewma_q4;
		g->mid_ms = now_ms;
	}
}

/**
 * Feed an RSSI sample and timestamp to the gate. Returns true if the gate should remain open (or
 * just opened). Handles EWMA smoothing, rise-rate fast-open when the signal climbs steeply within a
 * short window, hold-cap timeout to prevent indefinite deferral, and close-hysteresis to avoid
 * flapping on fades. Caller must supply configuration and current time; unavailable signals
 * (TC_RSSI_UNAVAILABLE) are skipped and do not alter the state.
 */
bool tc_rssi_gate_feed(struct tc_rssi_gate *g,
				  const struct tc_rssi_gate_cfg *cfg, int8_t rssi_dbm,
				  uint32_t now_ms)
{
	if (rssi_dbm == TC_RSSI_UNAVAILABLE) {
		return g->open;
	}

	int32_t sample_q4 = (int32_t)rssi_dbm * Q4;

	if (!g->primed) {
		/* First sample seeds the average outright: a walk-up that connects
		 * already at the door must open on sample one, not after the EWMA
		 * crawls up from zero. */
		g->ewma_q4 = sample_q4;
		g->primed = true;
	} else {
		/* Division, not shift: arithmetic right shift of negatives is
		 * implementation-defined and Q4 values are negative dBm. */
		g->ewma_q4 += (sample_q4 - g->ewma_q4) / (1 << cfg->ewma_shift);
	}
	slope_track(g, cfg, now_ms);

	if (!g->open) {
		bool open = g->ewma_q4 >= (int32_t)cfg->open_dbm * Q4;

		/* Rise-rate fast open: a fast approach climbs slope_open_db within
		 * the window while still shy of open_dbm; open early rather than
		 * spend that walking time smoothing. Floor at close_dbm so noise
		 * at the fringe cannot fast-open. */
		if (!open && cfg->slope_open_db > 0u && g->old_valid &&
		    now_ms - g->old_ms <= 2u * (uint32_t)cfg->slope_window_ms &&
		    g->ewma_q4 - g->old_q4 >= (int32_t)cfg->slope_open_db * Q4 &&
		    g->ewma_q4 > (int32_t)cfg->close_dbm * Q4) {
			open = true;
		}
		/* Hold cap: the reader has been deferring AP-Completed this long and the
		 * level still has not qualified. Open anyway rather than let the phone's
		 * own patience expire and take the link down with it. */
		if (!open && g->holding && cfg->max_hold_ms > 0u &&
		    now_ms - g->hold_since_ms >= (uint32_t)cfg->max_hold_ms) {
			open = true;
			g->capped = true;
		}
		if (open) {
			g->open = true;
			g->below = false;
			g->holding = false;
		}
		return g->open;
	}

	/* Open: close only on a sustained drop below close_dbm, so a single deep
	 * fade (body blocking, pocket) cannot flap the radio off mid-approach. */
	if (g->ewma_q4 <= (int32_t)cfg->close_dbm * Q4) {
		if (!g->below) {
			g->below = true;
			g->below_since_ms = now_ms;
		} else if (now_ms - g->below_since_ms >= cfg->close_hold_ms) {
			g->open = false;
			g->below = false;
		}
	} else {
		g->below = false;
	}
	return g->open;
}
