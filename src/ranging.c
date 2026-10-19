/** @file ranging.c — the post-auth M1-M4 ranging setup on tinyuwb's setup service: on a
 * completed credential authentication the session is opened with the derived URSK, the
 * engine's outbound SDUs are BleSK-sealed onto the peer's L2CAP channel, inbound M2 and M4
 * are fed back, and M4 starts the DW3000 responder with the negotiated parameters.
 *
 * The DW3000 is single-session, so one ranging session runs at a time, newest wins. The
 * whole lifecycle runs on the BLE host context: open, feed, close and the engine's
 * callbacks are all synchronous, so there is no locking.
 */

#include "tinycred/ranging.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "tinycred/ble.h"
#include "tinycred/crypto.h"
#include "tinycred/port.h"
#include "tinyuwb/setup.h"
#include "tinyuwb/uwb.h"

LOG_MODULE_REGISTER(tinycred_ranging, CONFIG_TINYCRED_LOG_LEVEL);

/* The reader offers one UWB configuration: channel 9, SYNC code 9. The capabilities match
 * the reference reader: every slot duration, SYNC codes 9 to 12, hopping default,
 * continuous and none, channels 5 and 9, one ranging round. */
#define TC_RANGING_CHANNEL 9u
#define TC_RANGING_CODE    9u

static const struct tu_setup_caps k_caps = {
	.slot_bitmask = 0xFFu,
	.sync_code_index_bitmask = 0x00000F00u,
	.hopping_config_bitmask = 0x1Au,
	.channel_bitmask = TU_RS_CHANNEL_BITMASK_CH5 | TU_RS_CHANNEL_BITMASK_CH9,
	.uwb_config_id = 0x0000u,
	.pulse_shape_combo = 0x00u,
	.min_ran_multiplier = 1u,
	.hop_prefs = {TU_HOP_PREF_DISABLED, TU_HOP_PREF_CONTINUOUS_DEFAULT},
	.hop_pref_count = 2u,
	.mac_mode = 0u,
};

static bool s_active;
static uint16_t s_conn;
/* Set after an ambiguous transport result: the owning connection is dropped and nothing
 * more is sealed on this channel, since the seal consumed a counter the peer never saw. */
static bool s_transport_failed;
/* The connection's BleSK ranging channel, owned by the reader session, borrowed here. */
static struct tc_secchan *s_sc_ble;

/* The engine hands over a plaintext [proto][id][len][payload]; it is sealed with the 4-byte
 * header as AAD and put on the wire. */
static void setup_tx(const uint8_t *msg, size_t len, void *user)
{
	uint16_t conn = (uint16_t)(uintptr_t)user;
	uint8_t wire[TU_RS_MSG_MAX + TC_GCM_TAG_LEN];
	size_t wl;
	int rc;

	if (s_transport_failed || s_sc_ble == NULL) {
		return;
	}
	if (tc_msg_seal(s_sc_ble, msg, len, wire, sizeof(wire), &wl) != 0) {
		LOG_ERR("[conn %u] ranging TX seal failed (%u B)", conn, (unsigned)len);
		s_transport_failed = true;
		(void)tc_ble_disconnect(conn);
		return;
	}
	rc = tc_ble_send(conn, wire, wl);
	LOG_DBG("[conn %u] ranging TX proto=0x%02x id=0x%02x (%u B, rc=%d)", conn, msg[0],
		msg[1], (unsigned)wl, rc);
	if (rc != 0) {
		s_transport_failed = true;
		LOG_ERR("[conn %u] ranging transport result ambiguous; disconnecting", conn);
		(void)tc_ble_disconnect(conn);
	}
}

static void setup_ev(enum tu_setup_event ev, void *user)
{
	uint16_t conn = (uint16_t)(uintptr_t)user;

	(void)conn; /* only the log reads it */
	switch (ev) {
	case TU_SETUP_EV_ACTIVE:
		(void)tc_lat_mark(TC_LAT_M4_DONE);
		LOG_INF("[conn %u] UWB ranging ACTIVE (negotiated params live)", conn);
		break;
	case TU_SETUP_EV_IDLE:
		LOG_INF("[conn %u] UWB session IDLE", conn);
		break;
	case TU_SETUP_EV_ERROR:
	default:
		LOG_WRN("[conn %u] UWB session ERROR", conn);
		break;
	}
}

int tc_ranging_init(void)
{
	/* Bring the radio up now, on the reader's start path, so the first M4 does not pay
	 * for the reset, the trims and the calibrations on the BLE host context. Not fatal:
	 * without a radio the authentication still runs and M4 reports the failure. */
	if (tu_prewarm(TC_RANGING_CHANNEL, TC_RANGING_CODE) == 0) {
		LOG_INF("DW3000 ready (M4 will reuse the PHY)");
	} else {
		LOG_WRN("DW3000 bring-up failed; M4 handoff may not range");
	}
	return 0;
}

int tc_ranging_start(uint16_t conn_handle, uint32_t session_id, const uint8_t *ursk,
		     struct tc_secchan *sc_ble)
{
	if (ursk == NULL || sc_ble == NULL) {
		LOG_WRN("[conn %u] ranging start: keys not ready", conn_handle);
		return -1;
	}
	if (s_active) {
		/* Newest wins: the peer that just authenticated is the one at the door; the
		 * holder is often a ghost of the same phone whose supervision timeout has not
		 * fired yet. */
		LOG_WRN("[conn %u] ranging active on conn %u; preempting it", conn_handle, s_conn);
		tc_ranging_stop(s_conn);
	}
	/* The PHY the M1 will offer, applied while the phone decides to send its
	 * Initiate-Ranging-Session, so the M4-time start skips the configure. */
	(void)tu_prewarm(TC_RANGING_CHANNEL, TC_RANGING_CODE);
	if (tu_setup_open(&k_caps, session_id, ursk, setup_tx, setup_ev,
			  (void *)(uintptr_t)conn_handle) != 0) {
		LOG_ERR("[conn %u] setup open failed", conn_handle);
		return -1;
	}
	s_sc_ble = sc_ble;
	s_conn = conn_handle;
	s_active = true;
	s_transport_failed = false;
	/* No eager M1: the engine emits it when the device sends Initiate-Ranging-Session. */
	LOG_INF("[conn %u] ranging armed (session id 0x%08x); awaiting Initiate-Ranging-Session",
		conn_handle, (unsigned)session_id);
	return 0;
}

int tc_ranging_feed(uint16_t conn_handle, const uint8_t *data, size_t len)
{
	enum tu_setup_err e;

	if (!s_active || s_transport_failed || s_conn != conn_handle) {
		return -1;
	}
	if (len < TU_RS_HEADER_LEN || len > TU_RS_MSG_MAX) {
		LOG_WRN("[conn %u] ranging SDU size %u out of range", conn_handle, (unsigned)len);
		return -1;
	}
	/* M4 starts the responder with the negotiated parameters; an error there went to the
	 * peer as a GeneralError already. */
	e = tu_setup_handle(data, len);
	if (e != TU_SETUP_OK) {
		LOG_WRN("[conn %u] setup handle err %d", conn_handle, (int)e);
		return -1;
	}
	return 0;
}

void tc_ranging_stop(uint16_t conn_handle)
{
	if (!s_active || s_conn != conn_handle) {
		return;
	}
	s_active = false;
	s_transport_failed = false;
	s_sc_ble = NULL; /* borrowed from the reader session; drop before it is freed */
	LOG_INF("[conn %u] tearing down UWB ranging session", conn_handle);
	tu_setup_close(); /* stops the radio when it was started */
}

bool tc_ranging_last_range_age_ms(int64_t *age_ms_out)
{
	int32_t cm;

	return tu_last_range_age_cm(&cm, age_ms_out);
}
