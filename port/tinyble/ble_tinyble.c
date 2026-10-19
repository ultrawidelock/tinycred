/** @file ble_tinyble.c — tinycred/ble.h on tinyble: the credential transaction on tinyble's
 * one L2CAP credit based channel (tb_coc.h), the 0xFFF2 service tinyble's Matter table
 * already serves (tb_aliro.h), the resolvable advertisement with its dynamic tag, and the
 * RSSI poll that feeds the reader's ranging power gate.
 *
 * One link, one channel: the connection handle the reader sees is always 0. tinyble's
 * hooks run on the system workqueue under tinyble's mutex, which is recursive, so every
 * entry point here takes it and the reader may call back in from a hook. tinyble takes one
 * SDU at a time and borrows the buffer until tb_on_coc_sent(); the reader hands over stack
 * frames, so they are copied into a two-deep queue.
 */

#include "tinycred/ble.h"
#include "tinycred/ble_tinyble.h"

#include <errno.h>
#include <string.h>

#include <zephyr/kernel.h>

#include <tinyble/tb_coc.h>
#include <tinyble/tb_zephyr.h>
#include <tinyble/tinyble.h>

#include "tinycred/advtag.h"
#include "tinycred/port.h"
#include "tinycred/prov.h"

LOG_MODULE_REGISTER(tinycred_ble, CONFIG_TINYCRED_LOG_LEVEL);

#define CONN 0u

/* A dynamic tag whose expiry is in the phone's past is ignored, so no expiry at all is
 * better than one from a clock that was never set. */
#define TIME_FLOOR    1700000000u
#define TAG_VALID_S   600u
#define TAG_MARGIN_S  60u
#define HCI_REMOTE_USER_TERM 0x13u

#ifndef CONFIG_TINYCRED_RSSI_GATE_POLL_MS
#define CONFIG_TINYCRED_RSSI_GATE_POLL_MS 250
#endif

static struct tc_ble_callbacks s_cb;
static bool s_started;

/* ── Outbound SDUs ───────────────────────────────────────────────────────── */

static struct {
	uint8_t buf[TB_COC_MTU];
	uint16_t len;
} s_tx[2];
static uint8_t s_tx_head, s_tx_n;
static bool s_tx_inflight;

/* Hand the oldest queued SDU to tinyble, if it will take it. Under the lock. The flag
 * goes up before the call: an SDU that fits one packet with a credit in hand goes out
 * inside tb_coc_send(), and tb_on_coc_sent() has already taken it down by the return. */
static void tx_kick(void)
{
	if (s_tx_inflight || s_tx_n == 0u) {
		return;
	}
	s_tx_inflight = true;
	if (tb_coc_send(s_tx[s_tx_head].buf, s_tx[s_tx_head].len) != 0) {
		s_tx_inflight = false;
	}
}

static void tx_reset(void)
{
	s_tx_head = 0u;
	s_tx_n = 0u;
	s_tx_inflight = false;
}

int tc_ble_send(uint16_t conn_handle, const uint8_t *data, size_t len)
{
	uint8_t slot;
	int rc = 0;

	ARG_UNUSED(conn_handle);
	if (len == 0u || len > TB_COC_MTU) {
		return -EMSGSIZE;
	}
	tb_zephyr_lock();
	if (!tb_coc_up()) {
		rc = -ENOTCONN;
	} else if (s_tx_n == ARRAY_SIZE(s_tx)) {
		rc = -ENOBUFS;
	} else {
		slot = (uint8_t)((s_tx_head + s_tx_n) % ARRAY_SIZE(s_tx));
		memcpy(s_tx[slot].buf, data, len);
		s_tx[slot].len = (uint16_t)len;
		s_tx_n++;
		LOG_DBG("coc tx queue %u B at %lld ms (queued %u, inflight %d)", (unsigned)len,
			(long long)k_uptime_get(), s_tx_n, s_tx_inflight);
		tx_kick();
	}
	tb_zephyr_unlock();
	return rc;
}

int tc_ble_disconnect(uint16_t conn_handle)
{
	ARG_UNUSED(conn_handle);
	tb_zephyr_lock();
	tb_disconnect(HCI_REMOTE_USER_TERM);
	tb_zephyr_unlock();
	return 0;
}

/* ── RSSI poll ───────────────────────────────────────────────────────────── */

static void rssi_work_fn(struct k_work *w);
static K_WORK_DELAYABLE_DEFINE(s_rssi_work, rssi_work_fn);

static void rssi_work_fn(struct k_work *w)
{
	ARG_UNUSED(w);
	tb_zephyr_lock();
	if (tb_coc_up()) {
		tb_rssi_request();
		(void)k_work_reschedule(&s_rssi_work, K_MSEC(CONFIG_TINYCRED_RSSI_GATE_POLL_MS));
	}
	tb_zephyr_unlock();
}

void tb_on_rssi(int err, int8_t rssi_dbm)
{
	if (err == 0 && s_cb.on_rssi != NULL && tb_coc_up()) {
		s_cb.on_rssi(CONN, rssi_dbm);
	}
}

/* ── tinyble's channel hooks ─────────────────────────────────────────────── */

void tb_on_coc_open(void)
{
	LOG_INF("L2CAP CoC open (SPSM 0x%04x)", (unsigned)TB_COC_SPSM);
	tx_reset();
	tc_lat_mark(TC_LAT_L2CAP_OPEN);
	if (s_cb.on_connected != NULL) {
		s_cb.on_connected(CONN);
	}
	if (s_cb.on_rssi != NULL) {
		(void)k_work_reschedule(&s_rssi_work, K_NO_WAIT);
	}
}

void tb_on_coc_close(void)
{
	LOG_INF("L2CAP CoC closed");
	tx_reset();
	(void)k_work_cancel_delayable(&s_rssi_work);
	if (s_cb.on_disconnected != NULL) {
		s_cb.on_disconnected(CONN);
	}
}

void tb_on_coc_data(const uint8_t *sdu, uint16_t len)
{
	if (s_cb.on_data != NULL) {
		s_cb.on_data(CONN, sdu, len);
	}
}

void tb_on_coc_sent(void)
{
	LOG_DBG("coc tx sent at %lld ms", (long long)k_uptime_get());
	s_tx_inflight = false;
	if (s_tx_n != 0u) {
		s_tx_head = (uint8_t)((s_tx_head + 1u) % ARRAY_SIZE(s_tx));
		s_tx_n--;
	}
	tx_kick();
}

/* ── Advertisement ───────────────────────────────────────────────────────── *
 * Flags, then service data 0xFFF2 (the layout the phone resolves):
 *   [0]      flags: bit 7 BLE+UWB supported, bits 2:0 version 0
 *   [1]      tx power
 *   [2..9]   reader group id, reader_id[0..7]
 *   [10..11] reader group sub id, reader_id[16..17]
 *   [12..15] dynamic tag expiry, big endian; 0xFFFFFFFF without a clock
 *   [16]     reserved
 *   [17..23] dynamic tag
 * 3 + 2 + 2 + 24 = 31 B, the whole legacy payload. Without a GRK the service data is
 * replaced by the bare 16-bit UUID list, which no phone approaches on. */

static uint8_t s_group[8], s_sub[2], s_grk[TC_GRK_LEN];
static int8_t s_txp;
static bool s_params, s_adv_on;
static uint32_t s_unix_base;      /* 0: no wall clock */
static int64_t s_unix_base_ms;    /* uptime when s_unix_base was set */
static uint8_t s_ad[31];
static uint8_t s_ad_len;

static void adv_work_fn(struct k_work *w);
static K_WORK_DELAYABLE_DEFINE(s_adv_work, adv_work_fn);

static uint32_t unix_now(void)
{
	if (s_unix_base == 0u) {
		return 0u;
	}
	return s_unix_base + (uint32_t)((tc_uptime_ms() - s_unix_base_ms) / 1000);
}

/* Build s_ad. Under the lock. Returns the expiry it carries, 0xFFFFFFFF for none. */
static uint32_t adv_build(void)
{
	const uint8_t *addr = tb_addr();
	uint8_t adva_msb[6], tag[TC_ADVTAG_LEN], *p = s_ad;
	uint32_t now = unix_now(), expiry = TC_ADVTAG_EXPIRY_UNAVAILABLE;

	*p++ = 0x02u;
	*p++ = 0x01u;
	*p++ = 0x06u; /* LE general discoverable, no BR/EDR */
	if (!s_params || addr == NULL) {
		*p++ = 0x03u;
		*p++ = 0x03u; /* complete list of 16-bit service UUIDs */
		*p++ = 0xF2u;
		*p++ = 0xFFu;
		s_ad_len = (uint8_t)(p - s_ad);
		return expiry;
	}
	if (now >= TIME_FLOOR && now <= UINT32_MAX - TAG_VALID_S) {
		expiry = now + TAG_VALID_S;
	}
	for (int i = 0; i < 6; i++) {
		adva_msb[i] = addr[5 - i];
	}
	if (tc_advtag_derive(s_grk, adva_msb, expiry, tag) != 0) {
		LOG_ERR("dynamic tag derive failed");
		memset(tag, 0, sizeof(tag));
	}
	*p++ = 0x1Bu;
	*p++ = 0x16u; /* service data, 16-bit UUID */
	*p++ = 0xF2u;
	*p++ = 0xFFu;
	*p++ = 0x80u;
	*p++ = (uint8_t)s_txp;
	memcpy(p, s_group, sizeof(s_group));
	p += sizeof(s_group);
	memcpy(p, s_sub, sizeof(s_sub));
	p += sizeof(s_sub);
	*p++ = (uint8_t)(expiry >> 24);
	*p++ = (uint8_t)(expiry >> 16);
	*p++ = (uint8_t)(expiry >> 8);
	*p++ = (uint8_t)expiry;
	*p++ = 0x00u;
	memcpy(p, tag, sizeof(tag));
	p += sizeof(tag);
	s_ad_len = (uint8_t)(p - s_ad);
	return expiry;
}

static void adv_work_fn(struct k_work *w)
{
	uint32_t expiry;

	ARG_UNUSED(w);
	tb_zephyr_lock();
	if (!s_started || !s_adv_on) {
		tb_zephyr_unlock();
		return;
	}
	expiry = adv_build();
#if TB_SCAN_RSP
	tb_scan_rsp(NULL, 0u);
#endif
	tb_adv(s_ad, s_ad_len);
	tb_zephyr_unlock();
	if (expiry != TC_ADVTAG_EXPIRY_UNAVAILABLE) {
		/* A fresh tag before the phone's view of this one expires. */
		(void)k_work_reschedule(&s_adv_work, K_SECONDS(TAG_VALID_S - TAG_MARGIN_S));
	}
	LOG_INF("advertising %s", s_params ? "resolvable 0xFFF2 service data" : "bare 0xFFF2");
}

void tc_ble_tinyble_advertise(bool on)
{
	tb_zephyr_lock();
	s_adv_on = on;
	if (!on) {
		(void)k_work_cancel_delayable(&s_adv_work);
		tb_adv(NULL, 0u);
	} else {
		(void)k_work_reschedule(&s_adv_work, K_NO_WAIT);
	}
	tb_zephyr_unlock();
}

void tc_ble_tinyble_set_time(uint32_t unix_now_s)
{
	tb_zephyr_lock();
	s_unix_base = unix_now_s;
	s_unix_base_ms = tc_uptime_ms();
	tb_zephyr_unlock();
	tc_ble_time_updated();
}

void tc_ble_set_adv_params(const uint8_t group_id8[8], const uint8_t sub_id2[2],
			   const uint8_t grk[16], int8_t tx_power)
{
	tb_zephyr_lock();
	memcpy(s_group, group_id8, sizeof(s_group));
	memcpy(s_sub, sub_id2, sizeof(s_sub));
	memcpy(s_grk, grk, sizeof(s_grk));
	s_txp = tx_power;
	s_params = true;
	tb_zephyr_unlock();
}

void tc_ble_readvertise(void)
{
	(void)k_work_reschedule(&s_adv_work, K_NO_WAIT);
}

void tc_ble_time_updated(void)
{
	(void)k_work_reschedule(&s_adv_work, K_NO_WAIT);
}

/* ── Bring-up ────────────────────────────────────────────────────────────── *
 * tinyble is brought up by the Matter port (matter_ble_start()); the reader attaches to
 * it. Both of tinycred's start paths land here. */

int tc_ble_prepare(const struct tc_ble_config *cfg)
{
	if (cfg == NULL) {
		return -EINVAL;
	}
	s_cb = cfg->cb;
	return 0;
}

const struct ble_gatt_svc_def *tc_ble_service_def(void)
{
	return NULL; /* the service is in tinyble's table, nothing to register */
}

int tc_ble_start_attached(void)
{
	tb_zephyr_lock();
	s_started = true;
	tb_zephyr_unlock();
	return 0;
}

int tc_ble_start(const struct tc_ble_config *cfg)
{
	int rc = tc_ble_prepare(cfg);

	return rc != 0 ? rc : tc_ble_start_attached();
}

uint16_t tc_ble_spsm(void)
{
	return TB_COC_SPSM;
}

/* ── Marshalling onto the system workqueue, where the hooks run ──────────── */

static void (*s_status_cb)(bool);
static bool s_status_unsecured;
static void (*s_tick_cb)(void);
static void (*s_presence_cb)(void);
static void (*s_revoke_cb)(void);

static void status_work_fn(struct k_work *w)
{
	ARG_UNUSED(w);
	if (s_status_cb != NULL) {
		s_status_cb(s_status_unsecured);
	}
}
static K_WORK_DEFINE(s_status_work, status_work_fn);

static void tick_work_fn(struct k_work *w)
{
	ARG_UNUSED(w);
	if (s_tick_cb != NULL) {
		s_tick_cb();
	}
}
static K_WORK_DEFINE(s_tick_work, tick_work_fn);

static void presence_work_fn(struct k_work *w)
{
	ARG_UNUSED(w);
	if (s_presence_cb != NULL) {
		s_presence_cb();
	}
}
static K_WORK_DEFINE(s_presence_work, presence_work_fn);

static void revoke_work_fn(struct k_work *w)
{
	ARG_UNUSED(w);
	if (s_revoke_cb != NULL) {
		s_revoke_cb();
	}
}
static K_WORK_DEFINE(s_revoke_work, revoke_work_fn);

void tc_ble_post_reader_status(void (*cb)(bool unsecured), bool unsecured)
{
	s_status_cb = cb;
	s_status_unsecured = unsecured;
	k_work_submit(&s_status_work);
}

void tc_ble_post_reader_tick(void (*cb)(void))
{
	s_tick_cb = cb;
	k_work_submit(&s_tick_work);
}

void tc_ble_post_presence_reset(void (*cb)(void))
{
	s_presence_cb = cb;
	k_work_submit(&s_presence_work);
}

void tc_ble_post_revoke_sweep(void (*cb)(void))
{
	s_revoke_cb = cb;
	k_work_submit(&s_revoke_work);
}
