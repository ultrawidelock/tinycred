/** @file fakes.c — the suite's doubles for the BLE transport, the provisioning store and
 * the ranging bridge, enough for reader.c to link; the standalone reader program carries
 * fuller recording versions of the same. */
#include <string.h>

#include "tinycred/ble.h"
#include "tinycred/prov.h"
#include "tinycred/ranging.h"
#include "tinycred/reader.h"

int tc_ble_start(const struct tc_ble_config *cfg)
{
	(void)cfg;
	return 0;
}

int tc_ble_prepare(const struct tc_ble_config *cfg)
{
	(void)cfg;
	return 0;
}

const struct ble_gatt_svc_def *tc_ble_service_def(void)
{
	return NULL;
}

int tc_ble_start_attached(void)
{
	return 0;
}

uint16_t tc_ble_spsm(void)
{
	return 0x0080u;
}

int tc_ble_send(uint16_t conn_handle, const uint8_t *data, size_t len)
{
	(void)conn_handle;
	(void)data;
	(void)len;
	return 0;
}

int tc_ble_disconnect(uint16_t conn_handle)
{
	(void)conn_handle;
	return 0;
}

void tc_ble_post_reader_status(void (*cb)(bool unsecured), bool unsecured)
{
	cb(unsecured);
}

void tc_ble_post_reader_tick(void (*cb)(void))
{
	cb();
}

void tc_ble_post_presence_reset(void (*cb)(void))
{
	cb();
}

void tc_ble_post_revoke_sweep(void (*cb)(void))
{
	cb();
}

void tc_ble_set_adv_params(const uint8_t group_id8[8], const uint8_t sub_id2[2],
			   const uint8_t grk[16], int8_t tx_power)
{
	(void)group_id8;
	(void)sub_id2;
	(void)grk;
	(void)tx_power;
}

void tc_ble_readvertise(void)
{
}

int tc_prov_load(struct tc_reader_identity *id, struct tc_trust_store *ts)
{
	tc_prov_dev_default(id, ts);
	return TC_PROV_LOAD_EMPTY;
}

int tc_prov_store(const struct tc_reader_identity *id, const struct tc_trust_store *ts)
{
	(void)id;
	(void)ts;
	return 0;
}

int tc_ranging_init(void)
{
	return 0;
}

int tc_ranging_start(uint16_t conn_handle, uint32_t session_id, const uint8_t *ursk,
		     struct tc_secchan *sc_ble)
{
	(void)conn_handle;
	(void)session_id;
	(void)ursk;
	(void)sc_ble;
	return 0;
}

int tc_ranging_feed(uint16_t conn_handle, const uint8_t *data, size_t len)
{
	(void)conn_handle;
	(void)data;
	(void)len;
	return -1;
}

void tc_ranging_stop(uint16_t conn_handle)
{
	(void)conn_handle;
}

bool tc_ranging_last_range_age_ms(int64_t *age_ms_out)
{
	(void)age_ms_out;
	return false;
}
