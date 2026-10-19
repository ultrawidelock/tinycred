/** @file store_settings.c — tc_prov_load, tc_prov_store and tc_prov_erase on Zephyr's
 * settings subsystem: one record, "tinycred/prov", holding the serialized identity and
 * trust store. The blob is static and shared by load and store under one lock, because it
 * grows past 1 KiB with the issuer keys and the nRF52833 has no stack for a second copy.
 */

#include "tinycred/prov.h"

#include <errno.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/settings/settings.h>

#define TC_STORE_KEY "tinycred/prov"

K_MUTEX_DEFINE(s_lock);
static uint8_t s_blob[TC_PROV_BLOB_MAX];
static size_t s_blob_len;
static bool s_found;

static int load_cb(const char *key, size_t len, settings_read_cb read_cb, void *cb_arg,
		   void *param)
{
	ARG_UNUSED(param);
	if (strcmp(key, "prov") != 0) {
		return 0;
	}
	if (len > sizeof(s_blob)) {
		return -ENOSPC;
	}
	if (read_cb(cb_arg, s_blob, len) != (ssize_t)len) {
		return -EIO;
	}
	s_blob_len = len;
	s_found = true;
	return 0;
}

int tc_prov_load(struct tc_reader_identity *id, struct tc_trust_store *ts)
{
	int rc;

	k_mutex_lock(&s_lock, K_FOREVER);
	s_found = false;
	s_blob_len = 0u;
	rc = settings_subsys_init();
	if (rc == 0) {
		rc = settings_load_subtree_direct("tinycred", load_cb, NULL);
	}
	if (rc != 0) {
		tc_prov_dev_default(id, ts);
	} else if (!s_found) {
		tc_prov_dev_default(id, ts);
		rc = TC_PROV_LOAD_EMPTY;
	} else if (tc_prov_deserialize(s_blob, s_blob_len, id, ts) != 0) {
		tc_prov_dev_default(id, ts);
		rc = -EBADMSG;
	}
	k_mutex_unlock(&s_lock);
	return rc;
}

int tc_prov_store(const struct tc_reader_identity *id, const struct tc_trust_store *ts)
{
	size_t len = 0u;
	int rc;

	k_mutex_lock(&s_lock, K_FOREVER);
	rc = settings_subsys_init();
	if (rc == 0 && tc_prov_serialize(id, ts, s_blob, sizeof(s_blob), &len) != 0) {
		rc = -EINVAL;
	}
	if (rc == 0) {
		rc = settings_save_one(TC_STORE_KEY, s_blob, len);
	}
	k_mutex_unlock(&s_lock);
	return rc;
}

int tc_prov_erase(void)
{
	int rc;

	k_mutex_lock(&s_lock, K_FOREVER);
	rc = settings_subsys_init();
	if (rc == 0) {
		rc = settings_delete(TC_STORE_KEY);
		if (rc == -ENOENT) {
			rc = 0; /* never stored: the record is gone either way */
		}
	}
	k_mutex_unlock(&s_lock);
	return rc;
}
