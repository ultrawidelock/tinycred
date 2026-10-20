# SPDX-FileCopyrightText: 2026 Aseem Chopra
# SPDX-License-Identifier: Apache-2.0

if(CONFIG_TINYCRED)
  zephyr_include_directories(../include)
  zephyr_library()
  zephyr_library_include_directories(../src)
  zephyr_library_sources(
    ../src/hash.c ../src/crypto.c ../src/ber.c ../src/apdu.c ../src/prov.c
    ../src/assert.c ../src/assert_ec.c ../src/approach.c ../src/advtag.c
    ../src/reader.c ../src/ranging.c
    ../port/zephyr/osal_zephyr.c ../port/zephyr/prim_tinypsa.c
    ../port/zephyr/store_settings.c)
  zephyr_library_sources_ifdef(CONFIG_TINYCRED_RSSI_GATE ../src/rssi_gate.c)
  zephyr_library_sources_ifdef(CONFIG_TINYCRED_STEPUP
    ../src/stepup.c ../src/stepup_parse.c ../src/stepup_wire.c)
  zephyr_library_sources_ifdef(CONFIG_TINYCRED_ML_LOS
    ../src/ml_los.c ../src/ml_lin.c ../src/ml_feat.c ../src/ml_range.c ../src/ml_log2.c)
  zephyr_library_sources_ifdef(CONFIG_TINYCRED_DEVICE ../src/device.c ../src/device_apdu.c)
  zephyr_library_sources_ifdef(CONFIG_TINYCRED_TINYBLE ../port/tinyble/ble_tinyble.c)
endif()
