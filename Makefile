# tinycred host build: the harness suite, the standalone suites carried from ultrawidelock,
# sanitizers, and the Cortex-M4 size gate.

export LC_ALL := C
BUILD := build/host

CSTD := -std=c11 -O1
WARN := -Wall -Wextra -Wformat -Wformat-security -Wpointer-arith -Werror -Wno-unused-parameter -Wno-unused-function -Wno-deprecated-declarations
SAN := -g -fsanitize=address,undefined -fno-sanitize-recover=all
DEFS := -DTC_PORT_HOST -DCONFIG_TINYCRED_STEPUP=1 -DCONFIG_TINYCRED_RSSI_GATE=1 \
	-DCONFIG_TINYCRED_ML_LOS=1 -DCONFIG_TINYCRED_ACCESS_LISTENER=1

INCS := -Iinclude -Isrc -Iport/host/include
# ranging.c needs tinyuwb and is built on the target and in its own test.
CORE := src/hash.c src/crypto.c src/ber.c src/apdu.c src/prov.c src/assert.c src/assert_ec.c \
	src/approach.c src/advtag.c src/rssi_gate.c src/stepup.c src/stepup_parse.c \
	src/stepup_wire.c src/reader.c src/device.c src/device_apdu.c \
	src/ml_los.c src/ml_lin.c src/ml_feat.c src/ml_range.c src/ml_log2.c
HOST_PORT := port/host/hash_host.c port/host/prim_host.c port/host/osal_host.c
HDRS := $(wildcard include/tinycred/*.h) $(wildcard src/*.h) $(wildcard port/host/include/*.h)
SUITE := tests/host/test.c tests/host/test_main.c tests/host/fakes.c tests/host/test_hash.c \
	tests/host/test_assert.c tests/host/test_prov.c tests/host/test_approach.c
# Standalone programs: each carries its own main and transport doubles.
STANDALONE := crypto apdu prov assert_ec device reader stepup

ARM_CC ?= arm-none-eabi-gcc
ARM_SIZE ?= $(patsubst %gcc,%size,$(ARM_CC))
ARM_FLAGS := -std=c11 -Os -mcpu=cortex-m4 -mthumb -mabi=aapcs -ffunction-sections \
	-fdata-sections -fno-common $(WARN) -D__ZEPHYR__ -Iinclude -Isrc

.PHONY: test asan size clean

$(BUILD)/suite: $(CORE) $(HOST_PORT) $(SUITE) $(HDRS)
	@mkdir -p $(@D)
	$(CC) $(CSTD) $(WARN) $(DEFS) $(INCS) -Itests/host $(CORE) $(HOST_PORT) $(SUITE) -o $@

$(BUILD)/suite-asan: $(CORE) $(HOST_PORT) $(SUITE) $(HDRS)
	@mkdir -p $(@D)
	$(CC) $(CSTD) $(SAN) $(WARN) $(DEFS) $(INCS) -Itests/host $(CORE) $(HOST_PORT) $(SUITE) -o $@

# The reader program carries its own transport, store and ranging doubles; the others take
# the suite's.
define standalone_rule
$(BUILD)/$(1): tests/standalone/$(1).c $(CORE) $(HOST_PORT) $(HDRS) tests/host/fakes.c
	@mkdir -p $$(@D)
	$(CC) $(CSTD) $(WARN) $(DEFS) $(INCS) -Itests/standalone tests/standalone/$(1).c $(CORE) $(HOST_PORT) $(if $(filter reader,$(1)),,tests/host/fakes.c) -o $$@
$(BUILD)/$(1)-asan: tests/standalone/$(1).c $(CORE) $(HOST_PORT) $(HDRS) tests/host/fakes.c
	@mkdir -p $$(@D)
	$(CC) $(CSTD) $(SAN) $(WARN) $(DEFS) $(INCS) -Itests/standalone tests/standalone/$(1).c $(CORE) $(HOST_PORT) $(if $(filter reader,$(1)),,tests/host/fakes.c) -o $$@
endef
$(foreach s,$(STANDALONE),$(eval $(call standalone_rule,$(s))))

test: $(BUILD)/suite $(foreach s,$(STANDALONE),$(BUILD)/$(s))
	$(BUILD)/suite
	@for s in $(STANDALONE); do echo "== $$s"; $(BUILD)/$$s > $(BUILD)/$$s.log || { tail -20 $(BUILD)/$$s.log; exit 1; }; tail -1 $(BUILD)/$$s.log; done

asan: $(BUILD)/suite-asan $(foreach s,$(STANDALONE),$(BUILD)/$(s)-asan)
	$(BUILD)/suite-asan
	@for s in $(STANDALONE); do echo "== $$s"; $(BUILD)/$$s-asan > $(BUILD)/$$s-asan.log || { tail -20 $(BUILD)/$$s-asan.log; exit 1; }; tail -1 $(BUILD)/$$s-asan.log; done

clean:
	rm -rf build
