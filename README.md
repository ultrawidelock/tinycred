# tinycred

A digital-key credential reader: the Aliro access protocol over a BLE L2CAP
channel, then UWB ranging on tinyuwb, then a predictive approach unlock that
opens the bolt as the phone arrives. Portable C11.

**Does** reader identity and trust store, AUTH0, AUTH1 and EXCHANGE, M1-M4
ranging setup, an RSSI gate before ranging. Optional: step-up, a
line-of-sight classifier, the phone side for bench tests.

12,955 B flash, 6,807 B RAM, LTO release build.

## Use

```conf
CONFIG_TINYCRED=y
```

Needs tinyble, tinypsa and tinyuwb. Identity and trust store live in
settings (`tinycred/prov`). Tunables: `zephyr/Kconfig`.

## Test

```sh
make test   # host suite and standalone programs
make asan
```

Apache-2.0
