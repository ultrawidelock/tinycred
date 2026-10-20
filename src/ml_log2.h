/* SPDX-FileCopyrightText: 2026 Aseem Chopra */
/* SPDX-License-Identifier: Apache-2.0 */

/**
 * @file tc_ml_log2.h — base-2 logarithm of an integer, without libm.
 *
 * Internal to tc_ml and deliberately not in include/: it is not a general
 * numeric utility and its accuracy is only justified for the two callers it has.
 *
 * Both of those callers want a logarithm of a positive integer and neither can
 * afford log10f. Pulling in libm would cost this module the one property its
 * README claims and `arm-none-eabi-nm -u` can check: not a single undefined
 * symbol, so the size that was measured is the whole size on every target
 * modules/ builds for.
 */
#ifndef TC_ML_LOG2_H
#define TC_ML_LOG2_H

#include <stdint.h>

/**
 * log2(v), from the leading-bit position plus a table of log2(1 + x).
 *
 * @param v  strictly positive. Zero returns 0.0f rather than diverging, because
 *           a defined answer beats undefined behaviour on a register read that
 *           failed; callers reject a zero before they get here, since a zeroed
 *           CIA register is a failed read rather than a very weak channel.
 *
 * 64-bit and not 32-bit because tc_ml_feat.c needs log2 of a 17-bit channel
 * area shifted left by 17 and of a sum of three squares, neither of which fits.
 * The range correction shares it rather than keeping a second copy of the same
 * table.
 *
 * Maximum error against float64 is 0.0029 in log2 units, which is 0.0086 dB
 * through a 10*log10 and 0.017 dB through a 20*log10. That is an order of
 * magnitude under the 0.183 dB the range correction already accepts from
 * centimetre-quantised input, so it is not the term that matters. See
 * tc_ml_log2.c.
 */
float tc_ml_log2_u64(uint64_t v);

#endif /* TC_ML_LOG2_H */
