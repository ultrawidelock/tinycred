/* SPDX-FileCopyrightText: 2026 Aseem Chopra */
/* SPDX-License-Identifier: Apache-2.0 */

/**
 * @file tc_ml_lin.c — how sure the tree is, which the tree itself cannot say.
 *
 * A single decision tree's leaf IS its class, so tc_ml_los_classify() answers
 * "obstructed" and has no second quantity to offer. This supplies one: the
 * distance from a linear boundary fitted on the same two features, which was
 * measured to separate the receptions the tree gets right from the ones it gets
 * wrong. See tc_ml.h for the measurement.
 *
 * The coefficients are generated; only the arithmetic is written by hand, and
 * there is not much of it.
 */

#include "tinycred/ml.h"
#include "ml_los_lin.h"

float tc_ml_los_confidence(const float feat[TC_ML_LOS_N_FEATURES])
{
	float m = tc_ml_los_lin_bias;

	for (int i = 0; i < TC_ML_LOS_N_FEATURES; i++) {
		m += tc_ml_los_lin_w[i] * feat[i];
	}

	/* Deliberately not fabsf(): this module's claim is that
	 * `arm-none-eabi-nm -u` on its objects is empty, and a ternary cannot
	 * put that claim at the mercy of whether a given compiler treats fabsf
	 * as a builtin. It compiles to the same single instruction on a M4F. */
	return (m < 0.0f) ? -m : m;
}
