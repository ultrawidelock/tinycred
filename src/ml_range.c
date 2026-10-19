/**
 * @file tc_ml_range.c — free-space spreading at a measured range, without libm.
 *
 * Removing 20*log10(d) normalises every reception to what it would have
 * measured at one metre; what is left is attenuation the range does not
 * explain, the classifier's strongest feature. log10f would cost tc_ml its
 * no-undefined-symbols property, so tc_ml_log2.c supplies the logarithm and
 * this file is only the change of base and the clamp. Accuracy does not bind:
 * even 2 dB rounding moves balanced accuracy by +0.0005, and the dominant
 * error is the reader's whole-centimetre range (~0.4 dB at the short end), not
 * the table (0.017 dB).
 */

#include "tinycred/ml.h"
#include "ml_log2.h"

/* Below this the correction diverges, and the reader does report 0 cm. Above it
 * the curve is flat enough that the clamp costs nothing a walk-up would notice.
 * Both bounds are mirrored in parse_alab.py (tinyml repo), which is what the model
 * was trained through. */
#define MIN_RANGE_CM 10u
#define MAX_RANGE_CM 2000u

/* 20*log10(x) = (20 / log2(10)) * log2(x), and the reference range is 1 m. */
#define K_DB_PER_LOG2 6.02059991f
#define LOG2_REF_CM   6.64385619f /* log2(100) */

float tc_ml_los_range_correction(uint16_t dist_cm)
{
	uint32_t d = dist_cm;

	if (d < MIN_RANGE_CM) {
		d = MIN_RANGE_CM;
	} else if (d > MAX_RANGE_CM) {
		d = MAX_RANGE_CM;
	}

	return K_DB_PER_LOG2 * (tc_ml_log2_u64(d) - LOG2_REF_CM);
}

float tc_ml_los_fp_resid(float fp_pwr_db, uint16_t dist_cm)
{
	return fp_pwr_db + tc_ml_los_range_correction(dist_cm);
}

/*
 * The two measured constants, in millimetres because both landed on a half
 * centimetre and rounding them here would be inventing precision in one
 * direction. RESULTS.md Result 19 is the measurement.
 *
 * ANTENNA_OFFSET is what this board reports short by, and it is not the model's:
 * nothing in this project has ever programmed the DW3000 antenna-delay
 * registers, so every range it produces carries a fixed offset. Two clear runs a
 * doubling of range apart measured -25.0 cm and -26.0 cm, agreeing to a
 * centimetre, which is the signature of an offset rather than a scale error.
 *
 * NLOS_BIAS is what a body in the path adds. Measured with the phone on a tripod
 * so only the subject moved: +80.0 cm at 1 m and +89.0 cm at 2 m, and the
 * difference between those two is +8.0 cm with a 95% interval of [-9, +17], so a
 * constant fits and a scale factor does not -- scaling would have predicted about
 * 160 cm at 2 m against an observed [73, 92].
 *
 * NLOS_BIAS DID NOT REPLICATE AND NOTHING SHOULD ENABLE IT. Result 21 repeated
 * the tripod capture with a second body at the same 100 cm and measured +115.0 cm
 * over all frames and +127.0 cm [+109, +136] at len=46, against session 1's +82.0
 * [+62, +93] in the same slice: the intervals do not overlap, so these are not two
 * estimates of one constant. What replicated was the CHANNEL, -10.1 dB and -9.6 dB
 * of first-path power in the two sessions, which is the classifier's input and not
 * this offset. The likeliest reason is that session 1's subject stood midway and
 * session 3's stood against the tripod, making the offset a function of where the
 * blocker is; session 1 could not have seen that, because it varied reader-to-phone
 * distance while holding blocker position fixed by accident.
 *
 * Subtracting the wrong amount fails in the dangerous direction -- a phone genuinely
 * at 185 cm reads as 100 and the door opens for a walk-by -- so tc_approach's
 * cfg.range_correct_en defaults false and should stay there. The supportable use of
 * the classifier is to WIDEN unlock_cm while obstructed, which needs the sign of the
 * effect (replicated) rather than its magnitude (not replicated).
 *
 * ANTENNA_OFFSET is unaffected: -25.0, -26.0, -21.0 and -24.0 cm across four clear
 * runs in two sessions is still an offset.
 */
#define ANTENNA_OFFSET_MM 255
#define NLOS_BIAS_MM      845

uint16_t tc_ml_los_range_true_cm(uint16_t reported_cm, enum tc_ml_los_class c)
{
	int32_t mm = (int32_t)reported_cm * 10 + ANTENNA_OFFSET_MM;

	if (c == TC_ML_LOS_OBSTRUCTED) {
		mm -= NLOS_BIAS_MM;
	}

	/* An obstructed reception at very short range can correct below zero, and
	 * a negative distance is not a smaller distance -- it is a reading the
	 * correction had no business being applied to. Clamped rather than
	 * signed, because every caller of this compares against a threshold in
	 * unsigned centimetres and a wrap would read as very far away. */
	if (mm < 0) {
		mm = 0;
	}

	return (uint16_t)((mm + 5) / 10);
}
