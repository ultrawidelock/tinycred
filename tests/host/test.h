/**
 * @file test.h — host-test harness: assertions + suite registry.
 *
 * T_OK/T_EQ for booleans and integers; t_vec/t_u32/t_u16 pin exact bytes. An
 * empty expect string RECORDS the value instead of checking it, so a new golden
 * is printed once and then baked in. Each module exposes one void
 * test_<module>(void); test_main.c runs them all and prints PASS/FAIL/RECORD.
 */
#ifndef TINYCRED_TEST_H
#define TINYCRED_TEST_H

#include <stddef.h>
#include <stdint.h>

extern int t_fail;
extern int t_pending;
extern int t_pass;

void t_hex(char *dst, const uint8_t *b, size_t n);
int t_unhex(uint8_t *dst, const char *hex, size_t cap);
void t_group(const char *name);
void t_vec(const char *name, const uint8_t *got, size_t len, const char *expect);
void t_u32(const char *name, uint32_t v, const char *expect);
void t_u16(const char *name, uint16_t v, const char *expect);
void t_ok_(const char *name, int cond, const char *file, int line);
void t_eqi_(const char *name, long got, long want, const char *file, int line);
#define T_OK(name, cond)      t_ok_((name), (cond), __FILE__, __LINE__)
#define T_EQ(name, got, want) t_eqi_((name), (long)(got), (long)(want), __FILE__, __LINE__)

void test_hash(void);
void test_assert(void);
void test_prov(void);
void test_approach(void);

#endif /* TINYCRED_TEST_H */
