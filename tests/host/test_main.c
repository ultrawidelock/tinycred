/** @file test_main.c — runs every harness suite; exit status is the verdict. */
#include <stdio.h>

#include "test.h"

int main(void)
{
	static const struct {
		const char *name;
		void (*fn)(void);
	} suites[] = {
		{"hash", test_hash},
		{"assert", test_assert},
		{"prov", test_prov},
		{"approach", test_approach},
	};

	for (size_t i = 0; i < sizeof(suites) / sizeof(suites[0]); i++) {
		int fail0 = t_fail;

		suites[i].fn();
		printf("%-8s %s\n", suites[i].name, t_fail == fail0 ? "ok" : "FAIL");
	}
	printf("%d passed, %d failed, %d to record\n", t_pass, t_fail, t_pending);
	return (t_fail == 0 && t_pending == 0) ? 0 : 1;
}
