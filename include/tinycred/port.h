/** @file port.h — what tinycred asks of the platform: a clock, a mutex, one atomic exchange,
 * work items, a semaphore, one thread, and the log macros. Two backends: Zephyr (the target)
 * and the host test double (TC_PORT_HOST), whose work and clock are driven by the suite
 * through port/host/osal_host.c.
 */

#ifndef TINYCRED_PORT_H
#define TINYCRED_PORT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct tc_work;
struct tc_dwork;
typedef void (*tc_work_fn)(struct tc_work *work);
typedef void (*tc_dwork_fn)(struct tc_dwork *dwork);

#define TC_WAIT_FOREVER (-1)

enum tc_thread_prio {
	TC_THREAD_PRIO_LOW,
	TC_THREAD_PRIO_NORM,
	TC_THREAD_PRIO_HIGH,
};

#if defined(__ZEPHYR__)

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/atomic.h>

static inline int64_t tc_uptime_ms(void)
{
	return k_uptime_get();
}

static inline int64_t tc_uptime_us(void)
{
	return k_ticks_to_us_floor64(k_uptime_ticks());
}

static inline void tc_sleep_ms(int32_t ms)
{
	k_msleep(ms);
}

typedef struct k_mutex tc_mutex_t;

static inline void tc_mutex_init(tc_mutex_t *m)
{
	k_mutex_init(m);
}

static inline void tc_mutex_lock(tc_mutex_t *m)
{
	k_mutex_lock(m, K_FOREVER);
}

static inline int tc_mutex_trylock(tc_mutex_t *m)
{
	return k_mutex_lock(m, K_NO_WAIT);
}

static inline void tc_mutex_unlock(tc_mutex_t *m)
{
	k_mutex_unlock(m);
}

typedef atomic_t tc_atomic_t;

static inline long tc_atomic_xchg(tc_atomic_t *a, long val)
{
	return (long)atomic_set(a, (atomic_val_t)val);
}

struct tc_work {
	struct k_work kw;
	tc_work_fn fn;
};

struct tc_dwork {
	struct k_work_delayable kw;
	tc_dwork_fn fn;
};

typedef struct k_sem tc_sem_t;
typedef struct {
	struct k_thread thread;
} tc_thread_t;
typedef k_thread_stack_t tc_thread_stack_t;
#define TC_THREAD_STACK_DEFINE(name, size) K_THREAD_STACK_DEFINE(name, size)
#define TC_THREAD_STACK_SIZEOF(name)       K_THREAD_STACK_SIZEOF(name)

#elif defined(TC_PORT_HOST)

#include <stdio.h>

int64_t tc_osal_host_now_ms(void);

static inline int64_t tc_uptime_ms(void)
{
	return tc_osal_host_now_ms();
}

static inline int64_t tc_uptime_us(void)
{
	return tc_osal_host_now_ms() * 1000;
}

static inline void tc_sleep_ms(int32_t ms)
{
	(void)ms;
}

/* A held-depth counter, never a blocking object: the suite is single-threaded, but
 * trylock has to be able to fail so the branch a caller takes without the lock is real. */
typedef int tc_mutex_t;

static inline void tc_mutex_init(tc_mutex_t *m)
{
	*m = 0;
}

static inline void tc_mutex_lock(tc_mutex_t *m)
{
	*m += 1;
}

static inline int tc_mutex_trylock(tc_mutex_t *m)
{
	if (*m != 0) {
		return -1;
	}
	*m = 1;
	return 0;
}

static inline void tc_mutex_unlock(tc_mutex_t *m)
{
	if (*m > 0) {
		*m -= 1;
	}
}

typedef long tc_atomic_t;

static inline long tc_atomic_xchg(tc_atomic_t *a, long val)
{
	long old = *a;

	*a = val;
	return old;
}

struct tc_work {
	tc_work_fn fn;
	struct tc_work *next;
	int pending;
};

struct tc_dwork {
	tc_dwork_fn fn;
	struct tc_dwork *next;
	int64_t deadline_ms;
	int pending;
};

typedef struct {
	unsigned count;
	unsigned limit;
} tc_sem_t;

/* Host threads never run: create() records the entry and the suite calls it. */
typedef struct {
	void (*entry)(void *arg);
	void *arg;
	const char *name;
	int created;
} tc_thread_t;
typedef uint8_t tc_thread_stack_t;
#define TC_THREAD_STACK_DEFINE(name, size) static uint8_t name[(size)]
#define TC_THREAD_STACK_SIZEOF(name)       sizeof(name)

/* Suite controls. */
void tc_osal_host_reset(void);
unsigned tc_osal_host_flush(void);
unsigned tc_osal_host_advance_ms(int64_t ms);

#define LOG_LEVEL_NONE 0
#define LOG_LEVEL_ERR  1
#define LOG_LEVEL_WRN  2
#define LOG_LEVEL_INF  3
#define LOG_LEVEL_DBG  4
#define LOG_MODULE_REGISTER(...)
#define LOG_MODULE_DECLARE(...)
#define LOG_ERR(...)             ((void)0)
#define LOG_WRN(...)             ((void)0)
#define LOG_INF(...)             ((void)0)
#define LOG_DBG(...)             ((void)0)
#define LOG_PRINTK(...)          printf(__VA_ARGS__)
#define LOG_HEXDUMP_ERR(p, l, s) ((void)0)
#define LOG_HEXDUMP_WRN(p, l, s) ((void)0)
#define LOG_HEXDUMP_INF(p, l, s) ((void)0)
#define LOG_HEXDUMP_DBG(p, l, s) ((void)0)

#else
#error "tinycred/port.h: build under Zephyr or define TC_PORT_HOST"
#endif

/* The contract, identical on both backends (port/host/osal_host.c, port/zephyr/osal.c). */
void tc_work_init(struct tc_work *work, tc_work_fn fn);
int tc_work_submit(struct tc_work *work);
void tc_dwork_init(struct tc_dwork *dwork, tc_dwork_fn fn);
int tc_dwork_schedule(struct tc_dwork *dwork, int32_t delay_ms);
int tc_dwork_reschedule(struct tc_dwork *dwork, int32_t delay_ms);
int tc_dwork_cancel(struct tc_dwork *dwork);
void tc_sem_init(tc_sem_t *sem, unsigned initial, unsigned limit);
void tc_sem_give(tc_sem_t *sem);
int tc_sem_take(tc_sem_t *sem, int32_t timeout_ms);
void tc_sem_reset(tc_sem_t *sem);
int tc_thread_create(tc_thread_t *thread, tc_thread_stack_t *stack, size_t stack_size,
		     void (*entry)(void *arg), void *arg, enum tc_thread_prio prio,
		     const char *name);

/* ── Walk-up latency marks and lab traces: diagnostics ultrawidelock carried; here they
 * compile to nothing, the phase names stay so the call sites read. ───────── */

enum tc_lat_phase {
	TC_LAT_BLE_CONNECT = 0,
	TC_LAT_GATT_SPSM_READ,
	TC_LAT_GATT_VER_WRITE,
	TC_LAT_L2CAP_OPEN,
	TC_LAT_OP05_RX,
	TC_LAT_AUTH0_TX,
	TC_LAT_AUTH0_RSP,
	TC_LAT_AUTH1_DONE,
	TC_LAT_EXCHANGE_DONE,
	TC_LAT_AP_COMPLETED,
	TC_LAT_IRS_RX,
	TC_LAT_M1_TX,
	TC_LAT_M2_RX,
	TC_LAT_M3_TX,
	TC_LAT_M4_RX,
	TC_LAT_M4_DONE,
	TC_LAT_FIRST_RANGE,
	TC_LAT_TRUSTED_RANGE,
	TC_LAT_NEAR_DWELL,
	TC_LAT_BOLT_DRIVEN,
	TC_LAT_PHASE_COUNT
};

#define tc_lat_begin()           ((void)0)
#define tc_lat_mark(phase)       ((void)(phase), 0)
#define tc_lat_report()          ((void)0)
#define tc_lab_set_enabled(on)   ((void)(on))
#define tc_lab_enabled()         false
#define tc_lab_ev(ev)            ((void)(ev))
#define tc_lab_evi(ev, k, v)     ((void)(ev), (void)(k), (void)(v))
#define tc_lab_evi2(ev, k1, v1, k2, v2)                                                      \
	((void)(ev), (void)(k1), (void)(v1), (void)(k2), (void)(v2))
#define tc_lab_dump()            ((void)0)

#endif /* TINYCRED_PORT_H */
