/* SPDX-FileCopyrightText: 2026 Aseem Chopra */
/* SPDX-License-Identifier: Apache-2.0 */

/*
 * osal_host.c - the host backend of tc_osal.h, which IS the test double.
 *
 * A FIFO for immediate work, a deadline-ordered list for delayable work, and
 * a virtual clock the suite steps (tc_osal_host_advance_ms / _flush). Runs
 * single-threaded and deterministic: nothing fires until the suite says time
 * passed. tc_sem_take with a timeout advances the clock itself, running
 * delayable work that falls due, so a handler's give can satisfy the take
 * without a second thread.
 */
#if defined(TC_PORT_HOST)

#include "tinycred/port.h"

/* ---- state ---------------------------------------------------------------- */

static struct tc_work *g_work_head, *g_work_tail;
static struct tc_dwork *g_dwork_head; /* deadline-ordered, FIFO among equals */
static int64_t g_now_ms;

#define TC_OSAL_HOST_MAX_INIT 16
static int (*g_init_fns[TC_OSAL_HOST_MAX_INIT])(void);
static unsigned g_init_count;
static int g_init_ran;

/* ---- init hooks ------------------------------------------------------------ */

void tc_osal_init_register(int (*fn)(void))
{
	if (g_init_count < TC_OSAL_HOST_MAX_INIT) {
		g_init_fns[g_init_count++] = fn;
	}
}

int tc_osal_init_all(void)
{
	int rc = 0;

	if (g_init_ran) {
		return 0;
	}
	g_init_ran = 1;
	for (unsigned i = 0; i < g_init_count; i++) {
		int r = g_init_fns[i]();

		if (r != 0 && rc == 0) {
			rc = r;
		}
	}
	return rc;
}

/* ---- immediate work -------------------------------------------------------- */

void tc_work_init(struct tc_work *work, tc_work_fn fn)
{
	work->fn = fn;
	work->next = NULL;
	work->pending = 0;
}

int tc_work_submit(struct tc_work *work)
{
	if (work->pending) {
		return 0;
	}
	work->pending = 1;
	work->next = NULL;
	if (g_work_tail) {
		g_work_tail->next = work;
	} else {
		g_work_head = work;
	}
	g_work_tail = work;
	return 0;
}

unsigned tc_osal_host_flush(void)
{
	/* Snapshot the queue: what these handlers submit waits for the next
	 * flush, so a self-resubmitting handler is stepped, not spun on. */
	struct tc_work *w = g_work_head;
	unsigned ran = 0;

	g_work_head = g_work_tail = NULL;
	while (w) {
		struct tc_work *next = w->next;

		w->next = NULL;
		w->pending = 0;
		w->fn(w);
		ran++;
		w = next;
	}
	return ran;
}

/* ---- delayable work -------------------------------------------------------- */

void tc_dwork_init(struct tc_dwork *dwork, tc_dwork_fn fn)
{
	dwork->fn = fn;
	dwork->next = NULL;
	dwork->deadline_ms = 0;
	dwork->pending = 0;
}

static void dwork_insert(struct tc_dwork *dwork)
{
	struct tc_dwork **at = &g_dwork_head;

	while (*at && (*at)->deadline_ms <= dwork->deadline_ms) {
		at = &(*at)->next;
	}
	dwork->next = *at;
	*at = dwork;
}

static void dwork_remove(struct tc_dwork *dwork)
{
	struct tc_dwork **at = &g_dwork_head;

	while (*at) {
		if (*at == dwork) {
			*at = dwork->next;
			dwork->next = NULL;
			return;
		}
		at = &(*at)->next;
	}
}

int tc_dwork_schedule(struct tc_dwork *dwork, int32_t delay_ms)
{
	if (dwork->pending) {
		return 0; /* the earlier deadline stands */
	}
	dwork->pending = 1;
	dwork->deadline_ms = g_now_ms + delay_ms;
	dwork_insert(dwork);
	return 0;
}

int tc_dwork_reschedule(struct tc_dwork *dwork, int32_t delay_ms)
{
	if (dwork->pending) {
		dwork_remove(dwork);
	}
	dwork->pending = 1;
	dwork->deadline_ms = g_now_ms + delay_ms;
	dwork_insert(dwork);
	return 0;
}

int tc_dwork_cancel(struct tc_dwork *dwork)
{
	if (dwork->pending) {
		dwork_remove(dwork);
		dwork->pending = 0;
	}
	return 0;
}

unsigned tc_osal_host_advance_ms(int64_t ms)
{
	int64_t target = g_now_ms + ms;
	unsigned ran = 0;

	while (g_dwork_head && g_dwork_head->deadline_ms <= target) {
		struct tc_dwork *due = g_dwork_head;

		g_now_ms = due->deadline_ms > g_now_ms ? due->deadline_ms : g_now_ms;
		g_dwork_head = due->next;
		due->next = NULL;
		due->pending = 0; /* cleared first, so the handler may re-arm */
		due->fn(due);
		ran++;
	}
	g_now_ms = target;
	return ran;
}

int64_t tc_osal_host_now_ms(void)
{
	return g_now_ms;
}

/* ---- semaphore ------------------------------------------------------------- */

void tc_sem_init(tc_sem_t *sem, unsigned initial, unsigned limit)
{
	sem->count = initial;
	sem->limit = limit;
}

void tc_sem_give(tc_sem_t *sem)
{
	if (sem->count < sem->limit) {
		sem->count++;
	}
}

int tc_sem_take(tc_sem_t *sem, int32_t timeout_ms)
{
	if (sem->count > 0) {
		sem->count--;
		return 0;
	}
	if (timeout_ms == 0) {
		return -1;
	}

	/* Single-threaded: the only sources of a give are queued handlers.
	 * Run what is already queued, then walk delayable work forward inside
	 * the window until a give lands or the window (or the work) runs out. */
	tc_osal_host_flush();
	if (timeout_ms < 0) {
		while (sem->count == 0 && g_dwork_head) {
			tc_osal_host_advance_ms(g_dwork_head->deadline_ms - g_now_ms);
			tc_osal_host_flush();
		}
	} else {
		int64_t target = g_now_ms + timeout_ms;

		while (sem->count == 0 && g_dwork_head &&
		       g_dwork_head->deadline_ms <= target) {
			tc_osal_host_advance_ms(g_dwork_head->deadline_ms - g_now_ms);
			tc_osal_host_flush();
		}
		if (target > g_now_ms) {
			g_now_ms = target; /* the rest of the wait elapses idle */
		}
	}
	if (sem->count > 0) {
		sem->count--;
		return 0;
	}
	return -1;
}

void tc_sem_reset(tc_sem_t *sem)
{
	sem->count = 0;
}

/* ---- thread ---------------------------------------------------------------- */

int tc_thread_create(tc_thread_t *thread, tc_thread_stack_t *stack,
				size_t stack_size, void (*entry)(void *arg), void *arg,
				enum tc_thread_prio prio, const char *name)
{
	(void)stack;
	(void)stack_size;
	(void)prio;
	thread->entry = entry;
	thread->arg = arg;
	thread->name = name;
	thread->created = 1;
	return 0;
}

/* ---- reset ------------------------------------------------------------------ */

void tc_osal_host_reset(void)
{
	while (g_work_head) {
		struct tc_work *w = g_work_head;

		g_work_head = w->next;
		w->next = NULL;
		w->pending = 0;
	}
	g_work_tail = NULL;
	while (g_dwork_head) {
		struct tc_dwork *d = g_dwork_head;

		g_dwork_head = d->next;
		d->next = NULL;
		d->pending = 0;
	}
	g_now_ms = 0;
}

#endif /* TC_PORT_HOST */
