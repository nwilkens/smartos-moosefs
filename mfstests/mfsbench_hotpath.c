/*
 * MooseFS Hot-Path Micro-Benchmark
 *
 * Tests the performance of optimized hot paths:
 *   1. CRC32 (hardware vs software)
 *   2. pcqueue put/get throughput (free-list vs malloc)
 *   3. RNG throughput (TLS vs mutex, single & multi-thread)
 *   4. Atomic stats vs mutex stats (simulated contention)
 *
 * Build:
 *   make mfsbench_hotpath    (via Makefile.am)
 * Or manually:
 *   gcc -O2 -I../mfscommon -DHAVE_CONFIG_H -D_USE_PTHREADS \
 *     -mpclmul -msse4.1 -pthread \
 *     mfsbench_hotpath.c ../mfscommon/crc.c ../mfscommon/crc_pclmul.c \
 *     ../mfscommon/clocks.c ../mfscommon/random.c ../mfscommon/pcqueue.c \
 *     -lm -o mfsbench_hotpath
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <pthread.h>

#include "config.h"
#include "clocks.h"
#include "crc.h"
#include "crc_pclmul.h"
#include "random.h"
#include "pcqueue.h"

/* ------------------------------------------------------------------ */
/*  Helpers                                                           */
/* ------------------------------------------------------------------ */

static double bench_overhead(void) {
	int k;
	double best = 1e9;
	for (k = 0; k < 10; k++) {
		double t0 = monotonic_seconds();
		double t1 = monotonic_seconds();
		double d = t1 - t0;
		if (d < best) best = d;
	}
	return best;
}

static inline double elapsed_safe(double t0, double t1, double corr) {
	double e = t1 - t0 - corr;
	return e > 1e-9 ? e : 1e-9;
}

#define BENCH_CRC_BYTES  (256ULL * 1048576ULL)  /* 256 MB total per measurement */
#define BENCH_ITERS_Q    2000000
#define BENCH_ITERS_RNG  5000000
#define BENCH_THREADS    4

/* ------------------------------------------------------------------ */
/*  1. CRC32 benchmark: hardware vs software                         */
/* ------------------------------------------------------------------ */

/* Declared in crc.c as static; we access software path via
 * a trick: call mycrc32 with hw disabled, then with hw enabled.
 * Since we can't easily toggle the function pointer at runtime,
 * we just call mycrc32_pclmul directly for the hw path and
 * implement a minimal software CRC for comparison. */

static uint32_t crc_table_bench[256];

static void bench_crc_init(void) {
	uint32_t c, i, j;
	for (i = 0; i < 256; i++) {
		c = i;
		for (j = 0; j < 8; j++)
			c = (c & 1) ? (0xEDB88320U ^ (c >> 1)) : (c >> 1);
		crc_table_bench[i] = c;
	}
}

static uint32_t bench_crc_sw(uint32_t crc, const uint8_t *buf, uint32_t len) {
	crc ^= 0xFFFFFFFF;
	while (len--)
		crc = crc_table_bench[(crc ^ *buf++) & 0xFF] ^ (crc >> 8);
	return crc ^ 0xFFFFFFFF;
}

static volatile uint32_t crc_sink;

static void bench_crc32(void) {
	uint8_t *block;
	uint32_t crc;
	double t0, t1, corr;
	int i;
	uint32_t sizes[] = {64, 1024, 65536, 1048576, 16*1048576};
	int nsizes = sizeof(sizes) / sizeof(sizes[0]);
	int s;

	printf("=== CRC32 Benchmark ===\n");
	printf("%-12s  %14s  %14s  %14s  %8s\n",
	       "BlockSize", "mycrc32 MB/s", "pclmul MB/s", "ref(1tab) MB/s", "hw/sw");

	block = malloc(16 * 1048576);
	if (!block) { printf("alloc failed\n"); return; }
	memset(block, 0x5A, 16 * 1048576);
	bench_crc_init();
	mycrc32_init();

	corr = bench_overhead();

	for (s = 0; s < nsizes; s++) {
		uint32_t sz = sizes[s];
		int iters = (int)(BENCH_CRC_BYTES / sz);
		if (iters < 2) iters = 2;
		double mycrc_mbs, hw_mbs, ref_mbs;

		/* mycrc32 (current implementation - may be hw or sw depending on CPU) */
		t0 = monotonic_seconds();
		for (i = 0; i < iters; i++)
			crc = mycrc32(0, block, sz);
		t1 = monotonic_seconds();
		crc_sink = crc;
		mycrc_mbs = ((double)sz * iters) / (elapsed_safe(t0, t1, corr) * 1048576.0);

		/* pclmul direct (hardware path, if available) */
#ifdef HAVE_PCLMULQDQ
		if (mycrc32_hw_available() && sz >= 64) {
			uint32_t hw_leng = sz & ~(uint32_t)15;
			t0 = monotonic_seconds();
			for (i = 0; i < iters; i++)
				crc = ~mycrc32_pclmul(~0U, block, hw_leng);
			t1 = monotonic_seconds();
			crc_sink = crc;
			hw_mbs = ((double)sz * iters) / (elapsed_safe(t0, t1, corr) * 1048576.0);
		} else
#endif
		{
			hw_mbs = 0.0;
		}

		/* reference (byte-at-a-time, single table) */
		t0 = monotonic_seconds();
		for (i = 0; i < iters; i++)
			crc = bench_crc_sw(0, block, sz);
		t1 = monotonic_seconds();
		crc_sink = crc;
		ref_mbs = ((double)sz * iters) / (elapsed_safe(t0, t1, corr) * 1048576.0);

		printf("%-12u  %11.1f     %11.1f     %11.1f     %6.1fx\n",
		       sz, mycrc_mbs, hw_mbs, ref_mbs,
		       hw_mbs > 0 ? hw_mbs / ref_mbs : mycrc_mbs / ref_mbs);
	}
	free(block);
	printf("\n");
}

/* ------------------------------------------------------------------ */
/*  2. pcqueue benchmark: free-list effect on put/get throughput      */
/* ------------------------------------------------------------------ */

static void bench_pcqueue(void) {
	void *q;
	uint32_t id, op, leng;
	uint8_t *data;
	double t0, t1, corr;
	int i;

	printf("=== pcqueue Benchmark (single-thread put/get cycles) ===\n");

	corr = bench_overhead();
	q = queue_new(0);

	t0 = monotonic_seconds();
	for (i = 0; i < BENCH_ITERS_Q; i++) {
		queue_put(q, 1, 2, NULL, 0);
		queue_get(q, &id, &op, &data, &leng);
	}
	t1 = monotonic_seconds();

	printf("  %d put+get cycles: %.3f sec (%.0f ns/cycle)\n",
	       BENCH_ITERS_Q, elapsed_safe(t0, t1, corr),
	       elapsed_safe(t0, t1, corr) * 1e9 / BENCH_ITERS_Q);

	queue_delete(q);
	printf("  (With free-list, most cycles avoid malloc/free)\n\n");
}

/* ------------------------------------------------------------------ */
/*  3. RNG benchmark: throughput single-thread and multi-thread       */
/* ------------------------------------------------------------------ */

static volatile uint64_t rng_sink;

static void *rng_thread_func(void *arg) {
	int iters = *(int *)arg;
	uint64_t sink = 0;
	int i;
	for (i = 0; i < iters; i++) {
		sink += rndu32();
	}
	rng_sink += sink;
	return NULL;
}

static void bench_rng(void) {
	double t0, t1, corr;
	int i;
	uint64_t sink = 0;

	printf("=== RNG Benchmark ===\n");
	rnd_init();
	corr = bench_overhead();

	/* single-thread */
	t0 = monotonic_seconds();
	for (i = 0; i < BENCH_ITERS_RNG; i++) {
		sink += rndu32();
	}
	t1 = monotonic_seconds();
	rng_sink = sink;
	printf("  Single-thread: %d rndu32() in %.3f sec (%.0f ns/call, %.1f Mops/s)\n",
	       BENCH_ITERS_RNG, elapsed_safe(t0, t1, corr),
	       elapsed_safe(t0, t1, corr) * 1e9 / BENCH_ITERS_RNG,
	       BENCH_ITERS_RNG / (elapsed_safe(t0, t1, corr) * 1e6));

	/* multi-thread */
	{
		pthread_t threads[BENCH_THREADS];
		int per_thread = BENCH_ITERS_RNG;
		int t;

		rng_sink = 0;
		t0 = monotonic_seconds();
		for (t = 0; t < BENCH_THREADS; t++) {
			pthread_create(&threads[t], NULL, rng_thread_func, &per_thread);
		}
		for (t = 0; t < BENCH_THREADS; t++) {
			pthread_join(threads[t], NULL);
		}
		t1 = monotonic_seconds();

		printf("  %d threads:     %d rndu32()/thread in %.3f sec (%.1f Mops/s aggregate)\n",
		       BENCH_THREADS,
		       per_thread, elapsed_safe(t0, t1, corr),
		       (double)(BENCH_THREADS * per_thread) / (elapsed_safe(t0, t1, corr) * 1e6));
	}

#ifdef HAVE___THREAD
	printf("  (TLS RNG active: lock-free after first call per thread)\n");
#else
	printf("  (TLS RNG not available: using global mutex)\n");
#endif
	printf("\n");
}

/* ------------------------------------------------------------------ */
/*  4. Atomic stats simulation                                        */
/* ------------------------------------------------------------------ */

static volatile uint64_t atomic_counter;
static volatile uint32_t atomic_ops;
static pthread_mutex_t bench_statslock = PTHREAD_MUTEX_INITIALIZER;
static uint64_t mutex_counter;
static uint32_t mutex_ops;

#define STATS_ITERS 2000000

static void *atomic_thread_func(void *arg) {
	int iters = *(int *)arg;
	int i;
	for (i = 0; i < iters; i++) {
#ifdef HAVE___SYNC_FETCH_AND_OP
		__sync_fetch_and_add(&atomic_counter, 1);
		__sync_fetch_and_add(&atomic_ops, 1);
#endif
	}
	return NULL;
}

static void *mutex_thread_func(void *arg) {
	int iters = *(int *)arg;
	int i;
	for (i = 0; i < iters; i++) {
		pthread_mutex_lock(&bench_statslock);
		mutex_counter++;
		mutex_ops++;
		pthread_mutex_unlock(&bench_statslock);
	}
	return NULL;
}

static void bench_stats(void) {
	double t0, t1, corr;
	pthread_t threads[BENCH_THREADS];
	int per_thread = STATS_ITERS;
	int t;

	printf("=== Stats Counter Benchmark (%d threads, 2 counters/iter) ===\n",
	       BENCH_THREADS);
	corr = bench_overhead();

#ifdef HAVE___SYNC_FETCH_AND_OP
	/* Atomic path */
	atomic_counter = 0;
	atomic_ops = 0;
	t0 = monotonic_seconds();
	for (t = 0; t < BENCH_THREADS; t++)
		pthread_create(&threads[t], NULL, atomic_thread_func, &per_thread);
	for (t = 0; t < BENCH_THREADS; t++)
		pthread_join(threads[t], NULL);
	t1 = monotonic_seconds();
	printf("  Atomic:  %.3f sec (%.0f ns/iter, %.1f Mops/s)\n",
	       elapsed_safe(t0, t1, corr),
	       elapsed_safe(t0, t1, corr) * 1e9 / (BENCH_THREADS * per_thread),
	       (double)(BENCH_THREADS * per_thread) / (elapsed_safe(t0, t1, corr) * 1e6));
#else
	printf("  Atomic:  (not available)\n");
#endif

	/* Mutex path */
	mutex_counter = 0;
	mutex_ops = 0;
	t0 = monotonic_seconds();
	for (t = 0; t < BENCH_THREADS; t++)
		pthread_create(&threads[t], NULL, mutex_thread_func, &per_thread);
	for (t = 0; t < BENCH_THREADS; t++)
		pthread_join(threads[t], NULL);
	t1 = monotonic_seconds();
	printf("  Mutex:   %.3f sec (%.0f ns/iter, %.1f Mops/s)\n",
	       elapsed_safe(t0, t1, corr),
	       elapsed_safe(t0, t1, corr) * 1e9 / (BENCH_THREADS * per_thread),
	       (double)(BENCH_THREADS * per_thread) / (elapsed_safe(t0, t1, corr) * 1e6));

	printf("\n");
}

/* ------------------------------------------------------------------ */
/*  Main                                                              */
/* ------------------------------------------------------------------ */

int main(void) {
	printf("MooseFS Hot-Path Micro-Benchmark\n");
	printf("================================\n\n");

	bench_crc32();
	bench_pcqueue();
	bench_rng();
	bench_stats();

	printf("Done.\n");
	return 0;
}
