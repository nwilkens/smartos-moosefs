/*
 * bench_multiblock.c - Standalone pread vs preadv micro-benchmark
 *
 * Opens real MooseFS chunk files directly on disk and compares:
 *   1. Single-block pread() per 64KB block (baseline path)
 *   2. Batched preadv() of N consecutive blocks (optimized path)
 *
 * Also measures CRC32 computation overhead per approach.
 *
 * Usage: ./bench_multiblock [-d chunk_dir] [-n iterations] [-b batch_size]
 * Defaults: chunk_dir=/opt/local/var/mfs/chunks  iterations=50  batch=16
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <inttypes.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <limits.h>

#include "clocks.h"
#include "crc.h"

/* match MooseFS standard (non-LIGHT) chunk layout */
#define MFSBLOCKSIZE   0x10000   /* 64 KB */
#define MFSBLOCKBITS   16
#define MFSCHUNKSIZE   0x04000000 /* 64 MB */
#define MFSBLOCKSINCHUNK 0x400   /* 1024 */
#define NEWHDRSIZE     4096
#define CHUNKCRCSIZE   4096
#define DATA_OFFSET    (NEWHDRSIZE + CHUNKCRCSIZE)

#define BATCH_MAX 16

static char *find_first_full_chunk(const char *basedir) {
	char subdir[PATH_MAX];
	DIR *d, *sd;
	struct dirent *de, *sde;
	struct stat sb;
	static char path[PATH_MAX];

	d = opendir(basedir);
	if (d == NULL) return NULL;
	while ((de = readdir(d)) != NULL) {
		if (de->d_name[0] == '.') continue;
		snprintf(subdir, sizeof(subdir), "%s/%s", basedir, de->d_name);
		sd = opendir(subdir);
		if (sd == NULL) continue;
		while ((sde = readdir(sd)) != NULL) {
			if (strncmp(sde->d_name, "chunk_", 6) != 0) continue;
			snprintf(path, sizeof(path), "%s/%s", subdir, sde->d_name);
			if (stat(path, &sb) == 0 && sb.st_size >= DATA_OFFSET + MFSCHUNKSIZE) {
				closedir(sd);
				closedir(d);
				return path;
			}
		}
		closedir(sd);
	}
	closedir(d);
	return NULL;
}

int main(int argc, char **argv) {
	char *chunkdir = "/opt/local/var/mfs/chunks";
	int iterations = 50;
	int batch = BATCH_MAX;
	int opt;
	char *chunkpath;
	int fd;
	int b, iter, bi;
	double t0, t1, t2, t3, t4, t5;
	uint64_t ns0, ns1;
	uint8_t *blockbuf;
	uint8_t *batchbufs[BATCH_MAX];
	struct iovec iov[BATCH_MAX];
	uint32_t crc;
	uint32_t crctab[MFSBLOCKSINCHUNK];
	ssize_t ret;
	double single_read_time, batch_read_time;
	double single_crc_time, batch_crc_time;
	double single_total, batch_total;
	uint64_t total_bytes;

	while ((opt = getopt(argc, argv, "d:n:b:")) != -1) {
		switch (opt) {
		case 'd': chunkdir = optarg; break;
		case 'n': iterations = atoi(optarg); break;
		case 'b':
			batch = atoi(optarg);
			if (batch < 2) batch = 2;
			if (batch > BATCH_MAX) batch = BATCH_MAX;
			break;
		default:
			fprintf(stderr, "Usage: %s [-d chunk_dir] [-n iterations] [-b batch_size]\n", argv[0]);
			return 1;
		}
	}

	printf("MooseFS pread vs preadv Micro-Benchmark\n");
	printf("========================================\n");
	printf("  Block size:    %d KB\n", MFSBLOCKSIZE / 1024);
	printf("  Blocks/chunk:  %d\n", MFSBLOCKSINCHUNK);
	printf("  Batch size:    %d blocks (%d KB)\n", batch, batch * MFSBLOCKSIZE / 1024);
	printf("  Iterations:    %d\n", iterations);

	/* find a full chunk */
	chunkpath = find_first_full_chunk(chunkdir);
	if (chunkpath == NULL) {
		fprintf(stderr, "ERROR: no full 64MB chunk found in %s\n", chunkdir);
		return 1;
	}
	printf("  Chunk file:    %s\n\n", chunkpath);

	/* open chunk */
	fd = open(chunkpath, O_RDONLY);
	if (fd < 0) {
		perror("open");
		return 1;
	}

	/* read CRC table */
	ret = pread(fd, crctab, CHUNKCRCSIZE, NEWHDRSIZE);
	if (ret != CHUNKCRCSIZE) {
		fprintf(stderr, "ERROR: failed to read CRC table\n");
		close(fd);
		return 1;
	}

	/* allocate buffers */
	blockbuf = malloc(MFSBLOCKSIZE);
	for (bi = 0; bi < batch; bi++) {
		batchbufs[bi] = malloc(MFSBLOCKSIZE);
	}

	total_bytes = (uint64_t)MFSBLOCKSINCHUNK * MFSBLOCKSIZE * iterations;

	/* ---- TEST 1: single-block pread + CRC ---- */
	printf("Test 1: Single-block pread() + CRC32 ...\n");

	/* warm up */
	for (b = 0; b < MFSBLOCKSINCHUNK; b++) {
		pread(fd, blockbuf, MFSBLOCKSIZE, DATA_OFFSET + ((uint32_t)b << MFSBLOCKBITS));
	}

	single_read_time = 0.0;
	single_crc_time = 0.0;
	for (iter = 0; iter < iterations; iter++) {
		for (b = 0; b < MFSBLOCKSINCHUNK; b++) {
			ns0 = monotonic_nseconds();
			ret = pread(fd, blockbuf, MFSBLOCKSIZE, DATA_OFFSET + ((uint32_t)b << MFSBLOCKBITS));
			ns1 = monotonic_nseconds();
			single_read_time += (double)(ns1 - ns0);
			if (ret != MFSBLOCKSIZE) {
				fprintf(stderr, "short pread at block %d\n", b);
				goto cleanup;
			}

			ns0 = monotonic_nseconds();
			crc = mycrc32(0, blockbuf, MFSBLOCKSIZE);
			ns1 = monotonic_nseconds();
			single_crc_time += (double)(ns1 - ns0);
			(void)crc;
		}
	}
	single_total = single_read_time + single_crc_time;

	printf("  pread() calls:    %d\n", MFSBLOCKSINCHUNK * iterations);
	printf("  I/O time:         %.3f ms\n", single_read_time / 1e6);
	printf("  CRC time:         %.3f ms\n", single_crc_time / 1e6);
	printf("  Total:            %.3f ms\n", single_total / 1e6);
	printf("  Throughput:       %.1f MB/s\n",
		(double)total_bytes / (single_total / 1e9) / (1024.0 * 1024.0));
	printf("  Avg pread() lat:  %.1f ns\n",
		single_read_time / (MFSBLOCKSINCHUNK * iterations));
	printf("\n");

	/* ---- TEST 2: batched preadv + CRC ---- */
	printf("Test 2: Batched preadv(%d) + CRC32 ...\n", batch);

	/* warm up */
	for (b = 0; b < MFSBLOCKSINCHUNK; b++) {
		pread(fd, blockbuf, MFSBLOCKSIZE, DATA_OFFSET + ((uint32_t)b << MFSBLOCKBITS));
	}

	batch_read_time = 0.0;
	batch_crc_time = 0.0;
	for (iter = 0; iter < iterations; iter++) {
		for (b = 0; b < MFSBLOCKSINCHUNK; b += batch) {
			int cnt = MFSBLOCKSINCHUNK - b;
			if (cnt > batch) cnt = batch;

			for (bi = 0; bi < cnt; bi++) {
				iov[bi].iov_base = batchbufs[bi];
				iov[bi].iov_len = MFSBLOCKSIZE;
			}

			ns0 = monotonic_nseconds();
			ret = preadv(fd, iov, cnt,
				DATA_OFFSET + ((uint32_t)b << MFSBLOCKBITS));
			ns1 = monotonic_nseconds();
			batch_read_time += (double)(ns1 - ns0);
			if (ret != (ssize_t)cnt * MFSBLOCKSIZE) {
				fprintf(stderr, "short preadv at block %d (got %zd, want %zd)\n",
					b, ret, (ssize_t)cnt * MFSBLOCKSIZE);
				goto cleanup;
			}

			ns0 = monotonic_nseconds();
			for (bi = 0; bi < cnt; bi++) {
				crc = mycrc32(0, batchbufs[bi], MFSBLOCKSIZE);
				(void)crc;
			}
			ns1 = monotonic_nseconds();
			batch_crc_time += (double)(ns1 - ns0);
		}
	}
	batch_total = batch_read_time + batch_crc_time;

	{
		int preadv_calls = ((MFSBLOCKSINCHUNK + batch - 1) / batch) * iterations;
		printf("  preadv() calls:   %d\n", preadv_calls);
		printf("  I/O time:         %.3f ms\n", batch_read_time / 1e6);
		printf("  CRC time:         %.3f ms\n", batch_crc_time / 1e6);
		printf("  Total:            %.3f ms\n", batch_total / 1e6);
		printf("  Throughput:       %.1f MB/s\n",
			(double)total_bytes / (batch_total / 1e9) / (1024.0 * 1024.0));
		printf("  Avg preadv() lat: %.1f ns\n",
			batch_read_time / preadv_calls);
	}

	printf("\n");
	printf("=== Summary ===\n");
	printf("  Syscall reduction: %dx fewer (%d pread vs %d preadv)\n",
		MFSBLOCKSINCHUNK / ((MFSBLOCKSINCHUNK + batch - 1) / batch),
		MFSBLOCKSINCHUNK * iterations,
		((MFSBLOCKSINCHUNK + batch - 1) / batch) * iterations);
	printf("  I/O speedup:       %.2fx (%.3f ms -> %.3f ms)\n",
		single_read_time / batch_read_time,
		single_read_time / 1e6, batch_read_time / 1e6);
	printf("  Total speedup:     %.2fx (%.3f ms -> %.3f ms)\n",
		single_total / batch_total,
		single_total / 1e6, batch_total / 1e6);

cleanup:
	close(fd);
	free(blockbuf);
	for (bi = 0; bi < batch; bi++) {
		free(batchbufs[bi]);
	}
	return 0;
}
