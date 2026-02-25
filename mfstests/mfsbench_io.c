/*
 * MooseFS Real I/O Benchmark
 *
 * Uses libmfsio to perform actual read/write operations through the
 * MooseFS cluster, exercising the full data path including:
 *   - CRC32 computation (every chunk read/write)
 *   - pcqueue job dispatch
 *   - RNG (chunk placement)
 *   - Stats accounting
 *
 * Usage:
 *   ./mfsbench_io [-h host] [-p port] [-s size_mb] [-b block_kb] [-n passes]
 *
 * Defaults: host=127.0.0.1  port=9421  size=256MB  block=1024KB  passes=3
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

#include "config.h"
#include "clocks.h"
#include "mfsio.h"

static void usage(const char *prog) {
	fprintf(stderr,
		"Usage: %s [-h host] [-p port] [-s size_mb] [-b block_kb] [-n passes]\n"
		"  -h host      MooseFS master host (default: 127.0.0.1)\n"
		"  -p port      MooseFS master port (default: 9421)\n"
		"  -s size_mb   Total file size in MB (default: 256)\n"
		"  -b block_kb  I/O block size in KB (default: 1024)\n"
		"  -n passes    Number of write+read passes (default: 3)\n",
		prog);
}

int main(int argc, char **argv) {
	mfscfg mcfg;
	char *host = "127.0.0.1";
	char *port = "9421";
	int size_mb = 256;
	int block_kb = 1024;
	int passes = 3;
	int opt;
	int fd;
	uint8_t *buf;
	size_t block_size;
	size_t file_size;
	size_t total_written, total_read;
	ssize_t ret;
	double t0, t1;
	int pass;
	char filepath[256];
	double write_mbs, read_mbs;
	double write_sum = 0.0, read_sum = 0.0;

	while ((opt = getopt(argc, argv, "h:p:s:b:n:")) != -1) {
		switch (opt) {
		case 'h': host = optarg; break;
		case 'p': port = optarg; break;
		case 's': size_mb = atoi(optarg); break;
		case 'b': block_kb = atoi(optarg); break;
		case 'n': passes = atoi(optarg); break;
		default: usage(argv[0]); return 1;
		}
	}

	block_size = (size_t)block_kb * 1024;
	file_size = (size_t)size_mb * 1048576;

	printf("MooseFS Real I/O Benchmark\n");
	printf("==========================\n");
	printf("  Master:     %s:%s\n", host, port);
	printf("  File size:  %d MB\n", size_mb);
	printf("  Block size: %d KB\n", block_kb);
	printf("  Passes:     %d\n\n", passes);

	/* Initialize libmfsio */
	mfs_set_defaults(&mcfg);
	mcfg.masterhost = host;
	mcfg.masterport = port;
	mcfg.masterpath = "/";
	mcfg.io_try_cnt = 5;
	mcfg.io_timeout = 60;
	mcfg.read_cache_mb = 0;       /* disable read cache for honest benchmark */
	mcfg.write_cache_mb = 128;
	mcfg.logminlevel = 5;         /* suppress info logs */

	if (mfs_init(&mcfg, 0) < 0) {
		fprintf(stderr, "mfs_init failed (is master running at %s:%s?)\n", host, port);
		return 1;
	}

	/* Allocate I/O buffer with a pattern */
	buf = malloc(block_size);
	if (!buf) {
		fprintf(stderr, "malloc(%zu) failed\n", block_size);
		mfs_term();
		return 1;
	}
	/* Fill with a recognizable pattern */
	{
		size_t k;
		for (k = 0; k < block_size; k++) {
			buf[k] = (uint8_t)(k * 7 + 13);
		}
	}

	snprintf(filepath, sizeof(filepath), "/bench_io_test_%d.dat", (int)getpid());

	for (pass = 0; pass < passes; pass++) {
		printf("--- Pass %d/%d ---\n", pass + 1, passes);

		/* ---- WRITE ---- */
		fd = mfs_open(filepath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
		if (fd < 0) {
			fprintf(stderr, "mfs_open(%s) for write failed: %s\n", filepath, strerror(errno));
			break;
		}

		total_written = 0;
		t0 = monotonic_seconds();
		while (total_written < file_size) {
			size_t to_write = block_size;
			if (total_written + to_write > file_size) {
				to_write = file_size - total_written;
			}
			ret = mfs_write(fd, buf, to_write);
			if (ret <= 0) {
				fprintf(stderr, "mfs_write failed at offset %zu: %s\n",
					total_written, strerror(errno));
				break;
			}
			total_written += (size_t)ret;
		}
		mfs_fsync(fd);
		mfs_close(fd);
		t1 = monotonic_seconds();

		write_mbs = (double)total_written / ((t1 - t0) * 1048576.0);
		printf("  Write: %zu bytes in %.3f sec = %.1f MB/s\n",
		       total_written, t1 - t0, write_mbs);
		write_sum += write_mbs;

		/* ---- READ ---- */
		fd = mfs_open(filepath, O_RDONLY);
		if (fd < 0) {
			fprintf(stderr, "mfs_open(%s) for read failed: %s\n", filepath, strerror(errno));
			break;
		}

		total_read = 0;
		t0 = monotonic_seconds();
		while (total_read < file_size) {
			size_t to_read = block_size;
			if (total_read + to_read > file_size) {
				to_read = file_size - total_read;
			}
			ret = mfs_read(fd, buf, to_read);
			if (ret <= 0) {
				if (ret == 0) break;  /* EOF */
				fprintf(stderr, "mfs_read failed at offset %zu: %s\n",
					total_read, strerror(errno));
				break;
			}
			total_read += (size_t)ret;
		}
		mfs_close(fd);
		t1 = monotonic_seconds();

		read_mbs = (double)total_read / ((t1 - t0) * 1048576.0);
		printf("  Read:  %zu bytes in %.3f sec = %.1f MB/s\n",
		       total_read, t1 - t0, read_mbs);
		read_sum += read_mbs;

		printf("\n");
	}

	/* Cleanup test file */
	mfs_unlink(filepath);

	printf("=== Summary (%d passes) ===\n", passes);
	printf("  Avg Write: %.1f MB/s\n", write_sum / passes);
	printf("  Avg Read:  %.1f MB/s\n", read_sum / passes);
	printf("\n");

	free(buf);
	mfs_term();
	return 0;
}
