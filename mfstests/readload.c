/*
 * readload.c - Generate read load against a MooseFS chunkserver
 *
 * Connects to chunkserver port 9422 and sends CLTOCS_READ requests
 * for known chunks, exercising the mainserv_read() code path.
 *
 * Usage: ./readload [-h host] [-p port] [-n iterations] chunkid version
 *   chunkid and version are hex (from chunk filename)
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "clocks.h"

/* MooseFS protocol constants */
#define CLTOCS_READ       200
#define CSTOCL_READ_STATUS 201
#define CSTOCL_READ_DATA   202
#define MFSBLOCKSIZE      0x10000    /* 64 KB */
#define MFSCHUNKSIZE      0x04000000 /* 64 MB */

/* packet header: cmd(4) + length(4) */
#define HEADER_SIZE 8

static void put32(uint8_t *p, uint32_t v) {
	p[0] = (v >> 24) & 0xFF;
	p[1] = (v >> 16) & 0xFF;
	p[2] = (v >> 8) & 0xFF;
	p[3] = v & 0xFF;
}

static void put64(uint8_t *p, uint64_t v) {
	put32(p, (uint32_t)(v >> 32));
	put32(p + 4, (uint32_t)v);
}

static uint32_t get32(const uint8_t *p) {
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
	       ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static uint64_t get64(const uint8_t *p) {
	return ((uint64_t)get32(p) << 32) | get32(p + 4);
}

static int readall(int fd, uint8_t *buf, size_t len) {
	size_t done = 0;
	while (done < len) {
		ssize_t r = read(fd, buf + done, len - done);
		if (r <= 0) {
			if (r < 0 && errno == EINTR) continue;
			return -1;
		}
		done += r;
	}
	return 0;
}

static int writeall(int fd, const uint8_t *buf, size_t len) {
	size_t done = 0;
	while (done < len) {
		ssize_t w = write(fd, buf + done, len - done);
		if (w <= 0) {
			if (w < 0 && errno == EINTR) continue;
			return -1;
		}
		done += w;
	}
	return 0;
}

static int tcp_connect(const char *host, int port) {
	struct sockaddr_in sa;
	struct hostent *he;
	int fd, one = 1;

	he = gethostbyname(host);
	if (he == NULL) {
		fprintf(stderr, "gethostbyname(%s) failed\n", host);
		return -1;
	}

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		perror("socket");
		return -1;
	}

	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	memcpy(&sa.sin_addr, he->h_addr_list[0], he->h_length);

	if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		perror("connect");
		close(fd);
		return -1;
	}
	return fd;
}

/* Send CLTOCS_READ and consume all response packets.
 * Returns bytes of data received, or -1 on error. */
static int64_t do_read_chunk(int fd, uint64_t chunkid, uint32_t version,
                             uint32_t offset, uint32_t size) {
	uint8_t pkt[HEADER_SIZE + 21];
	uint8_t hdr[HEADER_SIZE];
	uint8_t resp[20]; /* max fixed response fields */
	int64_t total_data = 0;

	/* build CLTOCS_READ packet (new protocol, 21 bytes payload) */
	put32(pkt, CLTOCS_READ);
	put32(pkt + 4, 21);          /* length */
	pkt[8] = 1;                  /* protocolid (new protocol) */
	put64(pkt + 9, chunkid);
	put32(pkt + 17, version);
	put32(pkt + 21, offset);
	put32(pkt + 25, size);

	if (writeall(fd, pkt, sizeof(pkt)) < 0) {
		fprintf(stderr, "write failed\n");
		return -1;
	}

	/* read responses until CSTOCL_READ_STATUS */
	for (;;) {
		uint32_t cmd, len;

		if (readall(fd, hdr, HEADER_SIZE) < 0) {
			fprintf(stderr, "read header failed\n");
			return -1;
		}
		cmd = get32(hdr);
		len = get32(hdr + 4);

		if (cmd == CSTOCL_READ_STATUS) {
			/* 9 bytes: chunkid(8) + status(1) */
			if (readall(fd, resp, len < sizeof(resp) ? len : sizeof(resp)) < 0) {
				return -1;
			}
			uint8_t status = resp[8];
			if (status != 0) {
				fprintf(stderr, "read error: status=%u\n", status);
				return -1;
			}
			break;
		} else if (cmd == CSTOCL_READ_DATA) {
			/* 16 bytes header: chunkid(8)+blocknum(2)+offset(2)+size(4)+crc(4) + data */
			if (len < 20) {
				fprintf(stderr, "short data packet\n");
				return -1;
			}
			if (readall(fd, resp, 20) < 0) {
				return -1;
			}
			uint32_t dsize = get32(resp + 12);
			/* consume data bytes */
			uint32_t remain = dsize;
			uint8_t discard[65536];
			while (remain > 0) {
				uint32_t chunk = remain > sizeof(discard) ? sizeof(discard) : remain;
				if (readall(fd, discard, chunk) < 0) {
					return -1;
				}
				remain -= chunk;
			}
			total_data += dsize;
		} else {
			/* skip unknown packet */
			uint8_t skip[4096];
			while (len > 0) {
				uint32_t chunk = len > sizeof(skip) ? sizeof(skip) : len;
				if (readall(fd, skip, chunk) < 0) return -1;
				len -= chunk;
			}
		}
	}
	return total_data;
}

int main(int argc, char **argv) {
	const char *host = "127.0.0.1";
	int port = 9422;
	int iterations = 10;
	int opt;
	uint64_t chunkid;
	uint32_t version;
	int fd, iter;
	int64_t bytes;
	double t0, t1, elapsed;
	uint64_t total_bytes = 0;

	while ((opt = getopt(argc, argv, "h:p:n:")) != -1) {
		switch (opt) {
		case 'h': host = optarg; break;
		case 'p': port = atoi(optarg); break;
		case 'n': iterations = atoi(optarg); break;
		default:
			fprintf(stderr, "Usage: %s [-h host] [-p port] [-n iterations] chunkid_hex version_hex\n", argv[0]);
			return 1;
		}
	}

	if (optind + 2 > argc) {
		fprintf(stderr, "Usage: %s [-h host] [-p port] [-n iterations] chunkid_hex version_hex\n", argv[0]);
		return 1;
	}

	chunkid = strtoull(argv[optind], NULL, 16);
	version = strtoul(argv[optind + 1], NULL, 16);

	printf("MooseFS Read Load Generator\n");
	printf("  Target:     %s:%d\n", host, port);
	printf("  Chunk:      0x%016" PRIX64 " v%u\n", chunkid, version);
	printf("  Iterations: %d\n", iterations);
	printf("  Read size:  %d MB (full chunk)\n\n", MFSCHUNKSIZE / (1024*1024));

	t0 = monotonic_seconds();

	for (iter = 0; iter < iterations; iter++) {
		fd = tcp_connect(host, port);
		if (fd < 0) {
			fprintf(stderr, "connect failed on iteration %d\n", iter);
			return 1;
		}

		bytes = do_read_chunk(fd, chunkid, version, 0, MFSCHUNKSIZE);
		close(fd);

		if (bytes < 0) {
			fprintf(stderr, "read failed on iteration %d\n", iter);
			return 1;
		}
		total_bytes += bytes;

		if ((iter + 1) % 5 == 0 || iter == 0) {
			t1 = monotonic_seconds();
			elapsed = t1 - t0;
			printf("  [%3d/%d] %'" PRIu64 " MB read, %.1f MB/s\n",
				iter + 1, iterations,
				total_bytes / (1024*1024),
				(double)total_bytes / elapsed / (1024.0*1024.0));
		}
	}

	t1 = monotonic_seconds();
	elapsed = t1 - t0;

	printf("\n=== Results ===\n");
	printf("  Total data:    %" PRIu64 " MB\n", total_bytes / (1024*1024));
	printf("  Elapsed:       %.3f s\n", elapsed);
	printf("  Throughput:    %.1f MB/s\n",
		(double)total_bytes / elapsed / (1024.0*1024.0));
	printf("  Avg chunk lat: %.1f ms\n",
		elapsed * 1000.0 / iterations);

	return 0;
}
