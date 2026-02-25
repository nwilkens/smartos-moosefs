# Performance Test Plan: Disk I/O Improvements

## Changes Under Test

| ID | Change | File(s) |
|----|--------|---------|
| P1 | Multi-block preadv() batched reads (up to 16 blocks/syscall) | hddspacemgr.c, mainserv.c |
| P2 | OPEN_DELAY increased from 0.5s to 5.0s | hddspacemgr.c |
| P3 | fdatasync() replaces fsync() (skips metadata flush) | hddspacemgr.c |

## Environment

- OS: illumos/SmartOS (SunOS 5.11)
- Network: 1 Gb/s
- Filesystem: ZFS (assumed)
- Block size: 64 KB (MFSBLOCKSIZE 0x10000), chunk size: 64 MB

## Prerequisites

```bash
# Build baseline (unmodified) binary
git stash
make -C mfschunkserver clean && make -C mfschunkserver
cp mfschunkserver/mfschunkserver /tmp/mfschunkserver.baseline

# Build optimized binary
git stash pop
make -C mfschunkserver clean && make -C mfschunkserver
cp mfschunkserver/mfschunkserver /tmp/mfschunkserver.optimized

# Ensure master is running, chunkserver data dir configured
# Drop filesystem caches between runs where noted
```

---

## Test 1: Sequential Read Throughput (targets P1)

**What it measures**: Sustained sequential read speed for large files —
exercises the preadv() batch path in mainserv_read.

**Method**: Use mfscli or a client to read back a large pre-written file.
Measure wall-clock time and bytes/sec. The multi-block path activates on
block-aligned reads of 2+ consecutive full blocks, which is the common
case for any sequential read larger than 128 KB.

```bash
# Preparation: write a 512 MB test file via MooseFS client
# (8 chunks x 64 MB each — enough to see sustained behavior)
dd if=/dev/urandom of=/mfs/testfile bs=1M count=512

# Flush caches
echo 3 > /proc/sys/vm/drop_caches  # Linux
# On illumos: use mdb or reboot to clear ARC, or use a file
# larger than ARC size

# Baseline run (repeat 5x, record median)
time dd if=/mfs/testfile of=/dev/null bs=1M

# Optimized run (repeat 5x, record median)
time dd if=/mfs/testfile of=/dev/null bs=1M
```

**Metrics to capture**:
- Wall-clock time (seconds)
- Throughput (MB/s)
- Syscall count via dtrace (should show ~16x fewer pread syscalls):

```bash
# Count pread/preadv syscalls on the chunkserver process
dtrace -n 'syscall::pread*:entry /pid == $target/ { @[probefunc] = count(); }' \
  -p $(pgrep mfschunkserver)
```

**Expected improvement**: 5-15% throughput increase from reduced syscall
overhead. Syscall count should drop ~16x for the read path. Larger gains
on high-latency storage (NFS-backed, cloud disks).

---

## Test 2: Repeated Small Reads — FD Reuse (targets P2)

**What it measures**: Cost of repeated access to the same chunks when
the access interval is between 0.5s and 5.0s (the old and new
OPEN_DELAY values).

**Method**: Read the same file repeatedly with ~2 second gaps. With the
old 0.5s delay, each read reopens the chunk file. With the new 5.0s
delay, subsequent reads reuse the open FD.

```bash
# Preparation: write a small test file (1 chunk = 64 MB)
dd if=/dev/urandom of=/mfs/testfile_small bs=1M count=64

# Test loop: read the same file 100 times with 2-second gaps
for run in baseline optimized; do
  echo "=== $run ==="
  t0=$(date +%s%N)
  for i in $(seq 1 100); do
    dd if=/mfs/testfile_small of=/dev/null bs=1M 2>/dev/null
    sleep 2
  done
  t1=$(date +%s%N)
  echo "Total: $(( (t1 - t0) / 1000000 )) ms"
done
```

**Metrics to capture**:
- Total elapsed time for 100 iterations
- open()/close() syscall count on the chunkserver:

```bash
dtrace -n '
  syscall::open*:entry /pid == $target/ { @opens = count(); }
  syscall::close:entry /pid == $target/ { @closes = count(); }
' -p $(pgrep mfschunkserver)
```

**Expected improvement**: ~50% fewer open/close syscalls. Measurable
latency reduction per read when access interval < 5s.

---

## Test 3: Write + Sync Latency (targets P3)

**What it measures**: Time spent in data sync operations. fdatasync()
should be faster than fsync() because it skips flushing unnecessary
metadata (timestamps).

**Requires**: `HDD_FSYNC_BEFORE_CLOSE=1` in mfschunkserver.cfg
(otherwise fsync is not called at all).

```bash
# Enable fsync in chunkserver config
echo "HDD_FSYNC_BEFORE_CLOSE = 1" >> /opt/local/etc/mfschunkserver.cfg

# Write test: many small files (each triggers chunk close + sync)
for run in baseline optimized; do
  echo "=== $run ==="
  t0=$(date +%s%N)
  for i in $(seq 1 500); do
    dd if=/dev/urandom of=/mfs/synctest_$i bs=64K count=1 2>/dev/null
  done
  sync
  t1=$(date +%s%N)
  echo "Total: $(( (t1 - t0) / 1000000 )) ms"
  # Cleanup
  rm /mfs/synctest_*
done
```

**Metrics to capture**:
- Total write time for 500 small files
- Per-sync latency via dtrace:

```bash
dtrace -n '
  syscall::fsync:entry /pid == $target/ {
    self->ts = timestamp;
    @fsync_count = count();
  }
  syscall::fsync:return /self->ts/ {
    @fsync_ns = quantize(timestamp - self->ts);
    self->ts = 0;
  }
  syscall::fdatasync:entry /pid == $target/ {
    self->ts = timestamp;
    @fdsync_count = count();
  }
  syscall::fdatasync:return /self->ts/ {
    @fdsync_ns = quantize(timestamp - self->ts);
    self->ts = 0;
  }
' -p $(pgrep mfschunkserver)
```

**Expected improvement**: On ZFS, fdatasync() can be 20-50% faster per
call since it avoids a ZIL transaction for metadata-only changes.
Baseline should show fsync syscalls; optimized should show fdatasync.

---

## Test 4: Mixed Workload — Combined Effect (targets P1+P2+P3)

**What it measures**: Real-world impact of all three changes together.

```bash
# Simulate a workload: concurrent sequential reads + small writes
# Run on the MooseFS-mounted filesystem

# Background: continuous sequential reads
for i in $(seq 1 4); do
  (while true; do dd if=/mfs/testfile of=/dev/null bs=1M 2>/dev/null; done) &
done

# Foreground: timed small file creates
t0=$(date +%s%N)
for i in $(seq 1 1000); do
  dd if=/dev/zero of=/mfs/mixed_$i bs=4K count=1 2>/dev/null
done
t1=$(date +%s%N)

# Kill background readers
kill %1 %2 %3 %4 2>/dev/null
wait

echo "Small writes during load: $(( (t1 - t0) / 1000000 )) ms"
rm /mfs/mixed_*
```

**Metrics to capture**:
- Small-write completion time under concurrent read load
- Overall throughput (background reads MB/s)
- chunkserver CPU usage (vmstat/prstat)

---

## Test 5: Chunkserver-Local Micro-Benchmark (no client needed)

**What it measures**: Raw hdd_read/hdd_read_multiblock performance
directly, isolating disk I/O from network. Useful when mfsmount is
not available.

**Method**: Write a small C test harness that calls hddspacemgr
functions directly.

```c
// test_multiblock.c - link against chunkserver objects
// Reads a known chunk repeatedly, comparing single-block vs multi-block
#include "hddspacemgr.h"
#include "clocks.h"

#define NBLOCKS 1024
#define ITERATIONS 100

int main() {
    uint8_t *data[HDD_READBLOCK_BATCH_MAX];
    uint8_t crcbuf[HDD_READBLOCK_BATCH_MAX][4];
    uint8_t *crc_ptrs[HDD_READBLOCK_BATCH_MAX];
    // ... allocate buffers, init hdd subsystem ...

    // Single-block reads
    double t0 = monotonic_seconds();
    for (int iter = 0; iter < ITERATIONS; iter++) {
        for (int b = 0; b < NBLOCKS; b++) {
            hdd_read(chunkid, version, b, data[0], 0,
                     MFSBLOCKSIZE, crcbuf[0]);
        }
    }
    double t1 = monotonic_seconds();
    printf("single-block: %.3f s\n", t1 - t0);

    // Multi-block reads
    double t2 = monotonic_seconds();
    for (int iter = 0; iter < ITERATIONS; iter++) {
        for (int b = 0; b < NBLOCKS; b += HDD_READBLOCK_BATCH_MAX) {
            int cnt = NBLOCKS - b;
            if (cnt > HDD_READBLOCK_BATCH_MAX) cnt = HDD_READBLOCK_BATCH_MAX;
            hdd_read_multiblock(chunkid, version, b, cnt,
                                data, crc_ptrs);
        }
    }
    double t3 = monotonic_seconds();
    printf("multi-block:  %.3f s\n", t3 - t2);
    printf("speedup:      %.1fx\n", (t1-t0) / (t3-t2));
}
```

**Expected improvement**: 1.3-2x for the read loop due to reduced
chunk hash lookups and syscalls.

---

## Test 6: DTrace Syscall Profile (all platforms with dtrace)

**What it measures**: Before/after syscall frequency and time
distribution — the most direct proof that the changes work.

```bash
# Run during a sustained sequential read workload
# Record for 30 seconds on each binary

dtrace -n '
  syscall::pread*:entry /pid == $target/ {
    self->ts = timestamp;
    @call[probefunc] = count();
  }
  syscall::pread*:return /self->ts/ {
    @time[probefunc] = sum(timestamp - self->ts);
    @dist[probefunc] = quantize(timestamp - self->ts);
    self->ts = 0;
  }
  syscall::open*:entry /pid == $target/ { @call["open"] = count(); }
  syscall::close:entry /pid == $target/ { @call["close"] = count(); }
  syscall::fsync:entry /pid == $target/ { @call["fsync"] = count(); }
  syscall::fdatasync:entry /pid == $target/ { @call["fdatasync"] = count(); }
  tick-30s { exit(0); }
' -p $(pgrep mfschunkserver)
```

**Expected results**:

| Syscall | Baseline (30s) | Optimized (30s) | Change |
|---------|---------------|-----------------|--------|
| pread   | ~N            | ~N/16           | -94%   |
| preadv  | 0             | ~N/16           | new    |
| open    | ~M            | ~M/10           | -90%   |
| close   | ~M            | ~M/10           | -90%   |
| fsync   | ~K            | 0               | -100%  |
| fdatasync| 0            | ~K              | new    |

---

## Recording Results

For each test, record in a table:

```
| Test | Metric           | Baseline | Optimized | Delta  | Notes |
|------|------------------|----------|-----------|--------|-------|
| T1   | Read MB/s        |          |           |        |       |
| T1   | pread syscalls   |          |           |        |       |
| T2   | Total time (ms)  |          |           |        |       |
| T2   | open() calls     |          |           |        |       |
| T3   | Write time (ms)  |          |           |        |       |
| T3   | sync latency p50 |          |           |        |       |
| T4   | Write under load |          |           |        |       |
| T5   | single vs multi  |          |           |        |       |
| T6   | syscall counts   |          |           |        |       |
```

## Run Order

1. **T6** first (dtrace profile) — quickest proof the code paths changed
2. **T5** (micro-benchmark) — no client dependency, isolates disk I/O
3. **T1** (sequential read) — primary throughput metric
4. **T2** (FD reuse) — validates OPEN_DELAY change
5. **T3** (sync latency) — validates fdatasync change
6. **T4** (mixed) — validates combined real-world impact
