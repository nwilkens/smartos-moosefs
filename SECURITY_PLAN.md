# MooseFS Multitenancy Security Plan

## Goal

Operate MooseFS as storage backend for a public cloud provider where tenants are mutually untrusted. A compromised or malicious tenant VM must not be able to read, write, or disrupt another tenant's data.

---

## Current State (Post 1A Implementation)

### What We've Done

**1A. Chunk Access Tokens** — DEPLOYED (build 2079)

- Master generates HMAC-SHA256 tokens per chunk operation: `HMAC(secret, chunkid || version || expiry)`
- Chunkservers validate tokens before serving any read/write
- Clients cache tokens alongside chunk location data
- CS-to-CS replication generates tokens locally using shared secret
- Strict enforcement: requests without valid tokens return `MFS_ERROR_BADTOKEN`
- Token observability: `tokaccept`/`tokreject` counters in chunkserver charts
- 300-second TTL, <0.1% throughput impact

### What This Fixes

Before tokens, any machine on the network could connect directly to a chunkserver on port 9422 and read ANY chunk by sending `CLTOCS_READ: chunkid version offset size`. Chunk IDs are sequential, versions start at 1. Complete data isolation failure.

With tokens, you must go through the master first. The master checks exports and permissions before issuing a scoped, time-limited token for one specific chunk.

### What This Does NOT Fix

Tokens close the chunkserver bypass, but the master still has weak authentication:

- Clients self-assert their UID/GID — the master trusts whatever the client claims
- Authentication is a single shared MD5 password per export entry
- Anyone matching an export's IP range and password gets a session
- The master has no concept of "tenants" — just POSIX users and export rules

**A malicious tenant who can mount the filesystem can claim any UID and access any file the master allows for that export.**

---

## Vulnerability Summary

| # | Vulnerability | Severity | Status |
|---|---|---|---|
| V1 | Direct chunkserver access (no auth) | CRITICAL | **FIXED** (1A tokens) |
| V2 | Client-asserted UID/GID | HIGH | Open |
| V3 | No encryption in transit | HIGH | Open |
| V4 | Shared/weak authentication (MD5) | MEDIUM | Open |
| V5 | Sequential chunk IDs (predictable) | MEDIUM | Open |
| V6 | No audit trail | MEDIUM | Open |
| V7 | No per-tenant resource limits | LOW | Open |

---

## Implementation Plan

### Phase 1: Foundation (Completed)

#### 1A. Chunk Access Tokens — DONE

- Files: `chunktoken.c/h`, `sha256.c/h`, `mainserv.c`, `masterconn.c`, `matoclserv.c`, `matocsserv.c`, `readdata.c`, `writedata.c`, `replicator.c`
- Protocol: CLTOCS_READ/WRITE protover==2, MATOCL responses protocolid==4/5
- Config: `CHUNK_TOKEN_SECRET` in mfsmaster.cfg (32-byte hex)

### Phase 2: Harden Token Security

#### 1C. Random Chunk IDs

**Problem:** `nextchunkid++` in `chunks.c` makes chunk IDs sequential and predictable. Even with tokens, sequential IDs leak information about cluster activity and chunk count.

**Fix:** Replace `nextchunkid++` with cryptographic random 64-bit IDs.

**Where:**
- `mfsmaster/chunks.c` — `chunk_new()` function, `nextchunkid` variable
- Need collision check against chunk hash table before inserting
- Hash table already has 16M buckets — collision probability <0.001% per insert

**Performance:** Zero. One RNG call on the chunk creation slow path.

**Complexity:** Low. Single-file change, master only.

#### 1B. TLS for All Connections

**Problem:** All MooseFS protocols are plaintext. Network eavesdropping reveals file contents, metadata operations, and token values. Token theft via packet capture allows replay within TTL window.

**Fix:** TLS 1.3 on all connections:
- Client ↔ Master (port 9421)
- Client ↔ Chunkserver (port 9422)
- Master ↔ Chunkserver (port 9420)
- Master ↔ Metalogger (port 9419)
- CS ↔ CS (replication)

**Performance:** Near-zero with AES-NI. AES-256-GCM runs at ~20 GB/s, faster than the existing CRC32. Handshake cost (1-2ms) amortized by connection pooling.

**Complexity:** HIGH. Largest code surface area. Every `tcptoread`/`tcptowrite`/`tcpnumconnect` call site needs SSL wrappers. Consider OpenSSL or mbedTLS.

**Approach:**
1. Add TLS wrapper layer in `mfscommon/` (connect, accept, read, write)
2. Certificate management: CA cert + per-node certs, or PSK mode using existing `AUTH_CODE`/`CHUNK_TOKEN_SECRET`
3. Modify `sockets.c` or add `tlssockets.c`
4. Config: `TLS_CERT_FILE`, `TLS_KEY_FILE`, `TLS_CA_FILE` in each daemon's config

### Phase 3: Per-Tenant Authentication (2A)

This is the critical missing piece for true multitenancy.

#### Current Auth Flow

```
Client (mfsmount)                    Master (matoclserv.c)
     │                                     │
     ├─ REGISTER_GETRANDOM ───────────────►│
     │◄─ 32 random bytes ─────────────────┤
     │                                     │
     │  md5(rnd[0:16] + password + rnd[16:32])
     │                                     │
     ├─ REGISTER_NEWSESSION ──────────────►│
     │   version, info, path,              │
     │   [sessionid], [metaid],            │  exports_check():
     │   [passcode:16B]                    │    match IP range
     │                                     │    match path
     │                                     │    verify MD5(rnd+pass+rnd)
     │                                     │    return sesflags, rootuid,
     │                                     │    rootgid, mapalluid, mapallgid
     │◄─ sessionid, sesflags, ────────────┤
     │   rootuid, rootgid,                 │
     │   mapalluid, mapallgid              │
     │                                     │
     │  (client now uses self-asserted     │
     │   UID/GID for all operations)       │
```

**Problems:**
1. Client sends its own UID/GID with every FUSE operation — master trusts it
2. `mapall` forces all users to one UID but loses per-user attribution
3. Password is shared per-export — all tenants on same export share one credential
4. No way to revoke a single tenant's access without changing the shared password

#### Proposed: Tenant-Aware Auth

```
Client (mfsmount)                    Master (matoclserv.c)
     │                                     │
     ├─ REGISTER_GETRANDOM ───────────────►│
     │◄─ 32 random bytes ─────────────────┤
     │                                     │
     ├─ REGISTER_NEWSESSION_V2 ───────────►│
     │   version, info, path,              │
     │   tenant_id, tenant_secret,         │  tenant_auth_check():
     │   [sessionid], [metaid]             │    lookup tenant by ID
     │                                     │    verify HMAC(secret, challenge)
     │                                     │    return tenant's UID/GID
     │                                     │    return tenant's allowed paths
     │                                     │    return tenant's sclass groups
     │                                     │
     │◄─ sessionid, sesflags, ────────────┤
     │   SERVER-ASSIGNED uid/gid,          │
     │   allowed sclassgroups              │
     │                                     │
     │  (master overrides client UID/GID   │
     │   with server-determined values     │
     │   for ALL subsequent operations)    │
```

#### Design Details

**Tenant Database:**
- New config file: `mfstenants.cfg`
- Format: `tenant_id:tenant_secret:uid:gid:root_path:sclassgroups:flags`
- Example:
  ```
  acme:a1b2c3d4e5f6...:1001:1001:/tenants/acme:1:rw
  globex:f6e5d4c3b2a1...:1002:1002:/tenants/globex:2:rw
  ```
- Hot-reloadable via `mfsmaster reload` (SIGHUP)

**Server-Enforced Identity:**
- On successful tenant auth, master creates session with `mapalluid=tenant_uid`, `mapallgid=tenant_gid`, `SESFLAG_MAPALL` forced on
- Client-asserted UID/GID is IGNORED — all operations run as the tenant's assigned identity
- This is equivalent to `mapall=tenant_uid:tenant_gid` in exports today, but cryptographically bound to the tenant credential

**Path Isolation:**
- Tenant's `root_path` becomes their mount root — they cannot traverse above it
- Equivalent to subpath export, but enforced per-credential rather than per-IP
- Multiple tenants can share an IP range (e.g., behind NAT) and still be isolated

**Storage Class Isolation:**
- Tenant's `sclassgroups` bitmask restricts which storage classes they can use
- Prevents tenant A from placing data on tenant B's dedicated hardware

**Session Binding:**
- Session ID cryptographically bound to tenant ID
- Session cannot be transferred between tenants
- Tenant revocation: delete from `mfstenants.cfg` + reload → existing sessions invalidated on next metadata operation

**Implementation Files:**
- New: `mfsmaster/tenants.c/h` — tenant database, lookup, auth
- Modify: `mfsmaster/matoclserv.c` — new REGISTER_NEWSESSION_V2 handler
- Modify: `mfsmaster/sessions.c` — add tenant_id to session struct
- Modify: `mfsmaster/exports.c` — tenant-aware export matching
- Modify: `mfsclient/mastercomm.c` — send tenant credentials at mount
- Modify: `mfsmount` CLI — `--tenant-id` and `--tenant-secret` options
- New protocol: `CLTOMA_FUSE_REGISTER` rcode=10 (REGISTER_TENANT_SESSION)

**Performance:** Zero data-path impact. Auth happens once at mount time.

### Phase 4: Observability & Compliance

#### 3A. Audit Logging

**What:** Log every metadata operation with tenant identity.

**Format:** Structured log entries:
```
AUDIT: tenant=acme uid=1001 op=READ inode=12345 path=/data/file.txt status=OK
AUDIT: tenant=globex uid=1002 op=WRITE inode=67890 path=/data/other.txt status=OK
AUDIT: tenant=acme uid=1001 op=UNLINK inode=12345 path=/data/file.txt status=DENIED
```

**Where:** `mfsmaster/matoclserv.c` — each FUSE operation handler.

**Performance:** ~1-5µs per operation (syslog write). Use async ring buffer at >100K ops/sec.

#### 3B. Per-Tenant Rate Limiting

**What:** Prevent noisy-neighbor by limiting operations per tenant per second.

**Where:** `mfsmaster/matoclserv.c` — per-session atomic counter checked at operation entry.

**Config:** In `mfstenants.cfg`:
```
acme:...:1001:1001:/tenants/acme:1:rw:max_iops=10000,max_bw=1G
```

**Performance:** ~10ns per operation (atomic increment + comparison).

### Phase 5: Encryption at Rest (2B)

#### Client-Side Encryption (Recommended)

**What:** Client encrypts data with per-tenant key before sending to chunkserver. Chunkserver stores ciphertext. Even with full chunkserver compromise, data is unreadable.

**Key Management:**
- Tenant key derived from tenant secret: `data_key = HKDF(tenant_secret, "moosefs-data-encryption")`
- Or separate key in tenant config
- Per-chunk IV derived from chunkid: `IV = HMAC(data_key, chunkid)` — deterministic for dedup compatibility

**Where:**
- `mfsclient/writedata.c` — encrypt blocks before CRC and send
- `mfsclient/readdata.c` — decrypt blocks after receive and CRC verify
- CRC32 computed on ciphertext (still valid for transport integrity)

**Performance:** ~3µs per 64KB block with AES-NI. <1% throughput impact.

**Trade-off:** Chunkserver cannot deduplicate across tenants. This is a feature, not a bug — cross-tenant dedup leaks information.

---

## Implementation Priority

| Phase | Feature | Fixes | Effort | Impact |
|---|---|---|---|---|
| 1 | **1A. Chunk tokens** | V1 | **DONE** | Blocks direct CS access |
| 2a | **1C. Random chunk IDs** | V5 | Small (1 file) | Removes predictability |
| 2b | **1B. TLS everywhere** | V3 | Large | Stops eavesdropping + token theft |
| 3 | **2A. Per-tenant auth** | V2, V4 | Medium | True tenant isolation |
| 4a | **3A. Audit logging** | V6 | Small | Compliance, forensics |
| 4b | **3B. Rate limiting** | V7 | Small | Noisy-neighbor protection |
| 5 | **2B. Client encryption** | At-rest | Medium | Data confidentiality at rest |

**Minimum viable multitenancy: Phases 1 + 2a + 3** (tokens + random IDs + per-tenant auth).

TLS (2b) is important but can be partially mitigated by network isolation (VLAN per storage network) until implemented.

---

## What Works Today Without Further Code Changes

For semi-trusted tenants (e.g., internal teams), the current deployment provides:

1. **Chunk access tokens** — no direct chunkserver access (DEPLOYED)
2. **`mapall` on every export** — force a fixed UID per tenant
3. **Subpath mounting** — each tenant mounts `/tenantN/` only
4. **IP-based export matching** — restrict which IPs can mount which paths
5. **`DISABLE_*` flags** — disable dangerous operations (unlink, truncate, etc.) per export
6. **Storage class groups** — restrict which storage classes each tenant can use

**This is NOT sufficient for hostile/untrusted tenants** because:
- UID/GID is still client-asserted (mapall is per-export, not per-credential)
- Shared password means any tenant on the same export can impersonate another
- No encryption means network eavesdropping exposes data and tokens

---

## Performance Impact Summary

| Feature | Data Path Overhead | Throughput Impact |
|---|---|---|
| 1A. Chunk tokens | 1 HMAC per chunk op (~1µs) | <0.1% |
| 1B. TLS | AES-GCM per byte (~3µs/64KB) | ~0% with AES-NI |
| 1C. Random chunk IDs | 1 RNG call at creation | 0% |
| 2A. Per-tenant auth | None (mount time only) | 0% |
| 2B. Client encryption | AES-GCM per block (~3µs/64KB) | <1% |
| 3A. Audit logging | 1 syslog per op (~1-5µs) | <0.5% |
| 3B. Rate limiting | 1 atomic inc per op (~10ns) | ~0% |
| **Combined all** | | **<2%** |

The bottleneck remains disk I/O, not security overhead.
