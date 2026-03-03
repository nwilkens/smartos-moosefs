/*
 * Copyright (C) 2025 Jakub Kruszona-Zawadzki, Saglabs SA
 *
 * This file is part of MooseFS.
 *
 * MooseFS is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2 (only).
 *
 * MooseFS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see
 * <https://www.gnu.org/licenses/>.
 */

#ifndef _CHUNKTOKEN_H_
#define _CHUNKTOKEN_H_

#include <inttypes.h>
#include "MFSCommunication.h"

/*
 * Chunk access token: HMAC-SHA256(secret, chunkid || version || expiry)
 *
 * Token is 32 bytes. The master generates it when returning chunk
 * locations to a client. The chunkserver validates it before serving data.
 *
 * The token binds (chunkid, version, expiry) together so that:
 * - A token for chunk X cannot be used to access chunk Y
 * - A token for version V cannot be used after the chunk is modified (version changes)
 * - A token expires after CHUNK_TOKEN_TTL seconds
 *
 * The 32-byte secret is generated once by the master at startup and distributed
 * to chunkservers via MATOCS_SET_CHUNK_TOKEN_SECRET during registration.
 */

/* Generate a chunk access token.
 * secret: 32-byte HMAC key shared between master and chunkservers
 * chunkid: the chunk being accessed
 * version: the chunk version
 * expiry: absolute timestamp (seconds since epoch) when token expires
 * token_out: 32-byte output buffer for the generated token
 */
void chunk_token_generate(const uint8_t secret[CHUNK_TOKEN_SIZE],uint64_t chunkid,uint32_t version,uint32_t expiry,uint8_t token_out[CHUNK_TOKEN_SIZE]);

/* Validate a chunk access token.
 * secret: 32-byte HMAC key
 * chunkid, version: the chunk being accessed
 * expiry: the expiry timestamp that was embedded in the token
 * token: the 32-byte token to validate
 * now: current time (seconds since epoch)
 * Returns 1 if valid and not expired, 0 otherwise.
 */
uint8_t chunk_token_validate(const uint8_t secret[CHUNK_TOKEN_SIZE],uint64_t chunkid,uint32_t version,uint32_t expiry,const uint8_t token[CHUNK_TOKEN_SIZE],uint32_t now);

#endif
