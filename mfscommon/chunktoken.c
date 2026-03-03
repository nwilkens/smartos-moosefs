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

#include <string.h>
#include <inttypes.h>
#include "chunktoken.h"
#include "sha256.h"
#include "datapack.h"

/* Token message = chunkid:8 || version:4 || expiry:4 = 16 bytes */
#define TOKEN_MSG_SIZE 16

void chunk_token_generate(const uint8_t secret[CHUNK_TOKEN_SIZE],uint64_t chunkid,uint32_t version,uint32_t expiry,uint8_t token_out[CHUNK_TOKEN_SIZE]) {
	uint8_t msg[TOKEN_MSG_SIZE];
	uint8_t *wptr;

	wptr = msg;
	put64bit(&wptr,chunkid);
	put32bit(&wptr,version);
	put32bit(&wptr,expiry);

	hmac_sha256(secret,CHUNK_TOKEN_SIZE,msg,TOKEN_MSG_SIZE,token_out);
}

uint8_t chunk_token_validate(const uint8_t secret[CHUNK_TOKEN_SIZE],uint64_t chunkid,uint32_t version,uint32_t expiry,const uint8_t token[CHUNK_TOKEN_SIZE],uint32_t now) {
	uint8_t expected[CHUNK_TOKEN_SIZE];

	if (now > expiry) {
		return 0;
	}

	chunk_token_generate(secret,chunkid,version,expiry,expected);

	/* constant-time comparison to prevent timing attacks */
	{
		uint8_t diff = 0;
		uint32_t i;
		for (i=0 ; i<CHUNK_TOKEN_SIZE ; i++) {
			diff |= token[i] ^ expected[i];
		}
		return (diff == 0) ? 1 : 0;
	}
}
