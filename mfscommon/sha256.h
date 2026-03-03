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

#ifndef _SHA256_H_
#define _SHA256_H_

#include <inttypes.h>

#define SHA256_DIGEST_SIZE 32
#define SHA256_BLOCK_SIZE 64

typedef struct _sha256ctx {
	uint32_t state[8];
	uint64_t count;
	uint8_t buffer[64];
} sha256ctx;

void sha256_init(sha256ctx *ctx);
void sha256_update(sha256ctx *ctx,const uint8_t *data,uint32_t len);
void sha256_final(uint8_t digest[32],sha256ctx *ctx);

void hmac_sha256(const uint8_t *key,uint32_t keylen,const uint8_t *data,uint32_t datalen,uint8_t digest[32]);

#endif
