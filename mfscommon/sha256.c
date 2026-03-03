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
#include "sha256.h"

/* SHA-256 constants: first 32 bits of the fractional parts of the cube roots of the first 64 primes */
static const uint32_t K[64] = {
	0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
	0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
	0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
	0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
	0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
	0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
	0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
	0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
	0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
	0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
	0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
	0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
	0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
	0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
	0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
	0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U
};

#define ROTR(x,n) (((x)>>(n))|((x)<<(32-(n))))
#define SHR(x,n) ((x)>>(n))

#define CH(x,y,z)  (((x)&(y))^((~(x))&(z)))
#define MAJ(x,y,z) (((x)&(y))^((x)&(z))^((y)&(z)))

#define SIGMA0(x) (ROTR(x,2)^ROTR(x,13)^ROTR(x,22))
#define SIGMA1(x) (ROTR(x,6)^ROTR(x,11)^ROTR(x,25))
#define sigma0(x) (ROTR(x,7)^ROTR(x,18)^SHR(x,3))
#define sigma1(x) (ROTR(x,17)^ROTR(x,19)^SHR(x,10))

static void sha256_transform(uint32_t state[8],const uint8_t block[64]) {
	uint32_t a,b,c,d,e,f,g,h;
	uint32_t W[64];
	uint32_t T1,T2;
	uint32_t i;

	/* prepare message schedule */
	for (i=0 ; i<16 ; i++) {
		W[i] = ((uint32_t)block[i*4]<<24) | ((uint32_t)block[i*4+1]<<16) |
		        ((uint32_t)block[i*4+2]<<8) | ((uint32_t)block[i*4+3]);
	}
	for (i=16 ; i<64 ; i++) {
		W[i] = sigma1(W[i-2]) + W[i-7] + sigma0(W[i-15]) + W[i-16];
	}

	a = state[0];
	b = state[1];
	c = state[2];
	d = state[3];
	e = state[4];
	f = state[5];
	g = state[6];
	h = state[7];

	for (i=0 ; i<64 ; i++) {
		T1 = h + SIGMA1(e) + CH(e,f,g) + K[i] + W[i];
		T2 = SIGMA0(a) + MAJ(a,b,c);
		h = g;
		g = f;
		f = e;
		e = d + T1;
		d = c;
		c = b;
		b = a;
		a = T1 + T2;
	}

	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
	state[4] += e;
	state[5] += f;
	state[6] += g;
	state[7] += h;
}

void sha256_init(sha256ctx *ctx) {
	ctx->count = 0;
	ctx->state[0] = 0x6a09e667U;
	ctx->state[1] = 0xbb67ae85U;
	ctx->state[2] = 0x3c6ef372U;
	ctx->state[3] = 0xa54ff53aU;
	ctx->state[4] = 0x510e527fU;
	ctx->state[5] = 0x9b05688cU;
	ctx->state[6] = 0x1f83d9abU;
	ctx->state[7] = 0x5be0cd19U;
}

void sha256_update(sha256ctx *ctx,const uint8_t *data,uint32_t len) {
	uint32_t i,idx,partlen;

	idx = (uint32_t)(ctx->count & 0x3F);
	ctx->count += len;

	partlen = 64 - idx;

	if (len >= partlen) {
		memcpy(ctx->buffer + idx,data,partlen);
		sha256_transform(ctx->state,ctx->buffer);

		for (i = partlen ; i + 63 < len ; i += 64) {
			sha256_transform(ctx->state,data + i);
		}
		idx = 0;
	} else {
		i = 0;
	}

	memcpy(ctx->buffer + idx,data + i,len - i);
}

void sha256_final(uint8_t digest[32],sha256ctx *ctx) {
	uint64_t bitcount;
	uint32_t idx;
	uint32_t i;

	bitcount = ctx->count << 3;
	idx = (uint32_t)(ctx->count & 0x3F);

	/* add 0x80 padding byte */
	ctx->buffer[idx++] = 0x80;

	if (idx > 56) {
		/* not enough room for length in current block - pad and process */
		memset(ctx->buffer + idx,0,64 - idx);
		sha256_transform(ctx->state,ctx->buffer);
		idx = 0;
	}

	/* pad remaining space with zeros up to byte 56 */
	memset(ctx->buffer + idx,0,56 - idx);

	/* append bit count (big-endian) at bytes 56-63 */
	ctx->buffer[56] = (uint8_t)(bitcount >> 56);
	ctx->buffer[57] = (uint8_t)(bitcount >> 48);
	ctx->buffer[58] = (uint8_t)(bitcount >> 40);
	ctx->buffer[59] = (uint8_t)(bitcount >> 32);
	ctx->buffer[60] = (uint8_t)(bitcount >> 24);
	ctx->buffer[61] = (uint8_t)(bitcount >> 16);
	ctx->buffer[62] = (uint8_t)(bitcount >> 8);
	ctx->buffer[63] = (uint8_t)(bitcount);
	sha256_transform(ctx->state,ctx->buffer);

	/* produce digest (big-endian) */
	for (i=0 ; i<8 ; i++) {
		digest[i*4]   = (uint8_t)(ctx->state[i] >> 24);
		digest[i*4+1] = (uint8_t)(ctx->state[i] >> 16);
		digest[i*4+2] = (uint8_t)(ctx->state[i] >> 8);
		digest[i*4+3] = (uint8_t)(ctx->state[i]);
	}

	memset(ctx,0,sizeof(sha256ctx));
}

/* HMAC-SHA256 (RFC 2104) */
void hmac_sha256(const uint8_t *key,uint32_t keylen,const uint8_t *data,uint32_t datalen,uint8_t digest[32]) {
	sha256ctx ctx;
	uint8_t kpad[SHA256_BLOCK_SIZE];
	uint8_t khash[SHA256_DIGEST_SIZE];
	uint32_t i;

	/* if key is longer than block size, hash it first */
	if (keylen > SHA256_BLOCK_SIZE) {
		sha256_init(&ctx);
		sha256_update(&ctx,key,keylen);
		sha256_final(khash,&ctx);
		key = khash;
		keylen = SHA256_DIGEST_SIZE;
	}

	/* inner hash: H(K ^ ipad, data) */
	memset(kpad,0x36,SHA256_BLOCK_SIZE);
	for (i=0 ; i<keylen ; i++) {
		kpad[i] ^= key[i];
	}
	sha256_init(&ctx);
	sha256_update(&ctx,kpad,SHA256_BLOCK_SIZE);
	sha256_update(&ctx,data,datalen);
	sha256_final(digest,&ctx);

	/* outer hash: H(K ^ opad, inner_hash) */
	memset(kpad,0x5c,SHA256_BLOCK_SIZE);
	for (i=0 ; i<keylen ; i++) {
		kpad[i] ^= key[i];
	}
	sha256_init(&ctx);
	sha256_update(&ctx,kpad,SHA256_BLOCK_SIZE);
	sha256_update(&ctx,digest,SHA256_DIGEST_SIZE);
	sha256_final(digest,&ctx);

	memset(kpad,0,SHA256_BLOCK_SIZE);
	memset(khash,0,SHA256_DIGEST_SIZE);
}
