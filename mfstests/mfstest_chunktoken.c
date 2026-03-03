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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "MFSCommunication.h"
#include "sha256.h"
#include "chunktoken.h"

#include "mfstest.h"

/* ---- SHA-256 tests ---- */

/* helper: compare digest to hex string */
static int digest_eq(const uint8_t digest[32], const char *hex) {
	uint8_t expected[32];
	unsigned int i, v;
	for (i = 0; i < 32; i++) {
		sscanf(hex + i*2, "%02x", &v);
		expected[i] = (uint8_t)v;
	}
	return memcmp(digest, expected, 32) == 0;
}

static void test_sha256(void) {
	sha256ctx ctx;
	uint8_t digest[32];

	mfstest_start(sha256_empty);
	/* SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 */
	sha256_init(&ctx);
	sha256_update(&ctx, (const uint8_t *)"", 0);
	sha256_final(digest, &ctx);
	mfstest_assert_uint8(digest_eq(digest, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"), ==, 1);
	mfstest_end();

	mfstest_start(sha256_abc);
	/* SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad */
	sha256_init(&ctx);
	sha256_update(&ctx, (const uint8_t *)"abc", 3);
	sha256_final(digest, &ctx);
	mfstest_assert_uint8(digest_eq(digest, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"), ==, 1);
	mfstest_end();

	mfstest_start(sha256_long);
	/* SHA-256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") */
	sha256_init(&ctx);
	sha256_update(&ctx, (const uint8_t *)"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56);
	sha256_final(digest, &ctx);
	mfstest_assert_uint8(digest_eq(digest, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"), ==, 1);
	mfstest_end();

	mfstest_start(sha256_incremental);
	/* same as above but fed in small chunks */
	sha256_init(&ctx);
	sha256_update(&ctx, (const uint8_t *)"abcdbcde", 8);
	sha256_update(&ctx, (const uint8_t *)"cdefdefg", 8);
	sha256_update(&ctx, (const uint8_t *)"efghfghi", 8);
	sha256_update(&ctx, (const uint8_t *)"ghijhijk", 8);
	sha256_update(&ctx, (const uint8_t *)"ijkljklm", 8);
	sha256_update(&ctx, (const uint8_t *)"klmnlmno", 8);
	sha256_update(&ctx, (const uint8_t *)"mnopnopq", 8);
	sha256_final(digest, &ctx);
	mfstest_assert_uint8(digest_eq(digest, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"), ==, 1);
	mfstest_end();

	mfstest_start(sha256_million_a);
	/* SHA-256(1,000,000 * 'a') = cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0 */
	{
		uint8_t buf[1000];
		uint32_t i;
		memset(buf, 'a', 1000);
		sha256_init(&ctx);
		for (i = 0; i < 1000; i++) {
			sha256_update(&ctx, buf, 1000);
		}
		sha256_final(digest, &ctx);
		mfstest_assert_uint8(digest_eq(digest, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"), ==, 1);
	}
	mfstest_end();
}

/* ---- HMAC-SHA256 tests (RFC 4231) ---- */

static void test_hmac_sha256(void) {
	uint8_t digest[32];

	mfstest_start(hmac_sha256_rfc4231_tc2);
	/* Test Case 2: Key = "Jefe", Data = "what do ya want for nothing?" */
	hmac_sha256(
		(const uint8_t *)"Jefe", 4,
		(const uint8_t *)"what do ya want for nothing?", 28,
		digest
	);
	mfstest_assert_uint8(digest_eq(digest, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"), ==, 1);
	mfstest_end();

	mfstest_start(hmac_sha256_rfc4231_tc1);
	/* Test Case 1: Key = 20 bytes of 0x0b, Data = "Hi There" */
	{
		uint8_t key[20];
		memset(key, 0x0b, 20);
		hmac_sha256(key, 20, (const uint8_t *)"Hi There", 8, digest);
		mfstest_assert_uint8(digest_eq(digest, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"), ==, 1);
	}
	mfstest_end();

	mfstest_start(hmac_sha256_rfc4231_tc3);
	/* Test Case 3: Key = 20 bytes of 0xaa, Data = 50 bytes of 0xdd */
	{
		uint8_t key[20], data[50];
		memset(key, 0xaa, 20);
		memset(data, 0xdd, 50);
		hmac_sha256(key, 20, data, 50, digest);
		mfstest_assert_uint8(digest_eq(digest, "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"), ==, 1);
	}
	mfstest_end();

	mfstest_start(hmac_sha256_rfc4231_tc4);
	/* Test Case 4: Key = 0x0102...19 (25 bytes), Data = 50 bytes of 0xcd */
	{
		uint8_t key[25], data[50];
		uint8_t i;
		for (i = 0; i < 25; i++) key[i] = i + 1;
		memset(data, 0xcd, 50);
		hmac_sha256(key, 25, data, 50, digest);
		mfstest_assert_uint8(digest_eq(digest, "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"), ==, 1);
	}
	mfstest_end();

	mfstest_start(hmac_sha256_rfc4231_tc6);
	/* Test Case 6: Key = 131 bytes of 0xaa, Data = "Test Using Larger Than Block-Size Key - Hash Key First" */
	{
		uint8_t key[131];
		memset(key, 0xaa, 131);
		hmac_sha256(key, 131, (const uint8_t *)"Test Using Larger Than Block-Size Key - Hash Key First", 54, digest);
		mfstest_assert_uint8(digest_eq(digest, "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"), ==, 1);
	}
	mfstest_end();
}

/* ---- chunk token tests ---- */

static void test_chunk_token(void) {
	uint8_t secret[CHUNK_TOKEN_SIZE];
	uint8_t token[CHUNK_TOKEN_SIZE];
	uint8_t token2[CHUNK_TOKEN_SIZE];
	uint64_t chunkid;
	uint32_t version, expiry, now;

	memset(secret, 0x42, CHUNK_TOKEN_SIZE);
	chunkid = 0x0123456789ABCDEFULL;
	version = 100;
	now = (uint32_t)time(NULL);
	expiry = now + CHUNK_TOKEN_TTL;

	/* generate and validate: should succeed */
	mfstest_start(token_generate_validate);
	chunk_token_generate(secret, chunkid, version, expiry, token);
	mfstest_assert_uint8(chunk_token_validate(secret, chunkid, version, expiry, token, now), ==, 1);
	mfstest_end();

	/* deterministic: same inputs produce same token */
	mfstest_start(token_deterministic);
	chunk_token_generate(secret, chunkid, version, expiry, token2);
	mfstest_assert_uint8((memcmp(token, token2, CHUNK_TOKEN_SIZE) == 0) ? 1 : 0, ==, 1);
	mfstest_end();

	/* expired token: should fail */
	mfstest_start(token_expired);
	{
		uint32_t old_expiry = now - 10;
		chunk_token_generate(secret, chunkid, version, old_expiry, token);
		mfstest_assert_uint8(chunk_token_validate(secret, chunkid, version, old_expiry, token, now), ==, 0);
	}
	mfstest_end();

	/* wrong chunkid: should fail */
	mfstest_start(token_wrong_chunkid);
	chunk_token_generate(secret, chunkid, version, expiry, token);
	mfstest_assert_uint8(chunk_token_validate(secret, chunkid + 1, version, expiry, token, now), ==, 0);
	mfstest_end();

	/* wrong version: should fail */
	mfstest_start(token_wrong_version);
	chunk_token_generate(secret, chunkid, version, expiry, token);
	mfstest_assert_uint8(chunk_token_validate(secret, chunkid, version + 1, expiry, token, now), ==, 0);
	mfstest_end();

	/* wrong secret: should fail */
	mfstest_start(token_wrong_secret);
	{
		uint8_t bad_secret[CHUNK_TOKEN_SIZE];
		memset(bad_secret, 0x99, CHUNK_TOKEN_SIZE);
		chunk_token_generate(secret, chunkid, version, expiry, token);
		mfstest_assert_uint8(chunk_token_validate(bad_secret, chunkid, version, expiry, token, now), ==, 0);
	}
	mfstest_end();

	/* tampered token: should fail */
	mfstest_start(token_tampered);
	chunk_token_generate(secret, chunkid, version, expiry, token);
	token[0] ^= 0x01;
	mfstest_assert_uint8(chunk_token_validate(secret, chunkid, version, expiry, token, now), ==, 0);
	mfstest_end();

	/* different expiry = different token */
	mfstest_start(token_different_expiry);
	chunk_token_generate(secret, chunkid, version, expiry, token);
	chunk_token_generate(secret, chunkid, version, expiry + 1, token2);
	mfstest_assert_uint8((memcmp(token, token2, CHUNK_TOKEN_SIZE) != 0) ? 1 : 0, ==, 1);
	mfstest_end();

	/* validate at exact expiry time: should succeed */
	mfstest_start(token_at_expiry_boundary);
	chunk_token_generate(secret, chunkid, version, expiry, token);
	mfstest_assert_uint8(chunk_token_validate(secret, chunkid, version, expiry, token, expiry), ==, 1);
	mfstest_end();

	/* validate 1 second after expiry: should fail */
	mfstest_start(token_one_past_expiry);
	chunk_token_generate(secret, chunkid, version, expiry, token);
	mfstest_assert_uint8(chunk_token_validate(secret, chunkid, version, expiry, token, expiry + 1), ==, 0);
	mfstest_end();
}

int main(void) {
	mfstest_init();

	test_sha256();
	test_hmac_sha256();
	test_chunk_token();

	mfstest_return();
}
