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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_PCLMULQDQ

#include <inttypes.h>
#include <wmmintrin.h>
#include <smmintrin.h>

/*
 * PCLMULQDQ-accelerated CRC32 (IEEE 802.3 polynomial 0xEDB88320 reflected).
 *
 * Based on "Fast CRC Computation for Generic Polynomials Using PCLMULQDQ
 * Instruction" by V. Gopal, E. Ozturk, et al. (Intel, 2009) and the
 * Chromium zlib crc32_simd.c implementation.
 *
 * All fold constants are x^N mod P(x) left-shifted by 1 bit, where
 * P(x) = 0x1DB710641 is the 33-bit reflected CRC32 polynomial.
 */

/* k1 = x^544 mod P << 1, k2 = x^480 mod P << 1 (for 4x128-bit folding) */
static const uint64_t __attribute__((aligned(16))) k1k2[] = {
	0x0154442bd4ULL, 0x01c6e41596ULL
};

/* k3 = x^160 mod P << 1, k4 = x^96 mod P << 1 (for 128-bit folding) */
static const uint64_t __attribute__((aligned(16))) k3k4[] = {
	0x01751997d0ULL, 0x00ccaa009eULL
};

/* k5 = x^64 mod P << 1, k0 = 0 */
static const uint64_t __attribute__((aligned(16))) k5k0[] = {
	0x0163cd6124ULL, 0x0000000000ULL
};

/* P(x) and mu for Barrett reduction */
static const uint64_t __attribute__((aligned(16))) poly[] = {
	0x01db710641ULL, 0x01f7011641ULL
};

uint32_t mycrc32_pclmul(uint32_t crc, const void *data, uint32_t leng) {
	const uint8_t *buf = (const uint8_t *)data;
	__m128i x0, x1, x2, x3, x4, x5;
	__m128i y5, y6, y7, y8;

	if (leng < 64) {
		return 0;
	}

	/*
	 * The caller (mycrc32_software / mycrc32_hardware) does ~crc at the
	 * start and ~result at the end. This function operates on the raw
	 * (inverted) CRC state, same as the Chromium zlib implementation.
	 */

	x1 = _mm_loadu_si128((const __m128i *)(buf + 0x00));
	x2 = _mm_loadu_si128((const __m128i *)(buf + 0x10));
	x3 = _mm_loadu_si128((const __m128i *)(buf + 0x20));
	x4 = _mm_loadu_si128((const __m128i *)(buf + 0x30));
	x1 = _mm_xor_si128(x1, _mm_cvtsi32_si128((int)crc));
	x0 = _mm_load_si128((const __m128i *)k1k2);
	buf += 64;
	leng -= 64;

	/* Fold 64 bytes at a time */
	while (leng >= 64) {
		x5 = _mm_clmulepi64_si128(x1, x0, 0x00);
		__m128i x6 = _mm_clmulepi64_si128(x2, x0, 0x00);
		__m128i x7 = _mm_clmulepi64_si128(x3, x0, 0x00);
		__m128i x8 = _mm_clmulepi64_si128(x4, x0, 0x00);
		x1 = _mm_clmulepi64_si128(x1, x0, 0x11);
		x2 = _mm_clmulepi64_si128(x2, x0, 0x11);
		x3 = _mm_clmulepi64_si128(x3, x0, 0x11);
		x4 = _mm_clmulepi64_si128(x4, x0, 0x11);
		y5 = _mm_loadu_si128((const __m128i *)(buf + 0x00));
		y6 = _mm_loadu_si128((const __m128i *)(buf + 0x10));
		y7 = _mm_loadu_si128((const __m128i *)(buf + 0x20));
		y8 = _mm_loadu_si128((const __m128i *)(buf + 0x30));
		x1 = _mm_xor_si128(x1, x5);
		x2 = _mm_xor_si128(x2, x6);
		x3 = _mm_xor_si128(x3, x7);
		x4 = _mm_xor_si128(x4, x8);
		x1 = _mm_xor_si128(x1, y5);
		x2 = _mm_xor_si128(x2, y6);
		x3 = _mm_xor_si128(x3, y7);
		x4 = _mm_xor_si128(x4, y8);
		buf += 64;
		leng -= 64;
	}

	/* Fold 4x128 -> 1x128 using k3/k4 */
	x0 = _mm_load_si128((const __m128i *)k3k4);
	x5 = _mm_clmulepi64_si128(x1, x0, 0x00);
	x1 = _mm_clmulepi64_si128(x1, x0, 0x11);
	x1 = _mm_xor_si128(x1, x2);
	x1 = _mm_xor_si128(x1, x5);
	x5 = _mm_clmulepi64_si128(x1, x0, 0x00);
	x1 = _mm_clmulepi64_si128(x1, x0, 0x11);
	x1 = _mm_xor_si128(x1, x3);
	x1 = _mm_xor_si128(x1, x5);
	x5 = _mm_clmulepi64_si128(x1, x0, 0x00);
	x1 = _mm_clmulepi64_si128(x1, x0, 0x11);
	x1 = _mm_xor_si128(x1, x4);
	x1 = _mm_xor_si128(x1, x5);

	/* Fold remaining 16-byte blocks */
	while (leng >= 16) {
		x2 = _mm_loadu_si128((const __m128i *)buf);
		x5 = _mm_clmulepi64_si128(x1, x0, 0x00);
		x1 = _mm_clmulepi64_si128(x1, x0, 0x11);
		x1 = _mm_xor_si128(x1, x2);
		x1 = _mm_xor_si128(x1, x5);
		buf += 16;
		leng -= 16;
	}

	/* Reduce 128 -> 64 bits */
	x2 = _mm_clmulepi64_si128(x1, x0, 0x10);
	x3 = _mm_setr_epi32(~0, 0, ~0, 0);
	x1 = _mm_srli_si128(x1, 8);
	x1 = _mm_xor_si128(x1, x2);

	/* Reduce 64 -> 32 bits */
	x0 = _mm_loadl_epi64((const __m128i *)k5k0);
	x2 = _mm_srli_si128(x1, 4);
	x1 = _mm_and_si128(x1, x3);
	x1 = _mm_clmulepi64_si128(x1, x0, 0x00);
	x1 = _mm_xor_si128(x1, x2);

	/* Barrett reduction */
	x0 = _mm_load_si128((const __m128i *)poly);
	x2 = _mm_and_si128(x1, x3);
	x2 = _mm_clmulepi64_si128(x2, x0, 0x10);
	x2 = _mm_and_si128(x2, x3);
	x2 = _mm_clmulepi64_si128(x2, x0, 0x00);
	x1 = _mm_xor_si128(x1, x2);

	return (uint32_t)_mm_extract_epi32(x1, 1);
}

int mycrc32_hw_available(void) {
	uint32_t eax, ebx, ecx, edx;
#if defined(__GNUC__) || defined(__clang__)
	__asm__ __volatile__ (
		"cpuid"
		: "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
		: "a"(1), "c"(0)
	);
	return (ecx & (1 << 1)) != 0;
#else
	return 0;
#endif
}

#else /* !HAVE_PCLMULQDQ */

uint32_t mycrc32_pclmul(uint32_t crc, const void *data, uint32_t leng) {
	(void)crc;
	(void)data;
	(void)leng;
	return 0;
}

int mycrc32_hw_available(void) {
	return 0;
}

#endif /* HAVE_PCLMULQDQ */
