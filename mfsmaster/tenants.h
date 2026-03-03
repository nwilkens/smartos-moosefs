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

#ifndef _TENANTS_H_
#define _TENANTS_H_

#include <inttypes.h>

int tenants_init(void);
void tenants_reload(void);
void tenants_term(void);

// Returns 1 if any tenants are defined, 0 otherwise
int tenants_are_defined(void);

// Returns tenant pointer (opaque) or NULL if not found
void* tenants_find(const char *tenant_id, uint32_t tenant_id_len);

// Verify HMAC(secret, challenge) == response
// Returns 1 on success, 0 on failure
int tenants_auth_check(void *tenant, const uint8_t challenge[32], const uint8_t response[32]);

// Accessors
uint32_t tenants_get_uid(void *tenant);
uint32_t tenants_get_gid(void *tenant);
const uint8_t* tenants_get_rootpath(void *tenant);
uint32_t tenants_get_rootpath_len(void *tenant);
uint16_t tenants_get_sclassgroups(void *tenant);
uint8_t tenants_get_sesflags(void *tenant);

#endif
