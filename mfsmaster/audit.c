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

#include <inttypes.h>

#include "audit.h"
#include "cfg.h"
#include "mfslog.h"
#include "mfsstrerr.h"

static uint32_t AuditLogEnabled;

void audit_log(uint32_t sessionid, uint32_t uid, uint32_t gid, const char *op, uint32_t inode, uint8_t status) {
	if (!AuditLogEnabled) {
		return;
	}
	mfs_log(MFSLOG_SYSLOG, MFSLOG_NOTICE, "AUDIT: session=%"PRIu32" uid=%"PRIu32" gid=%"PRIu32" op=%s inode=%"PRIu32" status=%s", sessionid, uid, gid, op, inode, mfsstrerr(status));
}

void audit_term(void) {
	/* nothing to clean up */
}

int audit_init(void) {
	AuditLogEnabled = cfg_getuint32("ENABLE_AUDIT_LOG", 0);
	mfs_log(MFSLOG_SYSLOG, MFSLOG_INFO, "audit: audit logging %s", AuditLogEnabled ? "enabled" : "disabled");
	return 0;
}
