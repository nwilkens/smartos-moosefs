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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <inttypes.h>

#include "MFSCommunication.h"
#include "tenants.h"
#include "sha256.h"
#include "datapack.h"
#include "main.h"
#include "cfg.h"
#include "mfslog.h"
#include "massert.h"

#define TENANT_ID_MAX 64
#define TENANT_SECRET_LEN 32

typedef struct _tenant {
	char tenant_id[TENANT_ID_MAX+1];
	uint32_t tenant_id_len;
	uint8_t secret[TENANT_SECRET_LEN];
	uint32_t uid;
	uint32_t gid;
	uint8_t *rootpath;
	uint32_t rootpath_len;
	uint16_t sclassgroups;
	uint8_t sesflags;
	struct _tenant *next;
} tenant;

static tenant *tenants_head;
static char *TenantsFileName;

static int hex_to_bytes(const char *hex, uint8_t *out, uint32_t outlen) {
	uint32_t i;
	for (i=0 ; i<outlen ; i++) {
		uint8_t hi,lo;
		if (hex[2*i]>='0' && hex[2*i]<='9') {
			hi = hex[2*i] - '0';
		} else if (hex[2*i]>='a' && hex[2*i]<='f') {
			hi = hex[2*i] - 'a' + 10;
		} else if (hex[2*i]>='A' && hex[2*i]<='F') {
			hi = hex[2*i] - 'A' + 10;
		} else {
			return -1;
		}
		if (hex[2*i+1]>='0' && hex[2*i+1]<='9') {
			lo = hex[2*i+1] - '0';
		} else if (hex[2*i+1]>='a' && hex[2*i+1]<='f') {
			lo = hex[2*i+1] - 'a' + 10;
		} else if (hex[2*i+1]>='A' && hex[2*i+1]<='F') {
			lo = hex[2*i+1] - 'A' + 10;
		} else {
			return -1;
		}
		out[i] = (hi << 4) | lo;
	}
	return 0;
}

static void tenants_freelist(tenant *tlist) {
	tenant *t;
	while (tlist) {
		t = tlist;
		tlist = tlist->next;
		if (t->rootpath) {
			free(t->rootpath);
		}
		free(t);
	}
}

// Parse a single line of mfstenants.cfg
// Format: tenant_id:hex_secret:uid:gid:root_path:sclassgroups:flags
static int tenants_parseline(char *line, uint32_t lineno, tenant *trec) {
	char *p;
	uint32_t len,i;
	char *tid,*secret,*uidstr,*gidstr,*path,*sclstr,*flagstr;

	// skip leading whitespace
	while (*line==' ' || *line=='\t') {
		line++;
	}
	// skip empty lines and comments
	if (*line==0 || *line=='#') {
		return -1;
	}

	// tokenize by ':'
	tid = line;
	p = strchr(tid,':');
	if (p==NULL) {
		mfs_log(MFSLOG_SYSLOG_STDERR,MFSLOG_WARNING,"mfstenants: line %"PRIu32": missing fields after tenant_id",lineno);
		return -1;
	}
	*p = 0;
	secret = p+1;

	p = strchr(secret,':');
	if (p==NULL) {
		mfs_log(MFSLOG_SYSLOG_STDERR,MFSLOG_WARNING,"mfstenants: line %"PRIu32": missing fields after secret",lineno);
		return -1;
	}
	*p = 0;
	uidstr = p+1;

	p = strchr(uidstr,':');
	if (p==NULL) {
		mfs_log(MFSLOG_SYSLOG_STDERR,MFSLOG_WARNING,"mfstenants: line %"PRIu32": missing fields after uid",lineno);
		return -1;
	}
	*p = 0;
	gidstr = p+1;

	p = strchr(gidstr,':');
	if (p==NULL) {
		mfs_log(MFSLOG_SYSLOG_STDERR,MFSLOG_WARNING,"mfstenants: line %"PRIu32": missing fields after gid",lineno);
		return -1;
	}
	*p = 0;
	path = p+1;

	p = strchr(path,':');
	if (p==NULL) {
		mfs_log(MFSLOG_SYSLOG_STDERR,MFSLOG_WARNING,"mfstenants: line %"PRIu32": missing fields after path",lineno);
		return -1;
	}
	*p = 0;
	sclstr = p+1;

	p = strchr(sclstr,':');
	if (p==NULL) {
		mfs_log(MFSLOG_SYSLOG_STDERR,MFSLOG_WARNING,"mfstenants: line %"PRIu32": missing fields after sclassgroups",lineno);
		return -1;
	}
	*p = 0;
	flagstr = p+1;

	// strip trailing whitespace from flagstr
	len = strlen(flagstr);
	while (len>0 && (flagstr[len-1]==' ' || flagstr[len-1]=='\t' || flagstr[len-1]=='\r' || flagstr[len-1]=='\n')) {
		len--;
	}
	flagstr[len] = 0;

	// validate tenant_id
	len = strlen(tid);
	if (len==0 || len>TENANT_ID_MAX) {
		mfs_log(MFSLOG_SYSLOG_STDERR,MFSLOG_WARNING,"mfstenants: line %"PRIu32": tenant_id length must be 1..%d",lineno,TENANT_ID_MAX);
		return -1;
	}
	for (i=0 ; i<len ; i++) {
		if (!((tid[i]>='a' && tid[i]<='z') || (tid[i]>='A' && tid[i]<='Z') || (tid[i]>='0' && tid[i]<='9') || tid[i]=='_' || tid[i]=='-')) {
			mfs_log(MFSLOG_SYSLOG_STDERR,MFSLOG_WARNING,"mfstenants: line %"PRIu32": tenant_id contains invalid character '%c'",lineno,tid[i]);
			return -1;
		}
	}
	memset(trec->tenant_id,0,TENANT_ID_MAX+1);
	memcpy(trec->tenant_id,tid,len);
	trec->tenant_id_len = len;

	// validate and parse secret (64 hex chars = 32 bytes)
	if (strlen(secret)!=TENANT_SECRET_LEN*2) {
		mfs_log(MFSLOG_SYSLOG_STDERR,MFSLOG_WARNING,"mfstenants: line %"PRIu32": secret must be exactly %d hex characters",lineno,TENANT_SECRET_LEN*2);
		return -1;
	}
	if (hex_to_bytes(secret,trec->secret,TENANT_SECRET_LEN)<0) {
		mfs_log(MFSLOG_SYSLOG_STDERR,MFSLOG_WARNING,"mfstenants: line %"PRIu32": secret contains invalid hex characters",lineno);
		return -1;
	}

	// parse uid
	{
		char *endp;
		unsigned long v;
		v = strtoul(uidstr,&endp,10);
		if (*endp!=0 || endp==uidstr) {
			mfs_log(MFSLOG_SYSLOG_STDERR,MFSLOG_WARNING,"mfstenants: line %"PRIu32": invalid uid '%s'",lineno,uidstr);
			return -1;
		}
		trec->uid = (uint32_t)v;
	}

	// parse gid
	{
		char *endp;
		unsigned long v;
		v = strtoul(gidstr,&endp,10);
		if (*endp!=0 || endp==gidstr) {
			mfs_log(MFSLOG_SYSLOG_STDERR,MFSLOG_WARNING,"mfstenants: line %"PRIu32": invalid gid '%s'",lineno,gidstr);
			return -1;
		}
		trec->gid = (uint32_t)v;
	}

	// parse root_path
	len = strlen(path);
	if (len>0) {
		// strip leading '/'
		p = path;
		while (*p=='/') {
			p++;
		}
		len = strlen(p);
		// strip trailing '/'
		while (len>0 && p[len-1]=='/') {
			len--;
		}
		if (len>0) {
			trec->rootpath = malloc(len+1);
			passert(trec->rootpath);
			memcpy(trec->rootpath,p,len);
			trec->rootpath[len] = 0;
		} else {
			trec->rootpath = NULL;
		}
		trec->rootpath_len = len;
	} else {
		trec->rootpath = NULL;
		trec->rootpath_len = 0;
	}

	// parse sclassgroups
	{
		char *endp;
		unsigned long v;
		if (*sclstr=='-' && sclstr[1]==0) {
			trec->sclassgroups = 0;
		} else {
			v = strtoul(sclstr,&endp,10);
			if (*endp!=0 || endp==sclstr || v>0xFFFF) {
				mfs_log(MFSLOG_SYSLOG_STDERR,MFSLOG_WARNING,"mfstenants: line %"PRIu32": invalid sclassgroups '%s'",lineno,sclstr);
				return -1;
			}
			trec->sclassgroups = (uint16_t)v;
		}
	}

	// parse flags: combination of r/w/a
	trec->sesflags = SESFLAG_READONLY; // default readonly
	len = strlen(flagstr);
	for (i=0 ; i<len ; i++) {
		switch (flagstr[i]) {
		case 'r':
			// read is default (we just don't set readonly if 'w' is also present)
			break;
		case 'w':
			trec->sesflags &= ~SESFLAG_READONLY;
			break;
		case 'a':
			trec->sesflags |= SESFLAG_ADMIN;
			trec->sesflags &= ~SESFLAG_READONLY;
			break;
		default:
			mfs_log(MFSLOG_SYSLOG_STDERR,MFSLOG_WARNING,"mfstenants: line %"PRIu32": unknown flag '%c' (use r/w/a)",lineno,flagstr[i]);
			return -1;
		}
	}
	// if flags contain 'w' or 'a', already handled above
	// if flags only contain 'r', sesflags stays READONLY

	trec->next = NULL;
	return 0;
}

static void tenants_loadconfig(void) {
	FILE *fd;
	char *linebuff;
	size_t lbsize;
	uint32_t s,lineno;
	tenant *newlist,**tail,*trec;

	fd = fopen(TenantsFileName,"r");
	if (fd==NULL) {
		if (errno==ENOENT) {
			if (tenants_head) {
				mfs_log(MFSLOG_SYSLOG,MFSLOG_WARNING,"mfstenants configuration file (%s) not found - tenants not changed",TenantsFileName);
			} else {
				mfs_log(MFSLOG_SYSLOG,MFSLOG_INFO,"mfstenants configuration file (%s) not found - no tenants defined (tenant auth disabled)",TenantsFileName);
			}
		} else {
			if (tenants_head) {
				mfs_log(MFSLOG_ERRNO_SYSLOG,MFSLOG_WARNING,"can't open mfstenants configuration file (%s) - tenants not changed, error",TenantsFileName);
			} else {
				mfs_log(MFSLOG_ERRNO_SYSLOG,MFSLOG_WARNING,"can't open mfstenants configuration file (%s) - no tenants defined, error",TenantsFileName);
			}
		}
		return;
	}
	newlist = NULL;
	tail = &newlist;
	lineno = 1;
	trec = malloc(sizeof(tenant));
	passert(trec);
	lbsize = 10000;
	linebuff = malloc(lbsize);
	while (getline(&linebuff,&lbsize,fd)!=-1) {
		s = strlen(linebuff);
		while (s>0 && (linebuff[s-1]=='\r' || linebuff[s-1]=='\n' || linebuff[s-1]=='\t' || linebuff[s-1]==' ')) {
			s--;
		}
		if (s>0) {
			linebuff[s] = 0;
			if (tenants_parseline(linebuff,lineno,trec)>=0) {
				*tail = trec;
				tail = &(trec->next);
				trec = malloc(sizeof(tenant));
				passert(trec);
			}
		}
		lineno++;
	}
	free(linebuff);
	free(trec);
	if (ferror(fd)) {
		fclose(fd);
		if (tenants_head) {
			mfs_log(MFSLOG_SYSLOG,MFSLOG_WARNING,"error reading mfstenants file - tenants not changed");
		} else {
			mfs_log(MFSLOG_SYSLOG,MFSLOG_WARNING,"error reading mfstenants file - no tenants defined");
		}
		tenants_freelist(newlist);
		return;
	}
	fclose(fd);
	tenants_freelist(tenants_head);
	tenants_head = newlist;
	mfs_log(MFSLOG_SYSLOG,MFSLOG_INFO,"mfstenants file has been loaded");
}

void tenants_reload(void) {
	int fd;
	if (TenantsFileName) {
		free(TenantsFileName);
	}
	if (!cfg_isdefined("TENANTS_FILENAME")) {
		TenantsFileName = strdup(ETC_PATH "/mfs/mfstenants.cfg");
		passert(TenantsFileName);
		if ((fd = open(TenantsFileName,O_RDONLY))<0 && errno==ENOENT) {
			char *tmpname;
			tmpname = strdup(ETC_PATH "/mfstenants.cfg");
			if ((fd = open(tmpname,O_RDONLY))>=0) {
				free(TenantsFileName);
				TenantsFileName = tmpname;
			} else {
				free(tmpname);
			}
		}
		if (fd>=0) {
			close(fd);
		}
		cfg_use_option("TENANTS_FILENAME",TenantsFileName);
	} else {
		TenantsFileName = cfg_getstr("TENANTS_FILENAME",ETC_PATH "/mfs/mfstenants.cfg");
	}
	tenants_loadconfig();
}

void tenants_term(void) {
	tenants_freelist(tenants_head);
	tenants_head = NULL;
	if (TenantsFileName) {
		free(TenantsFileName);
		TenantsFileName = NULL;
	}
}

int tenants_init(void) {
	tenants_head = NULL;
	TenantsFileName = NULL;
	tenants_reload();
	// tenants are optional - don't fail if none defined
	main_reload_register(tenants_reload);
	main_destruct_register(tenants_term);
	return 0;
}

int tenants_are_defined(void) {
	return (tenants_head!=NULL) ? 1 : 0;
}

void* tenants_find(const char *tenant_id, uint32_t tenant_id_len) {
	tenant *t;
	if (tenant_id==NULL || tenant_id_len==0 || tenant_id_len>TENANT_ID_MAX) {
		return NULL;
	}
	for (t=tenants_head ; t ; t=t->next) {
		if (t->tenant_id_len==tenant_id_len && memcmp(t->tenant_id,tenant_id,tenant_id_len)==0) {
			return t;
		}
	}
	return NULL;
}

int tenants_auth_check(void *vtenant, const uint8_t challenge[32], const uint8_t response[32]) {
	tenant *t = (tenant*)vtenant;
	uint8_t expected[32];
	uint32_t i;
	uint8_t diff;

	if (t==NULL) {
		return 0;
	}

	// HMAC-SHA256(secret, challenge)
	hmac_sha256(t->secret,TENANT_SECRET_LEN,challenge,32,expected);

	// constant-time comparison
	diff = 0;
	for (i=0 ; i<32 ; i++) {
		diff |= expected[i] ^ response[i];
	}
	return (diff==0) ? 1 : 0;
}

uint32_t tenants_get_uid(void *vtenant) {
	tenant *t = (tenant*)vtenant;
	return t->uid;
}

uint32_t tenants_get_gid(void *vtenant) {
	tenant *t = (tenant*)vtenant;
	return t->gid;
}

const uint8_t* tenants_get_rootpath(void *vtenant) {
	tenant *t = (tenant*)vtenant;
	if (t->rootpath==NULL) {
		return (const uint8_t*)"";
	}
	return t->rootpath;
}

uint32_t tenants_get_rootpath_len(void *vtenant) {
	tenant *t = (tenant*)vtenant;
	return t->rootpath_len;
}

uint16_t tenants_get_sclassgroups(void *vtenant) {
	tenant *t = (tenant*)vtenant;
	return t->sclassgroups;
}

uint8_t tenants_get_sesflags(void *vtenant) {
	tenant *t = (tenant*)vtenant;
	return t->sesflags;
}
