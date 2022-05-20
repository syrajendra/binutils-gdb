/*
 * Copyright (c) 2011, Juniper Networks, Inc.
 * All rights reserved.
 * Copyright (c) 2006 Peter Wemm
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <libkvm/kvm_hpt.h>

/* minidump must be the first item! */
struct vmstate {
	int minidump;		/* 1 = minidump mode */
	struct minidumphdr hdr;
	void *hpt_head[HPT_SIZE];
#if defined(KGDB_TGT_ARCH_amd64) || defined(KGDB_TGT_ARCH_aarch64)
	uint64_t *bitmap;
	uint64_t *page_map;
#elif defined(KGDB_TGT_ARCH_arm)
	uint32_t	*bitmap;
	void		*ptemap;
#elif defined(KGDB_TGT_ARCH_i386)
	uint32_t	*bitmap;
	void		*ptemap;
#elif defined(KGDB_TGT_ARCH_mips)
	uint32_t *bitmap;		/* bitmap for the dump */
	void *ptemap;			/* PTE map for the dump */
	int64_t dmapoff;		/* direct mapped memory offset */
#elif defined(KGDB_TGT_ARCH_mips64)
	uint32_t *bitmap;		/* bitmap for the dump */
	uint64_t *ptemap;			/* PTE map for the dump */
	int64_t dmapoff;		/* direct mapped memory offset */
#elif defined(KGDB_TGT_ARCH_powerpc64)
	uint64_t *bitmap;
	pte_t *ptemap;
#endif
};
