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

#include <defs.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>

#include <libkvm/kvm.h>
#include <libkvm/kvm_hpt.h>
#include <include/sys/target.h>
#include <include/sys/fnv_hash.h>

void
hpt_insert(void **hpt_head, uint64_t paddr, int64_t off)
{
	struct hpte *hpte;
	uint32_t fnv = FNV1_32_INIT;
#if defined(__mips__)
	uint64_t pa = be64toh(paddr);
#else
	uint64_t pa = paddr;
#endif

	fnv = fnv_32_buf(&pa, sizeof(pa), fnv);
	fnv &= (HPT_SIZE - 1);
	hpte = (struct hpte *)malloc(sizeof(*hpte));
	if (!hpte) {
		return;
	}
	hpte->pa = pa;
	hpte->off = off;
	hpte->next = (struct hpte *)hpt_head[fnv];
	hpt_head[fnv] = hpte;
}

int64_t
hpt_find(void **hpt_head, uint64_t pa)
{
	struct hpte *hpte;
	uint32_t fnv = FNV1_32_INIT;

	fnv = fnv_32_buf(&pa, sizeof(pa), fnv);
	fnv &= (HPT_SIZE - 1);
	for (hpte = (struct hpte *)hpt_head[fnv]; hpte != NULL;
	     hpte = hpte->next) {
		if (pa == hpte->pa) {
			return hpte->off;
		}
	}
	return -1;
}
