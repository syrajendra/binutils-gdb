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
#include <include/sys/target.h>
#include <libkvm/kvm_private.h>
#include <libkvm/kvm_minidump.h>
#include <include/sys/fnv_hash.h>

#include <libkvm/kvm_hpt.h>

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

#if defined(KGDB_TGT_ARCH_amd64) || defined(KGDB_TGT_ARCH_aarch64) || defined(KGDB_TGT_ARCH_arm)
static uint64_t
real_to_relative(kvm_t *kd, uint64_t pa)
{
        uint64_t adjust = 0;
        struct vmstate *vmst = kd->vmst;
        for (int i = 0; vmst->dump_avail[i+1] != 0; i+=2) {
                if (i == 0)
                        adjust += vmst->dump_avail[i];
                else
                        adjust += vmst->dump_avail[i] - vmst->dump_avail[i-1];
                if (pa >= vmst->dump_avail[i] && pa < vmst->dump_avail[i+1])
                        return pa - adjust;
        }
        return -1;
}

int64_t
hpt_find_rela(kvm_t *kd, uint64_t pa)
{
	struct hpte *hpte;
        void **hpt_head = kd->vmst->hpt_head;
	uint32_t fnv = FNV1_32_INIT;
        uint64_t rpa = real_to_relative(kd, pa);
        if (rpa == (uint64_t)-1)
                return -1;

	fnv = fnv_32_buf(&rpa, sizeof(rpa), fnv);
	fnv &= (HPT_SIZE - 1);
	for (hpte = (struct hpte *)hpt_head[fnv]; hpte != NULL;
	     hpte = hpte->next) {
		if (rpa == hpte->pa) {
			return hpte->off;
		}
	}
	return -1;
}
#endif
