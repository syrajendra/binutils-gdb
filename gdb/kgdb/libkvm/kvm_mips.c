/*	$Id: kvm_mips.c,v 1.1.1.1.2.7 2011/05/11 23:52:53 dmitrym Exp $ */
/*	$OpenBSD: kvm_mips.c,v 1.5 1998/08/31 18:02:21 pefo Exp $ */
/*	$NetBSD: kvm_mips.c,v 1.3 1996/03/18 22:33:44 thorpej Exp $	*/

/*-
 * Copyright (c) 1989, 1992, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software developed by the Computer Systems
 * Engineering group at Lawrence Berkeley Laboratory under DARPA contract
 * BG 91-66 and contributed to Berkeley. Modified for MIPS by Ralph Campbell.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * MIPS machine dependent routines for kvm.  Hopefully, the forthcoming 
 * vm code will one day obsolete this module.
 */

#ifdef __linux__
#include <endian.h>
#else
#include <sys/endian.h>
#endif
#include <defs.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>

#include <libkvm/kvm.h>
#include <include/sys/target.h>
#include <libkvm/kvm_private.h>
#include <libkvm/kvm_utils.h>

#define KREAD(kd, addr, p)\
	(kvm_read(kd, addr, (char *)(p), sizeof(*(p))) != sizeof(*(p)))

/*
 * Translate a physical memory address to a file-offset in the crash-dump.
 * (Taken from kvm_ia64.c)
 */
static size_t
_kvm_pa2off(kvm_t *kd, uint64_t pa, off_t *ofs)
{
        Elf32_Ehdr *e = (Elf32_Ehdr*)kd->vmst->mmapbase;
	Elf32_Phdr *p = (Elf32_Phdr*)((char*)e + be32toh(e->e_phoff));
	int n = be16toh(e->e_phnum);

	while (n && (pa < be32toh(p->p_paddr) || 
		     pa >= be32toh(p->p_paddr) + be32toh(p->p_memsz))) {
		p++, n--;
	}
	if (n == 0)
		return (0);
	*ofs = (pa - be32toh(p->p_paddr)) + be32toh(p->p_offset);
	return (PAGE_SIZE - ((size_t)pa & PAGE_MASK));
}

int
_kvm_initvtop(kvm_t *kd)
{
	struct vmstate *vm;
	Elf32_Ehdr *ehdr;
	size_t hdrsz;
	uint64_t kernel_segmap, tlb_entries;
	char minihdr[8];
	int i;

	if (pread(kd->pmfd, &minihdr, (size_t) 8, 0) == 8)
		if (memcmp(&minihdr, "minidump", 8) == 0)
			return (_kvm_minidump_initvtop(kd));

	vm = (struct vmstate *)_kvm_malloc(kd, sizeof(*vm));
	if (vm == 0)
		return (-1);
	kd->vmst = vm;

	if (_kvm_maphdrs(kd, sizeof(Elf32_Ehdr)) == -1)
		return (-1);

	ehdr = (Elf32_Ehdr*)kd->vmst->mmapbase;
	hdrsz = be32toh(ehdr->e_phoff) + 
	  be16toh(ehdr->e_phentsize) * be16toh(ehdr->e_phnum);
	if (_kvm_maphdrs(kd, hdrsz) == -1)
		return (-1);

	if (kvm_lookup(kd, "kernel_segmap", &kernel_segmap) != 0) {
		_kvm_err(kd, kd->program, "bad namelist");
		return (-1);
	}
	if (KREAD(kd, (uint32_t) kernel_segmap, &vm->sysmap)) {
		_kvm_err(kd, kd->program, "cannot read sysmap");
		return (-1);
	}

	vm->sysmap = be32toh(vm->sysmap);

	if (kvm_lookup(kd, "gbl_tlb_entries", &tlb_entries) != 0)
		return (0);

	if (kvm_read(kd, tlb_entries, vm->gbl_tlb_entries,
		     sizeof(vm->gbl_tlb_entries[0]) * 
		         GLOBAL_WIRED_TLB_ENTRY_NUM)
		!= sizeof(vm->gbl_tlb_entries[0]) * 
	                 GLOBAL_WIRED_TLB_ENTRY_NUM) {
		_kvm_err(kd, kd->program, "cannot read gbl_tlb_entries");
		return (-1);
	}

	for (i = 0; i < GLOBAL_WIRED_TLB_ENTRY_NUM; i++) {
		vm->gbl_tlb_entries[i].sz = 
			be32toh(vm->gbl_tlb_entries[i].sz);
		vm->gbl_tlb_entries[i].vaddr = 
			be32toh(vm->gbl_tlb_entries[i].vaddr);
		vm->gbl_tlb_entries[i].paddr = 
			be32toh(vm->gbl_tlb_entries[i].paddr);
		vm->gbl_tlb_entries[i].valid = 
			be32toh(vm->gbl_tlb_entries[i].valid);
		vm->gbl_tlb_entries[i].tlb_index = 
			be32toh(vm->gbl_tlb_entries[i].tlb_index);
	}
	return (0);
}

/*
 * Translate a kernel virtual address to a physical address.
 */
int
_kvm_kvatop(kvm_t *kd, uint64_t vaddr, off_t *pa)
{
	register struct vmstate *vm;
	uint32_t pte, addr, offset, pde, a, va;
	size_t s;
	off_t ofs;
	int i;

	if (kd->vmst->minidump)
		return (_kvm_minidump_kvatop(kd, vaddr, pa));

	if (ISALIVE(kd)) {
		_kvm_err(kd, 0, "vatop called in live kernel!");
		return((off_t)0);
	}
	va = (uint32_t) vaddr;
	vm = kd->vmst;
	offset = va & PGOFSET;
	/*
	 * If we are initializing (kernel segment table pointer not yet set)
	 * then return pa == va to avoid infinite recursion.
	 */
	if (vm->sysmap == 0) {

		addr = va;
		if (va < VM_MIN_KERNEL_ADDRESS) {
			addr = MIPS_CACHED_TO_PHYS(va);
		}

		s = _kvm_pa2off(kd, addr, pa);
		if (s == 0) {
			_kvm_err(kd, kd->program,
				"_kvm_vatop: bootstrap data not in dump");
			goto invalid;
		} else {
			return (NBPG - offset);
		}
	}
	if (va < KERNBASE ||
	    va >= VM_MAX_KERNEL_ADDRESS)
		goto invalid;
	if (va < VM_MIN_KERNEL_ADDRESS) {
		addr = MIPS_CACHED_TO_PHYS(va);
		s = _kvm_pa2off(kd, addr, pa);
		if (s == 0) {
			_kvm_err(kd, kd->program,
			    "_kvm_vatop: bootstrap data not in dump");
			goto invalid;
		} else {
			return (NBPG - offset);
		}
	}

	addr = (uint32_t)(vm->sysmap + sizeof (uint32_t) * (va >> SEGSHIFT));

	s = _kvm_pa2off(kd, MIPS_CACHED_TO_PHYS(addr), &ofs);
	if (s < sizeof (pde)) {
		_kvm_err(kd, kd->program, "_kvm_vatop: pdpe_pa not found");
		goto invalid;
	}

	if (lseek(kd->pmfd, ofs, 0) < 0 ||
	    read(kd->pmfd, (char *)&pde, sizeof(pde)) < 0) {
		_kvm_err(kd, kd->program, "addr %0x%" PRIx32 ", ofs = %" 
			 PRIu32 "\n", addr, ofs);
		goto invalid;
	}

	pde = be32toh(pde);
	if (!pde) {
		goto invalid;
	}

	/*
	 * Read pte in the second level page table
	 */
	addr = pde + vad_to_pte_offset(va) * sizeof(pt_entry_t);

	s =_kvm_pa2off(kd, MIPS_CACHED_TO_PHYS(addr), &ofs);
	if (s == 0) {
		_kvm_err(kd, kd->program, "_kvm_vatop: pde_pa not found");
		goto invalid;
	}

	if (lseek(kd->pmfd, ofs, 0) < 0 ||
	    read(kd->pmfd, (char *)&pte, sizeof(pte)) < 0) {
		_kvm_err(kd, kd->program, "addr 0x%" PRIx32 ", ofs = %" 
			 PRIu32 "\n", addr, ofs);
		goto invalid;
	}

	pte = be32toh(pte);
	if (!(pte & PG_V)) {
		goto invalid;
	}

	a = ((pte & PG_FRAME) << PG_SHIFT) | offset;

	s =_kvm_pa2off(kd, a, pa);
	if (s == 0) {
		_kvm_err(kd, kd->program, "_kvm_vatop: address not in dump");
		goto invalid;
	} else
		return (NBPG - offset);

invalid:
        /* Check if the address is belong to gbl mem */
        for ( i = 0; i < GLOBAL_WIRED_TLB_ENTRY_NUM; i++ ) {

            if (vm->gbl_tlb_entries[i].sz != 0  && 
                va >= vm->gbl_tlb_entries[i].vaddr &&
                va < vm->gbl_tlb_entries[i].vaddr + 
                     vm->gbl_tlb_entries[i].sz) {
                a = va - vm->gbl_tlb_entries[i].vaddr + 
                    vm->gbl_tlb_entries[i].paddr;
                s =_kvm_pa2off(kd, a, pa);
                if (s == 0) {
                    _kvm_err(kd, kd->program, 
                             "_kvm_vatop: address not in dump");
                    return (0);
                } else {
                    return (PAGE_SIZE - offset);
		}
            }
        }  
	_kvm_err(kd, 0, "invalid address (0x%" PRIx64 ")", va);
	return (0);
}
