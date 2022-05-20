/*	$Id: kvm_mips64.c,v 1.2.2.3 2011/02/01 23:10:36 dmitrym Exp $ */
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
	(kvm_read(kd, addr, p, sizeof(*(p))) != sizeof(*(p)))

/* 
   Note: MIPS_KSEG*_START constants are signed. To make sure we
   compare with 64-bit variant of the address, we must explicitly cast
   it to a 64-bit integer 
*/
#define IS_KSEG01_VA(va)			\
  (((va) >= (uint64_t)MIPS_KSEG0_START) &&	\
   ((va) < (uint64_t)MIPS_KSEG2_START))

#define IS_UNMAPPED_VA(va) 	(IS_KSEG01_VA(va) || MIPS_XKPHYS_P(va))
#define IS_MAPPED_VA(va)	(MIPS_XKSEG_P(va))
#define IS_VALID_VA(va)		(IS_UNMAPPED_VA(va) || IS_MAPPED_VA(va))

/*
 * Translate a physical memory address to a file-offset in the crash-dump.
 * (Taken from kvm_ia64.c)
 */
static size_t
_kvm_pa2off(kvm_t *kd, uint64_t pa, off_t *ofs)
{
	/* JUNOS begin */
	Elf64_Ehdr	*e64;
	Elf64_Phdr	*p64;
	unsigned char	*e_ident;
	int		n;

	e_ident = (unsigned char *)kd->vmst->mmapbase;
	if (ELFCLASS64 != e_ident[EI_CLASS]) {
		return (0);
	}

	e64 = (Elf64_Ehdr*)kd->vmst->mmapbase;
	p64 = (Elf64_Phdr*)((char*)e64 + be64toh(e64->e_phoff));
	n = be16toh(e64->e_phnum);

	while (n && (pa < be64toh(p64->p_paddr) ||
		     pa >= be64toh(p64->p_paddr) + be64toh(p64->p_memsz)))
		p64++, n--;
	if (n == 0)
		return (0);
	*ofs = (pa - be64toh(p64->p_paddr)) + be64toh(p64->p_offset);

	return (PAGE_SIZE - ((size_t)pa & PAGE_MASK));
	/* JUNOS end */
}

int
_kvm_initvtop(kvm_t *kd)
{
	struct vmstate *vm;
	Elf64_Ehdr	*ehdr64;
	unsigned char	*e_ident;
	uint64_t hdrsz;
	uint64_t kernel_segmap, kernel_segmap_entries, 
	  tlb_entries, tlb_entries_num;
	char minihdr[8];
	int i;

	if (pread(kd->pmfd, &minihdr, (size_t) 8, 0) == 8)
		if (memcmp(&minihdr, "minidump", 8) == 0)
			return (_kvm_minidump_initvtop(kd));

	vm = (struct vmstate *)_kvm_malloc(kd, sizeof(*vm));
	if (vm == 0) {
		_kvm_err(kd, kd->program, "cannot allocate vm");
		return (-1);
	}
	kd->vmst = vm;

	/*
	 * Initially, read only the ELF header 'e_ident' field as the
	 * information conveyed in this field tells us how to interpret
	 * the rest of the header.
	 */
	if (_kvm_maphdrs(kd, EI_NIDENT) == -1) {
		return (-1);
	}

	e_ident = (unsigned char *)kd->vmst->mmapbase;

        if (ELFCLASS64 != e_ident[EI_CLASS]) {
		return (-1);
        }

	if (_kvm_maphdrs(kd, sizeof(Elf64_Ehdr)) == -1) {
		return (-1);
	}
	ehdr64 = (Elf64_Ehdr*)kd->vmst->mmapbase;

	if (EM_MIPS != be16toh(ehdr64->e_machine)) {
		return (-1);
	}

	hdrsz = be64toh(ehdr64->e_phoff) + 
	        be16toh(ehdr64->e_phentsize) * be16toh(ehdr64->e_phnum);
	if (_kvm_maphdrs(kd, hdrsz) == -1) {
		return (-1);
	}

	if (kvm_lookup(kd, "kernel_segmap_entries", 
		       &kernel_segmap_entries) != 0) {
		_kvm_err(kd, kd->program, "bad namelist");
		return (-1);
	}
	if (KREAD(kd, kernel_segmap_entries, &vm->sysmap_entries)) {
		_kvm_err(kd, kd->program, "cannot read kernel_segmap_entries");
		return (-1);
	}
	vm->sysmap_entries = be32toh(vm->sysmap_entries);
	vm->sysmap = (uint64_t*)_kvm_malloc(kd, sizeof(uint64_t) * vm->sysmap_entries);
	if (vm->sysmap == NULL) {
		_kvm_err(kd, kd->program, "cannot allocate sysmap");
		return (-1);
	}

	if (kvm_lookup(kd, "kernel_segmap", &kernel_segmap) != 0) {
		_kvm_err(kd, kd->program, "bad namelist");
		return (-1);
	}
	if (kvm_read(kd, kernel_segmap, vm->sysmap, 
		      sizeof(vm->sysmap[0]) * vm->sysmap_entries)
	    != sizeof(vm->sysmap[0]) * vm->sysmap_entries) {
		_kvm_err(kd, kd->program, "cannot read sysmap");
		return (-1);
	}

	for (i = 0; i < vm->sysmap_entries; i++) {
		vm->sysmap[i] = be64toh(vm->sysmap[i]);
	}
	if (kvm_lookup(kd, "gbl_tlb_entries", &tlb_entries) != 0) {
		_kvm_err(kd, kd->program, "bad namelist");
		return (-1);
	}
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
			be64toh(vm->gbl_tlb_entries[i].sz);
		vm->gbl_tlb_entries[i].vaddr = 
			be64toh(vm->gbl_tlb_entries[i].vaddr);
		vm->gbl_tlb_entries[i].paddr = 
			be64toh(vm->gbl_tlb_entries[i].paddr);
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
_kvm_kvatop(kvm_t *kd, uint64_t va, off_t *pa)
{
	register struct vmstate *vm;
	pd_entry_t pde;
	pt_entry_t pte;
	uint64_t addr, offset, s, a;
	off_t ofs;
        int i;

	if (kd->vmst->minidump)
		return (_kvm_minidump_kvatop(kd, va, pa));

	if (ISALIVE(kd)) {
		_kvm_err(kd, 0, "vatop called in live kernel!");
		return((off_t)0);
	}
	vm = kd->vmst;
	offset = va & (PAGE_SIZE - 1);

	/*
	 * If we are initializing (kernel segment table pointer not yet set)
	 * then return pa == va to avoid infinite recursion.
	 */
	if (vm->sysmap == NULL) {
		addr = va;
		if (IS_UNMAPPED_VA(va)) {
			addr = MIPS_CACHED_TO_PHYS(va);
		}

		s = _kvm_pa2off(kd, addr, pa);
		if (s == 0) {
			_kvm_err(kd, kd->program,
				"_kvm_vatop: bootstrap data not in dump");
			goto invalid;
		} else {
			return (PAGE_SIZE - offset);
		}
	}

	
	if (!IS_VALID_VA(va)) {
		goto invalid;
	}


	if (IS_UNMAPPED_VA(va)) {
		addr = MIPS_CACHED_TO_PHYS(va);
		s = _kvm_pa2off(kd, addr, pa);
		if (s == 0) {
			_kvm_err(kd, kd->program,
			    "_kvm_vatop: bootstrap data not in dump");
			goto invalid;
		} else {
			return (PAGE_SIZE - offset);
		}
	}

	/* VA is mapped, so we need to peek into the pagetable */
	if (DIR_IDX(va) < vm->sysmap_entries) {
		addr = vm->sysmap[DIR_IDX(va)] + (SEG_IDX(va)<< PDE_SHIFT);
	} else {
		goto invalid;
	}

	if (!IS_UNMAPPED_VA(addr)) {
		_kvm_err(kd, kd->program, 
			 "_kvm_vatop: segment pointer is not accessible");
		goto invalid;
	}

	s = _kvm_pa2off(kd, MIPS_CACHED_TO_PHYS(addr), &ofs);
	if (s < sizeof pde) {
		_kvm_err(kd, kd->program, "_kvm_vatop: pdpe_pa not found");
		goto invalid;
	}

	if (lseek(kd->pmfd, ofs, 0) < 0 ||
	    read(kd->pmfd, (char *)&pde, sizeof(pde)) < 0) {
		_kvm_err(kd, kd->program, "addr 0x%" PRIx64 ", ofs = %" PRIu32 
			 "\n", addr, ofs);
		goto invalid;
	}
	pde = be64toh(pde);
	if (!pde) {
		goto invalid;
	}

	/*
	 * Read pte in the second level page table
	 */
	addr = pde + (PTE_IDX(va) << PTE_SHIFT);

	s =_kvm_pa2off(kd, MIPS_CACHED_TO_PHYS(addr), &ofs);
	if (s == 0) {
		_kvm_err(kd, kd->program, "_kvm_vatop: pde_pa not found");
		goto invalid;
	}

	if (lseek(kd->pmfd, ofs, 0) < 0 ||
	    read(kd->pmfd, (char *)&pte, sizeof(pte)) < 0) {
		_kvm_err(kd, kd->program, "addr 0x%" PRIx64 ", ofs = %" PRIu32 
			 "\n", addr, ofs);
		goto invalid;
	}
	pte = be32toh(pte);
	if (!(pte & PG_V)) {
		goto invalid;
	}

	a = (((uint64_t)pte & PG_FRAME) << PG_SHIFT) | offset;
 	s =_kvm_pa2off(kd, a, pa);

	if (s == 0) {
		_kvm_err(kd, kd->program, "_kvm_vatop: address not in dump");
		goto invalid;
	} else {
		return (PAGE_SIZE - offset);
	}
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
	_kvm_err(kd, 0, "invalid address (%" PRIx64 ")", va);
	return (0);
}
