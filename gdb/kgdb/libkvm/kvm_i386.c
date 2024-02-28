/*-
 * Copyright (c) 1989, 1992, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software developed by the Computer Systems
 * Engineering group at Lawrence Berkeley Laboratory under DARPA contract
 * BG 91-66 and contributed to Berkeley.
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
 * i386 machine dependent routines for kvm.  Hopefully, the forthcoming
 * vm code will one day obsolete this module.
 */

#include <defs.h>

#include <limits.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>

#include <libkvm/kvm.h>
#include <include/sys/target.h>
#include <libkvm/kvm_private.h>
#include <libkvm/kvm_utils.h>

#ifndef btop
#define	btop(x)		(i386_btop(x))
#define	ptob(x)		(i386_ptob(x))
#endif

#define	PG_FRAME_PAE	(~((uint64_t)PAGE_MASK))
#define	PDRSHIFT_PAE	21
#define	NPTEPG_PAE	(PAGE_SIZE/sizeof(uint64_t))
#define	NBPDR_PAE	(1<<PDRSHIFT_PAE)

/*
 * Translate a physical memory address to a file-offset in the crash-dump.
 * (Taken from kvm_ia64.c)
 */
static size_t
_kvm_pa2off(kvm_t *kd, uint64_t pa, off_t *ofs)
{
	Elf32_Ehdr *e = (Elf32_Ehdr*)kd->vmst->mmapbase;
	Elf32_Phdr *p = (Elf32_Phdr*)((char*)e + e->e_phoff);
	int n = e->e_phnum;

	while (n && (pa < p->p_paddr || pa >= p->p_paddr + p->p_memsz))
		p++, n--;
	if (n == 0)
		return (0);
	*ofs = (pa - p->p_paddr) + p->p_offset;
	return (PAGE_SIZE - ((size_t)pa & PAGE_MASK));
}

int
_kvm_initvtop(kvm_t *kd)
{
	uint32_t pa;
	uint64_t kernbase, idle_pdpt, idle_ptd;
	char		*PTD;
	Elf32_Ehdr	*ehdr;
	size_t		hdrsz;
	int		i;
	char		minihdr[8];

	if (pread(kd->pmfd, &minihdr, 8, 0) == 8)
		if (memcmp(&minihdr, "minidump", 8) == 0)
			return (_kvm_minidump_initvtop(kd));

	kd->vmst = (struct vmstate *)_kvm_malloc(kd, sizeof(*kd->vmst));
	if (kd->vmst == 0) {
		_kvm_err(kd, kd->program, "cannot allocate vm");
		return (-1);
	}
	kd->vmst->PTD = 0;

	if (_kvm_maphdrs(kd, sizeof(Elf32_Ehdr)) == -1)
		return (-1);

	ehdr = (Elf32_Ehdr*)kd->vmst->mmapbase;
	hdrsz = ehdr->e_phoff + ehdr->e_phentsize * ehdr->e_phnum;
	if (_kvm_maphdrs(kd, hdrsz) == -1)
		return (-1);

	if (kvm_lookup(kd, "kernbase", &kernbase) != 0)
		kernbase = KERNBASE;	/* for old kernels */

	if (kvm_lookup(kd, "IdlePDPT", &idle_pdpt) == 0) {
		uint64_t pa64;

		if (kvm_read(kd, (idle_pdpt - kernbase), &pa,
		    sizeof(pa)) != sizeof(pa)) {
			_kvm_err(kd, kd->program, "cannot read IdlePDPT");
			return (-1);
		}
		PTD = (char*)_kvm_malloc(kd, 4 * PAGE_SIZE);
		for (i = 0; i < 4; i++) {
			if (kvm_read(kd, (uint64_t) (pa + (i * sizeof(pa64))), 
				     &pa64,
			    sizeof(pa64)) != sizeof(pa64)) {
				_kvm_err(kd, kd->program, "Cannot read PDPT");
				free(PTD);
				return (-1);
			}
			if (kvm_read(kd, (uint64_t) (pa64 & PG_FRAME_PAE),
			    PTD + (i * PAGE_SIZE), PAGE_SIZE) != (PAGE_SIZE)) {
				_kvm_err(kd, kd->program, "cannot read PDPT");
				free(PTD);
				return (-1);
			}
		}
		kd->vmst->PTD = PTD;
		kd->vmst->pae = 1;
	} else {
		if (kvm_lookup(kd, "IdlePTD", &idle_ptd) != 0) {
			_kvm_err(kd, kd->program, "bad namelist");
			return (-1);
		}
		if (kvm_read(kd, (idle_ptd - kernbase), &pa,
		    sizeof(pa)) != sizeof(pa)) {
			_kvm_err(kd, kd->program, "cannot read IdlePTD");
			return (-1);
		}
		PTD = (char*)_kvm_malloc(kd, PAGE_SIZE);
		if (kvm_read(kd, (uint64_t) pa, PTD, PAGE_SIZE) != PAGE_SIZE) {
			_kvm_err(kd, kd->program, "cannot read PTD");
			return (-1);
		}
		kd->vmst->PTD = PTD;
		return (0);
		kd->vmst->pae = 0;
	}
	return (0);
}

static int
_kvm_vatop(kvm_t *kd, uint32_t va, off_t *pa)
{
	struct vmstate *vm;
	uint32_t offset;
	uint32_t pte_pa;
	uint32_t pde_pa;
	pd_entry_t pde;
	pt_entry_t pte;
	uint32_t pdeindex;
	uint32_t pteindex;
	size_t s;
	uint32_t a;
	off_t ofs;
	uint32_t *PTD;

	vm = kd->vmst;
	PTD = (uint32_t *)vm->PTD;
	offset = va & (PAGE_SIZE - 1);

	/*
	 * If we are initializing (kernel page table descriptor pointer
	 * not yet set) then return pa == va to avoid infinite recursion.
	 */
	if (PTD == 0) {
		s = _kvm_pa2off(kd, va, pa);
		if (s == 0) {
			_kvm_err(kd, kd->program, 
			    "_kvm_vatop: bootstrap data not in dump");
			goto invalid;
		} else
			return (PAGE_SIZE - offset);
	}

	pdeindex = va >> PDRSHIFT;
	pde = PTD[pdeindex];
	if (((uint32_t)pde & PG_V) == 0) {
		_kvm_err(kd, kd->program, "_kvm_vatop: pde not valid");
		goto invalid;
	}

	if ((uint32_t)pde & PG_PS) {
	      /*
	       * No second-level page table; ptd describes one 4MB page.
	       * (We assume that the kernel wouldn't set PG_PS without enabling
	       * it cr0).
	       */
#define	PAGE4M_MASK	(NBPDR - 1)
#define	PG_FRAME4M	(~PAGE4M_MASK)
		pde_pa = ((uint32_t)pde & PG_FRAME4M) + (va & PAGE4M_MASK);
		s = _kvm_pa2off(kd, pde_pa, &ofs);
		if (s < sizeof pde) {
			_kvm_syserr(kd, kd->program,
			    "_kvm_vatop: pde_pa not found");
			goto invalid;
		}
		*pa = ofs;
		return (NBPDR - (va & PAGE4M_MASK));
	}

	pteindex = (va >> PAGE_SHIFT) & (NPTEPG-1);
	pte_pa = ((uint32_t)pde & PG_FRAME) + (pteindex * sizeof(pde));

	s = _kvm_pa2off(kd, pte_pa, &ofs);
	if (s < sizeof pte) {
		_kvm_err(kd, kd->program, "_kvm_vatop: pdpe_pa not found");
		goto invalid;
	}

	/* XXX This has to be a physical address read, kvm_read is virtual */
	if (lseek(kd->pmfd, ofs, 0) == -1) {
		_kvm_syserr(kd, kd->program, "_kvm_vatop: lseek");
		goto invalid;
	}
	if (read(kd->pmfd, &pte, sizeof pte) != sizeof pte) {
		_kvm_syserr(kd, kd->program, "_kvm_vatop: read");
		goto invalid;
	}
	if (((uint32_t)pte & PG_V) == 0) {
		_kvm_err(kd, kd->program, "_kvm_kvatop: pte not valid");
		goto invalid;
	}

	a = ((uint32_t)pte & PG_FRAME) + offset;
	s =_kvm_pa2off(kd, a, pa);
	if (s == 0) {
		_kvm_err(kd, kd->program, "_kvm_vatop: address not in dump");
		goto invalid;
	} else
		return (PAGE_SIZE - offset);

invalid:
	_kvm_err(kd, 0, "invalid address (0x%" PRIx32 ")", va);
	return (0);
}

static int
_kvm_vatop_pae(kvm_t *kd, uint32_t va, off_t *pa)
{
	struct vmstate *vm;
	uint64_t offset;
	uint64_t pte_pa;
	uint64_t pde_pa;
	uint64_t pde;
	uint64_t pte;
	uint32_t pdeindex;
	uint32_t pteindex;
	size_t s;
	uint64_t a;
	off_t ofs;
	uint64_t *PTD;

	vm = kd->vmst;
	PTD = (uint64_t *)vm->PTD;
	offset = va & (PAGE_SIZE - 1);

	/*
	 * If we are initializing (kernel page table descriptor pointer
	 * not yet set) then return pa == va to avoid infinite recursion.
	 */
	if (PTD == 0) {
		s = _kvm_pa2off(kd, va, pa);
		if (s == 0) {
			_kvm_err(kd, kd->program, 
			    "_kvm_vatop_pae: bootstrap data not in dump");
			goto invalid;
		} else
			return (PAGE_SIZE - offset);
	}

	pdeindex = va >> PDRSHIFT_PAE;
	pde = PTD[pdeindex];
	if (((uint32_t)pde & PG_V) == 0) {
		_kvm_err(kd, kd->program, "_kvm_kvatop_pae: pde not valid");
		goto invalid;
	}

	if ((uint32_t)pde & PG_PS) {
	      /*
	       * No second-level page table; ptd describes one 2MB page.
	       * (We assume that the kernel wouldn't set PG_PS without enabling
	       * it cr0).
	       */
#define	PAGE2M_MASK	(NBPDR_PAE - 1)
#define	PG_FRAME2M	(~PAGE2M_MASK)
		pde_pa = ((uint32_t)pde & PG_FRAME2M) + (va & PAGE2M_MASK);
		s = _kvm_pa2off(kd, pde_pa, &ofs);
		if (s < sizeof pde) {
			_kvm_syserr(kd, kd->program,
			    "_kvm_vatop_pae: pde_pa not found");
			goto invalid;
		}
		*pa = ofs;
		return (NBPDR_PAE - (va & PAGE2M_MASK));
	}

	pteindex = (va >> PAGE_SHIFT) & (NPTEPG_PAE-1);
	pte_pa = ((uint64_t)pde & PG_FRAME_PAE) + (pteindex * sizeof(pde));

	s = _kvm_pa2off(kd, pte_pa, &ofs);
	if (s < sizeof pte) {
		_kvm_err(kd, kd->program, "_kvm_vatop_pae: pdpe_pa not found");
		goto invalid;
	}

	/* XXX This has to be a physical address read, kvm_read is virtual */
	if (lseek(kd->pmfd, ofs, 0) == -1) {
		_kvm_syserr(kd, kd->program, "_kvm_vatop_pae: lseek");
		goto invalid;
	}
	if (read(kd->pmfd, &pte, sizeof pte) != sizeof pte) {
		_kvm_syserr(kd, kd->program, "_kvm_vatop_pae: read");
		goto invalid;
	}
	if (((uint64_t)pte & PG_V) == 0) {
		_kvm_err(kd, kd->program, "_kvm_vatop_pae: pte not valid");
		goto invalid;
	}

	a = ((uint64_t)pte & PG_FRAME_PAE) + offset;
	s =_kvm_pa2off(kd, a, pa);
	if (s == 0) {
		_kvm_err(kd, kd->program,
		    "_kvm_vatop_pae: address not in dump");
		goto invalid;
	} else
		return (PAGE_SIZE - offset);

invalid:
	_kvm_err(kd, 0, "invalid address (0x%" PRIx32 ")", va);
	return (0);
}

int
_kvm_kvatop(kvm_t *kd, uint64_t va, off_t *pa)
{

	if (kd->vmst->minidump)
		return (_kvm_minidump_kvatop(kd, va, pa));
	if (ISALIVE(kd)) {
		_kvm_err(kd, 0, "vatop called in live kernel!");
		return (0);
	}
	if (kd->vmst->pae)
		return (_kvm_vatop_pae(kd, (uint32_t) va, pa));
	else
		return (_kvm_vatop(kd, (uint32_t) va, pa));
}
