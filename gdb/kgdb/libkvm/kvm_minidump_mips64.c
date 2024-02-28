/*
 * Copyright (c) 2011 Juniper Networks, Inc.
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * Description:
 *      MIPS machine dependent routines for kvm and minidumps. Derived from
 *      minidump implementation in libkvm/kvm_minidump_i386.c and
 *      libkvm/kvm_minidump_amd64.c
 */

#ifdef __linux__
#include <endian.h>
#else
#include <sys/endian.h>
#endif
#include <defs.h>
#include <stdlib.h>
#include <unistd.h>
#include <strings.h>
#include <limits.h>
#include <inttypes.h>

#include <libkvm/kvm.h>
#include <include/sys/target.h>
#include <libkvm/kvm_private.h>
#include <libkvm/kvm_minidump.h>

#if 0
static int
inithash(kvm_t *kd, uint64_t *base, int len, off_t off)
{
	uint64_t idx;
	uint64_t bit, bits;
	uint64_t pa;
	int bitnum;

	for (idx = 0; idx < len / sizeof(*base); idx++) {
		bits = be64toh(base[idx]);
		bitnum = 0;

		while (bits) {
			if (bits & 1ul) {
				pa = (((uint64_t)idx * sizeof(*base) * NBBY) +
				      bitnum) * PAGE_SIZE;
				hpt_insert(kd->vmst->hpt_head, pa, off);
				off += PAGE_SIZE;
			}
			bits >>= 1ul;
			bitnum++;
		}
	}

	return (off);
}
#endif

static int
inithash(kvm_t *kd, uint32_t *base, int len, off_t off)
{
	uint64_t idx;
	uint32_t bit, bits;
	uint64_t pa;
	int bitnum;

	for (idx = 0; idx < len / sizeof(*base); idx++) {
		bits = be32toh(base[idx]);
		bitnum = 0;

		while (bits) {
			if (bits & 1ul) {
				pa = (((uint64_t)idx * sizeof(*base) * NBBY) +
				      bitnum) * PAGE_SIZE;
				hpt_insert(kd->vmst->hpt_head, pa, off);
				off += PAGE_SIZE;
			}
			bits >>= 1ul;
			bitnum++;
		}
	}

	return (off);
}

void
_kvm_minidump_freevtop(kvm_t *kd)
{
	struct vmstate *vm = kd->vmst;

	if (vm->bitmap) {
		free(vm->bitmap);
	}
	if (vm->ptemap) {
		free(vm->ptemap);
	}
	free(vm);
	kd->vmst = NULL;
}

int
_kvm_minidump_initvtop(kvm_t *kd)
{
	struct vmstate *vmst;
	off_t off = 0;

	vmst = (vmstate*)_kvm_malloc(kd, sizeof(*vmst));
	if (vmst == 0) {
		_kvm_err(kd, kd->program, "cannot allocate vm");
		return (-1);
	}
	kd->vmst = vmst;
	bzero(vmst, sizeof(*vmst));
	vmst->minidump = 1;
	if (pread(kd->pmfd, &vmst->hdr, sizeof(vmst->hdr), 0) !=
	    sizeof(vmst->hdr)) {
		_kvm_err(kd, kd->program, "cannot read dump header");
		return (-1);
	}

	vmst->hdr.version = be32toh(vmst->hdr.version);
	vmst->hdr.msgbufsize = be32toh(vmst->hdr.msgbufsize);
	vmst->hdr.bitmapsize = be32toh(vmst->hdr.bitmapsize);
	vmst->hdr.ptesize = be32toh(vmst->hdr.ptesize);
	vmst->hdr.kernbase = be64toh(vmst->hdr.kernbase);
	vmst->hdr.dmapbase = be64toh(vmst->hdr.dmapbase);
	vmst->hdr.dmapend = be64toh(vmst->hdr.dmapend);

	if (strncmp(MINIDUMP_MAGIC, vmst->hdr.magic,
	    sizeof(vmst->hdr.magic)) != 0) {
		_kvm_err(kd, kd->program, "not a minidump for this platform");
		return (-1);
	}
	if (vmst->hdr.version != MINIDUMP_VERSION) {
		_kvm_err(kd, kd->program, "wrong minidump version. expected %d "
			 "got %" PRIu32, 
			 MINIDUMP_VERSION, vmst->hdr.version);
		return (-1);
	}

	/* Skip header and msgbuf */
	off = PAGE_SIZE + round_page(vmst->hdr.msgbufsize);
	vmst->bitmap = (uint32_t*)_kvm_malloc(kd, vmst->hdr.bitmapsize);
	if (vmst->bitmap == NULL) {
		_kvm_err(kd, kd->program, "cannot allocate %d bytes "
			 "for bitmap", vmst->hdr.bitmapsize);
		return (-1);
	}
	if (pread(kd->pmfd, vmst->bitmap, vmst->hdr.bitmapsize, off) !=
	    vmst->hdr.bitmapsize) {
		_kvm_err(kd, kd->program, "cannot read %d bytes for "
			 "page bitmap", vmst->hdr.bitmapsize);
		return (-1);
	}
	off += round_page(vmst->hdr.bitmapsize);

	vmst->ptemap = (uint64_t*)_kvm_malloc(kd, vmst->hdr.ptesize);
	if (vmst->ptemap == NULL) {
		_kvm_err(kd, kd->program, "cannot allocate %d bytes "
			 "for ptemap", vmst->hdr.ptesize);
		return (-1);
	}
	if (pread(kd->pmfd, vmst->ptemap, vmst->hdr.ptesize, off) !=
	    vmst->hdr.ptesize) {
		_kvm_err(kd, kd->program, "cannot read %d bytes for "
			 "ptemap", vmst->hdr.ptesize);
		return (-1);
	}
	off += vmst->hdr.ptesize;

	/* build physical address hash table for sparse pages */
	vmst->dmapoff = inithash(kd, vmst->bitmap, 
				 vmst->hdr.bitmapsize, off);
	return (0);
}

static int
_kvm_minidump_vatop(kvm_t *kd, uint64_t vaddr, off_t *pa)
{
	struct vmstate *vm;
	uint64_t offset, va;
	pt_entry_t pte;
	uint64_t pteindex;
	int i;
	uint64_t a;
	off_t ofs;
	uint64_t *ptemap;

	vm = kd->vmst;
	ptemap = vm->ptemap;
	va = vaddr;
	offset = va & (PAGE_SIZE - 1);
	va &= ~(PAGE_SIZE - 1ULL);

	if (va >= MIPS_XKPHYS_START && va < MIPS_XKPHYS_END) {
		a = va & XKPHYS_PA_MASK;
	} else if (va >= MIPS_KSEG0_START && va < MIPS_KSEG0_END) {
		a = va & MIPS_PHYS_MASK;
	} else if (va >= MIPS_KSEG1_START && va < MIPS_KSEG1_END) {
		a = va & MIPS_PHYS_MASK;
	} else if (va >= vm->hdr.kernbase) {
		pteindex = (va - vm->hdr.kernbase) >> PAGE_SHIFT;
		pte = be64toh(ptemap[pteindex]);
		if ((pte & PG_V) == 0) {
			_kvm_err(kd, kd->program, "_kvm_vatop: pte not valid");
			goto invalid;
		}
		if ((pte & PG_G) == 0) {
			_kvm_err(kd, kd->program, "_kvm_vatop: pte not global");
			goto invalid;
		}
		a = pfn64_to_vad(pte);
	} else {
		_kvm_err(kd, kd->program, "_kvm_vatop: virtual address %"
			 PRIx64 " not minidumped", va);
		goto invalid;
	}
	ofs = hpt_find(kd->vmst->hpt_head, a);
	if (ofs == -1) {
	  _kvm_err(kd, kd->program, "_kvm_vatop: physical address"
		   " %" PRIx64 " not in minidump", a);
	  goto invalid;
	}
	*pa = ofs + offset;
	return (PAGE_SIZE - offset);

invalid:
	_kvm_err(kd, 0, "invalid address (%" PRIx64 ")", va);
	return (0);
}

int
_kvm_minidump_kvatop(kvm_t *kd, uint64_t va, off_t *pa)
{
	if (ISALIVE(kd)) {
		_kvm_err(kd, 0, "kvm_kvatop called in live kernel!");
		return (0);
	}

	return (_kvm_minidump_vatop(kd, va, pa));
}
