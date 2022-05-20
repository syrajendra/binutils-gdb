/*-
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
 */

/*
 * Powerpc64 machine dependent routines for kvm and minidumps. 
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

size_t dump_header_size(struct kerneldumpheader *dh);

static __inline uint64_t
bsfq(uint64_t mask)
{
        uint32_t  result;

	uint32_t mask1 = (uint32_t) mask;
	uint32_t mask2 = (uint32_t) (mask >> 32);

	if (mask1) {
		__asm __volatile("bsfl %1,%0" : "=r" (result) : "rm" (mask1));
	}
	else {
		__asm __volatile("bsfl %1,%0" : "=r" (result) : "rm" (mask2));
		result += 32;
	}
        return ((uint64_t) result);
}

static int
inithash(kvm_t *kd, uint64_t *base, int len, off_t off)
{
	uint64_t idx;
	uint64_t bit, bits;
	uint64_t pa;

	for (idx = 0; idx < len / sizeof(*base); idx++) {
		bits = be64toh(base[idx]);
		while (bits) {
			bit = bsfq(bits);
			bits &= ~(1ull << bit);
			pa = (idx * sizeof(*base) * NBBY + bit) * PAGE_SIZE;
			hpt_insert(kd->vmst->hpt_head, pa, off);
			off += PAGE_SIZE;
		}
	}
	return (off);
}

void
_kvm_minidump_freevtop(kvm_t *kd)
{
	struct vmstate *vm = kd->vmst;

	if (vm->bitmap)
		free(vm->bitmap);
	if (vm->ptemap)
		free(vm->ptemap);
	free(vm);
	kd->vmst = NULL;
}

int
_kvm_minidump_initvtop(kvm_t *kd)
{
	uint64_t pa;
	struct vmstate *vmst;
	struct kerneldumpheader dh;
	off_t off = 0;

	if (pread(kd->pmfd, &dh, sizeof(dh), off) == sizeof(dh))
		off = dump_header_size(&dh);

	vmst = (vmstate*)_kvm_malloc(kd, sizeof(*vmst));
	if (vmst == 0) {
		_kvm_err(kd, kd->program, "cannot allocate vm");
		return (-1);
	}
	kd->vmst = vmst;
	vmst->minidump = 1;
	if (pread(kd->pmfd, &vmst->hdr, sizeof(vmst->hdr), off) !=
	    sizeof(vmst->hdr)) {
		_kvm_err(kd, kd->program, "cannot read dump header");
		return (-1);
	}
	if (strncmp(MINIDUMP_MAGIC, vmst->hdr.magic, 
		    sizeof(vmst->hdr.magic)) != 0) {
		_kvm_err(kd, kd->program, "not a minidump for this platform");
		return (-1);
	}
	if (be32toh(vmst->hdr.version) != MINIDUMP_VERSION) {
		_kvm_err(kd, kd->program, "wrong minidump version. expected "
			 "%d got %d",
			 MINIDUMP_VERSION, be32toh(vmst->hdr.version));
		return (-1);
	}

	/* Skip header and msgbuf */
	off += PAGE_SIZE + round_page(be32toh(vmst->hdr.msgbufsize));

	vmst->bitmap = (uint64_t*)_kvm_malloc(kd, be32toh(vmst->hdr.bitmapsize));
	if (vmst->bitmap == NULL) {
		_kvm_err(kd, kd->program, "cannot allocate %d bytes for "
			 "bitmap", be32toh(vmst->hdr.bitmapsize));
		return (-1);
	}
	if (pread(kd->pmfd, vmst->bitmap, be32toh(vmst->hdr.bitmapsize), off) !=
	    be32toh(vmst->hdr.bitmapsize)) {
		_kvm_err(kd, kd->program, "cannot read %d bytes for page "
			 "bitmap", be32toh(vmst->hdr.bitmapsize));
		return (-1);
	}
	off += round_page(be32toh(vmst->hdr.bitmapsize));

	int ss = be32toh(vmst->hdr.ptesize);
	vmst->ptemap = (pte_t*)_kvm_malloc(kd, be32toh(vmst->hdr.ptesize));
	if (vmst->ptemap == NULL) {
		_kvm_err(kd, kd->program, "cannot allocate %d bytes for "
			 "ptemap", be32toh(vmst->hdr.ptesize));
		return (-1);
	}
	if (pread(kd->pmfd, vmst->ptemap, be32toh(vmst->hdr.ptesize), off) !=
	    be32toh(vmst->hdr.ptesize)) {
		_kvm_err(kd, kd->program, "cannot read %d bytes for ptemap", 
			 be32toh(vmst->hdr.ptesize));
		return (-1);
	}
	off += be32toh(vmst->hdr.ptesize);

	/* build physical address hash table for sparse pages */
	inithash(kd, vmst->bitmap, be32toh(vmst->hdr.bitmapsize), off);

	return (0);
}

static int
_kvm_minidump_vatop(kvm_t *kd, uint64_t va, off_t *pa)
{
	struct vmstate *vm;
	uint64_t offset;
	pte_t pte;
	uint64_t pteindex;
	int i;
	uint64_t a;
	off_t ofs;

	vm = kd->vmst;
	offset = va & (PAGE_SIZE - 1);

	if (va >= be64toh(vm->hdr.kernbase)) {
		pteindex = (va - be64toh(vm->hdr.kernbase)) >> PAGE_SHIFT;
		pte = be64toh(vm->ptemap[pteindex]);
		if (!PTE_ISVALID(&pte)) {
			_kvm_err(kd, kd->program, "_kvm_vatop: pte not valid");
			goto invalid;
		}
		a = PTE_PA(&pte);
		ofs = hpt_find(kd->vmst->hpt_head, a);
		if (ofs == -1) {
			_kvm_err(kd, kd->program, 
				 "_kvm_vatop: physical address 0x%" PRIx64 
				 " not in minidump", a);
			goto invalid;
		}
		*pa = ofs + offset;
		return (PAGE_SIZE - offset);
	} else if (va >= be64toh(vm->hdr.dmapbase) && 
		   va < be64toh(vm->hdr.dmapend)) {
		a = (va - be64toh(vm->hdr.dmapbase)) & ~PAGE_MASK;
		ofs = hpt_find(kd->vmst->hpt_head, a);
		if (ofs == -1) {
			_kvm_err(kd, kd->program, "_kvm_vatop: direct map "
				 "address 0x%" PRIx64 " not in minidump", va);
			goto invalid;
		}
		*pa = ofs + offset;
		return (PAGE_SIZE - offset);
	} else {
		_kvm_err(kd, kd->program, "_kvm_vatop: virtual address 0x%"
			 PRIx64 " not minidumped", va);
		goto invalid;
	}

invalid:
	_kvm_err(kd, 0, "invalid address (0x%" PRIx64 ")", va);
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
