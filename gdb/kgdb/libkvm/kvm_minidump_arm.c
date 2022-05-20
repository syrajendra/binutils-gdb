/*-
 * Copyright (c) 2008 Semihalf, Grzegorz Bernacki
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
 * From: FreeBSD: src/lib/libkvm/kvm_minidump_i386.c,v 1.2 2006/06/05 08:51:14
 */

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

extern int is_armv6;

static int
inithash(kvm_t *kd, uint32_t *base, int len, off_t off)
{
	uint64_t idx, pa;
	uint32_t bit, bits;

	for (idx = 0; idx < len / sizeof(*base); idx++) {
		bits = base[idx];
		while (bits) {
			bit = ffs(bits) - 1;
			bits &= ~(1ul << bit);
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
	uint32_t pa;
	struct vmstate *vmst;
	off_t off;

	vmst = (vmstate *)_kvm_malloc(kd, sizeof(*vmst));
	if (vmst == 0) {
		_kvm_err(kd, kd->program, "cannot allocate vm");
		return (-1);
	}

	kd->vmst = vmst;
	vmst->minidump = 1;

	if (pread(kd->pmfd, &vmst->hdr,
	    sizeof(vmst->hdr), 0) != sizeof(vmst->hdr)) {
		_kvm_err(kd, kd->program, "cannot read dump header");
		return (-1);
	}

	if (strncmp(MINIDUMP_MAGIC, vmst->hdr.magic,
	    sizeof(vmst->hdr.magic)) != 0) {
		_kvm_err(kd, kd->program, "not a minidump for this platform");
		return (-1);
	}
	if (vmst->hdr.version != 1 && vmst->hdr.version != 2) {
		_kvm_err(kd, kd->program, "wrong minidump version. "
		    "Expected %d got %d", MINIDUMP_VERSION, vmst->hdr.version);
		return (-1);
	}
	if (vmst->hdr.version == 2 &&
	    vmst->hdr.mmuformat == MINIDUMP_MMU_FORMAT_UNKNOWN) {
		/* This is a safe default as 1K pages are not used. */
		vmst->hdr.mmuformat = MINIDUMP_MMU_FORMAT_V6;
	}

	/* Skip header and msgbuf */
	off = PAGE_SIZE + round_page(vmst->hdr.msgbufsize);

	vmst->bitmap = (uint32_t *)_kvm_malloc(kd, vmst->hdr.bitmapsize);
	if (vmst->bitmap == NULL) {
		_kvm_err(kd, kd->program, "cannot allocate %d bytes for "
		    "bitmap", vmst->hdr.bitmapsize);
		return (-1);
	}

	if (pread(kd->pmfd, vmst->bitmap, vmst->hdr.bitmapsize, off) !=
	    vmst->hdr.bitmapsize) {
		_kvm_err(kd, kd->program, "cannot read %d bytes for page bitmap",
		    vmst->hdr.bitmapsize);
		return (-1);
	}
	off += round_page(vmst->hdr.bitmapsize);

	vmst->ptemap = _kvm_malloc(kd, vmst->hdr.ptesize);
	if (vmst->ptemap == NULL) {
		_kvm_err(kd, kd->program, "cannot allocate %d bytes for "
		    "ptemap", vmst->hdr.ptesize);
		return (-1);
	}

	if (pread(kd->pmfd, vmst->ptemap, vmst->hdr.ptesize, off) !=
	    vmst->hdr.ptesize) {
		_kvm_err(kd, kd->program, "cannot read %d bytes for ptemap",
		    vmst->hdr.ptesize);
		return (-1);
	}

	off += vmst->hdr.ptesize;

	/* Build physical address hash table for sparse pages */
	inithash(kd, vmst->bitmap, vmst->hdr.bitmapsize, off);

	return (0);
}

int
_kvm_minidump_kvatop(kvm_t *kd, uint64_t vaddr, off_t *pa)
{
	struct vmstate *vm;
	pt_entry_t pte;
	uint32_t offset, pteindex, a, va;
	off_t ofs;
	uint32_t *ptemap;
	int i;

	if (ISALIVE(kd)) {
		_kvm_err(kd, 0, "kvm_kvatop called in live kernel!");
		return (0);
	}

	va = (uint32_t) vaddr;
	vm = kd->vmst;
	ptemap = (uint32_t *)vm->ptemap;

	if (va >= vm->hdr.kernbase) {
		pteindex = (va - vm->hdr.kernbase) >> PAGE_SHIFT;
		pte = ptemap[pteindex];

		if (vm->hdr.version == 2 && vm->hdr.arch > 6) {
			if ((pte & L2_TYPE_MASK) == L2_TYPE_INV) {
 				_kvm_err(kd, kd->program,
 				    "_arm_minidump_kvatop: pte not valid");
 				goto invalid;
 			}
 			if ((pte & L2_TYPE_MASK) == L2_TYPE_L) {
				/* 64K page -> convert to be like 4K page */
				offset = va & L2_S_OFFSET;
				a = (pte & L2_L_FRAME) +
				    (va & L2_L_OFFSET & L2_S_FRAME);
			} else {
				if (kd->vmst->hdr.mmuformat == MINIDUMP_MMU_FORMAT_V4 &&
				    (pte & L2_TYPE_MASK) == L2_TYPE_T) {
					_kvm_err(kd, kd->program,
					    "_arm_minidump_kvatop: pte not supported");
					goto invalid;
				}
				/* 4K page */
				offset = va & L2_S_OFFSET;
				a = pte & L2_S_FRAME;
			}
		}
		else {
			if (!pte) {
				_kvm_err(kd, kd->program,
					 "_kvm_vatop: pte not valid");
				goto invalid;
			}
			if ((pte & L2_TYPE_MASK) == L2_TYPE_L) {
				offset = va & L2_L_OFFSET;
				a = pte & L2_L_FRAME;
			} else if ((pte & L2_TYPE_MASK) == L2_TYPE_S) {
				offset = va & L2_S_OFFSET;
				a = pte & L2_S_FRAME;
			} else {
				goto invalid;
			}
			a = a + (offset & ~PAGE_MASK);
			offset = offset & PAGE_MASK;
		}

		ofs = hpt_find(kd->vmst->hpt_head, a);
		if (ofs == -1) {
			_kvm_err(kd, kd->program, "_kvm_vatop: physical "
			    "address 0x%" PRIx32 " not in minidump", a);
			goto invalid;
		}

		*pa = ofs + offset;
		return (PAGE_SIZE - offset);

	} else
		_kvm_err(kd, kd->program, "_kvm_vatop: virtual address 0x%"
		    PRIx32 " not minidumped", va);

invalid:
	_kvm_err(kd, 0, "invalid address (0x%" PRIx32 ")", va);
	return (0);
}
