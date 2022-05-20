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
 *
 * From: FreeBSD: src/lib/libkvm/kvm_minidump_amd64.c r261799
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

off_t pt_sparse_off;

static void *
_kvm_pmap_get(kvm_t *kd, u_long idx, size_t len)
{
  uintptr_t off = idx * len;

  if ((off_t)off >= pt_sparse_off)
    return (NULL);
  return (void *)((uintptr_t)kd->vmst->page_map + off);
}

static aarch64_pte_t
_aarch64_pte_get(kvm_t *kd, u_long pteindex)
{
  aarch64_pte_t *pte = (aarch64_pte_t*)_kvm_pmap_get(kd, pteindex, sizeof(*pte));

  return *pte;
}

void
_kvm_minidump_freevtop(kvm_t *kd)
{
	struct vmstate *vm = kd->vmst;

	if (vm->bitmap)
		free(vm->bitmap);
	if (vm->page_map)
		free(vm->page_map);
	free(vm);
	kd->vmst = NULL;
}

static int
inithash(kvm_t *kd, uint64_t *base, int len, off_t off)
{
	uint64_t idx;
	uint64_t bit, bits;
	uint64_t pa;
	int bitnum;

	for (idx = 0; idx < len / sizeof(*base); idx++) {
		bits = base[idx];
		bitnum = 0;

		while (bits) {
			if (bits & 1ul) {
				pa = (((uint64_t)idx * sizeof(*base) * NBBY) +
				      bitnum) * AARCH64_PAGE_SIZE;
				hpt_insert(kd->vmst->hpt_head, pa, off);
				off += AARCH64_PAGE_SIZE;
			}
			bits >>= 1ul;
			bitnum++;
		}
	}

	return (off);
}

int
_kvm_minidump_initvtop(kvm_t *kd)
{
	struct vmstate *vmst;
	off_t off;

	vmst = (vmstate*)_kvm_malloc(kd, sizeof(*vmst));
	if (vmst == NULL) {
		_kvm_err(kd, kd->program, "cannot allocate vm");
		return (-1);
	}
	kd->vmst = vmst;
	vmst->minidump = 1;
	if (pread(kd->pmfd, &vmst->hdr, sizeof(vmst->hdr), 0) !=
	    sizeof(vmst->hdr)) {
		_kvm_err(kd, kd->program, "cannot read dump header");
		return (-1);
	}
	if (strncmp(MINIDUMP_MAGIC, vmst->hdr.magic,
	    sizeof(vmst->hdr.magic)) != 0) {
		_kvm_err(kd, kd->program, "not a minidump for this platform");
		return (-1);
	}

	vmst->hdr.version = vmst->hdr.version;
	if (vmst->hdr.version != MINIDUMP_VERSION) {
		_kvm_err(kd, kd->program, "wrong minidump version. "
		    "Expected %d got %d", MINIDUMP_VERSION, vmst->hdr.version);
		return (-1);
	}
	vmst->hdr.msgbufsize = vmst->hdr.msgbufsize;
	vmst->hdr.bitmapsize = vmst->hdr.bitmapsize;
	vmst->hdr.pmapsize = vmst->hdr.pmapsize;
	vmst->hdr.kernbase = vmst->hdr.kernbase;
	vmst->hdr.dmapphys = vmst->hdr.dmapphys;
	vmst->hdr.dmapbase = vmst->hdr.dmapbase;
	vmst->hdr.dmapend = vmst->hdr.dmapend;

	/* Skip header and msgbuf */
	off = AARCH64_PAGE_SIZE + round_page(vmst->hdr.msgbufsize);

	vmst->bitmap = (uint64_t*)_kvm_malloc(kd, vmst->hdr.bitmapsize);
	if (vmst->bitmap == NULL) {
		_kvm_err(kd, kd->program, "cannot allocate %d bytes for "
			 "bitmap", vmst->hdr.bitmapsize);
		return (-1);
	}
	if (pread(kd->pmfd, vmst->bitmap, vmst->hdr.bitmapsize, off) !=
	    vmst->hdr.bitmapsize) {
		_kvm_err(kd, kd->program, "cannot read %d bytes for page "
			 "bitmap", vmst->hdr.bitmapsize);
		return (-1);
	}
	off += round_page(vmst->hdr.bitmapsize);

	vmst->page_map = (uint64_t*)_kvm_malloc(kd, vmst->hdr.pmapsize);
	if (vmst->page_map == NULL) {
		_kvm_err(kd, kd->program, "cannot allocate %d bytes for "
			 "page_map", vmst->hdr.pmapsize);
		return (-1);
	}
	if (pread(kd->pmfd, vmst->page_map, vmst->hdr.pmapsize, off) !=
	    vmst->hdr.pmapsize) {
		_kvm_err(kd, kd->program, "cannot read %d bytes for page_map",
			 vmst->hdr.pmapsize);
		return (-1);
	}
	pt_sparse_off = off + round_page(vmst->hdr.pmapsize);
	off += vmst->hdr.pmapsize;

	/* build physical address hash table for sparse pages */
	inithash(kd, vmst->bitmap, vmst->hdr.bitmapsize, off);

	return (0);
}

static int
_kvm_minidump_vatop(kvm_t *kd, uint64_t va, off_t *pa)
{
	struct vmstate *vm;
	aarch64_physaddr_t offset;
	aarch64_pte_t l3;
	uint64_t l3_index;
	aarch64_physaddr_t a;
	off_t ofs;

	vm = kd->vmst;
	offset = va & AARCH64_PAGE_MASK;

	if (va >= vm->hdr.dmapbase && va < vm->hdr.dmapend) {
		a = (va - vm->hdr.dmapbase + vm->hdr.dmapphys) &
		    ~AARCH64_PAGE_MASK;
		ofs = hpt_find(kd->vmst->hpt_head, a);
		if (ofs == -1) {
			_kvm_err(kd, kd->program, "_aarch64_minidump_vatop: "
			    "direct map address 0x%jx not in minidump",
			    (uintmax_t)va);
			goto invalid;
		}
		*pa = ofs + offset;
		return (AARCH64_PAGE_SIZE - offset);
	} else if (va >= vm->hdr.kernbase) {
		l3_index = (va - vm->hdr.kernbase) >> AARCH64_L3_SHIFT;
		if (l3_index >= vm->hdr.pmapsize / sizeof(l3))
			goto invalid;
		l3 = _aarch64_pte_get(kd, l3_index);
		if ((l3 & AARCH64_ATTR_DESCR_MASK) != AARCH64_L3_PAGE) {
			_kvm_err(kd, kd->program,
			    "_aarch64_minidump_vatop: pde not valid");
			goto invalid;
		}
		a = l3 & ~AARCH64_ATTR_MASK;
		ofs = hpt_find(kd->vmst->hpt_head, a);
		if (ofs == -1) {
			_kvm_err(kd, kd->program, "_aarch64_minidump_vatop: "
			    "physical address 0x%jx not in minidump",
			    (uintmax_t)a);
			goto invalid;
		}
		*pa = ofs + offset;
		return (AARCH64_PAGE_SIZE - offset);
	} else {
		_kvm_err(kd, kd->program,
	    "_aarch64_minidump_vatop: virtual address 0x%jx not minidumped",
		    (uintmax_t)va);
		goto invalid;
	}

invalid:
	_kvm_err(kd, 0, "invalid address (0x%jx)", (uintmax_t)va);
	return (0);
}

int
_kvm_minidump_kvatop(kvm_t *kd, uint64_t va, off_t *pa)
{
	if (ISALIVE(kd)) {
		_kvm_err(kd, 0,
		    "_aarch64_minidump_kvatop called in live kernel!");
		return (0);
	}
	return (_kvm_minidump_vatop(kd, va, pa));
}

/* Dummy definitions for elf core */
#include <assert.h>
int _kvm_initvtop(kvm_t *kd)
{
  char minihdr[8];

  if (pread(kd->pmfd, &minihdr, (size_t) 8, 0) == 8)
    if (memcmp(&minihdr, "minidump", 8) == 0)
      return (_kvm_minidump_initvtop(kd));
  /* Should never reach here */
  assert(0);
}

int
_kvm_kvatop(kvm_t *kd, uint64_t va, off_t *pa)
{
  if (kd->vmst->minidump)
    return (_kvm_minidump_kvatop(kd, va, pa));
  /* Should never reach here */
  assert(0);
}
