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
#include <sys/mman.h>
#include <stdlib.h>
#include <unistd.h>
#include <elf.h>
#include <limits.h>

#include <libkvm/kvm.h>
#include <include/sys/target.h>
#include <libkvm/kvm_private.h>
#include <libkvm/kvm_utils.h>

/*
 * Map the ELF headers into the process' address space. We do this in two
 * steps: first the ELF header itself and using that information the whole
 * set of headers. (Taken from kvm_ia64.c)
 */
int
_kvm_maphdrs(kvm_t *kd, size_t sz)
{
	struct vmstate *vm = kd->vmst;

	/* munmap() previous mmap(). */
	if (vm->mmapbase != NULL) {
		munmap(vm->mmapbase, vm->mmapsize);
		vm->mmapbase = NULL;
	}

	vm->mmapsize = sz;
	vm->mmapbase = mmap(NULL, sz, PROT_READ, MAP_PRIVATE, kd->pmfd, 0);
	if (vm->mmapbase == MAP_FAILED) {
		_kvm_err(kd, kd->program, "cannot mmap corefile");
		return (-1);
	}
	return (0);
}

void
_kvm_freevtop(kvm_t *kd)
{
	struct vmstate *vm = kd->vmst;

	if (vm == NULL)
		return;
	if (vm->minidump)
		return (_kvm_minidump_freevtop(kd));
	if (vm->mmapbase != NULL)
		munmap(vm->mmapbase, vm->mmapsize);

#if defined(KGDB_TGT_ARCH_amd64)
	if (vm->PML4)
		free(vm->PML4);
#elif defined(KGDB_TGT_ARCH_i386)
	if (vm->PTD)
		free(vm->PTD);
#elif defined(KGDB_TGT_ARCH_powerpc64)
	if (vm->eh != MAP_FAILED) {
		munmap(vm->eh, vm->mmapsize);
		vm->eh = (Elf64_Ehdr*)MAP_FAILED;
	}
#elif defined(KGDB_TGT_ARCH_powerpc)
	if (vm->eh != MAP_FAILED) {
		munmap(vm->eh, vm->mmapsize);
		vm->eh = (Elf32_Ehdr*)MAP_FAILED;
	}
#endif

	free(vm);
	kd->vmst = NULL;
}
