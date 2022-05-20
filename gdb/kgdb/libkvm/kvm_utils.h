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
#if defined(KGDB_TGT_ARCH_amd64)
#define CORE_ADDR uint64_t
#elif defined(KGDB_TGT_ARCH_arm)
#define CORE_ADDR uint32_t
#elif defined(KGDB_TGT_ARCH_i386)
#define CORE_ADDR uint32_t
#elif defined(KGDB_TGT_ARCH_mips)
#define CORE_ADDR uint32_t
#elif defined(KGDB_TGT_ARCH_mips64)
#define CORE_ADDR uint64_t
#elif defined(KGDB_TGT_ARCH_powerpc)
#define CORE_ADDR uint32_t
#elif defined(KGDB_TGT_ARCH_powerpc64)
#define CORE_ADDR uint64_t
#elif defined(KGDB_TGT_ARCH_aarch64)
#define CORE_ADDR uint64_t
#endif

#if defined(KGDB_TGT_ARCH_mips) || defined(KGDB_TGT_ARCH_mips64)
/* type-stable version of gbl_tlb_t from mips/include/gbl_mem.h */
#define GLOBAL_WIRED_TLB_ENTRY_NUM 2
typedef struct {
	CORE_ADDR	sz;
	CORE_ADDR	vaddr;
	CORE_ADDR	paddr;
	int	valid;
	int	tlb_index;
} kvm_gbl_tlb_t;
#endif

struct vmstate {
	int		minidump;	/* 1 = minidump mode */
	void		*mmapbase;
	size_t		mmapsize;
#if defined(KGDB_TGT_ARCH_amd64)
	pml4_entry_t	*PML4;
#elif defined(KGDB_TGT_ARCH_arm)
	pd_entry_t *l1pt;
#elif defined(KGDB_TGT_ARCH_i386)
	void		*PTD;
	int		pae;
#elif defined(KGDB_TGT_ARCH_mips)
	uint32_t	sysmap;
	kvm_gbl_tlb_t 	gbl_tlb_entries[GLOBAL_WIRED_TLB_ENTRY_NUM];
#elif defined(KGDB_TGT_ARCH_mips64)
	uint64_t	*sysmap;
	uint32_t	sysmap_entries;
	kvm_gbl_tlb_t 	gbl_tlb_entries[GLOBAL_WIRED_TLB_ENTRY_NUM];
#elif defined(KGDB_TGT_ARCH_powerpc)
	size_t		dmphdrsz;
	Elf32_Ehdr	*eh;
	Elf32_Phdr	*ph;
#elif defined(KGDB_TGT_ARCH_powerpc64)
	size_t		dmphdrsz;
	Elf64_Ehdr	*eh;
	Elf64_Phdr	*ph;
#endif
};

int      _kvm_maphdrs(kvm_t *kd, size_t sz);
