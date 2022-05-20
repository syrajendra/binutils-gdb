/*
 * Copyright (c) 2011, Juniper Networks, Inc.
 * All rights reserved.
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

#ifndef	_MACHINE_TARGET_H_
#define	_MACHINE_TARGET_H_ 1

typedef uint32_t pd_entry_t;		/* page directory entry */
typedef uint32_t pt_entry_t;		/* page table entry */
typedef uint32_t kgdb_vm_offset_t;
typedef uint32_t kgdb_cpumask_t;

/* from sys/sys/elf_common.h */
#define	PT_DUMP_DELTA	0x6fb5d000	/* va->pa map for kernel dumps

/* from machine/vmparam.h */
#define	KERNBASE		0xc0000000


/* from machine/param.h */
#define	PAGE_SHIFT	12
#define	PAGE_SIZE	(1 << PAGE_SHIFT)	/* Page size */
#define	PAGE_MASK	(PAGE_SIZE - 1)
#define	round_page(x)	(((x) + PAGE_MASK) & ~PAGE_MASK)


/* from machine/pte.h */
#define	L1_TABLE_SIZE	0x4000		/* 16K */
#define L1_ADDR_MASK	0xfffffc00
#define	L1_S_SHIFT	20
#define	L1_S_ADDR_MASK	0xfff00000	/* phys address of section */
#define	L1_S_SIZE	0x00100000	/* 1M */
#define	L1_S_OFFSET	(L1_S_SIZE - 1)
#define	L2_ADDR_BITS	0x000ff000	/* L2 PTE address bits */
#define	L2_TYPE_INV	0x00		/* Invalid (fault) */
#define	L2_TYPE_MASK	0x03		/* mask of type bits */
#define	L2_TYPE_L	0x01		/* Large Page */
#define	L2_TYPE_S	0x02		/* Small Page */
#define	L2_TYPE_T	0x03		/* Tiny Page  -  1k - not used */
#define	L2_L_SIZE	0x00010000	/* 64K */
#define	L2_L_OFFSET	(L2_L_SIZE - 1)
#define	L2_L_FRAME	(~L2_L_OFFSET)
#define	L2_S_SHIFT	12
#define	L2_S_SIZE	0x00001000	/* 4K */
#define	L2_S_OFFSET	(L2_S_SIZE - 1)
#define	L2_S_FRAME	(~L2_S_OFFSET)
#define	L2_XN		(1 << 0)


/* from machine/minidump.h */
#define	MINIDUMP_MAGIC		"minidump FreeBSD/arm"
#define	MINIDUMP_VERSION	2

struct minidumphdr {
	char magic[24];
	uint32_t version;
	uint32_t msgbufsize;
	uint32_t bitmapsize;
	uint32_t ptesize;
	uint32_t kernbase;
	uint32_t arch;
	uint32_t mmuformat;
};

#define MINIDUMP_MMU_FORMAT_UNKNOWN	0
#define MINIDUMP_MMU_FORMAT_V4		1
#define MINIDUMP_MMU_FORMAT_V6		2
#define MINIDUMP_MMU_FORMAT_V6_LPAE	3

#endif /* _MACHINE_TARGET_H_ */
