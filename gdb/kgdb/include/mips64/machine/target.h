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

typedef uint32_t pt_entry_t;
typedef uint64_t pd_entry_t;
typedef uint64_t pdp_entry_t;
typedef uint32_t kgdb_cpumask_t;


/* from machine/vmparam.h */
#define	KERNBASE	0x80000000	/* start of kernel virtual */


/* from machine/pte.h */
#define PTE_SHIFT       2                  /* log2(PTESIZE) */
#define PDE_SHIFT       3                  /* log2(PDESIZE) */
#define PDP_SHIFT       3                  /* log2(PDPSIZE) */
#define	PG_G		0x00000001	/* HW */
#define PG_V		0x00000002
#define PG_FRAME	0x3fffffc0
#define PG_SHIFT	6
#define pfn64_to_vad(x)	((((uint64_t)(x)) & PG_FRAME) << PG_SHIFT)


/* from machine/cpu.h */

#define MIPS_XKPHYS_START               0x8000000000000000
#define MIPS_XKPHYS_END                 0xbfffffffffffffff
#define MIPS_KSEG0_START                ((intptr_t)(int32_t)0x80000000)
#define MIPS_KSEG0_END                  ((intptr_t)(int32_t)0x9fffffff)
#define MIPS_KSEG1_START                ((intptr_t)(int32_t)0xa0000000)
#define MIPS_KSEG1_END                  ((intptr_t)(int32_t)0xbfffffff)
#define MIPS_KSEG2_START                ((intptr_t)(int32_t)0xc0000000)
#define MIPS_KSEG2_END                  ((intptr_t)(int32_t)0xdfffffff)
#define MIPS_KSEG3_START                ((intptr_t)(int32_t)0xe0000000)
#define MIPS_KSEG3_END                  ((intptr_t)(int32_t)0xffffffff)
#define MIPS_PHYS_MASK                  (0x1fffffff)
#define XKPHYS_PABITS         		40
#define XKPHYS_PA_MASK                	((1ULL<<XKPHYS_PABITS)-1)
#define MIPS_XKPHYS_P(x)                (((uint64_t)(x) >> 62) == 2)
#define MIPS_XKSEG_P(x)                 (((uint64_t)(x) >> 62) == 3	\
					 && (x) < MIPS_KSEG0_START)
#define MIPS_KSEG0_TO_PHYS(x)   ((uint64_t)(x) & MIPS_PHYS_MASK)
#define	MIPS_XKPHYS_TO_PHYS(x)	((x) & XKPHYS_PA_MASK)
#define MIPS_IS_KSEG01_ADDR(x) \
  (((uint64_t)(x) >= MIPS_KSEG0_START) && ((uint64_t)(x) <= MIPS_KSEG2_START))
#define MIPS_CACHED_TO_PHYS(x) MIPS_IS_KSEG01_ADDR(x) ? \
   MIPS_KSEG0_TO_PHYS(x) : MIPS_XKPHYS_TO_PHYS((uint64_t)(x))

/* from machine/param.h */
#define PAGE_SHIFT	12		/* LOG2(PAGE_SIZE) */ 
#define PAGE_SIZE	(1<<PAGE_SHIFT) /* bytes/page */
#define PAGE_MASK	(PAGE_SIZE-1)
#define	NBPG		PAGE_SIZE	/* bytes/page */
#define NPTEPGSHIFT	(PAGE_SHIFT-PTE_SHIFT) /* LOG2(NPTEPT) */
#define NSEGSHIFT	(PAGE_SHIFT-PDE_SHIFT)	 /* LOG2(NSEGPG) */
#define SEGSHIFT	(PAGE_SHIFT+NPTEPGSHIFT) /* LOG2(NBSEG) */
#define MIPS_VM_BITS    35
#define MIPS_VM_SIZE	(1ULL<<MIPS_VM_BITS)
#define MIPS_VM_MASK	(MIPS_VM_SIZE-1)
#define NBDIR		(1ULL<<DIRSHIFT)
#define NBSEG		(1<<SEGSHIFT)		 /* bytes/segment */
#define DIRSHIFT	(NSEGSHIFT+SEGSHIFT)
#define DIRMASK		(NBDIR-1)
#define SEGMASK	        (NBSEG-1)
#define DIR_IDX(v)	(((uint64_t)(v) & MIPS_VM_MASK) >> DIRSHIFT)
#define SEG_IDX(v)	(((uint64_t)(v) & DIRMASK) >> SEGSHIFT)
#define PTE_IDX(v)	(((uint64_t)(v) & SEGMASK) >> PAGE_SHIFT)
#define mips_round_page(x)	((((uint64_t)(x)) + NBPG - 1) & ~(NBPG-1))
#define round_page	mips_round_page


/* from machine/minidump.h */
#define MINIDUMP_MAGIC		"minidump FreeBSD/mips"
#define MINIDUMP_VERSION	1

struct minidumphdr {
	char magic[24];
	uint32_t version;
	uint32_t msgbufsize;
	uint32_t bitmapsize;
	uint32_t ptesize;
	uint64_t kernbase;
	uint64_t dmapbase;
	uint64_t dmapend;
};

#endif /* _MACHINE_TARGET_H_ */
