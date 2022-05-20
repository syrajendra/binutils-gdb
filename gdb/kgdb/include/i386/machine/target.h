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

typedef uint32_t kgdb_vm_offset_t;
typedef uint32_t kgdb_vm_paddr_t;
typedef uint32_t kgdb_cpumask_t;


/* from machine/param.h */
#ifdef PAE
#define NPGPTD		4
#define PDRSHIFT	21		/* LOG2(NBPDR) */
#else
#define NPGPTD		1
#define PDRSHIFT	22		/* LOG2(NBPDR) */
#endif

#define PAGE_SHIFT	12		/* LOG2(PAGE_SIZE) */
#define PAGE_SIZE	(1<<PAGE_SHIFT)	/* bytes/page */
#define PAGE_MASK	(PAGE_SIZE-1)

#define NPTEPG		(PAGE_SIZE/(sizeof (pt_entry_t)))
#define round_page(x)	(((x) + PAGE_MASK) & ~PAGE_MASK)
#define trunc_page(x)	((x) & ~PAGE_MASK)


/* from machine/pmap.h */
#define VADDR(pdi, pti) ((kgdb_vm_offset_t)(((pdi)<<PDRSHIFT)|((pti)<<PAGE_SHIFT)))

#ifdef PAE
#define NPGPTD		4
#define PDRSHIFT	21		/* LOG2(NBPDR) */
#else
#define NPGPTD		1
#define PDRSHIFT	22		/* LOG2(NBPDR) */
#endif

#define NBPTD		(NPGPTD<<PAGE_SHIFT)
#define NPDEPTD		(NBPTD/(sizeof (pd_entry_t)))
#define NBPDR		(1<<PDRSHIFT)	/* bytes/page dir */

#ifdef SMP
#define MPPTDI		(NPDEPTD-1)	/* per cpu ptd entry */
#define	KPTDI		(MPPTDI-NKPDE)	/* start of kernel virtual pde's */
#else
#define	KPTDI		(NPDEPTD-NKPDE)/* start of kernel virtual pde's */
#endif	/* SMP */

#ifdef PAE
typedef uint64_t pdpt_entry_t;
typedef uint64_t pd_entry_t;
typedef uint64_t pt_entry_t;

#define	PTESHIFT	(3)
#define	PDESHIFT	(3)
#else
typedef uint32_t pd_entry_t;
typedef uint32_t pt_entry_t;

#define	PTESHIFT	(2)
#define	PDESHIFT	(2)
#endif

#ifndef KVA_PAGES
#ifdef PAE
#define KVA_PAGES	512
#else
#define KVA_PAGES	256
#endif
#endif

#ifndef NKPDE
#ifdef SMP
#define NKPDE	(KVA_PAGES - 1) /* number of page tables/pde's */
#else
#define NKPDE	(KVA_PAGES)	/* number of page tables/pde's */
#endif
#endif

#define	PG_V		0x001	/* P	Valid			*/
#define	PG_PS		0x080	/* PS	Page size (0=4k,1=4M)	*/
#define	PG_FRAME	(~((kgdb_vm_paddr_t)PAGE_MASK))


/* from machine/vmparam.h */
#define KERNBASE                VADDR(KPTDI, 0)


/* from machine/segments.h */
#define	NGDT 		19
#define	GPROC0_SEL	9	/* Task state process slot zero and up */
#define	SDT_SYS386BSY	11	/* system 386 TSS busy */

/*
 * Memory and System segment descriptors
 */
struct	segment_descriptor	{
	unsigned sd_lolimit:16 ;	/* segment extent (lsb) */
	unsigned sd_lobase:24 __attribute__((packed)); /* seg base addr (lsb) */
	unsigned sd_type:5 ;		/* segment type */
	unsigned sd_dpl:2 ;		/* segment descriptor priority level */
	unsigned sd_p:1 ;		/* segment descriptor present */
	unsigned sd_hilimit:4 ;		/* segment extent (msb) */
	unsigned sd_xx:2 ;		/* unused */
	unsigned sd_def32:1 ;		/* default 32 vs 16 bit size */
	unsigned sd_gran:1 ;		/* limit granularity (byte/page units)*/
	unsigned sd_hibase:8 ;		/* segment base address  (msb) */
} ;


/* from machine/minidump.h */
#define	MINIDUMP_MAGIC		"minidump FreeBSD/i386"
#define	MINIDUMP_VERSION	1

struct minidumphdr {
	char magic[24];
	uint32_t version;
	uint32_t msgbufsize;
	uint32_t bitmapsize;
	uint32_t ptesize;
	uint32_t kernbase;
	uint32_t paemode;
};

#endif /* _MACHINE_TARGET_H_ */
