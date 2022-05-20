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

typedef uint64_t pml4_entry_t;
typedef uint64_t pdp_entry_t;
typedef uint64_t pd_entry_t;
typedef uint64_t pt_entry_t;
typedef uint32_t kgdb_cpumask_t;


/* from machine/param.h */
#define	PML4SHIFT	39		/* LOG2(NBPML4) */
#define	PDPSHIFT	30		/* LOG2(NBPDP) */
#define	PDRSHIFT	21              /* LOG2(NBPDR) */
#define PAGE_SHIFT	12		/* LOG2(PAGE_SIZE) */
#define PAGE_SIZE	(1<<PAGE_SHIFT)	/* bytes/page */
#define PAGE_MASK	(PAGE_SIZE-1)

#define	NPDPEPG		(PAGE_SIZE/(sizeof (pdp_entry_t)))
#define	NPML4EPG	(PAGE_SIZE/(sizeof (pml4_entry_t)))
#define	NPDEPG		(PAGE_SIZE/(sizeof (pd_entry_t)))
#define	NBPDR		(1<<PDRSHIFT)   /* bytes/page dir */
#define	NPTEPG		(PAGE_SIZE/(sizeof (pt_entry_t)))
#define	NPTEPGSHIFT	9		/* LOG2(NPTEPG) */
#define	PDRMASK		(NBPDR-1)
#define	round_page(x)	((((unsigned long)(x)) + PAGE_MASK) & ~(PAGE_MASK))


/* from machine/pmap.h */
#define	KPML4I		(NPML4EPG-1)	/* Top 512GB for KVM */
#define	KPDPI		(NPDPEPG-2)	/* kernbase at -2GB */
#define	PG_V		0x001	/* P	Valid			*/
#define	PG_PS		0x080	/* PS	Page size (0=4k,1=4M)	*/
#define	PG_FRAME	(0x000ffffffffff000ull)
#define	PG_PS_FRAME	(0x000fffffffe00000ull)

#define KVADDR(l4, l3, l2, l1) ( \
	((unsigned long long)-1 << 47) | \
	((unsigned long long)(l4) << PML4SHIFT) | \
	((unsigned long long)(l3) << PDPSHIFT) | \
	((unsigned long long)(l2) << PDRSHIFT) | \
	((unsigned long long)(l1) << PAGE_SHIFT))


/* from machine/vmparam.h */
#define	KERNBASE		KVADDR(KPML4I, KPDPI, 0, 0)


/* from machine/minidump.h */
#define	MINIDUMP_MAGIC		"minidump FreeBSD/amd64"
#define	MINIDUMP_VERSION	2

struct minidumphdr {
	char magic[24];
	uint32_t version;
	uint32_t msgbufsize;
	uint32_t bitmapsize;
	uint32_t pmapsize;
	uint64_t kernbase;
	uint64_t dmapbase;
	uint64_t dmapend;
};

#endif /* _MACHINE_TARGET_H_ */
