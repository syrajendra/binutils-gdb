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
typedef uint32_t pt_entry_t;
typedef uint32_t kgdb_cpumask_t;


/* from machine/vmparam.h */
#define VM_MIN_KERNEL_ADDRESS	((kgdb_vm_offset_t)0xC0000000)
#define VM_MAX_KERNEL_ADDRESS	((kgdb_vm_offset_t)0xFFFFC000)


/* from machine/param.h */
#define	KERNBASE	0x80000000	/* start of kernel virtual */
#define	NBPG		4096		/* bytes/page */
#define PAGE_SHIFT      12              /* LOG2(PAGE_SIZE) */ 
#define PAGE_SIZE       (1<<PAGE_SHIFT) /* bytes/page */
#define PAGE_MASK       (PAGE_SIZE-1)
#define	PGOFSET		(NBPG-1)	/* byte offset into page */
#define	PGSHIFT		12		/* LOG2(NBPG) */
#define	SEGSHIFT	22		/* LOG2(NBSEG) */
#define NPTEPG          (PAGE_SIZE/(sizeof (pt_entry_t)))


/* from machine/pte.h */
#define	PG_G		0x00000001	/* HW */
#define	PG_V		0x00000002
#define	PG_FRAME	0x3fffffc0
#define PG_SHIFT	6
#define vad_to_pte_offset(adr) (((adr) >> PGSHIFT) & (NPTEPG -1))


/* from machine/cpu.h */

/*
 * CPU identification, from PRID register.
 */
union cpuprid {
	int	cpuprid;
	struct {
#if BYTE_ORDER == BIG_ENDIAN
		u_int	pad1:8;	/* reserved */
		u_int	cp_vendor:8;	/* company identifier */
		u_int	cp_imp:8;	/* implementation identifier */
		u_int	cp_majrev:4;	/* major revision identifier */
		u_int	cp_minrev:4;	/* minor revision identifier */
#else
		u_int	cp_minrev:4;	/* minor revision identifier */
		u_int	cp_majrev:4;	/* major revision identifier */
		u_int	cp_imp:8;	/* implementation identifier */
		u_int	cp_vendor:8;	/* company identifier */
		u_int	pad1:8;	/* reserved */
#endif
	} cpu;
};

static union	cpuprid cpu_id;
#define	MIPS_RM9000	0x34	/* E9000 CPU		                */
#define PHOENIX_ADDR_MEM_CACHED		0xc0000000
#define PHOENIX_ADDR_MEM_UNCACHED	0xa0000000
#define PHOENIX_ADDR_PHY_MEM		0x40000000  /* physical address of memory */

#define mips_proc_type()   ((cpu_id.cpu.cp_vendor << 8) | cpu_id.cpu.cp_imp)
#define mips_round_page(x)	((((uint32_t)(x)) + NBPG - 1) & ~(NBPG-1))
#define round_page		mips_round_page
#define pfn64_to_vad(x)	((((uint64_t)(x)) & PG_FRAME) << PG_SHIFT)

#define MIPS_CACHED_TO_PHYS_MINT(x) ((unsigned)(x) & 0x1fffffff)
#define MIPS_CACHED_TO_PHYS_PHOENIX(x) \
  (((unsigned)(x) - PHOENIX_ADDR_MEM_CACHED) + PHOENIX_ADDR_PHY_MEM)
#define MIPS_CACHED_TO_PHYS(x)     ((mips_proc_type() == MIPS_RM9000) ?  \
                                         MIPS_CACHED_TO_PHYS_PHOENIX(x) : \
				         MIPS_CACHED_TO_PHYS_MINT(x))


/* from machine/minidump.h */
#define MINIDUMP_MAGIC		"minidump JUNOS/mips"
#define MINIDUMP_VERSION	1
#define MINIDUMP_FAMILY_GENERIC	0

struct minidumphdr {
	char magic[24];
	uint32_t version;
	uint32_t family;
	uint32_t msgbufsize;
	uint32_t bitmapsize;
	uint32_t ptesize;
	uint32_t kernbase;
	uint32_t dmapbase;
	uint32_t dmapend;
};

#endif /* _MACHINE_TARGET_H_ */
