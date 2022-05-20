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

#include <elf.h>
#include <machine/target.h>

typedef uintptr_t u_register_t;


/* from sys/proc.h */
#define	NOCPU	0xff		/* For when we aren't on a CPU. */

enum {
  TDS_INACTIVE = 0x0,
  TDS_INHIBITED,
  TDS_CAN_RUN,
  TDS_RUNQ,
  TDS_RUNNING
};


/* from sys/param.h */
#define	MAXCOMLEN	19		/* max command name remembered */
#ifndef NBBY
#define	NBBY		8		/* number of bits in a byte */
#endif


/* from sys/kerneldump.h */
/*
 * All uintX_t fields are in dump byte order, which is the same as
 * network byte order. Use the macros defined above to read or
 * write the fields.
 */
struct kerneldumpheader {
	char		magic[20];
#define	KERNELDUMPMAGIC		"FreeBSD Kernel Dump"
#define	KERNELDUMPMAGIC_CLEARED	"Cleared Kernel Dump"
    /* JUNOS begins */
#define KERNELSHUTDOWNMAGIC     "Juniper Normal Shdn"
    /* JUNOS begins */
	char		architecture[12];
	uint32_t	version;
#define	KERNELDUMPVERSION	1
	uint32_t	architectureversion;
#define	KERNELDUMP_ALPHA_VERSION	1
#define	KERNELDUMP_I386_VERSION	2
#define	KERNELDUMP_IA64_VERSION	1
#define	KERNELDUMP_POWERPC_VERSION	1
#define	KERNELDUMP_POWERPC64_VERSION	1
#define	KERNELDUMP_SPARC64_VERSION	1
#define	KERNELDUMP_AMD64_VERSION	2
#define	KERNELDUMP_ARM_VERSION		1
#define	KERNELDUMP_MIPS_VERSION		1
	uint64_t	dumplength;		/* excl headers */
	uint64_t	dumptime;
	uint32_t	blocksize;
	char		hostname[64];
	char		versionstring[192];
	char		panicstring[192];
	uint32_t	parity;
};


/* from sys/elf_common.h */
#define IS_ELF(ehdr)	((ehdr).e_ident[EI_MAG0] == ELFMAG0 && \
			 (ehdr).e_ident[EI_MAG1] == ELFMAG1 && \
			 (ehdr).e_ident[EI_MAG2] == ELFMAG2 && \
			 (ehdr).e_ident[EI_MAG3] == ELFMAG3)
