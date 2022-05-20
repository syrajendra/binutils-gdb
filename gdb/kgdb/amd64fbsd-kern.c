/*
 * Copyright (c) 2004 Marcel Moolenaar
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "defs.h"
#include "frame-unwind.h"
#include "gdbcore.h"
#include "osabi.h"
#include "regcache.h"
#include "solib.h"
#include "stack.h"
#include "symtab.h"
#include "trad-frame.h"
#include "amd64-tdep.h"
#include "gdbsupport/x86-xstate.h"

#include "kgdb.h"

enum {
      IDX_AMD64_RAX = 0,
      IDX_AMD64_RBX,
      IDX_AMD64_RCX,
      IDX_AMD64_RDX,
      IDX_AMD64_RSI,
      IDX_AMD64_RDI,
      IDX_AMD64_RBP,
      IDX_AMD64_RSP,
      IDX_AMD64_R8,
      IDX_AMD64_R9,
      IDX_AMD64_R10,
      IDX_AMD64_R11,
      IDX_AMD64_R12,
      IDX_AMD64_R13,
      IDX_AMD64_R14,
      IDX_AMD64_R15,
      IDX_AMD64_RIP,
      IDX_AMD64_EFLAGS,
      IDX_AMD64_CS,
      IDX_AMD64_SS,
      IDX_AMD64_DS,
      IDX_AMD64_ES,
      IDX_AMD64_FS,
      IDX_AMD64_GS
};

static int amd64fbsd_pcb_offset[] = {
  -1,                           /* %rax */
  -1,                           /* %rbx */
  -1,                           /* %rcx */
  -1,                           /* %rdx */
  -1,                           /* %rsi */
  -1,                           /* %rdi */
  -1,                           /* %rbp */
  -1,                           /* %rsp */
  -1,                           /* %r8 ...  */
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,                           /* ... %r15 */
  -1,                           /* %rip */
  -1,                           /* %eflags */
  -1,                           /* %cs */
  -1,                           /* %ss */
  -1,                           /* %ds */
  -1,                           /* %es */
  -1,                           /* %fs */
  -1                            /* %gs */
};

#define	CODE_SEL	(4 << 3)
#define	DATA_SEL	(5 << 3)

static void
amd64fbsd_init_pcb()
{
	amd64fbsd_pcb_offset[IDX_AMD64_RBX] = parse_and_eval_address
		("&((struct pcb *)0)->pcb_rbx");
	amd64fbsd_pcb_offset[IDX_AMD64_RBP] = parse_and_eval_address
		("&((struct pcb *)0)->pcb_rbp");
	amd64fbsd_pcb_offset[IDX_AMD64_RSP] = parse_and_eval_address
		("&((struct pcb *)0)->pcb_rsp");
	amd64fbsd_pcb_offset[IDX_AMD64_R12] = parse_and_eval_address
		("&((struct pcb *)0)->pcb_r12");
	amd64fbsd_pcb_offset[IDX_AMD64_R13] = parse_and_eval_address
		("&((struct pcb *)0)->pcb_r13");
	amd64fbsd_pcb_offset[IDX_AMD64_R14] = parse_and_eval_address
		("&((struct pcb *)0)->pcb_r14");
	amd64fbsd_pcb_offset[IDX_AMD64_R15] = parse_and_eval_address
		("&((struct pcb *)0)->pcb_r15");
	amd64fbsd_pcb_offset[IDX_AMD64_RIP] = parse_and_eval_address
		("&((struct pcb *)0)->pcb_rip");
}

static void
amd64fbsd_print_pcb_offsets()
{
  printf("=============Register Offsets=============\n");
  printf("RBX=>%d\n", amd64fbsd_pcb_offset[IDX_AMD64_RBX]);
  printf("RBP=>%d\n", amd64fbsd_pcb_offset[IDX_AMD64_RBP]);
  printf("RSP=>%d\n", amd64fbsd_pcb_offset[IDX_AMD64_RSP]);
  printf("R12=>%d\n", amd64fbsd_pcb_offset[IDX_AMD64_R12]);
  printf("R13=>%d\n", amd64fbsd_pcb_offset[IDX_AMD64_R13]);
  printf("R14=>%d\n", amd64fbsd_pcb_offset[IDX_AMD64_R14]);
  printf("R15=>%d\n", amd64fbsd_pcb_offset[IDX_AMD64_R15]);
  printf("RIP=>%d\n", amd64fbsd_pcb_offset[IDX_AMD64_RIP]);
  printf("==========================================\n");
}

static void
amd64fbsd_supply_pcb(struct regcache *regcache, CORE_ADDR pcb_addr)
{
  gdb_byte buf[8];
  int i;

  memset(buf, 0, sizeof(buf));

  /*
   * XXX The PCB may have been swapped out.  Supply a dummy %rip value
   * so as to avoid triggering an exception during stack unwinding.
   */
  regcache->raw_supply(AMD64_RIP_REGNUM, buf);
  for (i = 0; i < ARRAY_SIZE (amd64fbsd_pcb_offset); i++)
    if (amd64fbsd_pcb_offset[i] != -1) {
      if (target_read_memory(pcb_addr + amd64fbsd_pcb_offset[i], buf,
			     sizeof buf) != 0)
	continue;
      regcache->raw_supply(i, buf);
    }

  regcache->raw_supply_unsigned(AMD64_CS_REGNUM, CODE_SEL);
  regcache->raw_supply_unsigned(AMD64_SS_REGNUM, DATA_SEL);
}

static const int amd64fbsd_trapframe_offset[] = {
  6 * 8,			/* %rax */
  7 * 8,			/* %rbx */
  3 * 8,			/* %rcx */
  2 * 8,			/* %rdx */
  1 * 8,			/* %rsi */
  0 * 8,			/* %rdi */
  8 * 8,			/* %rbp */
  22 * 8,			/* %rsp */
  4 * 8,			/* %r8 ...  */
  5 * 8,
  9 * 8,
  10 * 8,
  11 * 8,
  12 * 8,
  13 * 8,
  14 * 8,			/* ... %r15 */
  19 * 8,			/* %rip */
  21 * 8,			/* %eflags */
  20 * 8,			/* %cs */
  23 * 8,			/* %ss */
  -1,				/* %ds */
  -1,				/* %es */
  -1,				/* %fs */
  -1				/* %gs */
};

#define TRAPFRAME_SIZE	192

static struct trad_frame_cache *
amd64fbsd_trapframe_cache (struct frame_info *this_frame, void **this_cache)
{
  struct gdbarch *gdbarch = get_frame_arch (this_frame);
  enum bfd_endian byte_order = gdbarch_byte_order (gdbarch);
  struct trad_frame_cache *cache;
  CORE_ADDR addr, func, pc, sp;
  const char *name;
  int i;

  if (*this_cache != NULL)
    return ((struct trad_frame_cache *)*this_cache);

  cache = trad_frame_cache_zalloc (this_frame);
  *this_cache = cache;

  func = get_frame_func (this_frame);
  sp = get_frame_register_unsigned (this_frame, AMD64_RSP_REGNUM);

  find_pc_partial_function (func, &name, NULL, NULL);
  if (strcmp(name, "fork_trampoline") == 0 && get_frame_pc (this_frame) == func)
    {
      /* fork_exit hasn't been called (kthread has never run), so %rsp
	 in the pcb points to the trapframe.  GDB has auto-adjusted
	 %rsp for this frame to account for the "call" into
	 fork_trampoline, so "undo" the adjustment.  */
      sp += 8;
    }
  
  for (i = 0; i < ARRAY_SIZE (amd64fbsd_trapframe_offset); i++)
    if (amd64fbsd_trapframe_offset[i] != -1)
      trad_frame_set_reg_addr (cache, i, sp + amd64fbsd_trapframe_offset[i]);

  /* Read %rip from trap frame.  */
  addr = sp + amd64fbsd_trapframe_offset[AMD64_RIP_REGNUM];
  pc = read_memory_unsigned_integer (addr, 8, byte_order);

  if (pc == 0 && strcmp(name, "fork_trampoline") == 0)
    {
      /* Initial frame of a kthread; terminate backtrace.  */
      trad_frame_set_id (cache, outer_frame_id);
    }
  else
    {
      /* Construct the frame ID using the function start.  */
      trad_frame_set_id (cache, frame_id_build (sp + TRAPFRAME_SIZE, func));
    }

  return cache;
}

static void
amd64fbsd_trapframe_this_id (struct frame_info *this_frame,
			     void **this_cache, struct frame_id *this_id)
{
  struct trad_frame_cache *cache =
    amd64fbsd_trapframe_cache (this_frame, this_cache);
  
  trad_frame_get_id (cache, this_id);
}

static struct value *
amd64fbsd_trapframe_prev_register (struct frame_info *this_frame,
				   void **this_cache, int regnum)
{
  struct trad_frame_cache *cache =
    amd64fbsd_trapframe_cache (this_frame, this_cache);

  return trad_frame_get_register (cache, this_frame, regnum);
}

static int
amd64fbsd_trapframe_sniffer (const struct frame_unwind *self,
			     struct frame_info *this_frame,
			     void **this_prologue_cache)
{
  const char *name;

  find_pc_partial_function (get_frame_func (this_frame), &name, NULL, NULL);
  return (name && ((strcmp (name, "calltrap") == 0)
		   || (strcmp (name, "fast_syscall_common") == 0)
		   || (strcmp (name, "fork_trampoline") == 0)
		   || (strcmp (name, "mchk_calltrap") == 0)
		   || (strcmp (name, "nmi_calltrap") == 0)
		   || (name[0] == 'X' && name[1] != '_')));
}

static const struct frame_unwind amd64fbsd_trapframe_unwind = {
  "amd64 FreeBSD kernel trap",
  SIGTRAMP_FRAME,
  default_frame_unwind_stop_reason,
  amd64fbsd_trapframe_this_id,
  amd64fbsd_trapframe_prev_register,
  NULL,
  amd64fbsd_trapframe_sniffer
};

static void
amd64fbsd_kernel_init_abi(struct gdbarch_info info, struct gdbarch *gdbarch)
{

	amd64_init_abi(info, gdbarch,
		       amd64_target_description (X86_XSTATE_SSE_MASK, true));

	frame_unwind_prepend_unwinder(gdbarch, &amd64fbsd_trapframe_unwind);

	set_solib_ops(gdbarch, &kld_so_ops);

	fbsd_vmcore_set_init_pcb(gdbarch, amd64fbsd_init_pcb);
	fbsd_vmcore_set_print_pcb_offsets(gdbarch, amd64fbsd_print_pcb_offsets);
	fbsd_vmcore_set_supply_pcb(gdbarch, amd64fbsd_supply_pcb);
	fbsd_vmcore_set_cpu_pcb_addr(gdbarch, kgdb_trgt_stop_pcb);
}

void _initialize_amd64_kgdb_tdep ();
void
_initialize_amd64_kgdb_tdep ()
{
	gdbarch_register_osabi (bfd_arch_i386, bfd_mach_x86_64,
	    GDB_OSABI_FREEBSD_KERNEL, amd64fbsd_kernel_init_abi);
}
