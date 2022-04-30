#define _XOPEN_SOURCE 500
#define _GNU_SOURCE
#include <stdarg.h>
#include <ucontext.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <err.h>

#include "xrun.h"

#define ABS 0x80000000
#define EOL 0x80000000
#define FLAGADDR 0x88888888
#define FLAGOFFSET 0xa5000000
static void *get_addr(uint8_t *ep, int32_t bias, uint32_t offset, ...) {
	uint32_t addr = *(uint32_t *) &ep[offset];
	*(uint32_t *) &ep[offset] = bias == ABS ? FLAGADDR : FLAGOFFSET;

	va_list argp;
	va_start(argp, offset);
	while (1) {
		uint32_t checkoff = va_arg(argp, uint32_t);
		if (checkoff == EOL)
			break;
		uint32_t checkaddr = *(uint32_t *) &ep[checkoff];
		*(uint32_t *) &ep[checkoff] = FLAGADDR;
		if (checkaddr != addr)
			errx(131, "incorrect value at check offset 0x%03x: %08x expecting %08x", checkoff, checkaddr, addr);
	}
	va_end(argp);

	if (bias != ABS)
		addr = addr + (uint32_t) ep + bias;
	return (void *) addr;
}

const char *copyright_id = "High C Run-time Library Copyright (C) 1983-1990 MetaWare Incorporated.";

static void do_exit(void) {
	exit(0);
}

void init_mwhc(uint8_t *ep, uint32_t heapsize, uint32_t esp, uint32_t stacksize, uint32_t loadbase, uint32_t loadlimit,
		uint32_t heaplimit, char **envv, char **argv) {
	if (ep[0] != 0xeb || ep[1] != 0x56)
		errx(131, "incorrect entry point signature %02x %02x", ep[0], ep[1]);
	if (strncmp((char *) &ep[0x012], copyright_id, strlen(copyright_id))) {
		uint8_t temp[strlen(copyright_id) + 1];
		memcpy(temp, &ep[0x012], strlen(copyright_id));
		temp[strlen(copyright_id)] = 0;
		errx(131, "incorrect copyright string '%s'", temp);
	}

	// subroutines called by init
	void *__main = get_addr(ep, 0x007, 0x003, EOL); // offset of __main(), which simply calls main()
	void *finitfunc_unknown = get_addr(ep, 0x00d,  0x009, EOL); // unknown cleanup function, might be exit() / atexit()
	uint8_t *initfunc_retn = get_addr(ep, 0x4ea, 0x4e6, EOL); // address of an init function that is always a single RET
	void *initfunc_unknown = get_addr(ep, 0x4ef, 0x4eb, EOL); // address of an init function of unknown purpose
	void *set_up_args = get_addr(ep, 0x4fc, 0x4f8, EOL); // function that builds argvp from argp, ie. splits the args
	// DOS extender type: SG_ENV = 1 (SoftGuard), PL_ENV = 2 (Phar Lap), AI_ENV = 3 (unknown)
	uint8_t *env = get_addr(ep, ABS, 0x06a, 0x079, 0x0ad, 0x1dc, 0x2ac, 0x369, 0x38a, 0x3ac, 0x450, 0x459, EOL);
	uint32_t *_gda = get_addr(ep, ABS, 0x071, EOL); // location of GDA (global data area) in SG_ENV (SoftGuard)
	uint8_t *lahey_format_file = get_addr(ep, ABS, 0x1f2, 0x2f5, 0x3b8, EOL); // 1 if file in Lahey Systems linker format
	// stack / heap config
	uint32_t *stack_margin_big = get_addr(ep, ABS, 0x085, 0x099, EOL);
	uint32_t *stack_margin_small = get_addr(ep, ABS, 0x08f, 0x0a3, EOL);
	uint32_t *start_of_stack = get_addr(ep, ABS, 0x09d, 0x0a7, EOL);
	uint32_t *_base = get_addr(ep, ABS, 0x0b6, 0x0de, EOL); // bottom of stack, top of code / data image
	uint32_t *_top = get_addr(ep, ABS, 0x0c3, 0x0e6, 0x391, EOL); // top of stack, bottom of heap
	uint32_t *_heaphi = get_addr(ep, ABS, 0x0cd, 0x0f3, 0x3ce, EOL); // top of heap
	uint32_t *cur_pages = get_addr(ep, ABS, 0x3a1, EOL); // number of currently allocated heap pages (size of heap)
	void **_mwinitfrstcall = get_addr(ep, ABS, 0x4be, EOL); // start of init-function call table
	void **_mwinitlastcall = get_addr(ep, ABS, 0x4c3, EOL); // end of init-function call table
	// FPU detection stuff
	uint8_t *fpu_1167 = get_addr(ep, ABS, 0x10f, 0x20c, 0x257, 0x4ff, EOL); // ancient Weitek 1167 FPU presence flag
	uint16_t *fpu_temp = get_addr(ep, ABS, 0x119, 0x125, 0x130, 0x139, 0x143, 0x14e, 0x161, EOL); // 8087 init temp loc
	uint8_t *fpu_tmp = get_addr(ep, ABS, 0x167, EOL); // second byte of fpu_temp
	uint16_t *fpu_init_cw_emc = get_addr(ep, ABS, 0x15a, EOL); // EMC87 FPU control word
	uint16_t *fpu_init_cw = get_addr(ep, ABS, 0x179, EOL); // 8087 FPU control word
	uint8_t *fpu_mw387 = get_addr(ep, ABS, 0x170, 0x1a0, 0x581, EOL); // 80387 FPU presence flag
	uint8_t *fpu_mwemc87 = get_addr(ep, ABS, 0x17f, 0x1a7, 0x528, EOL); // EMC87 FPU presence flag
	uint16_t *fpu_mw8087 = get_addr(ep, ABS, 0x186, 0x3f9, 0x403, 0x551, EOL); // 8087 FPU presence flag
	// standard C environment: arguments, program name, enviornment
	uint32_t *argp = get_addr(ep, ABS, 0x2da, 0x34a, EOL); // argument string (ie. un-split)
	uint16_t *argp_seg = get_addr(ep, ABS, 0x2b8, EOL); // segment address part of argp
	uint32_t *_psp = get_addr(ep, ABS, 0x2be, EOL); // address of DOS PSP
	uint16_t *_psp_seg = get_addr(ep, ABS, 0x2c4, 0x31a, 0x320, EOL); // segment address part of _psp
	uint32_t *arglen = get_addr(ep, ABS, 0x2d4, 0x334, 0x4a7, EOL); // length of argp string
	uint32_t *envp = get_addr(ep, ABS, 0x2e7, 0x3d4, EOL); // address of environment area
	uint16_t *envp_seg = get_addr(ep, ABS, 0x2ed, 0x327, 0x49d, EOL); // segment address part of envp
	uint16_t *_osmajor = get_addr(ep, ABS, 0x363, 0x447, EOL); // DOS major + minor version number
	uint32_t *prognamep = get_addr(ep, ABS, 0x462, 0x473, 0x490, EOL); // address of program name
	uint16_t *prognamep_seg = get_addr(ep, ABS, 0x468, EOL); // segment address part of prognamep
	uint32_t *argvp = get_addr(ep, ABS, 0x4b7, 0x4f1, EOL); // address of the argv array passed to main()
	// misc FPU required flags
	uint16_t *fpu_need1167 = get_addr(ep, ABS, 0x509, EOL);
	uint32_t *fpu_need1167_str1 = get_addr(ep, ABS, 0x512, 0x520, EOL);
	uint32_t *fpu_need1167_str2 = get_addr(ep, ABS, 0x518, EOL);
	uint16_t *fpu_needemc87 = get_addr(ep, ABS, 0x532, EOL);
	uint32_t *fpu_needemc87_str1 = get_addr(ep, ABS, 0x53b, 0x549, EOL);
	uint32_t *fpu_needemc87_str2 = get_addr(ep, ABS, 0x541, EOL);
	uint16_t *fpu_need8087 = get_addr(ep, ABS, 0x55b, EOL);
	uint32_t *fpu_need8087_str1 = get_addr(ep, ABS, 0x564, 0x572, 0x5a0, EOL);
	uint32_t *fpu_need8087_str2 = get_addr(ep, ABS, 0x56a, EOL);
	uint16_t *fpu_need80387 = get_addr(ep, ABS, 0x58b, EOL);
	uint32_t *fpu_need80387_str1 = get_addr(ep, ABS, 0x596, EOL);
	uint32_t *fpu_need80387_str2 = get_addr(ep, ABS, 0x5af, EOL);
	// internal consistency conditions. fpu_tmp ist just the second byte of fpu_temp, and some fields are within the
	// entry point region
	if (fpu_tmp != &((uint8_t *) fpu_temp)[1])
		errx(131, "illegal value for FPU temp location: %p / %p", fpu_temp, fpu_tmp);
	if (fpu_init_cw_emc != (uint16_t *) &ep[0x5ba])
		errx(131, "illegal value for FPU EMC87 control word location: %p", fpu_init_cw_emc);
	if (fpu_init_cw != (uint16_t *) &ep[0x5b8])
		errx(131, "illegal value for FPU 8087 control word location: %p", fpu_init_cw);
	if (fpu_need80387_str1 != (uint32_t *) &ep[0x5af])
		errx(131, "illegal value for FPU 80387 string location: %p", fpu_need80387_str1);
	if (fpu_need80387_str2 != (uint32_t *) &ep[0x5a9])
		errx(131, "illegal value for FPU 80387 string location: %p", fpu_need80387_str2);
	if (*initfunc_retn != 0xc3)
		errx(131, "initfunc_retn doesn't point to a RET instruction");

	*env = 2; // pretend we're Phar Lap
	*stack_margin_big = 0x200 + *start_of_stack;
	*stack_margin_small = 0x100 + *start_of_stack;
	*_base = loadlimit;
	*_top = esp;
	*_heaphi = heaplimit;
	*cur_pages = heapsize / (PAGEMASK + 1);

	// build environment block
	// note MACHINE=IBMPC is crucial. otherwise the libc tries to read the machine type byte from BIOS using a physical
	// memory read. physical memory reads set the magic descriptor DS=0x34, and that in turn obviously fails on Linux.
	int envlen = 15;
	for (char **envvar = envv; *envvar; envvar++)
		envlen += strlen(*envvar) + 1;
	uint8_t *envblock = malloc(envlen);
	memcpy(envblock, "MACHINE=IBMPC", 14);
	uint8_t *envpos = &envblock[14];
	for (char **envvar = envv; *envvar; envvar++) {
		for (char *ch = *envvar; *ch; ch++)
			*envpos++ = *ch;
		*envpos++ = 0;
	}
	*envpos++ = 0; // terminated by empty string (or equivalently, double null byte)
	int argc = 0;
	for (char **arg = argv; *arg; arg++)
		argc++;

	*envp = (uint32_t) envblock;
	*prognamep = (uint32_t) argv[0];
	*argvp = (uint32_t) &argv[0];
	*_osmajor = 0x6606; // 6.66
	*fpu_mwemc87 = *fpu_1167 = 0;
	*fpu_mw387 = *fpu_mw8087 = 1;
	*argp = 0xaaaaaaaa;
	*_psp = 0xaaaaaaaa;
	*arglen = -1;

	uint16_t ds;
	asm("mov %%ds, %0" : "=a" (ds) :);
	*argp_seg = *_psp_seg = *envp_seg = *prognamep_seg = ds;

#define PTR(name) \
	if (dostrace) fprintf(dostrace, "%20s @%08x\n", #name, (uint32_t) name)
#define VAL32(name) \
	if (dostrace) fprintf(dostrace, "%20s @%08x = %08x\n", #name, (uint32_t) name, *(uint32_t *) name)
#define VAL16(name) \
	if (dostrace) fprintf(dostrace, "%20s @%08x = %04x\n", #name, (uint32_t) name, *(uint16_t *) name)
#define VAL8(name) \
	if (dostrace) fprintf(dostrace, "%20s @%08x = %02x\n", #name, (uint32_t) name, *(uint8_t *) name)

	PTR(__main); PTR(finitfunc_unknown); VAL8(initfunc_retn); PTR(initfunc_unknown); PTR(set_up_args);
	VAL8(env); VAL32(_gda); VAL8(lahey_format_file);

	VAL32(stack_margin_big); VAL32(stack_margin_small); VAL32(start_of_stack); VAL32(_base); VAL32(_top);
	VAL32(_heaphi); VAL32(cur_pages); VAL32(_mwinitfrstcall); VAL32(_mwinitlastcall);

	VAL16(fpu_1167); VAL16(fpu_temp); VAL16(fpu_init_cw_emc); VAL16(fpu_init_cw); VAL8(fpu_mw387);
	VAL8(fpu_mwemc87); VAL16(fpu_mw8087);

	VAL32(argp); VAL16(argp_seg); VAL32(_psp); VAL16(_psp_seg); VAL32(arglen); VAL32(envp); VAL16(envp_seg);
	VAL16(_osmajor); VAL32(prognamep); VAL16(prognamep_seg); VAL32(argvp);

	VAL16(fpu_need1167); PTR(fpu_need1167_str1); PTR(fpu_need1167_str2);
	VAL16(fpu_needemc87); PTR(fpu_needemc87_str1); PTR(fpu_needemc87_str2);
	VAL16(fpu_need8087); PTR(fpu_need8087_str1); PTR(fpu_need8087_str2);
	VAL16(fpu_need80387); PTR(fpu_need80387_str1); PTR(fpu_need80387_str2);

	// these init functions technically run with the wrong stack. they don't seem to care.
	if (dostrace) fprintf(dostrace, "call initfunc @%p\n", initfunc_unknown);
	((void (*)(void)) initfunc_unknown)();
	for (void **initfunc = _mwinitfrstcall; initfunc < _mwinitlastcall; initfunc++) {
		if (dostrace) fprintf(dostrace, "call initfunc @%p\n", *initfunc);
		uint16_t realgs;
		asm("mov %%gs, %0" : "=a" (realgs));
		((void (*)(void)) *initfunc)();
		asm volatile("mov %0, %%gs" :: "a" (realgs));
	}

	uint32_t *sp = (void *) esp;
	*--sp = (uint32_t) argv;
	*--sp = argc;
	*--sp = (uint32_t) do_exit;
	ucontext_t ctx;
	memset(&ctx, 0, sizeof(ctx));
	if (getcontext(&ctx))
		err(131, "failed to read CPU registers");
	greg_t *regs = ctx.uc_mcontext.gregs;
	regs[REG_EIP] = (uint32_t) __main;
	regs[REG_ESP] = (uint32_t) sp;
	regs[REG_EBP] = (uint32_t) sp - 4;
	regs[REG_EAX] = 0;
	regs[REG_EBX] = 0;
	regs[REG_ECX] = 0;
	regs[REG_EDX] = 0;
	regs[REG_ESI] = 0;
	regs[REG_EDI] = 0;
	ctx.uc_stack.ss_flags = 0;
	ctx.uc_stack.ss_size = stacksize;
	ctx.uc_stack.ss_sp = sp;
	if (dostrace)
		fprintf(dostrace, "call __main @%08x, ESP=%08x EBP=%08x\n", regs[REG_EIP], regs[REG_ESP], regs[REG_EBP]);
	setcontext(&ctx);
	errx(1, "failed to call __main\n");
};
