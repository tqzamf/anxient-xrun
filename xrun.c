#define _GNU_SOURCE
#include <ucontext.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/time.h>
#include <err.h>

#include "xrun.h"
#include "binpatch.h"

extern char **environ;

// type of DOS extender: SG_ENV = 1 (SoftGuard), PL_ENV = 2 (Phar Lap), AI_ENV = 3 (some unknown other vendor).
// even though the binaries themselves have Phar Lap compiled in, the MetaWare libc is compiled to detect and support
// all three
static uint8_t *dos_extender_type;

// init function that sets up custom interrupt handlers for Print Screen, Ctrl-Break, Ctrl-C – and then also disables
// Ctrl-Break checking entirely, to be extra sure. there are two versions of that function, only one of which is used,
// for whatever reason. we just disable them both; there's no interrupts on Linux.
// there is a corresponding restore_break function, but that function doesn't do anything if the "breaks disabled" flag
// isn't set – which it isn't, if we skip the function that would set it.
static uint32_t *break_disabled;
static bin_patch disable_break1 = {
	"disable_break1", 24, 0x8c4d0551,
	0, 7, "\x55\x52\x51\x53\x06\x83\x3d",
	{ BP_RET },
	{ { "break_disabled", &break_disabled, -1, { 0x007, -1 }}, BP_EOL }
};
static bin_patch disable_break2 = {
	"disable_break2", 24, 0x7fe156cb,
	0, 7, "\x55\x53\x51\x52\x06\x83\x3d",
	{ BP_RET },
	{ { "break_disabled", &break_disabled, -1, { 0x007, -1 }}, BP_EOL }
};
// an alternative version of disable_break that also disables the DOS critical error handler, interrupt 0x24. not sure
// whether that's a good idea under DOS, but it's certainly pointless on Linux.
// this is a huge function that does different things depending on which DOS extender it's running on. its only data
// dependency, however, is dos_extender_type; all other offsets are relative.
static bin_patch disable_break3 = {
	"disable_break3", 102, 0x290f1914,
	46, 9, "\x8a\x4d\x08\x66\xb8\x06\x25\xcd\x21",
	{ BP_RET },
	{ { "dos_extender_type", (void *) &dos_extender_type, -1, { 0x00a, 0x017, -1 }}, BP_EOL }
};

// the MetaWare High C runtime initialization code. huge function that initializes several variables, but also
// tries to detect and initialize 3 types of FPUs.
// since any modern x87 has an 80387-style FPU, the FPU detection is pointless. and it's easier to initialize the
// variables directly from C rather than trying to simulate an environment so the initialization code computes the
// right values.
// then the whole thing is just stubbed out. we directly call __main(), which then calls main().
static void *__main; // offset of __main(), which simply calls main()
static uint8_t *initfunc_retn; // address of a pointless init function that is always a single RET
static void *initfunc_unknown; // address of an init function of unknown purpose
static uint32_t *stack_margin_big;
static uint32_t *stack_margin_small;
static uint32_t *start_of_stack;
static uint32_t *_base; // bottom of stack, top of code / data image
static uint32_t *_top; // top of stack, bottom of heap
static uint32_t *_heaphi; // top of heap
static uint32_t *cur_pages; // number of currently allocated heap pages (size of heap)
static void **_mwinitfrstcall; // start of init-function call table
static void **_mwinitlastcall; // end of init-function call table
// FPU detection stuff
static uint8_t *fpu_1167; // ancient Weitek 1167 FPU presence flag
static uint8_t *fpu_mw387; // 80387 FPU presence flag
static uint8_t *fpu_mwemc87; // EMC87 FPU presence flag
static uint16_t *fpu_mw8087; // 8087 FPU presence flag
// standard C environment: arguments, program name, enviornment
static uint32_t *argp; // argument string (ie. un-split)
static uint16_t *argp_seg; // segment address part of argp
static uint32_t *_psp; // address of DOS PSP
static uint16_t *_psp_seg; // segment address part of _psp
static uint32_t *arglen; // length of argp string
static char **envp; // address of environment area
static uint16_t *envp_seg; // segment address part of envp
static char **prognamep; // address of program name
static uint16_t *prognamep_seg; // segment address part of prognamep
static char ***argvp; // address of the argv array passed to main()
static uint16_t *_osmajor; // DOS major + minor version number
static bin_patch libc_init = {
	"libc_init", 1466, 0xd13b264e,
	17, 71, "\xc3High C Run-time Library Copyright (C) 1983-1990 MetaWare Incorporated.",
	{ BP_PAD_INT3(17) },
	{
		{ "__main", (void *) &__main, 4, { 0x003, -1 }},
		{ "finitfunc_unknown", NULL, 4, { 0x009, -1 }},
		{ "initfunc_retn", (void *) &initfunc_retn, 4, { 0x4e6, -1 }},
		{ "initfunc_unknown", (void *) &initfunc_unknown, 4, { 0x4eb, -1 }},
		{ "set_up_args", NULL, 4, { 0x4f8, -1 }},
		{ "dos_extender_type", (void *) &dos_extender_type, -1,
				{ 0x06a, 0x079, 0x0ad, 0x1dc, 0x2ac, 0x369, 0x38a, 0x3ac, 0x450, 0x459, -1 }},
		{ "_gda", NULL, -1, { 0x071, -1 }},
		{ "lahey_format_file", NULL, -1, { 0x1f2, 0x2f5, 0x3b8, -1 }},
		{ "stack_margin_big", &stack_margin_big, -1, { 0x085, 0x099, -1 }},
		{ "stack_margin_small", &stack_margin_small, -1, { 0x08f, 0x0a3, -1 }},
		{ "start_of_stack", &start_of_stack, -1, { 0x09d, 0x0a7, -1 }},
		{ "_base", &_base, -1, { 0x0b6, 0x0de, -1 }},
		{ "_top", &_top, -1, { 0x0c3, 0x0e6, 0x391, -1 }},
		{ "_heaphi", &_heaphi, -1, { 0x0cd, 0x0f3, 0x3ce, -1 }},
		{ "cur_pages", &cur_pages, -1, { 0x3a1, -1 }},
		{ "_mwinitfrstcall", (void *) &_mwinitfrstcall, -1, { 0x4be, -1 }},
		{ "_mwinitlastcall", (void *) &_mwinitlastcall, -1, { 0x4c3, -1 }},
		{ "fpu_1167", (void *) &fpu_1167, -1, { 0x10f, 0x20c, 0x257, 0x4ff, -1 }},
		{ "fpu_mw387", (void *) &fpu_mw387, -1, { 0x170, 0x1a0, 0x581, -1 }},
		{ "fpu_mwemc87", (void *) &fpu_mwemc87, -1, { 0x17f, 0x1a7, 0x528, -1 }},
		{ "fpu_mw8087", (void *) &fpu_mw8087, -1, { 0x186, 0x3f9, 0x403, 0x551, -1 }},
		{ "fpu_temp", NULL, -1, { 0x119, 0x125, 0x130, 0x139, 0x143, 0x14e, 0x161, -1 }},
		{ "fpu_tmp", NULL, -1, { 0x167, -1 }},
		{ "fpu_init_cw_emc", NULL, -1, { 0x15a, -1 }},
		{ "fpu_init_cw", NULL, -1, { 0x179, -1 }},
		{ "argp", &argp, -1, { 0x2da, 0x34a, -1 }},
		{ "argp_seg", (void *) &argp_seg, -1, { 0x2b8, -1 }},
		{ "_psp", &_psp, -1, { 0x2be, -1 }},
		{ "_psp_seg", (void *) &_psp_seg, -1, { 0x2c4, 0x31a, 0x320, -1 }},
		{ "arglen", &arglen, -1, { 0x2d4, 0x334, 0x4a7, -1 }},
		{ "envp", (void *) &envp, -1, { 0x2e7, 0x3d4, -1 }},
		{ "envp_seg", (void *) &envp_seg, -1, { 0x2ed, 0x327, 0x49d, -1 }},
		{ "_osmajor", (void *) &_osmajor, -1, { 0x363, 0x447, -1 }},
		{ "prognamep", (void *) &prognamep, -1, { 0x462, 0x473, 0x490, -1 }},
		{ "prognamep_seg", (void *) &prognamep_seg, -1, { 0x468, -1 }},
		{ "argvp", (void *) &argvp, -1, { 0x4b7, 0x4f1, -1 }},
		{ "fpu_need1167",NULL, -1, { 0x509, -1 }},
		{ "fpu_need1167_str1", NULL, -1, { 0x512, 0x520, -1 }},
		{ "fpu_need1167_str2", NULL, -1, { 0x518, -1 }},
		{ "fpu_needemc87", NULL, -1, { 0x532, -1 }},
		{ "fpu_needemc87_str1", NULL, -1, { 0x53b, 0x549, -1 }},
		{ "fpu_needemc87_str2", NULL, -1, { 0x541, -1 }},
		{ "fpu_need8087", NULL, -1, { 0x55b, -1 }},
		{ "fpu_need8087_str1", NULL, -1, { 0x564, 0x572, 0x5a0, -1 }},
		{ "fpu_need8087_str2", NULL, -1, { 0x56a, -1 }},
		{ "fpu_need80387", NULL, -1, { 0x58b, -1 }},
		{ "fpu_need80387_str1", NULL, -1, { 0x596, -1 }},
		{ "fpu_need80387_str2", NULL, -1, { 0x5af, -1 }},
		BP_EOL
	}
};

// function used to set the global errno inside MetaWare libc. takes the DOS error number in EAX (not on the stack!),
// maps it, sets errno and then returns the mapped value.
static uint32_t *set_errno;
uint32_t dos_set_errno(uint32_t dos_error_code) {
	// this way of calling it only works if it doesn't mess with GS. however, it's an extremely simply function, doesn't
	// call anything else, and in fact doesn't use GS at all.
	uint32_t eax_ret;
	asm("call *%%edx" : "=a" (eax_ret) : "d" (set_errno), "a" (dos_error_code));
	return eax_ret;
}

// Linux uses GS as the Global Segment, simulating the constant Global Pointer register of other architectures.
// the MetaWare compiler uses GS as the Gereal-purpose Segment and liberally reloads it using LGS when handling 48-bit
// segment + offset addresses.
// the upshot is that before calling Linux-side code, we need to save GS and reload Linux's global segment selector. and
// then restore GS before returning to the XACT side, because the MetaWare compiler probably assumes that the value is
// preserved across function calls.
static uint32_t linux_gs;
#define ENTER_GS BP_ENTER, BP_PUSH_GS, BP_MOV_GS(linux_gs)
#define LEAVE_GS BP_POP_GS, BP_LEAVE
#define LEAVE_GS_POP(bytes) BP_POP_GS, BP_LEAVE_POP(bytes)

// the generic DOS call trampoline. used by 99% of all DOS calls. it's a large function because it needs to set up all
// the registers from memory for the actual INT 21 call. because we don't need any of that, there is plenty of room to
// inline not just GS switching, but also the actual DOS API decode...
x86reg *eax, *ebx, *ecx, *edx, *esi, *edi;
uint32_t *eflags;
static bin_patch call_dos = {
	"call_dos", 126, 0x85e9a644,
	55, 8, "\x1f\xf8\xcd\x21\x5d\x1e\x8e\xdd",
	{ ENTER_GS, BP_CALL_VIA_EAX(dos_call), LEAVE_GS },
	{
		{ "eax_ptr", (uint32_t **) &eax, -1, { 0x007, 0x04d, -1 }},
		{ "ebx_ptr", (uint32_t **) &ebx, -1, { 0x00d, 0x053, -1 }},
		{ "ecx_ptr", (uint32_t **) &ecx, -1, { 0x013, 0x059, -1 }},
		{ "edx_ptr", (uint32_t **) &edx, -1, { 0x019, 0x05f, -1 }},
		{ "esi_ptr", (uint32_t **) &esi, -1, { 0x01f, 0x065, -1 }},
		{ "edi_ptr", (uint32_t **) &edi, -1, { 0x025, 0x06b, -1 }},
		{ "es_ptr", NULL, -1, { 0x02b, 0x048, -1 }},
		{ "ds_ptr", NULL, -1, { 0x033, 0x041, -1 }},
		{ "eflags_ptr", &eflags, -1, { 0x074, -1 }},
		BP_EOL
	}
};

// the call to AH=4E FIND FIRST, always preceeded by AH=1A SET DTA, which is probably why it gets its own separate
// helper function.
// this is calls directly into Linux-side C, so we just replace the entire function with something that handles GS
// as well. (the MetaWare compiler uses GS as the General-purpose Segment, while Linux uses it to emulate a Global
// Pointer.)
static bin_patch find_first = {
	"find_first", 46, 0xe734e768,
	19, 10, "\xb4\x4e\xcd\x21\x0f\x83\x0a\x00\x00\x00",
	{
		ENTER_GS,
		BP_PUSH_ARG(2), // struct dta *dta
		BP_PUSH_ARG(0), // char *filename
		BP_CALL_VIA_EAX(dos_find_first), // call to cdecl-style function
		BP_ADD_ESP(8), // clean up stack, cdecl is caller cleanup
		LEAVE_GS
	},
	{ { "set_errno", &set_errno, 4, { 0x01e, -1 }}, BP_EOL }
};

// a call to AX=4300 GET FILE ATTRIBUTES. sometimes used instead of FIND FIRST to determine whether a file exists.
// looks like an access() call emulation; probably find_first is only used for stat().
static bin_patch file_check_access = {
	"file_check_access", 69, 0x87929cb6,
	9, 13, "\xb8\x00\x43\x00\x00\xcd\x21\x0f\x82\x1c\x00\x00\x00",
	{
		ENTER_GS,
		BP_PUSH_ARG(1), // uint32_t mode
		BP_PUSH_ARG(0), // char *filename
		BP_CALL_VIA_EAX(dos_access), // call to cdecl-style function
		BP_ADD_ESP(8), // clean up stack, cdecl is caller cleanup
		LEAVE_GS
	},
	{ { "set_errno", &set_errno, 4, { 0x038, -1 }}, BP_EOL }
};

// a call to AH=19 GET CURRENT DRIVE plus AH=47 GET WORKING DIRECTORY. basically, unix getcwd, so we might as well
// implement it as such.
static bin_patch get_cwd = {
	"get_cwd", 142, 0xd068f063,
	8, 6, "\xb4\x19\xcd\x21\x04\x41",
	{
		ENTER_GS,
		BP_PUSH_ARG(1), // uint32_t size
		BP_PUSH_ARG(0), // char *buffer
		BP_CALL_VIA_EAX(dos_getcwd), // call to cdecl-style function
		BP_ADD_ESP(8), // clean up stack, cdecl is caller cleanup
		LEAVE_GS
	}, {
		{ "strlen", NULL, 4, { 0x029, -1 }},
		{ "strcpy", NULL, 4, { 0x048, 0x075, -1 }},
		{ "__unknown", NULL, 4, { 0x063, -1 }},
		{ "set_errno", &set_errno, 4, { 0x082, -1 }},
		BP_EOL
	}
};

// a call to AH=19 GET CURRENT DRIVE, whose result then seems to be mostly ignored. XACT certainly doesn't mess with
// drives very much; in fact it works perfectly fine if passed UNIX-style paths with forward slashes and no drive...
// so we simply pretend that everything is on A: – floppies ftw!
// this is an inline patch as well, because the function returns the drive in a pointer variable
static bin_patch get_current_drive = {
	"get_current_drive", 11, 0x4b20236c,
	0, 11, "\xb4\x19\xcd\x21\x25\xff\x00\x00\x00\xfe\xc0",
	{ BP_MOV_EAX_IMM(1), BP_PAD_TO(11) },
	{ BP_EOL }
};

// a call to AX=4400 GET DEVICE INFORMATION, used by the paginator functionality present in all binaries when writing to
// the console device.
// we pretend that everything is an ordinary file (type 0x00): for the smart paginator, that keeps it from trying to
// talk to the keyboard controller. for the simpler paginator, it avoids an annyoing "--more" prompt every 25 lines.
static bin_patch get_device_info = {
	"get_device_info", 36, 0xadca8f6e,
	10, 7, "\xb8\x00\x44\x00\x00\xcd\x21",
	{ BP_MOV_EAX_IMM(0), BP_RET },
	{ BP_EOL }
};

// some binaries contain a smart paginator talks directly to the keyboard controller. it can be defeated by
// pretending that STDOUT isn't connected to the console devices (and disabling pagination is desirable even for the
// simpler paginators). but it still tries to detect the keyboard type by reading from physical memory, so we have
// to patch out that code.
// this patch is in the middle of a function, not at its start, so it has to be careful not to mess up the stack.
static bin_patch detect_keyboard = {
	"detect_keyboard", 28, 0x91e2d885,
	6, 8, "\x68\x96\x04\x00\x00\x6a\x34\xe8",
	{
		BP_SUB_ESP(0x10), // compensate for an "add esp, 0x10" later on in the function
		BP_MOV_EAX_IMM(1), // set the flag that indicates an extended 101/102-key keyboard
		BP_PAD_TO(27) // pad remainder of replaced bytes
		// note the CRC checks the first byte of the next instruction too, but we must not overwrite that byte!
	},
	{ { "read_physical_memory", NULL, 4, { 0x00e, -1 }}, BP_EOL }
};

// the generic BIOS call trampoline. generally not used, except by programs trying to enter GUI mode. very similar to
// the DOS call trampoline, including saving/restoring registers, and to the same locations. unlike the DOS call
// trampoline, it self-modifies to set the interrupt vector number.
// graphics is somewhat pointless to emulate because it works perfectly in dosbox. this isn't limited to emulating the
// VGA BIOS; the XACT GUI also wants to talk to the BIOS keyboard interface and the mouse driver, and hijacks the system
// tick interrupt. the only case where the GUI could be scripted is for printing an LCA design to PostScript, but that
// also doesn't work that well on modern PostScript interpreters, and that same design can simply be viewed in editlca
// in dosbox...
// so instead we just show a message that GUI mode isn't supported.
static bin_patch call_bios = {
	"call_bios", 138, 0xe0e11daf,
	67, 8, "\x1f\xf8\xcd\x0d\x5d\x1e\x8e\xdd",
	{
		ENTER_GS,
		BP_PUSH_ARG(0), // interrupt number
		BP_CALL_VIA_EAX(dos_call_bios), // call to cdecl-style function
		BP_ADD_ESP(4), // clean up stack, cdecl is caller cleanup
		LEAVE_GS_POP(4) // that function itself is callee-cleanup, though!
	}, {
		{ "intnum_loc", NULL, -1, { 0x00a, -1 }}, // self-modified location, second byte of INT 0x?? instruction
		{ "eax_ptr", (uint32_t **) &eax, -1, { 0x013, 0x059, -1 }},
		{ "ebx_ptr", (uint32_t **) &ebx, -1, { 0x019, 0x05f, -1 }},
		{ "ecx_ptr", (uint32_t **) &ecx, -1, { 0x01f, 0x065, -1 }},
		{ "edx_ptr", (uint32_t **) &edx, -1, { 0x025, 0x06b, -1 }},
		{ "esi_ptr", (uint32_t **) &esi, -1, { 0x02b, 0x071, -1 }},
		{ "edi_ptr", (uint32_t **) &edi, -1, { 0x031, 0x077, -1 }},
		{ "es_ptr", NULL, -1, { 0x037, 0x054, -1 }},
		{ "ds_ptr", NULL, -1, { 0x03f, 0x04d, -1 }},
		{ "eflags_ptr", &eflags, -1, { 0x080, -1 }},
		BP_EOL
	}
};

// the (pretty complex) routine that emits a beep from the PC speaker, by direct IO port access. this beep isn't
// terribly useful, and in xrun actually crashes the program on (rather minor) error conditions. so instead of emulating
// the beep by sending 0x0a (BEL) to the terminal, we simply stub out the entire routine.
static bin_patch pcspeaker_beep = {
	"pcspeaker_beep", 179, 0x0a7030e9,
	43, 8, "\x97\x8b\xc6\x0b\xc7\x50\x6a\x61",
	{ BP_RET },
	{
		{ "beep_enable", NULL, -1, { 0x010, -1 }},
		{ "get_machine_type", NULL, 4, { 0x01b, -1 }},
		{ "inb_helper", NULL, 4, { 0x027, -1 }},
		{ "outb_helper", NULL, 4, { 0x034, 0x089, 0x0a8, -1 }},
		{ "read_bios_ticks", NULL, 4, { 0x04a, 0x066, -1 }},
		BP_EOL
	}
};

// large block of self-modifying code that eventually talks to the parallel port ­– using direct in/out instructions.
// doesn't seem to affect the rest of the program, so it can just be skipped entirely.
static bin_patch parport_access = {
	"parport_access", 19, 0xdeacc472,
	9, 8, "\x8b\x75\x14\xe8\x0b\xfe\xff\xff",
	{ BP_MOV_EAX_IMM(1), BP_RET }, // makebits needs a return value >0
	{{ NULL }}
};

// xnfmerge uses AH=62 GET PSP ADDRESS as a (very bad) RNG. we substitute getpsp_badrng_seed, the low few bits of
// tv_usec, which is probably a much more random value.
static uint32_t getpsp_badrng_seed;
static bin_patch getpsp_badrng = {
	"getpsp_badrng", 10, 0x9deb95cc,
	0, 10, "\x53\xb4\x62\xcd\x21\x0f\xb7\xc3\x5b\xc3",
	{ BP_MOV_EAX_VALUEOF(getpsp_badrng_seed), BP_RET },
	{{ NULL }}
};

static void callinit(void *initfunc) {
	if (dostrace)
		fprintf(dostrace, "call initfunc @%p\n", initfunc);
	((void (*)(void)) initfunc)();
	asm volatile("mov %0, %%gs" :: "a" (linux_gs));
}

static char *exists(char *dir, char *basename, char *ext) {
	char *progname = malloc(strlen(dir) + strlen(basename) + strlen(ext) + 2);
	strcpy(progname, dir);
	if (*progname && progname[strlen(progname) - 1] != '/')
		strcat(progname, "/");
	strcat(progname, basename);
	strcat(progname, ext);
	if (!access(progname, F_OK))
		return progname;
	free(progname);
	return NULL;
}

int main(int argc, char **argv) {
	char *xactdir = getenv("XACT");
	if (argc < 2 || !xactdir)
		errx(255, "usage: XACT=/path/to/xactstep %s tool[.exe] [options]", argv[0]);

	// find the binary to run
	char *progname = exists("", argv[1], "");
	if (!progname)
		progname = exists(xactdir, argv[1], "");
	if (!progname)
		progname = exists("", argv[1], ".exe");
	if (!progname)
		progname = exists(xactdir, argv[1], ".exe");
	if (!progname)
		errx(255, "cannot find %s or %s.exe here or in %s", argv[1], argv[1], xactdir);
	char *basename = rindex(progname, '/');
	argv[1] = basename ? basename + 1 : progname;

	// debug mode: enable SIGSEGV-based emulation of DOS calls, and also trace all DOS API calls
	char *tracefile = getenv("XRUN_TRACE");
	if (tracefile)
		dosemu_init(tracefile);

	// load the .EXP (32-bit) part of the EXE file into memory. use 16MB heap because we cannot enlarge it heap later
	// on. 16MB should be plenty given the age of XACTstep. in any case, this is only uncommitted address space at this
	// point, so enlarging it wouldn't use any actual memory.
	uint32_t eip, esp, stacksize, loadbase, loadlimit, heaplimit, heapsize = 16 * 1024 * 1024;
	load_exe(progname, heapsize, &eip, &esp, &stacksize, &loadbase, &loadlimit, &heaplimit);

	// patch out all the DOS-isms
	asm("mov %%gs, %0" : "=a" (linux_gs) :);
	binpatch((void *) loadbase, loadlimit - loadbase, &disable_break1);
	binpatch((void *) loadbase, loadlimit - loadbase, &disable_break2);
	binpatch((void *) loadbase, loadlimit - loadbase, &disable_break3);
	if (!binpatch((void *) loadbase, loadlimit - loadbase, &libc_init))
		errx(255, "failed to detect libc init code!");
	binpatch((void *) loadbase, loadlimit - loadbase, &call_dos);
	binpatch((void *) loadbase, loadlimit - loadbase, &find_first);
	binpatch((void *) loadbase, loadlimit - loadbase, &file_check_access);
	binpatch((void *) loadbase, loadlimit - loadbase, &get_cwd);
	binpatch((void *) loadbase, loadlimit - loadbase, &get_current_drive);
	binpatch((void *) loadbase, loadlimit - loadbase, &get_device_info);
	binpatch((void *) loadbase, loadlimit - loadbase, &detect_keyboard);
	binpatch((void *) loadbase, loadlimit - loadbase, &call_bios);
	binpatch((void *) loadbase, loadlimit - loadbase, &pcspeaker_beep);
	char *ppapatch = memmem((void *) loadbase, loadlimit - loadbase, "\xb8\x01\x00\x00\x00\xc3\x8b\x7d\x08", 9);
	if (!ppapatch)
		binpatch((void *) loadbase, loadlimit - loadbase, &parport_access);
	else if (dostrace)
		fprintf(dostrace, "skipping patch parport_access: already applied at %p\n", ppapatch);
	struct timeval tv;
	gettimeofday(&tv, NULL);
	getpsp_badrng_seed = tv.tv_usec;
	binpatch((void *) loadbase, loadlimit - loadbase, &getpsp_badrng);

	// build environment block
	// note MACHINE=IBMPC is crucial. otherwise the libc tries to read the machine type byte from BIOS using a physical
	// memory read. physical memory reads set the magic descriptor DS=0x34, and that in turn obviously fails on Linux.
	// COMSPEC is read, and then not used, by apr.exe. it may be an attempt at entropy generation, but it's a very bad
	// one at that because the value is basically constant under DOS. the address might be less constant, but it should
	// be mostly deterministic, too. (ironically, the address *is* somewhat random, and actually quite unpredictable,
	// on Linux because of ASLR... but in any case, it should be as random as can be expected under DOS.)
	// and yes, we just pass the entire shebang... BASH option, PATH, XAUTHORITY... XACT is at its heart a UNIX
	// toolchain and just simply doesn't care. and while it translates / to \ in most cases, it doesn't even notice that
	// it's messing with a UNIX-style path for $XACT here ;)
	int envlen = 32;
	for (char **envvar = environ; *envvar; envvar++)
		envlen += strlen(*envvar) + 1;
	char *envblock = malloc(envlen);
	memcpy(envblock, "MACHINE=IBMPC\0COMSPEC=A:\\bin\\sh", 32);
	char *envpos = &envblock[32];
	for (char **envvar = environ; *envvar; envvar++) {
		for (char *ch = *envvar; *ch; ch++)
			*envpos++ = *ch;
		*envpos++ = 0;
	}
	*envpos++ = 0; // terminated by empty string (or equivalently, double null byte)

	// set up argv etc, basically simulating most of what the libc init function would have done had we run in
	*envp = envblock;
	*prognamep = argv[1];
	*argvp = &argv[1];
	*fpu_mwemc87 = *fpu_1167 = 0;
	*fpu_mw387 = *fpu_mw8087 = 1;
	// dummy values that will show up if used:
	*_osmajor = 0x6606; // 6.66
	*argp = 0xa5000000;
	*_psp = 0xa5000000;
	*arglen = -1;

	// initialize the heap addresses
	*dos_extender_type = 2; // pretend we're Phar Lap
	*stack_margin_big = 0x200 + *start_of_stack;
	*stack_margin_small = 0x100 + *start_of_stack;
	*_base = loadlimit;
	*_top = esp;
	*_heaphi = heaplimit;
	*cur_pages = heapsize / (PAGEMASK + 1);
	// flat addressing, except that it isn't: Linux very much does use different descriptors for CS, DS/ES/SS and GS!
	uint16_t linux_ds;
	asm("mov %%ds, %0" : "=a" (linux_ds) :);
	asm("mov %0, %%fs" :: "a" (linux_ds));
	*argp_seg = *_psp_seg = *envp_seg = *prognamep_seg = linux_ds;

	// call initialization functions. technically on the wrong stack, but they don't seem to care.
	callinit(initfunc_retn);
	callinit(initfunc_unknown);
	for (void **initfunc = _mwinitfrstcall; initfunc < _mwinitlastcall; initfunc++)
		callinit(*initfunc);

	// call the main program. this time on the correct stack, to guard against pointer arithmetic that relies on stack
	// being below heap.
	ucontext_t ctx;
	memset(&ctx, 0, sizeof(ctx));
	if (getcontext(&ctx))
		err(255, "failed to read current CPU context");
	ctx.uc_stack.ss_flags = 0;
	ctx.uc_stack.ss_size = stacksize;
	ctx.uc_stack.ss_sp = (void *) (esp - stacksize);
	ctx.uc_link = NULL;
	makecontext(&ctx, __main, 2, argc - 1, &argv[1]);
	if (dostrace)
		fprintf(dostrace, "call __main @%p, ESP=%08x\n", __main, esp);
	setcontext(&ctx);
	errx(255, "failed to call __main\n");
}
