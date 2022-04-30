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

extern char **environ;

static uint32_t getpsp_badrng_seed;
static patch_addr getpsp_badrng_patches[] = {
	{ "seed", 0x01, &getpsp_badrng_seed, NULL },
	{ NULL }
};
static uint32_t *break_disabled;
static detect_addr disable_break_addrs[] = {
	{ "break_disabled", &break_disabled, -1, { 0x007, -1 }},
	{ NULL }
};
// type of DOS extender: SG_ENV = 1 (SoftGuard), PL_ENV = 2 (Phar Lap), AI_ENV = 3 (unknown other vendor)
static uint8_t *dos_extender_type;
static detect_addr disable_break3_addrs[] = {
	{ "dos_extender_type", (void *) &dos_extender_type, -1, { 0x00a, 0x017, -1 }},
	{ NULL }
};
static detect_addr detect_keyboard_addrs[] = {
	{ "read_physical_memory", NULL, 0x012, { 0x00e, -1 }},
	{ NULL }
};

static uint32_t *set_errno;
static uint32_t linux_gs;
static detect_addr find_first_addrs[] = {
	{ "set_errno", &set_errno, 0x022, { 0x01e, -1 }},
	{ NULL }
};
static patch_addr find_first_patches[] = {
	{ "linux_gs", 0x07, &linux_gs, NULL },
	{ "dos_find_first", 0x12, &dos_find_first, NULL },
	{ "set_errno", 0x22, NULL, &set_errno },
	{ NULL }
};
static detect_addr file_get_access_addrs[] = {
	{ "set_errno", &set_errno, 0x03c, { 0x038, -1 }},
	{ NULL }
};
static patch_addr file_get_access_patches[] = {
	{ "linux_gs", 0x07, &linux_gs, NULL },
	{ "dos_access", 0x12, &dos_access, NULL },
	{ "set_errno", 0x22, NULL, &set_errno },
	{ NULL }
};

x86reg *eax, *ebx, *ecx, *edx, *esi, *edi;
uint32_t *eflags;
static detect_addr call_dos_addrs[] = {
	{ "eax_ptr", (uint32_t **) &eax, -1, { 0x007, 0x04d, -1 }},
	{ "ebx_ptr", (uint32_t **) &ebx, -1, { 0x00d, 0x053, -1 }},
	{ "ecx_ptr", (uint32_t **) &ecx, -1, { 0x013, 0x059, -1 }},
	{ "edx_ptr", (uint32_t **) &edx, -1, { 0x019, 0x05f, -1 }},
	{ "esi_ptr", (uint32_t **) &esi, -1, { 0x01f, 0x065, -1 }},
	{ "edi_ptr", (uint32_t **) &edi, -1, { 0x025, 0x06b, -1 }},
	{ "es_ptr", NULL, -1, { 0x02b, 0x048, -1 }},
	{ "ds_ptr", NULL, -1, { 0x033, 0x041, -1 }},
	{ "eflags_ptr", &eflags, -1, { 0x074, -1 }},
	{ NULL }
};
static patch_addr call_dos_patches[] = {
	{ "eax_ptr", 0x04, NULL, (uint32_t **) &eax },
	{ "dosapi", 0x0e, dosapi, NULL },
	{ "dos_unimpl", 0x17, &dos_unimpl, NULL },
	{ "linux_gs", 0x1f, &linux_gs, NULL },
	{ "eflags_ptr", 0x27, NULL, &eflags },
	{ NULL }
};

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
static detect_addr libc_init_addrs[] = {
	{ "__main", (void *) &__main, 0x007, { 0x003, -1 }},
	{ "finitfunc_unknown", NULL, 0x00d, { 0x009, -1 }},
	{ "initfunc_retn", (void *) &initfunc_retn, 0x4ea, { 0x4e6, -1 }},
	{ "initfunc_unknown", (void *) &initfunc_unknown, 0x4ef, { 0x4eb, -1 }},
	{ "set_up_args", NULL, 0x4fc, { 0x4f8, -1 }},
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
	{ NULL }
};
static bin_patch patches[] = {
	// large block of self-modifying code that eventually talks to the parallel port ­– using direct in/out instructions.
	// doesn't seem to affect the rest of the program, so it can just be skipped entirely.
	{ "parport_access", 0, 6,
			"\xb8\x01\x00\x00\x00" // mov eax, 1
			"\xc3",                // ret
			9, 8, "\x8b\x75\x14\xe8\x0b\xfe\xff\xff", 19, 0xdeacc472, NULL, NULL },
	// xnfmerge uses AH=62 GET PSP ADDRESS as a (very bad) RNG. we substitute getpsp_badrng_seed, the low few bits of
	// tv_usec, which is probably a much more random value.
	{ "getpsp_badrng", 0, 6,
			"\xa1...."             // mov eax, [getpsp_badrng_seed]
			"\xc3",                // ret
			0, 10, "\x53\xb4\x62\xcd\x21\x0f\xb7\xc3\x5b\xc3", 10, 0x9deb95cc, NULL, getpsp_badrng_patches },
	// init function that sets up interrupt handlers for Print Screen, Ctrl-Break, Ctrl-C – and then also disables
	// Ctrl-Break checking entirely, to be extra sure. there are two versions of that function, only one of which is
	// used, for whatever reason. we just disable them both; there's no interrupts on Linux.
	// there is a corresponding restore_break function, but that function doesn't do anything if the "breaks disabled"
	// flag isn't set – which it isn't, if we skip the function that would set it.
	{ "disable_break1", 0, 1,
			"\xc3",                // ret
			0, 7, "\x55\x52\x51\x53\x06\x83\x3d", 24, 0x8c4d0551, disable_break_addrs, NULL },
	{ "disable_break2", 0, 1,
			"\xc3",                // ret
			0, 7, "\x55\x53\x51\x52\x06\x83\x3d", 24, 0x7fe156cb, disable_break_addrs, NULL },
	// an alternative version of disable_break that also disables the DOS critical error handler, interrupt 0x24. not
	// sure whether that's a good idea under DOS, but it's certainly pointless on Linux.
	// this is a huge function that does different things depending on which DOS extender it's running on. its only data
	// dependency, however, is dos_extender_type; all other offsets are relative.
	{ "disable_break3", 0, 1,
			"\xc3",                // ret
			46, 9, "\x8a\x4d\x08\x66\xb8\x06\x25\xcd\x21", 102, 0x290f1914, disable_break3_addrs, NULL },
	// some binaries contain a smart paginator talks directly to the keyboard controller. it can be defeated by
	// pretending that STDOUT isn't connected to the console devices (and disabling pagination is desirable even for the
	// simpler paginators). but it still tries to detect the keyboard type by reading from physical memory, so we have
	// to patch out that code.
	// this patch is in the middle of a function, not at its start, so it has to be careful not to mess up the stack.
	{ "detect_keyboard", 0, 7,
			"\x83\xec\x10"         // sub esp, 0x10 ; compensate for corresponding add later on
			"\xb0\x01"             // mov al, 1
			"\xeb\x11",            // jmp short start + 0x18 ; skip unused bytes
			6, 8, "\x68\x96\x04\x00\x00\x6a\x34\xe8", 28, 0x91e2d885, detect_keyboard_addrs, NULL },
	// a call to AX=4400 GET DEVICE INFORMATION, used by the paginator. we pretend that everything is an ordinary file:
	// for the smart paginator, that keeps it from trying to talk to the keyboard controller. for the simpler paginator,
	// is still avoids an annyoing "--more" prompt every 25 lines.
	{ "get_device_info", 0, 3,
			"\x31\xc0"             // xor eax, eax
			"\xc3",                // ret
			10, 7, "\xb8\x00\x44\x00\x00\xcd\x21", 36, 0xadca8f6e, NULL, NULL },
	// a call to AH=19 GET CURRENT DRIVE, whose result then seems to be mostly ignored. XACT certainly doesn't mess with
	// drives very much; in fact it works perfectly fine if passed UNIX-style paths with forward slashes and no drive...
	// so we simply pretend that everything is on A: – floppies ftw!
	// this is an inline patch as well, because the function returns the drive in a pointer variable
	{ "get_current_drive", 0, 7,
			"\xb8\x01\x00\x00\x00" // mov eax, 1
			"\xeb\x04",            // jmp short start + 0x0b ; skip unused bytes
			0, 11, "\xb4\x19\xcd\x21\x25\xff\x00\x00\x00\xfe\xc0", 11, 0x4b20236c, NULL, NULL },
	// the call to AH=4E FIND FIRST, always preceeded by AH=1A SET DTA, which is probably why it gets its own separate
	// helper function.
	// this is calls directly into Linux-side C, so we just replace the entire function with something that handles GS
	// as well. (the MetaWare compiler uses GS as the General-purpose Segment, while Linux uses it to emulate a Global
	// Pointer.)
	{ "find_first", 1, 43,
			"\x55"                 // push ebp ; (standard stackframe building)
			"\x89\xe5"             // mov ebp, esp
			"\x0f\xa8"             // push gs ; switch GS to what Linux expects
			"\x8e\x2d...."         // mov gs, [dword linux_gs]
			"\xff\x75\x10"         // push dword [ebp+0x10] ; push second arg: dta
			"\xff\x75\x08"         // push dword [ebp+0x8] ; push first arg: filename
			"\xb8...."             // mov eax, dos_find_first ; call the function (must be declared cdecl)
			"\xff\xd0"             // call eax
			"\x83\xc4\x08"         // add esp, byte +0x8 ; cdecl is caller-cleanup
			"\x0f\xa9"             // pop gs ; restore GS, in case XACT wants to keep it across calls
			"\x85\xc0"             // test eax, eax ; skip set_errno if successful
			"\x74\x07"             // jz return
			"\xba...."             // mov edx, set_errno ; call set_errno, passing argument in eax
			"\xff\xd2"             // call edx
			"\x5d"                 // return: pop ebp
			"\xc3",                // ret
			19, 10, "\xb4\x4e\xcd\x21\x0f\x83\x0a\x00\x00\x00", 46, 0xe734e768, find_first_addrs, find_first_patches },
	// a call to AX=4300 GET FILE ATTRIBUTES. sometimes used instead of FIND FIRST to determine whether a file exists.
	// looks like an access() call emulation; probably find_first is only used for stat().
	{ "file_get_access", 0, 48,
			"\x55"                 // push ebp ; (standard stackframe building)
			"\x89\xe5"             // mov ebp, esp
			"\x0f\xa8"             // push gs ; switch GS to what Linux expects
			"\x8e\x2d...."         // mov gs, [dword linux_gs]
			"\xff\x75\x0c"         // push dword [ebp+0xc] ; push second arg: mode
			"\xff\x75\x08"         // push dword [ebp+0x8] ; push first arg: filename
			"\xb8...."             // mov eax, dos_access ; call the function (must be declared cdecl)
			"\xff\xd0"             // call eax
			"\x83\xc4\x08"         // add esp, byte +0x8 ; (caller cleanup)
			"\x0f\xa9"             // pop gs ; restore GS, in case XACT still needed that value
			"\x85\xc0"             // test eax, eax ; skip set_errno if successful
			"\x74\x0c"             // jz return
			"\xba...."             // mov edx, get_errno ; call set_errno, passing argument in eax
			"\xff\xd2"             // call edx
			"\xb8\xff\xff\xff\xff" // mov eax, -1 ; unlike find_first, we actually return -1 on error
			"\x5d"                 // return: pop ebp
			"\xc3",                // ret
			9, 13, "\xb8\x00\x43\x00\x00\xcd\x21\x0f\x82\x1c\x00\x00\x00",
			69, 0x87929cb6, file_get_access_addrs, file_get_access_patches },
	// the generic DOS call trampoline. used by 99% of all DOS calls. it's a large function because it needs to set up
	// all the registers from memory for the actual INT 21 call. because we don't need any of that, there is plenty of
	// room to inline not just GS switching, but also the actual DOS API decode...
	{ "call_dos", 1, 47,
			"\x55"                 // push ebp ; (standard stackframe building)
			"\x89\xe5"             // mov ebp, esp
			"\xa1...."             // mov eax, [eax_ptr] ; load EAX from the memory location that XACT passes it in
			"\x0f\xb6\xc4"         // movzx eax, ah ; extract AH
			"\x8b\x04\x85...."     // mov eax, [eax*4+dosapi] ; index into table of DOS APIs
			"\x85\xc0"             // test eax, eax ; if null pointer, replace with dos_unimplemented
			"\x75\x05"             // jnz $+5 ; (skip the mov)
			"\xb8...."             // mov eax, dos_unimplemented
			"\x0f\xa8"             // push gs ; switch GS to what Linux expects
			"\x8e\x2d...."         // mov gs, [dword linux_gs]
			"\xff\xd0"             // call eax
			"\x66\xa3...."         // mov [eflags_ptr], ax ; save eflags
			"\x0f\xa9"             // pop gs
			"\x5d"                 // pop ebp
			"\xc3",                // ret
			55, 8, "\x1f\xf8\xcd\x21\x5d\x1e\x8e\xdd", 126, 0x85e9a644, call_dos_addrs, call_dos_patches },
	// the MetaWare High C runtime initialization code. huge function that initializes several variables, but also
	// tries to detect and initialize 3 types of FPUs.
	// since any modern x87 has an 80387-style FPU, the FPU detection is pointless. and it's easier to initialize the
	// variables directly from C rather than trying to simulate an environment so the initialization code computes the
	// right values.
	// then the whole thing is just stubbed out. we directly call __main(), which then calls main().
	{ "libc_init", 1, 1, "\xcc", 18, 70, "High C Run-time Library Copyright (C) 1983-1990 MetaWare Incorporated.",
			1466, 0xd13b264e, libc_init_addrs, NULL },
	{ NULL }
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
		progname = exists("", argv[1], ".exe");
	if (!progname)
		progname = exists(xactdir, argv[1], "");
	if (!progname)
		progname = exists(xactdir, argv[1], ".exe");
	if (!progname)
		errx(255, "cannot find %s or %s.exe here or in %s", argv[1], argv[1], xactdir);
	//char *progname = argv[1];
	argv[1] = progname;

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
	struct timeval tv;
	gettimeofday(&tv, NULL);
	getpsp_badrng_seed = tv.tv_usec;
	binpatch((void *) loadbase, loadlimit - loadbase, patches);

	// build environment block
	// note MACHINE=IBMPC is crucial. otherwise the libc tries to read the machine type byte from BIOS using a physical
	// memory read. physical memory reads set the magic descriptor DS=0x34, and that in turn obviously fails on Linux.
	// and yes, we just pass the entire shebang... BASH option, PATH, XAUTHORITY... XACT is at its heart a UNIX
	// toolchain and just simply doesn't care. and while it translates / to \ in most cases, it doesn't even notice that
	// it's messing with a UNIX-style path for $XACT here ;)
	int envlen = 15;
	for (char **envvar = environ; *envvar; envvar++)
		envlen += strlen(*envvar) + 1;
	char *envblock = malloc(envlen);
	strcpy(envblock, "MACHINE=IBMPC");
	char *envpos = &envblock[14];
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
