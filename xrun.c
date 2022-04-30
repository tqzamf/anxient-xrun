#define _GNU_SOURCE
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/time.h>

#include "xrun.h"

extern char **environ;

static uint32_t getpsp_badrng_seed;
static patch_addr getpsp_badrng_patches[] = {
	{ "seed", 0x01, NULL, (uint32_t **) &getpsp_badrng_seed },
	{ NULL }
};
static uint32_t *break_disabled;
static detect_addr disable_break_addrs[] = {
	{ "break_disabled", &break_disabled, -1, { 0x007, -1 }},
	{ NULL }
};
static uint32_t *dos_extender_type;
static detect_addr disable_break3_addrs[] = {
	{ "dos_extender_type", &dos_extender_type, -1, { 0x00a, 0x017, -1 }},
	{ NULL }
};
static detect_addr detect_keyboard_addrs[] = {
	{ "read_physical_memory", NULL, 0x012, { 0x00e, -1 }},
	{ NULL }
};
static uint32_t *set_errno;
static detect_addr find_first_addrs[] = {
	{ "set_errno", &set_errno, 0x022, { 0x01e, -1 }},
	{ NULL }
};
static uint32_t linux_gs;
static patch_addr find_first_patches[] = {
	{ "linux_gs", 0x07, &linux_gs, NULL },
	{ "dos_find_first", 0x12, &dos_find_first, NULL },
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
	{ "eflags_ptr", 0x26, NULL, &eflags },
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
	{ "get_device_info", 1, 3,
			"\x31\xc0"             // xor eax, eax
			"\xc3",                // ret
			10, 7, "\xb8\x00\x44\x00\x00\xcd\x21", 36, 0xadca8f6e, NULL, NULL },
	// a call to AH=19 GET CURRENT DRIVE, whose result then seems to be mostly ignored. XACT certainly doesn't mess with
	// drives very much; in fact it works perfectly fine if passed UNIX-style paths with forward slashes and no drive...
	// so we simply pretend that everything is on A: – floppies ftw!
	// this is an inline patch as well, because the function returns the drive in a pointer variable
	{ "get_current_drive", 1, 7,
			"\xb8\x01\x00\x00\x00" // mov eax, 1
			"\xeb\x04",            // jmp short start + 0x0b ; skip unused bytes
			0, 11, "\xb4\x19\xcd\x21\x25\xff\x00\x00\x00\xfe\xc0", 11, 0x4b20236c, NULL, NULL },
	// the call to AH=4E FIND FIRST, always preceeded by AH=1A SET DTA, which is probably why it gets its own separate
	// helper function.
	// this is calls directly into Linux-side C, so we just replace the entire function with something that handles GS
	// as well. (the MetaWare compiler uses GS as the General-purpose Segment, while Linux uses it to emulate a Global
	// Pointer.)
	{ "find_first", 1, 43,
			"\x55"                 // push ebp ; (standard stackframe creation)
			"\x89\xe5"             // mov ebp, esp
			"\x0f\xa8"             // push gs ; switch GS to what Linux expects
			"\x8e\x2d...."         // mov gs, [dword linux_gs]
			"\xff\x75\x10"         // push dword [ebp+0x10] ; push second arg: dta
			"\xff\x75\x08"         // push dword [ebp+0x8] ; push first arg: filename
			"\xb8...."             // mov eax, dos_find_first ; call the function (must be declared cdecl)
			"\xff\xd0"             // call eax
			"\x83\xc4\x08"         // add esp,byte +0x8 ; cdecl is caller-cleanup
			"\x0f\xa9"             // pop gs ; restore GS, in case XACT wants to keep it across calls
			"\x85\xc0"             // test eax, eax ; skip set_errno if successful
			"\x74\x07"             // jz 0x28
			"\xba...."             // mov edx, 0x22222222 ; call set_errno, passing argument in eax
			"\xff\xd2"             // call edx
			"\x5d"                 // pop ebp
			"\xc3",                // ret
			19, 10, "\xb4\x4e\xcd\x21\x0f\x83\x0a\x00\x00\x00", 46, 0xe734e768, find_first_addrs, find_first_patches },
	// the generic DOS call trampoline. used by 99% of all DOS calls. it's a large function because it needs to set up
	// all the registers from memory for the actual INT 21 call. because we don't need any of that, there is plenty of
	// room to inline not just GS switching, but also the actual DOS API decode...
	{ "call_dos", 1, 46,
			"\x55"                 // push ebp ; (standard stackframe creation)
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
			"\xa3...."             // mov [eflags_ptr], eax ; save eflags
			"\x0f\xa9"             // pop gs
			"\x5d"                 // pop ebp
			"\xc3",                // ret
			55, 8, "\x1f\xf8\xcd\x21\x5d\x1e\x8e\xdd", 126, 0x85e9a644, call_dos_addrs, call_dos_patches },
	{ NULL }
};

int main(int argc, char **argv) {
	char *tracefile = getenv("XRUN_TRACE");
	if (tracefile)
		dosemu_init(tracefile);

	asm("mov %%gs, %0" : "=a" (linux_gs) :);
	struct timeval tv;
	gettimeofday(&tv, NULL);
	getpsp_badrng_seed = tv.tv_usec;

	uint32_t eip, esp, stacksize, loadbase, loadlimit, heaplimit, heapsize = 16 * 1024 * 1024;
	load_exe(argv[1], heapsize, &eip, &esp, &stacksize, &loadbase, &loadlimit, &heaplimit);
	binpatch((void *) loadbase, loadlimit - loadbase, patches);

	// yes, we just pass the entire shebang... BASH option, PATH, XAUTHORITY... XACT is at its heart
	// a UNIX toolchain and just simply doesn't care. and while it translates / to \, it doesn't even
	// notice that it's messing with a UNIX-style path here ;)
	init_mwhc((void *) eip, heapsize, esp, stacksize, loadbase, loadlimit, heaplimit, environ, &argv[1]);
}
