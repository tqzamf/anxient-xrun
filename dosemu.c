#define _XOPEN_SOURCE 500
#define _GNU_SOURCE
#include <ucontext.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <err.h>

#include "xrun.h"

static void dumpregs(volatile greg_t *regs) {
	fprintf(stderr, " at EIP=%08x ESP=%08x EBP=%08x *ESP=%08x\n", regs[REG_EIP], regs[REG_ESP], regs[REG_EBP],
			regs[REG_ESP] != 0 ? *(uint32_t *) regs[REG_ESP] : 0);
	fprintf(stderr, "    EAX=%08x EBX=%08x ECX=%08x EDX=%08x\n", regs[REG_EAX], regs[REG_EBX], regs[REG_ECX],
			regs[REG_EDX]);
	fprintf(stderr, "    ESI=%08x EDI=%08x EFLAGS=%08x\n", regs[REG_ESI], regs[REG_EDI], regs[REG_EFL]);
	fprintf(stderr, "    CS=%04x DS=%04x SS=%04x ES=%04x FS=%04x GS=%04x\n", regs[REG_CS], regs[REG_DS], regs[REG_SS],
			regs[REG_ES], regs[REG_FS], regs[REG_GS]);
	fflush(stderr);
}

static void dumpsegv(siginfo_t *info, char *reason, volatile greg_t *regs) {
	fprintf(stderr, "SEGFAULT type %d (%s) TRAP=%d ERR=%d @%08x\n", info->si_code, reason, regs[REG_TRAPNO],
			regs[REG_ERR], (uint32_t) info->si_addr);
	dumpregs(regs);
	exit(128);
}

#define TRAPNO_GPF 13
#define TRAPERR_INT 266

uint16_t realgs, realfs;

static void trapsegv(int sig, siginfo_t *info, void *ctx) {
	// restore GS to what Linux expects it to be. GS is silently expected to point to the GOT; if it doesn't, any
	// library call will immediately crash and burn. because the MetaWare compiler liberally uses GS for other
	// purposes, we're left with no other choice than to save and restore it here...
	uint16_t emulgs, emulfs;
	asm("mov %%gs, %0" : "=a" (emulgs));
	asm("mov %%fs, %0" : "=a" (emulfs));
	asm volatile("mov %0, %%gs" :: "a" (realgs));
	asm volatile("mov %0, %%fs" :: "a" (realfs));

	volatile greg_t *regs = ((ucontext_t *) ctx)->uc_mcontext.gregs;
	if (info->si_code != SI_KERNEL) {
		char *reason;
		if (info->si_code == SEGV_MAPERR)
			reason = "address not mapped";
		else if (info->si_code == SEGV_ACCERR)
			reason = "invalid permissions";
		else if (info->si_code == SEGV_BNDERR)
			reason = "failed bounds check";
		else
			reason = "other";
		dumpsegv(info, reason, regs);
	}
	uint8_t *eip = (void *) regs[REG_EIP];
	if (eip[0] == 0xfa || eip[0] == 0xfb || eip[0] == 0xec) {
		fprintf(stderr, "CLI/STI %02x!\n", eip[0]);
		regs[REG_EIP] += 1;
		asm volatile("mov %0, %%gs" :: "a" (emulgs));
		asm volatile("mov %0, %%fs" :: "a" (emulfs));
		return;
	}
	if (eip[0] == 0x8e && eip[1] == 0x5d && eip[2] == 0x08) {
		uint32_t *ebp = (void *) regs[REG_EBP];
		uint32_t *esp = (void *) regs[REG_ESP];
		fprintf(stderr, "MOV DS %08x %08x %08x %08x @%08x %08x→%08x\n", ebp[2], ebp[3], ebp[4], ebp[5], regs[REG_EIP], regs[REG_ESP], esp[4]);
		*(uint8_t *) ebp[4] = 0;
		fprintf(stderr, "=%08x\n", *(uint32_t *) ebp[4]);
		regs[REG_EIP] += 15;
		asm volatile("mov %0, %%gs" :: "a" (emulgs));
		asm volatile("mov %0, %%fs" :: "a" (emulfs));
		return;
	}
	if (regs[REG_TRAPNO] != TRAPNO_GPF)
		dumpsegv(info, "unexpected exception", regs);
	if (regs[REG_ERR] != TRAPERR_INT)
		dumpsegv(info, "unexpected GPF", regs);
	if (eip[0] != 0xcd || eip[1] != 0x21)
		dumpsegv(info, "unexpected interrupt", regs);

	fprintf(dostrace, "INT 21 @%08x EAX=%04x EBX=%08x ECX=%08x EDX=%08x ESI=%08x EDI=%08x\n", regs[REG_EIP], eax->ex,
			ebx->ex, ecx->ex, edx->ex, esi->ex, edi->ex);
	fflush(dostrace);
	eax->ex = regs[REG_EAX],
	ebx->ex = regs[REG_EBX],
	ecx->ex = regs[REG_ECX],
	edx->ex = regs[REG_EDX],
	esi->ex = regs[REG_ESI],
	edi->ex = regs[REG_EDI],
	*eflags = regs[REG_EFL] & (EFLAG_CARRY | EFLAG_ZERO);
	dosapi_handler handler = dosapi[eax->h];
	if (handler == NULL)
		dos_unimpl();
	handler();
	regs[REG_EAX] = eax->ex;
	regs[REG_EBX] = ebx->ex;
	regs[REG_ECX] = ecx->ex;
	regs[REG_EDX] = edx->ex;
	regs[REG_ESI] = esi->ex;
	regs[REG_EDI] = edi->ex;
	regs[REG_EFL] = (regs[REG_EFL] & ~(EFLAG_CARRY | EFLAG_ZERO)) | *eflags;

	regs[REG_EIP] += 2; // skip the int 0x21 instruction
	asm volatile("mov %0, %%gs" :: "a" (emulgs));
	asm volatile("mov %0, %%fs" :: "a" (emulfs));
}

static void trap(int sig, siginfo_t *info, void *ctx) {
	asm volatile("mov %0, %%gs" :: "a" (realgs));
	asm volatile("mov %0, %%fs" :: "a" (realfs));

	greg_t *regs = ((ucontext_t *) ctx)->uc_mcontext.gregs;
	char *reason;
	if (sig == SIGBUS)
		reason = "BUS ERRROR";
	else if (sig == SIGTRAP)
		reason = "DEBUG TRAP";
	else if (sig == SIGILL)
		reason = "ILLEGAL OPCODE";
	else if (sig == SIGFPE)
		reason = "FP EXCEPTION";
	else
		reason = "SIGNAL";
	fprintf(stderr, "%s (%d) code %d TRAP=%d ERR=%d @%08x\n", reason, sig, info->si_code, regs[REG_TRAPNO],
			regs[REG_ERR], (uint32_t) info->si_addr);
	dumpregs(regs);
	exit(128);
}

static void sighandler(int sig, void (*handler)(int, siginfo_t *, void *)) {
	struct sigaction act;
	act.sa_sigaction = handler;
	act.sa_flags = SA_ONSTACK | SA_SIGINFO;
	sigemptyset(&act.sa_mask);
	if (sigaction(sig, &act, NULL))
		err(129, "failed to install signal handler for signal %d", sig);
}

void dosemu_init(char *tracefile) {
	dostrace = fopen(tracefile, "w");
	asm("mov %%gs, %0" : "=a" (realgs) :);
	asm("mov %%fs, %0" : "=a" (realfs) :);

	stack_t stack = {
		.ss_flags = 0,
		.ss_size = 5 * SIGSTKSZ,
	};
	stack.ss_sp = malloc(stack.ss_size);
	if (!stack.ss_sp)
		err(129, "failed to allocate signal stack");
	stack.ss_sp += stack.ss_size;
	if (sigaltstack(&stack, NULL))
		err(129, "failed to install signal stack");

	sighandler(SIGSEGV, trapsegv);
	sighandler(SIGBUS, trap);
	sighandler(SIGILL, trap);
	sighandler(SIGFPE, trap);
	sighandler(SIGTRAP, trap);
}
