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
	fprintf(stderr, " at EIP=%08x ESP=%08x EBP=%08x\n", regs[REG_EIP], regs[REG_ESP], regs[REG_EBP]);
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
#define EFLAG_CARRY 1

uint16_t realgs;

static void trapsegv(int sig, siginfo_t *info, void *ctx) {
	// restore GS to what Linux expects it to be. GS is silently expected to point to the GOT; if it doesn't, any
	// library call will immediately crash and burn. because the MetaWare compiler liberally uses GS for other
	// purposes, we're left with no other choice than to restore it here...
	uint16_t emulgs;
	asm("mov %%gs, %0" : "=a" (emulgs));
	asm volatile("mov %0, %%gs" :: "a" (realgs));

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

	if (regs[REG_TRAPNO] != TRAPNO_GPF)
		dumpsegv(info, "unexpected exception", regs);
	if (regs[REG_ERR] != TRAPERR_INT)
		dumpsegv(info, "unexpected GPF", regs);
	uint8_t *eip = (void *) regs[REG_EIP];
	if (eip[0] != 0xcd || eip[1] != 0x21)
		dumpsegv(info, "unexpected interrupt", regs);
	uint16_t ax = regs[REG_EAX] & 0xffff;
	uint16_t cx = regs[REG_ECX] & 0xffff;
	uint8_t ah = ax >> 8, al = ax & 255;
	uint8_t ch = cx >> 8, cl = cx & 255;
	fprintf(stderr, "DOS CALL: INT 21 AH=%02x AL=%02x @%08x\n", ah, al, regs[REG_EIP]);
	if (ah == 0x2a) {
		regs[REG_ECX] = 2022;
		regs[REG_EDX] = (4 << 8) + 24;
		regs[REG_EAX] = 0;
	} else if (ah == 0x2c) {
		regs[REG_ECX] = (18 << 8) + 11;
		regs[REG_EDX] = (50 << 8) + 00;
	} else if (ah == 0x30) {
		regs[REG_EAX] = 0x6606;
		regs[REG_ECX] = 0x3456;
		regs[REG_EBX] = 0x0012;
	} else if (ax == 0x2502) {
		fprintf(stderr, "GETINT PROT INT=%d\n", cl);
		regs[REG_EBX] = 0x99999900 + cl;
		regs[REG_EFL] &= ~EFLAG_CARRY;
	} else if (ax == 0x2503) {
		fprintf(stderr, "GETINT REAL INT=%d\n", cl);
		regs[REG_EBX] = 0x99999900 + cl;
		regs[REG_EFL] &= ~EFLAG_CARRY;
	} else if (ah == 0x33) {
		fprintf(stderr, "CTRL-BREAK %s %d\n", al == 0 ? "get" : al == 1 ? "set" : "set/get", regs[REG_EDX] & 255);
		if (al != 1)
			regs[REG_EDX] = 0;
	} else if (ax == 0x2506) {
		fprintf(stderr, "SETINT INT=%d %08x\n", cl, regs[REG_EDX]);
		regs[REG_EFL] &= ~EFLAG_CARRY;
	} else if (ah == 0x40) {
		int fd = regs[REG_EBX];
		uint32_t num = regs[REG_ECX];
		uint8_t *ptr = regs[REG_EDX];
		fprintf(stderr, "WRITE fd=%d num=%d %08x\n", fd, num, ptr);
		write(fd, ptr, num);
		regs[REG_EAX] = regs[REG_ECX];
		regs[REG_EFL] &= ~EFLAG_CARRY;
	} else if (ah == 0x43) {
		uint8_t *ptr = regs[REG_EDX];
		fprintf(stderr, "GETFATTR %s\n", ptr);
		regs[REG_ECX] = 0x10; // FIXME this needs actual emulation now
		regs[REG_EFL] &= ~EFLAG_CARRY;
	} else if (ah == 0x4e) {
		uint8_t *ptr = regs[REG_EDX];
		fprintf(stderr, "FINDFIRST %02x %04x %s\n", al, regs[REG_ECX], ptr);
		regs[REG_ECX] = 0x10; // FIXME this needs actual emulation now
		regs[REG_EFL] &= ~EFLAG_CARRY;
	} else if (ax == 0x4400) {
		uint8_t *ptr = regs[REG_EDX];
		fprintf(stderr, "DEVINFO %04x\n", regs[REG_EBX]);
		regs[REG_EDX] = 0x82; // /dev/stdin
		regs[REG_EFL] &= ~EFLAG_CARRY;
	} else if (ah == 0x1a) {
		uint8_t *ptr = regs[REG_EDX];
		fprintf(stderr, "SETDTA %08x\n", ptr);
	} else {
		fprintf(stderr, "unsupported DOS call: INT 21 AH=%02x AL=%02x\n", ah, al);
		dumpregs(regs);
		exit(0);
	}
	regs[REG_EIP] += 2;

	asm volatile("mov %0, %%gs" :: "a" (emulgs));
}

static void trap(int sig, siginfo_t *info, void *ctx) {
	asm volatile("mov %0, %%gs" :: "a" (realgs));

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

void dosemu_init(void) {
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

	asm("mov %%gs, %0" : "=a" (realgs) :);
}
