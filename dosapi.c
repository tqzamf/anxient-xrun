#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <err.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>

#include "xrun.h"

static void get_int_handler(struct regs *r) {
	fprintf(dostrace, "GET INT %02x", r->cl);
	r->ebx = 0x99999900 + r->cl;
	r->carry = 0;
}

static void set_int_handler(struct regs *r) {
	fprintf(dostrace, "SET INT %02x = %p", r->cl, r->edx);
	r->carry = 0;
}

static void get_ctrl_break(struct regs *r) {
	fprintf(dostrace, "GET Ctrl-Break");
	r->dl = 0;
}

static void set_ctrl_break(struct regs *r) {
	fprintf(dostrace, "SET Ctrl-Break = %d", r->dl);
}

static void get_date(struct regs *r) {
	struct timeval t;
	gettimeofday(&t, NULL);
	struct tm *now = localtime(&t.tv_sec);
	r->cx = now->tm_year + 1900;
	r->dh = now->tm_mon + 1;
	r->dl = now->tm_mday;
	r->al = now->tm_wday;
}

static void get_time(struct regs *r) {
	struct timeval t;
	gettimeofday(&t, NULL);
	struct tm *now = localtime(&t.tv_sec);
	r->ch = now->tm_hour;
	r->cl = now->tm_min;
	r->dh = now->tm_sec;
	r->dl = t.tv_usec / 10000;
}

static void get_version(struct regs *r) {
	r->al = 6;
	r->ah = 66;
	r->bl = 0;
	r->bh = 0;
	r->cx = 0;
}

static void dos_exit(struct regs *r) {
	fprintf(dostrace, "EXIT %d\n", r->al);
	exit(r->al);
}

uint8_t *dta;

static void dos_set_dta(struct regs *r) {
	fprintf(dostrace, "DTA = %p", r->edx);
	dta = r->edx;
}

static void dos_read(struct regs *r) {
	fprintf(dostrace, "READ %d %d", r->ebx, r->ecx);
	int len = read(r->ebx, r->edx, r->ecx);
	if (len < 0)
		err(128, "read failed");
	r->carry = 0;
	r->eax = len;
}

static void dos_write(struct regs *r) {
	fprintf(dostrace, "WRITE %d %d", r->ebx, r->ecx);
	if (r->ecx == 0)
		errx(128, "truncate not implemented");
	int len = write(r->ebx, r->edx, r->ecx);
	if (len < 0)
		err(128, "write failed");
	r->carry = 0;
	r->eax = len;
}

static void dos_seek(struct regs *r) {
	// FIXME map properly
	fprintf(dostrace, "SEEK %d %d +%d %d", r->ebx, r->al, r->ecx, (uint32_t) r->edx);
	lseek(r->ebx, r->al, r->ecx);
	r->carry = 0;
	r->eax = r->edx;
	r->edx = r->ecx;
}

static void dos_open(struct regs *r) {
	fprintf(dostrace, "OPEN %s %d", (char *) r->edx, r->al);
	r->eax = open(r->edx, O_RDONLY);
	r->carry = 0;
}

static void dos_close(struct regs *r) {
	fprintf(dostrace, "CLOSE %d", r->ebx);
	close(r->ebx);
	r->carry = 0;
}

static void dos_devinfo(struct regs *r) {
	fprintf(dostrace, "DEVINFO %d", r->ebx);
	// TODO emulate correct value? only used to write to STDOUT without buffering
	r->dx = 0x82; // correct for STDOUT
	r->carry = 0;
}

static void dos_getattr(struct regs *r) {
	fprintf(dostrace, "GETATTR %s", (char *) r->edx);
	// TODO emulate correctly!
	r->ecx = 0x10;
	r->carry = 0;
}

static void dos_get_drive(struct regs *r) {
	// TODO emulate correctly!
	r->al = 0;
}

static void dos_find_first(struct regs *r) {
	fprintf(dostrace, "FIND FIRST %s", (char *) r->edx);
	// TODO emulate correctly!
	dta[0x15] = 0x10;
	*(uint16_t *) &dta[0x16] = 0x10;
	*(uint16_t *) &dta[0x18] = 0x10;
	*(uint32_t *) &dta[0x1a] = 10;
	strcpy(&dta[0x1e], "TheFile.FIL");
	r->carry = 0;
}

dosapi_handler dosapi[65536] = {
	[0x2502] = get_int_handler,
	[0x2503] = get_int_handler,
	[0x2504] = set_int_handler,
	[0x2505] = set_int_handler,
	[0x2506] = set_int_handler,
	[0x3300] = get_ctrl_break,
	[0x3301] = set_ctrl_break,
	[0x2a] = get_date,
	[0x2c] = get_time,
	[0x30] = get_version,
	[0x4c] = dos_exit,

	[0x19] = dos_get_drive,
	[0x1a] = dos_set_dta,
	[0x3d] = dos_open,
	[0x3e] = dos_close,
	[0x3f] = dos_read,
	[0x40] = dos_write,
	[0x42] = dos_seek,
	[0x4300] = dos_getattr,
	[0x4400] = dos_devinfo,
	[0x4e] = dos_find_first,
};
