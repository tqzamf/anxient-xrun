#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <err.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <string.h>

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
	fprintf(dostrace, "GET DATE");
	struct timeval t;
	gettimeofday(&t, NULL);
	struct tm *now = localtime(&t.tv_sec);
	r->cx = now->tm_year + 1900;
	r->dh = now->tm_mon + 1;
	r->dl = now->tm_mday;
	r->al = now->tm_wday;
}

static void get_time(struct regs *r) {
	fprintf(dostrace, "GET TIME");
	struct timeval t;
	gettimeofday(&t, NULL);
	struct tm *now = localtime(&t.tv_sec);
	r->ch = now->tm_hour;
	r->cl = now->tm_min;
	r->dh = now->tm_sec;
	r->dl = t.tv_usec / 10000;
}

static void get_version(struct regs *r) {
	r->al = 3;
	r->ah = 0;
	r->bl = 0;
	r->bh = 0;
	r->cx = 0;
}

static void dos_exit(struct regs *r) {
	fprintf(dostrace, "EXIT %d\n", r->al);
	exit(r->al);
}

static void dos_getkey(struct regs *r) {
	fprintf(dostrace, "GETKEY");
	// TODO implement properly? only used for paging, and that isn't necessary on Linux
	r->al = ' ';
}

// filing functions. DOS 2+ (non-FCB) FS API is very, very close to UNIX FS API. and XACT does very little to its
// filenames; it doesn't even consistently replace / with \ for filename separators.
// internally, something crams file handles into a byte. so file descriptors have to be ≤255. luckily, they are
// allocated in ascending order on Linux, and a DOS program won't open many files anyway because DOS has a fairly
// low limit on open files. it does, however, mean that we should return 32 bits of file descriptor in ebx, but
// only look at the low 8 bits in bl when using them.

uint8_t *dta;

static void dos_set_dta(struct regs *r) {
	fprintf(dostrace, "DTA = %p", r->edx);
	dta = r->edx;
}

static void dos_read(struct regs *r) {
	fprintf(dostrace, "READ %d %d", r->bl, r->ecx);
	int len = read(r->bl, r->edx, r->ecx);
	if (len < 0)
		err(133, "read failed");
	r->carry = 0;
	r->eax = len;
}

static void dos_write(struct regs *r) {
	fprintf(dostrace, "WRITE %d %d", r->bl, r->ecx);
	if (r->ecx == 0)
		// TODO implement? probably only ever used to actually emulate ftruncate(), if at all
		errx(128, "truncate not implemented");
	int len = write(r->bl, r->edx, r->ecx);
	if (len < 0)
		err(133, "write failed");
	r->carry = 0;
	r->eax = len;
}

static void dos_seek(struct regs *r) {
	// as silly as it looks, this really does seem to represent offsets as CX:DX, instead of simply using EDX like
	// sensible people. 64-bit pointers apparently don't look that nice if the underlying API cannot use them anyway?
	off_t pos = (r->cx << 16) | r->dx;
	// the "whence" values match. man lseek doesn't document them, but they're so traditional that even Python (!)
	// documents their numerical values...
	char *whence[] = { "SET", "CUR", "END" };
	fprintf(dostrace, "SEEK %d %s %d", r->bl, whence[r->al], (uint32_t) pos);
	off_t res = lseek(r->bl, pos, r->al);
	if (res == (off_t) -1)
		err(133, "lseek failed");
	fprintf(dostrace, " = %d", (uint32_t) res);
	r->eax = res & 0xffff;
	r->edx = (void *) ((res >> 16) & 0xffff);
	r->carry = 0;
}

static void dos_devinfo(struct regs *r) {
	fprintf(dostrace, "DEVINFO %d", r->ebx);
	// here we pretend that STDOUT isn't the console device. this has two effects:
	// - XACT doesn't attempt to paginate its output, which on a Linux terminal is pointless and needs more APIs (and
	//   makebits.exe even attempts to talk directly to the keyboard controller to paginate!?)
	// - the MetaWare High C runtime library buffers output (theoretically saving syscalls, but it still calls DEVINFO
	//   for every internal write)
	r->dx = 0; // ordinary file
	r->carry = 0;
}

static void dos_get_drive(struct regs *r) {
	fprintf(dostrace, "GET DRIVE");
	// TODO emulate correctly?
	r->al = 0;
}

static int dos_errno(char *syscall, char *pathname) {
	if (errno == ENOENT)
		return 2;
	if (errno == ENOTDIR)
		return 3;
	if (errno == EACCES)
		return 5; // yes, DOS actually does have that one, despite having no concept of permissions...
	err(133, "%s %s failed", syscall, pathname); // symlink loop, or other *really bad* condition
}

static int dos_stat(void *pathname, uint8_t *attr, uint16_t *time, uint16_t *date, uint32_t *size) {
	struct stat s;
	int res = stat(pathname, &s);
	if (res < 0)
		return dos_errno("stat", pathname);

	if (S_ISREG(s.st_mode))
		*attr = 0x20; // regular file, with archive flag set
	else if (S_ISDIR(s.st_mode))
		*attr = 0x10; // directory, with archive flag clear because it isn't clear whether it would be set
	else
		*attr = 0x04; // something weird. say it's a system file; DOS programs tend to leave those alone
	if (!(s.st_mode & S_IRUSR))
		*attr |= 0x01; // set readonly flag if not owner-writable (assuming we're the owner)

	if (size)
		*size = s.st_size;
	if (date || time) {
		struct tm *mtime = localtime(&s.st_mtime);
		if (time)
			*time = (mtime->tm_hour << 11) | (mtime->tm_min << 5) | (mtime->tm_sec >> 1);
		if (date)
			*date = ((mtime->tm_year + 1900 - 1980) << 9) | ((mtime->tm_mon + 1) << 5) | mtime->tm_mday;
	}
	return 0;
}

// TODO we probably shouldn't jsut modify the string inplace?
// then again: it works just fine, and sometimes we even get the already-transformed string...
static void dos_to_unix(char *pathname) {
	for (char *ch = pathname; *ch; ch++)
		if (*ch == '\\')
			*ch = '/';
}

static void dos_getattr(struct regs *r) {
	fprintf(dostrace, "GETATTR %s", (char *) r->edx);
	uint8_t attr;
	int res = dos_stat(r->edx, &attr, NULL, NULL, NULL);
	if (res) {
		r->eax = res;
		r->carry = 1;
	} else {
		r->ecx = attr;
		r->carry = 0;
	}
}

static void dos_find_first(struct regs *r) {
	fprintf(dostrace, "FIND FIRST %s", (char *) r->edx);
	if (index(r->edx, '*') || index(r->edx, '?'))
		// TODO implement? probably not used, though
		errx(133, "FIND FIRST placeholders not implemented");
	dos_to_unix(r->edx);

	int res = dos_stat(r->edx, &dta[0x15], (uint16_t *) &dta[0x16], (uint16_t *) &dta[0x18], (uint32_t *) &dta[0x1a]);
	if (res) {
		r->eax = res;
		r->carry = 1;
	} else {
		strcpy((char *) &dta[0x1e], "__dummy_.FIL");
		r->carry = 0;
	}
}

static void dos_open(struct regs *r, int mode) {
	dos_to_unix(r->edx);
	int res = open(r->edx, mode, 0777);
	if (res < 0) {
		r->eax = dos_errno("open", r->edx);
		r->carry = 1;
	} else {
		r->eax = res;
		r->carry = 0;
	}
}

static void dos_open_existing(struct regs *r) {
	fprintf(dostrace, "OPEN %s %d", (char *) r->edx, r->al);
	int mode;
	switch (r->al & 7) {
	case 0:
		mode = O_RDONLY;
		break;
	case 1:
		mode = O_WRONLY;
		break;
	case 2:
		mode = O_RDWR;
		break;
	default:
		errx(133, "invalid file mode %d for opening %s", r->al, (char *) r->edx);
	}
	dos_open(r, mode);
	fprintf(dostrace, " = %d", r->ebx);
}

static void dos_create(struct regs *r) {
	fprintf(dostrace, "CREATE %s %02x", (char *) r->edx, r->cx);
	dos_open(r, O_WRONLY | O_CREAT | O_TRUNC); // TODO O_RDWR?
	fprintf(dostrace, " = %d", r->ebx);
}

static void dos_close(struct regs *r) {
	fprintf(dostrace, "CLOSE %d", r->ebx);
	close(r->bl);
	r->carry = 0;
}

static void dos_getcwd(struct regs *r) {
	fprintf(dostrace, "GETCWD %d", r->dl);
	strcpy(r->esi, "\\nowhere");
	r->carry = 0;
}

static void dos_unlink(struct regs *r) {
	fprintf(dostrace, "UNLINK %s", (char *) r->edx);
	dos_to_unix(r->edx);
	int res = unlink((char *) r->edx);
	if (res < 0) {
		r->eax = dos_errno("unlink", r->edx);
		r->carry = 1;
	} else
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
	//[0x07] = dos_getkey,

	[0x19] = dos_get_drive,
	[0x1a] = dos_set_dta,
	[0x3c] = dos_create,
	[0x3d] = dos_open_existing,
	[0x3e] = dos_close,
	[0x3f] = dos_read,
	[0x40] = dos_write,
	[0x42] = dos_seek,
	[0x4300] = dos_getattr,
	[0x4400] = dos_devinfo,
	[0x4e] = dos_find_first,
	[0x47] = dos_getcwd,
	[0x41] = dos_unlink,
};
