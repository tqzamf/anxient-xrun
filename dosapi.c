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
#include <stdarg.h>

#include "xrun.h"

FILE *dostrace;
static void trace(char *format, ...) {
	if (!dostrace)
		return;

	va_list argp;
	va_start(argp, format);
	vfprintf(dostrace, format, argp);
	va_end(argp);
}

static uint32_t get_date(void) {
	trace("GET DATE\n");
	struct timeval t;
	gettimeofday(&t, NULL);
	struct tm *now = localtime(&t.tv_sec);
	ecx->x = now->tm_year + 1900;
	edx->h = now->tm_mon + 1;
	edx->l = now->tm_mday;
	eax->l = now->tm_wday;
	return 0;
}

static uint32_t get_time(void) {
	trace("GET TIME\n");
	struct timeval t;
	gettimeofday(&t, NULL);
	struct tm *now = localtime(&t.tv_sec);
	ecx->h = now->tm_hour;
	ecx->l = now->tm_min;
	edx->h = now->tm_sec;
	edx->l = t.tv_usec / 10000;
	return 0;
}

static uint32_t get_version(void) {
	eax->l = 3;
	eax->h = 0;
	ebx->l = 0;
	ebx->h = 0;
	ecx->x = 0;
	return 0;
}

static uint32_t dos_exit(void) {
	trace("EXIT %d\n", eax->l);
	exit(eax->l);
}

void dos_unimpl(void) {
	errx(133, "unsupported DOS call: INT 21 AH=%02x AL=%02x", eax->h, eax->l);
}

// filing functions. DOS 2+ (non-FCB) FS API is very, very close to UNIX FS API. and XACT does very little to its
// filenames; it doesn't even consistently replace / with \ for filename separators.
// internally, something crams file handles into a byte. so file descriptors have to be ≤255. luckily, they are
// allocated in ascending order on Linux, and a DOS program won't open many files anyway because DOS has a fairly
// low limit on open files. it does, however, mean that we should return 32 bits of file descriptor in ebx, but
// only look at the low 8 bits in bl when using them.

static uint32_t dos_read(void) {
	trace("READ %d %d\n", ebx->l, ecx->ex);
	int len = read(ebx->l, edx->ptr, ecx->ex);
	if (len < 0)
		err(133, "read failed");
	eax->ex = len;
	return 0;
}

static uint32_t dos_write(void) {
	trace("WRITE %d %d\n", ebx->l, ecx->ex);
	if (ecx->ex == 0)
		// TODO implement? probably only ever used to actually emulate ftruncate(), if at all
		errx(133, "truncate not implemented");
	int len = write(ebx->l, edx->ptr, ecx->ex);
	if (len < 0)
		err(133, "write failed");
	eax->ex = len;
	return 0;
}

static uint32_t dos_seek(void) {
	// as silly as it looks, this really does seem to represent offsets as CX:DX, instead of simply using EDX like
	// sensible people. 64-bit pointers apparently don't look that nice if the underlying API cannot use them anyway?
	off_t pos = (ecx->x << 16) | edx->x;
	// the "whence" values match. man lseek doesn't document them, but they're so traditional that even Python (!)
	// documents their numerical values...
	char *whence[] = { "SET", "CUR", "END" };
	trace("SEEK %d %s %d", ebx->l, whence[eax->l], (uint32_t) pos);
	off_t res = lseek(ebx->l, pos, eax->l);
	if (res == (off_t) -1)
		err(133, "lseek failed");
	trace(" = %d\n", (uint32_t) res);
	eax->ex = res & 0xffff;
	edx->ex = (res >> 16) & 0xffff;
	return 0;
}

static uint32_t dos_get_drive(void) {
	trace("GET DRIVE\n");
	eax->l = 0;
	return 0;
}

static uint32_t dos_errno(char *syscall, char *pathname) {
	if (errno == ENOENT)
		return 2;
	if (errno == ENOTDIR)
		return 3;
	if (errno == EACCES)
		return 5; // yes, DOS actually does have that one, despite having no concept of permissions...
	err(133, "%s %s failed", syscall, pathname); // symlink loop, or other *really bad* condition
}

static uint32_t dos_stat(char *pathname, uint8_t *attr, uint16_t *time, uint16_t *date, uint32_t *size) {
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

// TODO we probably shouldn't just modify the string inplace?
// then again: it works just fine, and sometimes we even get the already-transformed string...
static void dos_to_unix(char *pathname) {
	for (char *ch = pathname; *ch; ch++)
		if (*ch == '\\')
			*ch = '/';
}

static uint32_t dos_getattr(void) {
	if (eax->l != 0)
		dos_unimpl();

	trace("GETATTR %s\n", edx->ptr);
	uint8_t attr;
	int res = dos_stat(edx->ptr, &attr, NULL, NULL, NULL);
	if (res) {
		eax->ex = res;
		return EFLAG_CARRY;
	} else {
		ecx->ex = attr;
		return 0;
	}
}

struct dta {
	uint8_t internal[21];
	uint8_t attrib;
	uint16_t time;
	uint16_t date;
	uint32_t size;
	uint8_t name[13];
} __attribute__((packed));
uint32_t dos_find_first(char *filename, struct dta *dta) {
	if (index(filename, '*') || index(filename, '?')) {
		trace(" pretending to find nothing for wildcards");
		return 2;
	}
	dos_to_unix(filename);

	int res = dos_stat(filename, &dta->attrib, &dta->time, &dta->date, &dta->size);
	if (!res)
		strcpy((char *) &dta[0x1e], "__dummy_.FIL");
	return res;
}

static uint32_t dos_open(int mode) {
	dos_to_unix(edx->ptr);
	int res = open(edx->ptr, mode, 0777);
	if (res < 0) {
		eax->ex = dos_errno("open", edx->ptr);
		return EFLAG_CARRY;
	} else {
		eax->ex = res;
		return 0;
	}
}

static uint32_t dos_open_existing(void) {
	trace("OPEN %s %d", edx->ptr, eax->l);
	int mode;
	switch (eax->l & 7) {
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
		errx(133, "invalid file mode %d for opening %s", eax->l, edx->ptr);
	}
	int res = dos_open(mode);
	trace(" = %d\n", ebx->ex);
	return res;
}

static uint32_t dos_create(void) {
	trace("CREATE %s %02x", edx->ptr, ecx->x);
	int res = dos_open(O_WRONLY | O_CREAT | O_TRUNC); // TODO O_RDWR?
	trace(" = %d\n", ebx->ex);
	return res;
}

static uint32_t dos_close(void) {
	trace("CLOSE %d\n", ebx->l);
	close(ebx->l);
	return 0;
}

static uint32_t dos_getcwd(void) {
	trace("GETCWD %d\n", edx->l);
	strcpy(esi->ptr, "\\nowhere");
	return 0;
}

static uint32_t dos_unlink(void) {
	trace("UNLINK %s\n", edx->ptr);
	dos_to_unix(edx->ptr);
	int res = unlink(edx->ptr);
	if (res < 0) {
		eax->ex = dos_errno("unlink", edx->ptr);
		return EFLAG_CARRY;
	} else
		return 0;
}

static uint32_t dos_rename(void) {
	trace("RENAME %s → %s\n", edx->ptr, edi->ptr);
	dos_to_unix(edx->ptr);
	dos_to_unix(edi->ptr);
	int res = rename(edx->ptr, edi->ptr);
	if (res < 0) {
		eax->ex = dos_errno("rename", edx->ptr);
		return EFLAG_CARRY;
	} else
		return 0;
}

static struct dta *global_dta;
static uint32_t dos_set_dta(void) {
	trace("DTA = %p\n", edx->ptr);
	global_dta = (void *) edx->ptr;
	return 0;
}
static uint32_t _dos_find_first(void) {
	trace("FIND FIRST %s %p\n", edx->ptr, global_dta);
	int res = dos_find_first(edx->ptr, global_dta);
	if (res) {
		eax->ex = res;
		return EFLAG_CARRY;
	} else
		return 0;
}

static uint32_t dos_get_psp(void) {
	trace("GET PSP\n");
	// only used as a (bad) RNG to name the MRGxxxxx temp file, so make it (badly) random:
	struct timeval t;
	gettimeofday(&t, NULL);
	ebx->ex = t.tv_usec;
	return 0;
}

static uint32_t dos_devinfo(void) {
	if (eax->l != 0)
		dos_unimpl();

	trace("GET DEVICE INFO\n");
	// here we pretend that STDOUT isn't the console device. this has two effects:
	// - XACT doesn't attempt to paginate its output, which on a Linux terminal is pointless and needs more APIs (and
	//   makebits.exe even attempts to talk directly to the keyboard controller to paginate!?)
	// - the MetaWare High C runtime library buffers output (theoretically saving syscalls, but it still calls DEVINFO
	//   for every internal write)
	edx->x = 0; // ordinary file
	return 0;
}

dosapi_handler dosapi[256] = {
	// general API
	[0x2a] = get_date,
	[0x2c] = get_time,
	[0x30] = get_version,
	[0x4c] = dos_exit,
	[0x19] = dos_get_drive,

	// DOS 2.0+ file API
	[0x3c] = dos_create,
	[0x3d] = dos_open_existing,
	[0x3e] = dos_close,
	[0x3f] = dos_read,
	[0x40] = dos_write,
	[0x42] = dos_seek,
	[0x43] = dos_getattr,
	[0x47] = dos_getcwd,
	[0x41] = dos_unlink,
	[0x56] = dos_rename,

	// stuff that should never be called via the API table because it is inlined directly
	[0x1a] = dos_set_dta,
	[0x4e] = _dos_find_first,
	[0x62] = dos_get_psp,
	[0x44] = dos_devinfo,
};
