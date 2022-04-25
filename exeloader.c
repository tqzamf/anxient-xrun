#define _GNU_SOURCE
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <err.h>
#include <sys/mman.h>
#include <errno.h>
#include <fcntl.h>

#include "xrun.h"

#define OFF_PADDING 0x2c4c0
#define OFF_EXP 0x2c524

#define SIG_PHARLAP386 "P3"
#define SIG_RTPARAMS "DX"
#define LEVEL_FLAT 1
#define FLAGS_PACKED 1
struct offsize {
	uint32_t offset;
	uint32_t size;
} __attribute__((packed));
struct exp_header {
	uint8_t sig[2];
	uint16_t level;
	uint16_t headersize;
	uint32_t filesize;
	uint16_t checksum16;
	struct offsize rtparam;
	struct offsize reltab;
	struct offsize seginfotab;
	uint16_t seginfotab_entry;
	struct offsize image;
	struct offsize symtab;
	struct offsize gdttab;
	struct offsize ldttab;
	struct offsize idttab;
	struct offsize tsstab;
	uint32_t minheap;
	uint32_t maxheap;
	uint32_t base;
	uint32_t initesp;
	uint16_t initss;
	uint32_t initeip;
	uint16_t initcs;
	uint16_t initldt;
	uint16_t inittss;
	uint16_t flags;
	uint32_t memsize;
	uint32_t checksum32;
	uint32_t stacksize;
} __attribute__((packed));
struct rt_params {
	uint8_t sig[2];
	uint16_t minparams;
	uint16_t maxparams;
	uint16_t minint;
	uint16_t maxint;
	uint16_t numint;
	uint16_t intsize;
	uint32_t realend;
	uint16_t callbufs;
	uint16_t flags;
	uint16_t unpriv;
} __attribute__((packed));

static int sigequals(uint8_t sig[2], char *expected) {
	return sig[0] == (uint8_t) expected[0] && sig[1] == (uint8_t) expected[1];
}

static void readall(char *what, int fd, void *buffer, off_t len) {
	int rem = len;
	while (rem > 0) {
		int res = read(fd, buffer, len);
		if (res < 0)
			err(130, "cannot read %s", what);
		if (res == 0)
			errx(130, "cannot read %s, EOF with %d bytes remaining", what, rem);
		rem -= res;
	}
}

void load_exe(char *filename, uint32_t heapsize, uint32_t *eip, uint32_t *esp, uint32_t *stacksize, uint32_t *loadbase,
		uint32_t *loadlimit, uint32_t *heaplimit) {
	int fd = open(filename, O_RDONLY | O_NOATIME);
	if (fd < 0)
		err(130, "cannot open %s", filename);
	if (lseek(fd, OFF_PADDING, SEEK_SET) == (off_t) -1)
		err(130, "cannot seek to %08x", OFF_PADDING);
	uint8_t padding[100];
	readall("magic padding", fd, padding, sizeof(padding));
	for (int i = 0; i < sizeof(padding); i++)
		if (padding[i] != 0xa5)
			errx(130, "illegal padding at offset %05x", OFF_PADDING + i);

	if (lseek(fd, OFF_EXP, SEEK_SET) == (off_t) -1)
		err(130, "cannot seek to %08x", OFF_EXP);
	struct exp_header exp;
	readall("P3 header", fd, &exp, sizeof(struct exp_header));
	if (!sigequals(exp.sig, SIG_PHARLAP386))
		errx(130, "invalid file signature '%c%c'", exp.sig[0], exp.sig[1]);
	if (exp.level != LEVEL_FLAT)
		errx(130, "file is not a flat binary");
	if (lseek(fd, OFF_EXP + exp.rtparam.offset, SEEK_SET) == (off_t) -1)
		err(130, "cannot seek to %08x", OFF_EXP + exp.rtparam.offset);
	if (exp.reltab.size != 0)
		errx(130, "binary uses a relocation table");
	if (exp.symtab.size != 0)
		errx(130, "binary has a symbol table"); // probably harmless
	if (exp.gdttab.size != 0)
		errx(130, "binary uses a GDT table");
	if (exp.ldttab.size != 0)
		errx(130, "binary uses a LDT table");
	if (exp.idttab.size != 0)
		errx(130, "binary uses a IDT table");
	if (exp.tsstab.size != 0)
		errx(130, "binary uses a TSS table");
	if (exp.initcs != 0)
		errx(130, "binary cares about initial CS");
	if (exp.initss != 0)
		errx(130, "binary cares about initial SS");
	if ((exp.base & PAGEMASK) != 0)
		errx(130, "load address isn't page aligned: %08x", exp.base);

	struct rt_params rt;
	readall("DX header", fd, &rt, sizeof(struct rt_params));
	if (!sigequals(rt.sig, SIG_RTPARAMS))
		errx(130, "invalid runtime signature '%c%c'", rt.sig[0], rt.sig[1]);
	if (lseek(fd, OFF_EXP + exp.image.offset, SEEK_SET) == (off_t) -1)
		err(130, "cannot seek to %08x", OFF_EXP + exp.image.offset);
	if (rt.minparams != 0)
		errx(130, "binary requires real-mode parameters");
	if (rt.realend != 0)
		errx(130, "binary has a real-mode part");
	if (rt.callbufs != 0)
		errx(130, "binary requires a call buffer");
	if (rt.flags != 0)
		errx(130, "binary has runtime flags %04x", rt.flags);
	if (rt.unpriv == 0)
		errx(130, "binary requires ring 0");

	int mapsize = (exp.memsize + exp.minheap + heapsize + PAGEMASK) & ~PAGEMASK;
	uint8_t *mapping = mmap((void *) exp.base, mapsize, PROT_EXEC | PROT_READ | PROT_WRITE,
			MAP_FIXED_NOREPLACE | MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
	if (mapping == MAP_FAILED || mapping != (void *) exp.base) {
		int e = errno;
		int minfd = open("/proc/sys/vm/mmap_min_addr", O_RDONLY);
		if (minfd >= 0) {
			char buffer[20];
			int len = read(minfd, buffer, sizeof(buffer) - 1);
			if (len < 0)
				err(130, "cannot read sysctl vm.mmap_min_addr");
			buffer[len] = 0;
			close(minfd);
			uint32_t minmap = strtoul(buffer, NULL, 10);
			if (exp.base < minmap)
				warnx("lower sysctl vm.mmap_min_addr to %d or lower (currently %d)", exp.base, minmap);
		}
		errno = e;
		err(130, "failed to map binary at %08x (return code %08x)", exp.base, (uint32_t) mapping);
	}

	if (exp.flags & FLAGS_PACKED) {
		uint8_t *target = mapping;
		while (target < &mapping[exp.memsize]) {
			uint16_t blocksize;
			readall("block size", fd, &blocksize, 2);
			if (blocksize & 0x8000) {
				blocksize &= 0x7fff;
				uint8_t datasize;
				readall("data size", fd, &datasize, 1);
				if (datasize > 0) {
					readall("repeat block", fd, target, datasize);
					for (int pos = datasize; pos < blocksize; pos += datasize)
						memcpy(&target[pos], target, datasize);
				} else
					memset(target, 0, blocksize);
			} else
				readall("image block", fd, target, blocksize);
			target += blocksize;
		}
	} else
		readall("image data", fd, mapping, exp.image.size);
	close(fd);

	*eip = exp.initeip;
	*esp = exp.initesp;
	*stacksize = exp.stacksize;
	*loadbase = exp.base;
	*loadlimit = exp.base + exp.memsize;
	*heaplimit = exp.base + mapsize;
}
