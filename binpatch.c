#define _GNU_SOURCE
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <err.h>

#include "xrun.h"

static uint32_t crc32_table[256];

static void crc32_init(void) {
	if (crc32_table[1]) // already initialized (note that crc32_table[0] == 0 for mathematical reasons)
		return;

	for (size_t b = 0; b < 256; ++b) {
		uint32_t r = b;
		for (size_t i = 0; i < 8; ++i) {
			if (r & 1)
				r = (r >> 1) ^ 0xedb88320;
			else
				r >>= 1;
		}
		crc32_table[b] = r;
	}
}

static uint32_t crc32(const char *buf, size_t size) {
	crc32_init();

	uint32_t crc = 0xffffffff;
	while (size--)
		crc = crc32_table[(uint8_t) (*buf++) ^ (crc & 255)] ^ (crc >> 8);
	return ~crc;
}

void binpatch(char *base, size_t length, bin_patch *patches) {
	for (bin_patch *patch = patches; patch->name; patch++) {
		char *loc = memmem(base, length, patch->match, patch->matchlen);
		if (!loc) {
			if (patch->required)
				errx(131, "no match for patch %s", patch->name);
			continue;
		}
		loc -= patch->matchpos;
		if (dostrace)
			fprintf(dostrace, "applying patch %s at %p\n", patch->name, loc);

		// detect embedded address constants and replace them with flag values that are really obvious to spot in a
		// SIGSEGV trace. this helps if the supposedly "unreachable" code is reached, and also makes the CRC independent
		// of the address immediates in the code.
		if (patch->detect)
			for (detect_addr *addr = patch->detect; addr->name; addr++) {
				void *a = 0;
				for (int i = 0; addr->offsets[i] != (uint16_t) -1; i++) {
					uint16_t offset = addr->offsets[i];
					void **aptr = (void **) &loc[offset];
					if (i == 0)
						a = *aptr;
					else if (a != *aptr)
						errx(131, "incorrect address at offset 0x%03x: %p expecting %p", offset, *aptr, a);
					*aptr = (void *) 0xa5000000;
				}
				if (addr->bias != (uint16_t) -1)
					a += (uint32_t) loc + addr->bias;

				if (addr->target && *addr->target && *addr->target != a)
					errx(131, "incorrect address: %p expecting %p", a, *addr->target);
				if (dostrace)
					fprintf(dostrace, "  detected %s = %p\n", addr->name, a);
				if (addr->target)
					*addr->target = a;
			}

		// check that CRC matches, so we don't patch a spurious match and corrupt the program
		uint32_t crc = crc32(loc, patch->crclen);
		if (crc != patch->crc)
			errx(131, "spurious match for patch %s at %p: CRC %08x expect %08x", patch->name, loc, crc, patch->crc);
		memcpy(loc, patch->replacement, patch->replen);

		// patch in required addresses
		if (patch->patch)
			for (patch_addr *addr = patch->patch; addr->name; addr++) {
				uint32_t *value = addr->addr ? addr->addr : *addr->value;
				if (dostrace)
					fprintf(dostrace, "  patching %s = %p\n", addr->name, value);
				*(uint32_t **) &loc[addr->offset] = value;
			}

		size_t offset = loc - base;
		loc = memmem(loc + patch->crclen, length - offset - patch->crclen, patch->match, patch->matchlen);
		if (loc)
			errx(131, "ambiguous match for patch %s at %p", patch->name, loc);
	}
}
