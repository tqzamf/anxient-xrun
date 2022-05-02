#define _GNU_SOURCE
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <err.h>

#include "xrun.h"
#include "binpatch.h"

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

int binpatch(char *base, size_t length, bin_patch *patch) {
	char *loc = memmem(base, length, patch->match, patch->matchlen);
	if (!loc) {
		if (dostrace)
			fprintf(dostrace, "skipping patch %s\n", patch->name);
		return 0;
	}
	loc -= patch->matchpos;
	if (dostrace)
		fprintf(dostrace, "applying patch %s at %p\n", patch->name, loc);

	// detect embedded address constants and replace them with flag values that are really obvious to spot in a
	// SIGSEGV trace. this helps if the supposedly "unreachable" code is reached, and also makes the CRC independent
	// of the address immediates in the code.
	for (binpatch_detect *addr = patch->detect; addr->name; addr++) {
		void *target = 0;
		for (int i = 0; addr->offsets[i] > 0; i++) {
			uint16_t offset = addr->offsets[i];
			void **aptr = (void **) &loc[offset];
			void *current = addr->bias >= 0 ? *aptr + (uint32_t) aptr + addr->bias : *aptr;
			if (i == 0)
				target = current;
			else if (target != current)
				errx(131,
						"failed to apply patch %s at %p, inconsistent address for %s at offset 0x%03x: %p expecting %p",
						patch->name, loc, addr->name, offset, current, target);
			*aptr = (void *) 0xa5000000;
		}

		if (addr->target && *addr->target && *addr->target != target)
			errx(131, "failed to apply patch %s at %p, inconsistent address for %s: %p expecting %p",
					patch->name, loc, addr->name, target, *addr->target);
		if (dostrace)
			fprintf(dostrace, "  detected %s = %p\n", addr->name, target);
		if (addr->target)
			*addr->target = target;
	}

	// check that CRC matches, so we don't patch a spurious match and corrupt the program
	uint32_t crc = crc32(loc, patch->crclen);
	if (crc != patch->crc)
		errx(131, "spurious match for patch %s at %p: CRC %08x expect %08x", patch->name, loc, crc, patch->crc);

	// replace by defined code
	int pos = 0;
	binpatch_instr *instr = patch->patch;
	while (1) {
		int len = instr->length & BPT_LEN_MASK;
		if (instr->length & BPT_SPECIAL) {
			switch (instr->length) {
			case BPT_CONST32:
			case BPT_LAST | BPT_CONST32:
				*(void **) &loc[pos] = instr->data;
				break;
			case BPT_CONST16:
			case BPT_LAST | BPT_CONST16:
				*(uint16_t *) &loc[pos] = (uint32_t) instr->data;
				break;
			case BPT_CONST8:
			case BPT_LAST | BPT_CONST8:
				*(uint8_t *) &loc[pos] = (uint32_t) instr->data;
				break;
			case BPT_PAD(0x90):
			case BPT_PAD(0xcc): ;
				uint8_t byte = instr->length & 255;
				len = (uint32_t) instr->data - pos;
				memset(&loc[pos], byte, len);
				break;
			default:
				errx(131, "illegal instruction type %04x in patch %s", instr->length, patch->name);
			}
		} else
			memcpy(&loc[pos], instr->data, len);

		pos += len;
		if (instr->length & BPT_LAST)
			break;
		instr++;
	}
	if (pos > patch->crclen)
		errx(131, "too many instructions for patch %s: %d bytes max %d", patch->name, pos, patch->crclen);

	size_t offset = loc - base;
	loc = memmem(loc + patch->crclen, length - offset - patch->crclen, patch->match, patch->matchlen);
	if (loc)
		errx(131, "ambiguous match for patch %s at %p", patch->name, loc);
	return 1;
}
