#ifndef _BINPATCH_H
#define _BINPATCH_H

#include <stdint.h>

typedef struct {
	char *name;
	uint32_t **target;
	int bias;
	int offsets[11];
} binpatch_detect;
typedef struct {
	int length;
	void *data;
} binpatch_instr;
typedef struct {
	char *name;
	int crclen;
	uint32_t crc;
	int matchpos;
	int matchlen;
	char *match;
	binpatch_instr patch[16];
	binpatch_detect detect[];
} bin_patch;
#define BP_EOL { NULL }

int binpatch(char *loadbase, size_t length, bin_patch *patch);

#define BPT_SPECIAL 0x8000
#define BPT_LAST 0x4000
#define BPT_LEN_MASK 0x0fff
#define BPT_CONST32 (BPT_SPECIAL | 4)
#define BPT_CONST16 (BPT_SPECIAL | 2)
#define BPT_CONST8 (BPT_SPECIAL | 1)
#define BPT_PAD(byte) (BPT_SPECIAL | BPT_LAST | (byte))

#define BP_MOV_EAX_IMM(imm) { 1, "\xb8" }, { BPT_CONST32, (void *) imm }
#define BP_MOV_EAX_VALUEOF(var) { 1, "\xa1" }, { BPT_CONST32, &var }
#define BP_CALL_VIA_EAX(func) BP_MOV_EAX_IMM(func), { 2, "\xff\xd0" }
#define BP_PUSH_ARG(num) { 2, "\xff\x75" }, { BPT_CONST8, (void *) (4 * (num) + 8) }

#define BP_ENTER { 3, "\x55" "\x89\xe5" }
#define BP_LEAVE { BPT_LAST | 2, "\x5d" "\xc3" }
#define BP_LEAVE_POP(bytes) { 2, "\x5d" "\xc2" }, { BPT_LAST | BPT_CONST16 , (void *) (bytes) }
#define BP_PAD_TO(bytes) { BPT_PAD(0x90), (void *) bytes }
#define BP_PAD_INT3(bytes) { BPT_PAD(0xcc), (void *) bytes }
#define BP_RET { BPT_LAST | 1, "\xc3" }
#define BP_RET_POP(bytes) { 1, "\xc2" }, { BPT_LAST | BPT_CONST16, (void *) (bytes) }

#define BP_SUB_ESP(bytes) { 2, "\x83\xec"}, { BPT_CONST8, (void *) bytes }
#define BP_ADD_ESP(bytes) { 2, "\x83\xc4"}, { BPT_CONST8, (void *) bytes }
#define BP_PUSH_GS { 2, "\x0f\xa8" }
#define BP_MOV_GS(loc) { 2, "\x8e\x2d" }, { BPT_CONST32, &loc }
#define BP_POP_GS { 2, "\x0f\xa9" }

#endif
