#ifndef _XRUN_H
#define _XRUN_H

#include <stdint.h>

#define PAGEMASK 4095

void dosemu_init(char *tracefile);

void load_exe(char *filename, uint32_t heapsize, uint32_t *eip, uint32_t *esp, uint32_t *stacksize, uint32_t *loadbase,
		uint32_t *loadlimit, uint32_t *heaplimit);
void init_mwhc(uint8_t *ep, uint32_t heapsize, uint32_t esp, uint32_t stacksize, uint32_t loadbase, uint32_t loadlimit,
		uint32_t heaplimit, char **envv, char **argv);

#define EFLAG_CARRY 0x01
#define EFLAG_ZERO  0x40
typedef union {
	char *ptr;
	uint32_t ex;
	uint16_t x;
	struct {
		uint8_t l;
		uint8_t h;
	};
} x86reg;
extern x86reg *eax, *ebx, *ecx, *edx, *esi, *edi;
extern uint32_t *eflags;

extern FILE *dostrace;
struct dta;
uint32_t dos_find_first(char *filename, struct dta *dta);
uint32_t dos_access(char *filename, uint32_t mode);
void dos_unimpl(void);
typedef uint32_t (*dosapi_handler)(void);
extern dosapi_handler dosapi[256];

typedef struct {
	char *name;
	uint32_t **target;
	uint16_t bias;
	uint16_t offsets[11];
} detect_addr;
typedef struct {
	char *name;
	uint16_t offset;
	void *addr;
	uint32_t **value;
} patch_addr;
typedef struct {
	char *name;
	uint16_t required;
	uint16_t replen;
	char *replacement;
	int16_t matchpos;
	uint16_t matchlen;
	char *match;
	uint16_t crclen;
	uint32_t crc;
	detect_addr *detect;
	patch_addr *patch;
} bin_patch;

void binpatch(char *loadbase, size_t length, bin_patch *patches);

#endif
