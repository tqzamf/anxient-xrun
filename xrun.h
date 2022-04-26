#ifndef _XRUN_H
#define _XRUN_H

#include <stdint.h>

#define PAGEMASK 4095

void dosemu_init(void);
extern FILE *dostrace;
void load_exe(char *filename, uint32_t heapsize, uint32_t *eip, uint32_t *esp, uint32_t *stacksize, uint32_t *loadbase,
		uint32_t *loadlimit, uint32_t *heaplimit);
void init_mwhc(uint8_t *ep, uint32_t heapsize, uint32_t esp, uint32_t stacksize, uint32_t loadbase, uint32_t loadlimit,
		uint32_t heaplimit, char **envv, char **argv);

struct regs {
	union {
		uint32_t eax;
		uint16_t ax;
		struct {
			uint8_t al;
			uint8_t ah;
		};
	};
	union {
		uint32_t ebx;
		uint16_t bx;
		struct {
			uint8_t bl;
			uint8_t bh;
		};
	};
	union {
		uint32_t ecx;
		uint16_t cx;
		struct {
			uint8_t cl;
			uint8_t ch;
		};
	};
	union {
		void *edx; // if used, almost invariably a pointer
		uint16_t dx;
		struct {
			uint8_t dl;
			uint8_t dh;
		};
	};
	union {
		void *esi; // only ever used as a pointer
		uint16_t si;
	};
	int carry:1;
} __attribute__((packed));

typedef void (*dosapi_handler)(struct regs *regs);
extern dosapi_handler dosapi[];

#endif
