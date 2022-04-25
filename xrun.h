#ifndef _XRUN_H
#define _XRUN_H

#include <stdint.h>

#define PAGEMASK 4095

void dosemu_init(void);
void load_exe(char *filename, uint32_t heapsize, uint32_t *eip, uint32_t *esp, uint32_t *stacksize, uint32_t *loadbase,
		uint32_t *loadlimit, uint32_t *heaplimit);
void init_mwhc(uint8_t *ep, uint32_t heapsize, uint32_t esp, uint32_t stacksize, uint32_t loadbase, uint32_t loadlimit,
		uint32_t heaplimit, char **envv, char **argv);

#endif
