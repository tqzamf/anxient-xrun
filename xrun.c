//#define _XOPEN_SOURCE 500
//#define _GNU_SOURCE
//#include <ucontext.h>
//#include <string.h>
//#include <signal.h>
#include <stdio.h>
//#include <stdlib.h>
#include <stdint.h>
//#include <unistd.h>
//#include <err.h>
//#include <sys/mman.h>
//#include <sys/types.h>
//#include <sys/stat.h>
//#include <fcntl.h>

#include "xrun.h"

int main(int argc, char **argv) {
	dosemu_init();
	uint32_t eip, esp, stacksize, loadbase, loadlimit, heaplimit, heapsize = 16 * 1024 * 1024;
	load_exe(argv[1], heapsize, &eip, &esp, &stacksize, &loadbase, &loadlimit, &heaplimit);
	printf("loaded: %08x .. %08x, heap to %08x\n", loadbase, loadlimit, heaplimit);
	printf("initial EIP=%08x, ESP=%08x size=%08x\n", eip, esp, stacksize);
	char *envv[] = { "XACT=X:\\", NULL };
	init_mwhc((void *) eip, heapsize, esp, stacksize, loadbase, loadlimit, heaplimit, envv, &argv[1]);
}
