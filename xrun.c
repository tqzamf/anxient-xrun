#define _GNU_SOURCE
#include <string.h>
#include <stdio.h>
#include <stdint.h>

#include "xrun.h"

extern char **environ;

int main(int argc, char **argv) {
	dosemu_init();

	uint32_t eip, esp, stacksize, loadbase, loadlimit, heaplimit, heapsize = 16 * 1024 * 1024;
	load_exe(argv[1], heapsize, &eip, &esp, &stacksize, &loadbase, &loadlimit, &heaplimit);
	fprintf(dostrace, "loaded: %08x .. %08x, heap to %08x\n", loadbase, loadlimit, heaplimit);
	fprintf(dostrace, "initial EIP=%08x, ESP=%08x size=%08x\n", eip, esp, stacksize);
	uint8_t *pos = memmem((void *) loadbase, loadlimit - loadbase, "\x75\x14\xe8\x0b\xfe", 5);
	if (pos) {
		fprintf(dostrace, "patched out hardware access at %p\n", &pos[-10]);
		memcpy(&pos[-10], "\xb8\x01\x00\x00\x00\xc3", 6);
	}

	// yes, we just pass the entire shebang... BASH option, PATH, XAUTHORITY... XACT is at its heart
	// a UNIX toolchain and just simply doesn't care. and while it translates / to \, it doesn't even
	// notice that it's messing with a UNIX-style path here ;)
	init_mwhc((void *) eip, heapsize, esp, stacksize, loadbase, loadlimit, heaplimit, environ, &argv[1]);
}
