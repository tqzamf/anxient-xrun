CC=gcc
CFLAGS=-O2 -Wall -g -std=gnu99 -m32 -Wno-address-of-packed-member
LD=gcc
LDFLAGS=-m32
TARGETS=xrun

all: $(TARGETS)

clean:
	rm -f *.o *~ $(TARGETS)

xrun: xrun.o dosemu.o exeloader.o dosapi.o binpatch.o

.PHONY: all clean
