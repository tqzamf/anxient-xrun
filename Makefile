CC=gcc
CFLAGS=-O2 -Wall -g -std=gnu99 -m32
LD=gcc
LDFLAGS=-m32
TARGETS=xrun

all: $(TARGETS)

clean:
	rm -f *.o *~ $(TARGETS)

xrun: xrun.o dosemu.o exeloader.o mwhcinit.o dosapi.o

.PHONY: all clean
