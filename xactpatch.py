#!/usr/bin/python3
import io
import sys
import os

MAGIC = b"\x55\x8b\xec\x53\x56\x57\x8b\x7d\x08\x8b\x75\x14\xe8\x0b\xfe\xff\xff"
MORE_MAGIC = b"\xb8\x01\x00\x00\x00\xc3\x8b\x7d\x08\x8b\x75\x14\xe8\x0b\xfe\xff\xff"

if len(sys.argv) == 1:
	sys.stderr.write("usage: xactpatch.py xact.exe apr.exe xblox.exe ppr.exe\n")
	sys.exit(1)

for file in sys.argv[1:]:
	with io.open(file, 'rb') as exe:
		blob = exe.read()

	pos = blob.find(MAGIC)
	if pos < 0:
		pos = blob.find(MORE_MAGIC)
		if pos >= 0:
			print("skipping %s: already patched" % file)
		else:
			print("skipping %s: code snippet not matched!" % file)
		continue

	with io.open(file + "~", 'wb') as exeback:
		exeback.write(blob)
	blob = blob[:pos] + MORE_MAGIC + blob[pos + len(MAGIC):]
	with io.open(file, 'wb') as exe:
		exe.write(blob)
	print("patched %s" % file)
