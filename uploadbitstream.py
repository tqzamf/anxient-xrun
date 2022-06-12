#!/usr/bin/python3
# very rough tool to upload a .rbt bitstream via a Bus Pirate
# pins are wired as for JTAG:
# MOSI/TDI = DIN
# CLK/TCK = CCLK
# MISO/TDO = DONE/PROG
# CS/TMS = DONE/PROG via a diode, cathode to CS/TMS, anode to DONE/PROG
import serial, re, sys, io

# open buspirate (hardcoded)
port = serial.Serial("/dev/ttyUSB0", 115200, timeout=1)
def write(cmd):
	port.write(cmd.encode("utf-8") + b"\n")
	port.flush()
def read(end):
	return port.read_until(end.encode("utf-8")).decode("utf-8")

def menu(option):
	prompt = read(")>").split("\r\n")
	opt = None
	for line in prompt:
		m = re.search(r"([0-9]+)\. " + option, line)
		if m:
			opt = m.group(1)
	if opt is None:
		sys.stderr.write("no option %s:\n" % option)
		for line in prompt:
			sys.stderr.write("  %s\n" % line)
		raise Exception("menu selection failed")
	write(opt)
def exec(cmd):
	write(cmd)
	input = read("SPI>").split("\r\n")
	if input[0] != cmd or input[-1] != "SPI>":
		sys.stderr.write("command misbehaved:\n")
		for line in input:
			sys.stderr.write("  %s\n" % line)
		raise Exception("command execution failed")
	return input[1:-1]

# leave any menus that the buspirate might be stuck in
write("")
while True:
	line = read(">")
	if not re.search(r"\([0-9]+\)>", line):
		break # out of menu
	write("")
# navigate the menu to select 1MHz SPI mode
write("m")
menu("SPI")
menu("1MHz")
menu("Idle high")
menu("Idle to active")
menu("Middle")
menu("/CS")
menu("Normal")
read("SPI>")
# set MSB first, pulse PROG (10ms)
exec("l[%:10]")

bits = []
with io.open(sys.argv[1], "r") as rbt:
	acc = ""
	for line in rbt:
		line = line.rstrip()
		if not re.match("[01]+", line):
			continue # skip header lines

		# begroup into 8-bit groups called "bytes"
		while True:
			rem = 8 - len(acc)
			if rem > len(line):
				break;
			acc += line[0:rem]
			line = line[rem:]
			bits.append(int(acc, 2))
			acc = ""
		acc += line

	# pad any leftover bits with ones. might up sending 8 additional 1 bits, but that's fine
	while len(acc) < 8:
		acc += "1"
	bits.append(int(acc, 2))

# send to chip, byte by byte
sys.stdout.write("upload")
while len(bits) > 16:
	exec(" ".join("%d" % x for x in bits[0:16]))
	bits = bits[16:]
	sys.stdout.write(".")
	sys.stdout.flush()
exec(" ".join("%d" % x for x in bits[0:16]))
sys.stdout.write(".\nMISO aka DONE should now read H:\n")
# at this point, MISO = H (ie. DONE is active)
for line in exec("v"):
	print(line)
