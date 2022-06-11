# purpose

run Xilinx XACTstep 5.2.0 on a modern system, quickly and non-interactively from a Makefile. this is possible because
XACTstep is actually a 32-bit i386 binary with Phar Lap 386|DOS-Extender integrated into the binaries, so the i386
code can instead be run natively on modern x86 CPUs. since XACTstep comes from the Unix workstation world, it has
astonishingly few actual dependencies on DOS, and happily accepts Unix-style pathnames as long as they are presented
through the DOS APIs.

XACTstep is, of course, the only way to target XC2000/L, XC3000, XC3100 family FPGAs and XC7300 series CPLDs. it can
also be used to target XC3000A/L, XC3100A/L, XC4000/A/H and XC5200 series parts, using a slightly different set of
tools for each chip family. (yes, the XC3000A family does use very different tools than the XC3000 family!)

various old releases of Xilinx software have recently been made available on archive.org, including a version of
[XACTstep 5.2.0](https://archive.org/details/1995-1996-xilinx-xact-520-600-601). they run well in DOSBox, but do so at
period-accurate speed (or lack of speed), and obviously in an interactive DOS environment. the tools do run remarkably
fast on a modern multi-GHz CPU ;)

# installation

in order to use xrun, a copy of XACTstep is required, preferably 5.2.0 because this is the latest and most complete
version in terms of device support. also, the CD as archived by archive.org contains all relevant files in the `xact`
directory. this entire directory can be copied somewhere and is immediately ready to use.

xrun itself is built using `make`, and then simply copied to a convenient location:

```
make clean all
cp xrun /opt/xilinx/xrun
```

because xrun natively runs XACTstep's 32-bit x86 code, it has to be a 32-bit x86 binary itself. on 32- or 64-bit x86,
that's what `gcc -m32` produces, and it's what the Makefile is set up to use. it should be possible to cross-compile it
using the `i686-*-gcc` toolchain on other architectures, but running it on an ARMv7 using `qemu-user` failed to allocate
memory at address zero. (it should be doable by tweaking `qemu-user`)

XACTstep can also be installed. installing only the `ds502` product saves about 100MB of installation space (of ~150MB).
however, ~50MB of that is very useful documentation in the `online` directory, including the "Development System User
Guide" at `online/online/dsuser.pdf`. also, installing from DOSBox produces all-uppercase names, while XACTstep
internally uses all-lowercase names. xrun doesn't bother to translate these; rename all files to lowercase to use them.

# usage

in order to run the XACTstep binaries, the sysctl `vm.mmap_min_addr` has to be set to allow mapping memory at address 0,
that is:

```
sudo sysctl vm.mmap_min_addr=0
```

alternatively, `vm.mmap_min_addr=0` can be put into `/etc/sysctl.conf` or `/etc/sysctl.d/mmap_min_addr.conf`. that
doesn't avoid the above sysctl command; it simply avoids having to repeat it after every reboot.

the reason for this tweak is that the XACTstep binaries expect to be running in a flat 32-bit address space, starting
at address 0. that is what Phar Lap 386|DOS-Extender sets them up for, and that is how the binaries are linked. Linux
provides a flat 32-bit address space, but typically doesn't allow memory to be mapped below address 0x00010000 for
security reasons (it makes it much harder to exploit NULL pointer dereferences). this has been required for wine and
qemu for some time; [the Debian wiki](https://wiki.debian.org/mmap_min_addr) explains it in more detail.

after that, XACTstep can be used almost exactly as described in Xilinx' "Development System User Guide": the `XACT`
environment variable has to point to the directory where XACTstep has been installed, and every command has to be
prepended with `xrun`. for example, instead of `xnfmerge` (the first step of compilation), the command would be
something like `XACT=/opt/xilinx/xactstep /opt/xilinx/xrun xnfmerge`. note that `XACT` is set to the Linux path: xrun
doesn't bother to present DOS pathnames because XACTstep doesn't even seem to notice.

xrun itself doesn't take any options. the first argument has to be the name of the tool or the path to its `.exe` file.
all remaining arguments are simply passed to the tool itself. however, the environment variable `XRUN_TRACE` can be set
to the name of a file to log DOS API calls to. this can be very helpful to trace failures, which will almost invariably
show up as segfaults. (they aren't. usually it's an `INT 21` DOS call or some other privileged instruction.) setting
`XRUN_TRACE` also sets up a SIGSEGV handler that emulates DOS calls, so it may actually fix the bug for the time being.

# alternatives

## DOSBox

XACTstep works fine in DOSBox. some binaries have to be patched with `xactpatch.py` because they try to access the
parallel port, and DOSBox doesn't emulate anything other than a `/dev/null` parallel port. `dosbox.conf` demonstrates
an example config file for XACTstep installed in `/opt/xilinx/xactstep`. you may want to set `keyboardlayout` to your
preferred keyboard layout if you aren't German, and adjust `windowresolution` so it fills a readable amount of your
screen.

one important tool that requires DOSBox is the `editlca` command of `xact.exe`. actually editing `.lca` files at that
level isn't recommended, but it's a great way to check a design. `editlca.sh` shows how to directly start a command in
DOSBox; omitting `-e $*` would start the main XACTstep GUI. to ungrab the mouse, press Ctrl-F10.

however, DOSBox pops up a window, and on a 3GHz CPU it is equivalent to a ~25MHz i386. that's actually an advantage for
speed-sensitive games, but it means XACTstep runs about as fast as it did back in the day: very slowly.

# Xilinx Alliance / Foundation Series toolchains

the Alliance / Foundation toolchains can target the XC3000A/L, XC3100A/L, XC4000* + Spartan-I and XC5200 FPGA families,
as well as XC9500/XL CPLDs and possibly even early Virtex chips. they do not support XC2000 or XC3000/XC3100, again
demonstrating that the XC3000 and XC3000A series are very different. Xilinx Foundation Series 3.1i is also available
from archive.org, but is an exercise in software incompatibility to install and run. (Windows 7 32-bit seems to be the
most recent system that it sort-of runs on. its native environment would probably have been NT 3.51 or Windows 2000.)

it does, however, provide period-accurate schematic entry, which can cause period-accurate amounts of frustration. do
not forget to add IO pad symbols for IO pads (IPAD and OPAD symbols, not the hierarchy connectors)!
