# Makefiles for XACTstep with xrun

this directory contains Makefiles that compile a design using xrun and XACTstep. there are several files because
different chip families use different tools and different intermediate files.

- `Makefile.2k` and `Makefile.3k` both work for XC2000, XC3000 and XC3100 chips. the resulting bitstream also works for
  XC3000A / XC3100A chips because they are bitstream compatible. (the difference between the file is whether they build
  the demo design for an XC2000 or XC3000 series chip.)
- `Makefile.3ka` works for XC3000A and XC3100A chips. the resulting bitstream does *not* necessarily work for XC3000
  and XC3100 chips because the A-suffix chips have additional features that the bitstream might be using.
- `Makefile.5k2` works for XC5200 and XC4000 chips.

these Makefiles also use XSynth to build the design from Verilog. the demo design `blinker.v` simply blinks a few LEDs,
but is enough to verify that the toolchain (or a chip) works. they also call `improvex`, which is part of the ds371 ABEL
package, not the primary ds502 package. it can be removed by replacing

```
%.xtf: %.xnf
	$(XRUN) improvex -o temp.xnf -p 3k -x $<
	$(XRUN) xnfmerge temp.xnf temp.xff
```

with 

```
%.xtf: %.xnf
	$(XRUN) xnfmerge $< temp.xff
```

however, because XSynth puts zero effort into reducing logic depth, `improvex` greatly improves speed (at least in terms
of estimated maximum clock frequency). it does tend to produce a larger but faster design, especially when there are
unused CLBs.

# `.gitignore`

XACTstep uses a ridiculous number of temporary files. `gitignore.txt` lists all the extensions that XACTstep might
produce, and can be directly used as a `.gitignore` file. note that it also excludes:

- `.xnf` files, because while they're the input design to XACTstep, they themselves are usually generated.
- the `.bit` and `.rbt` output bitstream files. it may be a good idea to check those in anyway because it takes an
  XACTstep / xrun setup to rebuild them. `.rbt` is a git-friendly ASCII file.
- the infamous `.lca` files. these can be edited and a design maintained from them, but in most cases it's a generated
  file that will be rebuilt anyway. however, it only takes `makebits` to create a bitstream from an `.lca` file.
