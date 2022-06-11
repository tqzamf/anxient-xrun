#!/bin/sh
exec dosbox -conf /opt/xilinx/xactstep/dosbox.conf -c "xact -gvesa16 -e $*" -c exit
