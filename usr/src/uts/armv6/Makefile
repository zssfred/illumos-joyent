#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#

#
# Copyright 2013 (c) Joyent, Inc.  All rights reserved.
#

#
# This drives the generation of all of the different platform modules that are
# based on armv6. Generally each different board or SOC will end up as its own
# platform and thus with its own unix. For those who have only ever really lived
# in i86pc with its psm modules, yes, this is a bit different. This Makefile
# itself is totally broken, but it's here to just give us a bit of something to
# start with. Yay, team.
#

include ../../Makefile.master

AS_CPPFLAGS = \
	-D_ASM \
	-I$(ROOT)/usr/include

OBJS = \
	locore.o \
	faketty.o

OBJCOPY=$(GNU_ROOT)/bin/gobjcopy

all: unix.bin

%.o: %.s
	$(AS) -P $(AS_CPPFLAGS) -o $@ $<

%.o: %.c
	$(COMPILE.c) -o $@ -c $<

unix: $(OBJS)
	$(LD) -dn -e _start -o $@ $(OBJS)

#
# XXX This should probably be done via elfextract. But for now we're using what
# we know, eg. OBJCOPY, even if it is kind of not what we want.
#
%.bin: %
	$(OBJCOPY) $< -O binary $@

clean:
	rm -f $(OBJS)

clobber: clean
	rm -f unix unix.bin
