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
# Copyright (c) 2013, Joyent, Inc.  All rights reserved.
#

UTSBASE = ../..

UNIX		= unix

#
# Include common rules
#
include $(SRC)/Makefile.master
include $(UTSBASE)/armv6/bcm2835/Makefile.files
include $(UTSBASE)/armv6/Makefile.armv6

OBJECTS	= \
	$(BCM2835_OBJS:%=$(OBJS_DIR)/%) \
	$(CORE_OBJS:%=$(OBJS_DIR)/%)

CLEANFILES += \
	$(OBJECTS) \
	$(UNIX)

CERRWARN	+= -_gcc=-Wno-parentheses
CERRWARN	+= -_gcc=-Wno-uninitialized

#
# XXX We have no CTF support, so override CTFCONVERT_O for now.
#
CTFCONVERT_O = /bin/true

def: $(DEF_DEPS)

all: def $(UNIX) 

clean: $(CLEAN_DEPS)

clobber: $(CLOBBER_DEPS)

install_h:

$(UNIX): $(OBJECTS)
	$(LD) -dn -e _start -o $@ $(OBJECTS)

#
# Include common targets
#
include $(UTSBASE)/armv6/bcm2835/Makefile.targ
