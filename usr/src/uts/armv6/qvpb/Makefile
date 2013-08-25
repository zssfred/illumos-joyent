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
UNIX_BIN	= $(OBJS_DIR)/$(UNIX)
GENUNIX		= genunix
GENUNIX_DIR	= ../../arm/$(GENUNIX)
#LIBOPTS		= -L $(GENUNIX_DIR)/$(OBJS_DIR) -l $(GENUNIX)
LIBOPTS		= -L $(OBJS_DIR) -l $(GENUNIX)
LIBGENUNIX	= $(OBJS_DIR)/libgenunix.so

OBJECTS	= \
	$(QVPB_OBJS:%=$(OBJS_DIR)/%) \
	$(CORE_OBJS:%=$(OBJS_DIR)/%) \
	$(KRTLD_OBJS:%=$(OBJS_DIR)/%) \
	$(OBJS_DIR)/zlib_obj.o

#
# Include common rules
#
include $(UTSBASE)/armv6/qvpb/Makefile.qvpb

ALL_TARGET 	= $(UNIX_BIN)
INSTALL_TARGET 	= $(UNIX_BIN)

CLEANFILES += \
	$(OBJECTS) \
	$(UNIX) \
	$(LIBGENUNIX)

CERRWARN	+= -_gcc=-Wno-parentheses
CERRWARN	+= -_gcc=-Wno-uninitialized
CERRWARN	+= -_gcc=-Wno-unused-label
CERRWARN	+= -_gcc=-Wno-unused-function
CERRWARN	+= -_gcc=-Wno-unused-variable
CERRWARN	+= -_gcc=-Wno-unused-but-set-variable

#
# XXX For some reason CTF_FLAGS aren't getting set for us.
#
CFLAGS += $(CTF_FLAGS)

def: $(DEF_DEPS)

all: $(ALL_DEPS)

clean: $(CLEAN_DEPS)

clobber: $(CLOBBER_DEPS)

install_h:

$(LIBGENUNIX): ../misc/fake_stubs.c
	$(COMPILE.c) -o $(OBJS_DIR)/fake_stubs.o ../misc/fake_stubs.c
	$(LD) -r $(LDFLAGS) -o $(OBJS_DIR)/genunix $(OBJS_DIR)/fake_stubs.o
	$(BUILD.SO) genunix $(OBJS_DIR)/genunix

#
# XXX When we have a real genunix we should uniquify against it...
#
$(UNIX_BIN): $(OBJECTS) $(LIBGENUNIX)
	$(LD) -dy -b -znointerp -e _start -o $@ $(OBJECTS) $(LIBOPTS) -MMapfile
	$(CTFMERGE) $(CTFMRGFLAGS) -L VERSION -o $@ $(OBJECTS)
	$(POST_PROCESS)
	pfexec ./tools/mkplatform.sh $(UNIX_BIN) $(OBJS_DIR)/genunix
	mv boot_archive $(OBJS_DIR)/

#
# Include common targets
#
include $(UTSBASE)/armv6/qvpb/Makefile.targ
