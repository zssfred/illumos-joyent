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
# Copyright 2018 (c) Joyent, Inc.  All rights reserved.
#

UTSBASE = ../..

UNIX		= unix
UNIX_BIN	= $(OBJS_DIR)/$(UNIX)
GENUNIX		= genunix
GENUNIX_DIR	= ../../arm/$(GENUNIX)
#LIBOPTS	= -L $(GENUNIX_DIR)/$(OBJS_DIR) -l $(GENUNIX)
LIBOPTS		= -L $(OBJS_DIR) -l $(GENUNIX)
LIBGENUNIX	= $(OBJS_DIR)/libgenunix.so

#
# Include common rules
#
include $(UTSBASE)/aarch64/qv/Makefile.qv

ALL_TARGET = $(UNIX_BIN)
INSTALL_TARGET = $(UNIX_BIN)

OBJECTS	= \
	$(QV_OBJS:%=$(OBJS_DIR)/%) \
	$(CORE_OBJS:%=$(OBJS_DIR)/%) \
	$(KRTLD_OBJS:%=$(OBJS_DIR)/%) \
	$(OBJS_DIR)/zlib_obj.o

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

#XXX for some reason CTF_FLAGS arent getting set
# ASFLAGS += $(CTF_FLAGS)
CFLAGS += $(CTF_FLAGS)
CFLAGS64 += $(CTF_FLAGS)

OBJCOPY=$(GNU_ROOT)/bin/objcopy

all: $(ALL_DEPS)

def: $(DEF_DEPS)

clean: $(CLEAN_DEPS)

clobber: $(CLOBBER_DEPS)

install_h:

$(LIBGENUNIX): ../misc/fake_stubs.c
	$(COMPILE64.c) -o $(OBJS_DIR)/fake_stubs.o ../misc/fake_stubs.c
	$(LD) -r $(LDFLAGS) -o $(OBJS_DIR)/genunix $(OBJS_DIR)/fake_stubs.o
	$(BUILD.SO) genunix $(OBJS_DIR)/genunix

$(UNIX_BIN): $(OBJECTS) $(LIBGENUNIX)
	$(LD) -dy -b -znointerp -e _start -o $@ $(OBJECTS) $(LIBOPTS) -M test_mapfile
	$(CTFMERGE) $(CTFMRGFLAGS) -L VERSION -o $@ $(OBJECTS)
	$(POST_PROCESS)
	pfexec ./tools/mkplatform.sh $(UNIX_BIN) $(OBJS_DIR)/genunix
	mv boot_archive $(OBJS_DIR)/

# %.bin: %
# 	$(OBJCOPY) $< -O binary $@
# 	pfexec ./tools/mkplatform.sh $@ debug64/genunix

#
# Include common targets
#
include $(UTSBASE)/aarch64/qv/Makefile.targ
