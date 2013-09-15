#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#

#
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE	= ../../..

#
#	Define the module and object file sets.
#
UNIX		= unix
OBJECTS		= $(QVPB_OBJS:%=$(OBJS_DIR)/%) \
		  $(CORE_OBJS:%=$(OBJS_DIR)/%) \
		  $(KRTLD_OBJS:%=$(OBJS_DIR)/%)

ROOTMODULE	= $(ROOT_QVPB_KERN_DIR)/$(UNIX)
UNIX_BIN	= $(OBJS_DIR)/$(UNIX)

LIBS		= $(GENLIB)

GENUNIX		= genunix
GENUNIX_DIR	= ../../../arm/$(GENUNIX)
GENOPTS		= -L $(GENUNIX_DIR)/$(OBJS_DIR) -l $(GENUNIX)

LIBOPTS		= $(GENOPTS)

CTFEXTRAOBJS	= $(OBJS_DIR)/vers.o

#
#	Include common rules.
#
include $(UTSBASE)/armv6/qvpb/Makefile.qvpb

#
#	Define targets
#
ALL_TARGET	= $(UNIX_BIN)
INSTALL_TARGET	= $(UNIX_BIN) $(ROOTMODULE)

#
#	This is UNIX_DIR. Use a short path.
#
UNIX_DIR	= .

#
#	Overrides
#
CLEANFILES	+= $(OBJECTS) \
		   $(UNIX_O)

CLOBBERFILES	= $(CLEANFILES) $(UNIX_BIN)

CFLAGS += $(CCVERBOSE)

CERRWARN	+= -_gcc=-Wno-parentheses
CERRWARN	+= -_gcc=-Wno-uninitialized
CERRWARN	+= -_gcc=-Wno-unused-label
CERRWARN	+= -_gcc=-Wno-unused-function
CERRWARN	+= -_gcc=-Wno-unused-variable
CERRWARN	+= -_gcc=-Wno-unused-but-set-variable

# The mapfile used to link unix
MAPFILE		= $(UTSBASE)/armv6/qvpb/conf/Mapfile

#
#	Default build targets.
#
.KEEP_STATE:

def:		$(DEF_DEPS)

all:		$(ALL_DEPS)

clean:		$(CLEAN_DEPS)

clobber:	$(CLOBBER_DEPS)

MKPLATFORM	= $(UTSBASE)/$(PLATFORM)/tools/mkplatform.sh

install:  	$(INSTALL_DEPS)
	pfexec $(MKPLATFORM) -u $(ROOT_QVPB_MOD_DIR:$(ROOT)/%=/%) $(UNIX_BIN) \
	    $(GENUNIX_DIR)/$(OBJS_DIR)/genunix
	$(MV) boot_archive $(OBJS_DIR)/

symcheck:       $(SYM_DEPS)

$(UNIX_BIN): $(UNIX_O) $(MAPFILE) $(LIBS) $(DTRACESTUBS)
	$(LD) -dy -b -znointerp -o $@ -e _start -M $(MAPFILE) \
	    $(UNIX_O) $(LIBOPTS) $(DTRACESTUBS)
	$(CTFMERGE_UNIQUIFY_AGAINST_GENUNIX)
	$(POST_PROCESS)

$(UNIX_O):	$(OBJECTS) $(OBJS_DIR)/vers.o
	$(LD) -r -o $@ $(OBJECTS) $(OBJS_DIR)/vers.o

symcheck.targ:	$(UNIX_O) $(KRTLD_O) $(MODSTUBS_O) $(LIBS) $(DTRACESTUBS) 
	$(LD) -dy -b -o $(SYM_MOD) -M $(MAPFILE) \
	$(UNIX_O) $(KRTLD_O) $(MODSTUBS_O) $(LIBOPTS) $(DTRACESTUBS) 

$(KRTLD_O):	$(KRTLD_OBJECTS)
	$(LD) -r -o $@ -M$(KRTLD_MAPFILE) $(KRTLD_OBJECTS)

#
#	Include common targets.
#
include $(UTSBASE)/armv6/qvpb/Makefile.targ
