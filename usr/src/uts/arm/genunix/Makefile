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
# Copyright (c) 2013, Joyent, Inc.  All rights reserved.
#

#
#	This makefile drives the production of the generic
#	unix kernel module.
#
#	ARM implementation architecture dependent
#

#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE	= ../..

#
#	Define the module and object file sets.
#
MODULE		= genunix
GENUNIX		= $(OBJS_DIR)/$(MODULE)

OBJECTS		= $(GENUNIX_OBJS:%=$(OBJS_DIR)/%) \
		  $(NOT_YET_KMODS:%=$(OBJS_DIR)/%)

ROOTMODULE	= $(ROOT_KERN_DIR)/$(MODULE)

LIBGEN		= $(OBJS_DIR)/libgenunix.so
LIBSTUBS	= $(GENSTUBS_OBJS:%=$(OBJS_DIR)/%)

#
#      Include common rules.
#
include $(UTSBASE)/arm/Makefile.arm

#
#	Define targets
#
ALL_TARGET	= $(LIBGEN)
INSTALL_TARGET	= $(GENUNIX) $(ROOTMODULE) $(LIBGEN)

#
#	Overrides
#
CLEANFILES	+= $(LIBSTUBS) $(LIBGEN)
BINARY		=

#
# Non-patch genunix builds merge a version of the ip module called ipctf.  This
# is to ensure that the common network-related types are included in genunix and
# can thus be uniquified out of other modules.  We don't want to do this for
# patch builds, since we can't guarantee that ip and genunix will be in the same
# patch.
#
#IPCTF_TARGET	= $(IPCTF)
IPCTF_TARGET=	#XXX: We don't have ip yet
$(PATCH_BUILD)IPCTF_TARGET =

CPPFLAGS	+= -I$(SRC)/common
CPPFLAGS	+= -I$(SRC)/uts/common/fs/zfs

#XXX: If this is necessary, something is wrong surely?
CPPFLAGS	+= -I$(UTSBASE)/armv6

CERRWARN	+= -_gcc=-Wno-unused-label
CERRWARN	+= -_gcc=-Wno-unused-variable
CERRWARN	+= -_gcc=-Wno-unused-value
CERRWARN	+= -_gcc=-Wno-unused-function
CERRWARN	+= -_gcc=-Wno-parentheses
CERRWARN	+= -_gcc=-Wno-switch
CERRWARN	+= -_gcc=-Wno-type-limits
CERRWARN	+= -_gcc=-Wno-uninitialized
CERRWARN	+= -_gcc=-Wno-clobbered
CERRWARN	+= -_gcc=-Wno-empty-body

#
# XXX fix this
#
CERRWARN	+= -_gcc=-Wno-unused-but-set-variable

#
# Ensure that lint sees 'struct cpu' containing a fully declared
# embedded 'struct machcpu'
#
LINTFLAGS	+= -D_MACHDEP -I../../armv6

#
#	Default build targets.
#
.KEEP_STATE:

#
# XXX I clearly have something wrong here such that this Makefile is being made
# in the wrong one. I've changed the default target and def/all as a result.
#
def:		$(DEF_DEPS)

all:		$(ALL_DEPS)

clean:		$(CLEAN_DEPS)

clobber:	$(CLOBBER_DEPS)

lint:		$(LINT_DEPS)

modlintlib:	$(MODLINTLIB_DEPS)

clean.lint:	$(CLEAN_LINT_DEPS)

install:	$(INSTALL_DEPS)

$(LIBGEN):	$(GENUNIX) $(LIBSTUBS)
	$(BUILD.SO) $(GENUNIX) $(LIBSTUBS)

$(IPCTF_TARGET) ipctf_target: FRC
	@cd $(IPDRV_DIR); pwd; $(MAKE) ipctf.$(OBJS_DIR)
	@pwd

$(GENUNIX): $(IPCTF_TARGET) $(OBJECTS)
	$(LD) -r $(LDFLAGS) -o $@ $(OBJECTS)
	$(CTFMERGE_GENUNIX_MERGE)
	$(POST_PROCESS)

#
#	Include common targets.
#
include $(UTSBASE)/arm/Makefile.targ

#
# Override.
#
$(MODULE).lint := GEN_LINT_LIB =
