#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
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
# Copyright (c) 2001 by Sun Microsystems, Inc.
# All rights reserved.
#

include		../../Makefile.tools

SUBDIRS	= aarch64 arm i386 sparc

all	:= TARGET= all
install	:= TARGET= install
clean	:= TARGET= clean
clobber	:= TARGET= clobber
lint	:= TARGET= lint

.KEEP_STATE:

install all clean clobber lint: $(SUBDIRS)

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) TARG_MACH=$@ $(TARGET)

install: $(ROOTONBLDBINMACH)/ctfconvert $(ROOTONBLDBINMACH)/ctfmerge

$(ROOTONBLDBINMACH)/ctfmerge: FRC
	$(RM) $@; $(SYMLINK) ctfmerge.$(NATIVE_MACH) $@

$(ROOTONBLDBINMACH)/ctfconvert: FRC
	$(RM) $@; $(SYMLINK) ctfconvert.$(NATIVE_MACH) $@

FRC:
