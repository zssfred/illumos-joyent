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

UTSBASE = ..

include Makefile.armv6

all		:=	TARGET= all
def		:=	TARGET= def
check		:=	TARGET= check
clean		:=	TARGET= clean
clobber		:=	TARGET= clobber
install_h	:=	TARGET= install_h

all def clean clobber: genassym $(IMPLEMENTATIONS)

genassym: FRC
	@cd $@; pwd; $(MAKE) $(NO_STATE) $(TARGET)

$(IMPLEMENTATIONS):	FRC
	@cd $@; pwd; THISIMPL=$@ $(MAKE) $(NO_STATE) $(TARGET)

install_h check: $(IMPLEMENTATIONS) FRC
	@cd sys; pwd; $(MAKE) $(TARGET)

FRC:
