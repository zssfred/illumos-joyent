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
# Copyright (c) 2015, Josef 'Jeff' Sipek <jeffpc@josefsipek.net>
#

UTSBASE = ../..

include $(UTSBASE)/armv7/bcm2836/Makefile.bcm2836

def		:=	TARGET= def
all		:=	TARGET= all
install		:=	TARGET= install
install_h	:=	TARGET= install_h
clean		:=	TARGET= clean
clobber		:=	TARGET= clobber
lint		:=	TARGET= lint
lintlib		:=	TARGET= lintlib
modlintlib	:=	TARGET= modlintlib
modlist		:=	TARGET= modlist
modlist		:=	NO_STATE= -K $$MODSTATE$$$$
clean.lint	:=	TARGET= clean.lint
check		:=	TARGET= check


#
#	Default build targets.
#
.KEEP_STATE:

def all clean clobber clean.lint: unix loader .WAIT \
		$(BCM2836_CPU_KMODS) $(BCM2836_KMODS)

modlist:	unix \
		loader \
		$(BCM2836_CPU_KMODS) $(BCM2836_KMODS)

IMPLEMENTED_PLATFORM = Raspberry,Pi2

install: $(ROOT_BCM2836_DIR) $(USR_BCM2836_DIR) \
	$(USR_BCM2836_INC_DIR) \
	$(USR_BCM2836_SBIN_DIR) \
	$(USR_BCM2836_LIB_DIR) \
	$(BCM2836_CRYPTO_LINKS) \
	unix .WAIT $(BCM2836_CPU_KMODS) \
	$(BCM2836_KMODS) loader

unix loader $(BCM2836_KMODS) $(BCM2836_CPU_KMODS): FRC
	@cd $@; pwd; $(MAKE) $(NO_STATE) $(TARGET)

install_h check:	FRC

#
#	Include common targets.
#
include $(UTSBASE)/armv7/bcm2836/Makefile.targ

