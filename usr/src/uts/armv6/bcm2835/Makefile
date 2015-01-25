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

include $(UTSBASE)/armv6/bcm2835/Makefile.bcm2835

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
		$(BCM2835_CPU_KMODS) $(BCM2835_KMODS)

modlist:	unix \
		loader \
		$(BCM2835_CPU_KMODS) $(BCM2835_KMODS)

IMPLEMENTED_PLATFORM = Raspberry,Pi

install: $(ROOT_BCM2835_DIR) $(USR_BCM2835_DIR) \
	$(USR_BCM2835_INC_DIR) \
	$(USR_BCM2835_SBIN_DIR) \
	$(USR_BCM2835_LIB_DIR) \
	$(BCM2835_CRYPTO_LINKS) \
	unix .WAIT $(BCM2835_CPU_KMODS) \
	$(BCM2835_KMODS) loader

unix loader $(BCM2835_KMODS) $(BCM2835_CPU_KMODS): FRC
	@cd $@; pwd; $(MAKE) $(NO_STATE) $(TARGET)

install_h check:	FRC

#
#	Include common targets.
#
include $(UTSBASE)/armv6/bcm2835/Makefile.targ

