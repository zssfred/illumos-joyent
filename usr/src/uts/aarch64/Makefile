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

# include $(SRC)/Makefile.master

UTSBASE = ..

include Makefile.aarch64

all		:=	TARGET= all
def		:=	TARGET= def
check		:=	TARGET= check
clean		:=	TARGET= clean
clobber		:=	TARGET= clobber
install_h	:=	TARGET= install_h
modlist	:=	TARGETf= modlist
modlist	modlist.armv8	:=	NO_STATE= -k $$MODSTATE$$$$


.KEEP_STATE:

.PARALLEL: $(PARALLEL_KMODS) $(XMODS) modlist modlist.arm

INITIAL_TARGETS = \
	genassym
	#unix would be here...

all def clean clobber: genassym .WAIT $(KMODS) $(XMODS) $(IMPLEMENTATIONS)
install: install_platforms genassym .WAIT $(KMODS) $(XMODS) $(IMPLEMENTATIONS)

modlist: $(KMODS) $(XMODS) $(IMPLEMENTATIONS)

modlist.karch: modlist modlist.armv8

modlist.armv8:
	@cd $(SRC)/uts/armv8; pwd; $(MAKE) $(NO_STATE) modlist

setup: FRC

genassym: FRC
	@cd $@; pwd; $(MAKE) $(NO_STATE) $(TARGET)

$(IMPLEMENTATIONS): FRC
	@cd $@; pwd; THISIMPL=$@ $(MAKE) $(NO_STATE) $(TARGET)

$(XMODS): FRC
	@cd $@; pwd; $(MAKE) $(NO_STATE) $(TARGET); \



install_h check: $(IMPLEMENTATIONS) FRC
	cd sys; pwd; $(MAKE) $(TARGET)

PLAT_LINKS =

install_platforms: $(ROOT_PSM_DIR) $(USR_PSM_DIR) \
	$(ROOT_PLAT_LINKS) $(USR_PLAT_LINKS) \
	$(OEM_USR_PLAT_LINKS)

include ../Makefile.targ

XRDIRS = ../aarch64 ../armv8 ../common

XRPRUNE = sun4u sun4v sun sffmu i86pc i86xpv intel sparc armv7 arm

cscope.out tags: FRC
	$(XREF) -x $@

all.prereq install.prereq def.prereq install_h.prereq clean.prereq:
	echo "Don't think any pre-reqs yet"

%.prereq:
	echo "Don't think any pre-reqs yet2"
