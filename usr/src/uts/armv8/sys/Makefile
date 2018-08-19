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
# Copyright 2013 (c) Joyent, Inc.  All rights reserved.
#

include ../../../Makefile.master

HDRS =	\
	archsystm.h		\
	asm_linkage.h		\
	boot_console.h		\
	bootconf.h		\
	bootsvcs.h		\
	bootvfs.h		\
	ddi_isa.h		\
	flush.h			\
	kdi_machimpl.h		\
	machbrand.h		\
	machlock.h		\
	machsig.h		\
	machtypes.h		\
	obpdefs.h		\
	pcb.h			\
	procfs_isa.h 		\
	promif.h		\
	promimpl.h		\
	regset.h		\
	spl.h 			\
	stack.h			\
	stat_impl.h		\
	ucontext.h		\
	utrap.h			\
	vmparam.h


ROOTDIR=	$(ROOT)/usr/include/sys
ROOTHDRS=	$(HDRS:%=$(ROOTDIR)/%)
CHECKHDR=	$(HDRS:%.h=%.check)

$(ROOTDIR):
	$(INS.dir)

$(ROOTDIR)/%: %
	$(INS.file)

install_h: $(ROOTDIR) .WAIT $(ROOTHDRS)

check:	$(CHECKHDR)
