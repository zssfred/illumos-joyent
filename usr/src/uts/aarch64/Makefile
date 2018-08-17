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

# BUILD_TYPE = DBG64

include Makefile.aarch64

all		:=	TARGET= all
def		:=	TARGET= def
check		:=	TARGET= check
clean		:=	TARGET= clean
clobber		:=	TARGET= clobber
install_h	:=	TARGET= install_h
modlist	:=	TARGETf= modlist
modlist	modlist.arm	:=	NO_STATE= -k $$MODSTATE$$$$


.KEEP_STATE:

.PARALLEL: $(PARALLEL_KMODS) $(XMODS) modlist modlist.arm

INITIAL_TARGETS = \
	genassym
	#unix would be here...

all def clean clobber: genassym .WAIT $(KMODS) $(XMODS) $(IMPLEMENTATIONS)
install: install_platforms genassym .WAIT $(KMODS) $(XMODS) $(IMPLEMENTATIONS)

modlist: $(KMODS) $(XMODS) $(IMPLEMENTATIONS)

modlist.karch: modlist modlist.arm

modlist.arm:
	@cd $(SRC)/uts/arm; pwd; $(MAKE) $(NO_STATE) modlist

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

XRDIRS = ../aarch64 ../arm ../common

XRPRUNE = sun4u sun4v sun sffmu i86pc i86xpv intel sparc armv7

cscope.out tags: FRC
	$(XREF) -x $@

# AS_CPPFLAGS = \
# 	-D_ASM \
# 	-D_KERNEL \
# 	-I$(ROOT)/usr/include \
# 	-xarch=aarch64

# # XXX these override makefile.master but i think that's fine.
# CPPFLAGS = \
# 	-D_KERNEL \
# 	-I$(ROOT)/usr/include \
# 	-I$(UTSBASE)/common

# GEN_OBJS = \
# 	misc/copy.o \
# 	misc/string.o \
# 	boot/fdt.o \
# 	os/fakebop.o \
# 	ml/byteorder.o

# COM_OBJS = \
# 	string.o #Contains vsnprintf

# QEMU_VIRT_OBJS = \
# 	qv/locore.o \
# 	qv/boot_console.o

# OBJS = \
# 	$(QEMU_VIRT_OBJS) \
# 	$(GEN_OBJS) \
# 	$(COM_OBJS)


# OBJCOPY=$(GNU_ROOT)/bin/objcopy

# CERRWARN += -_gcc=-Wno-parentheses
# CERRWARN += -_gcc=-Wno-uninitialized

# all: unix.elf unix.bin

# %.o: %.s
# 	$(AS) -P $(AS_CPPFLAGS) -o $@ $<

# %.o: %.c
# 	$(COMPILE64.c) -o $@ -c $<

# %.o: ../../common/util/%.c
# 	$(COMPILE64.c) -o $@ -c $<

# %.o: ../common/krtld/%.c
# 	$(COMPILE64.c) -o $@ -c $<

# unix: $(OBJS)
# 	$(LD) -dn -e _start -o $@.elf $(OBJS) -M test_mapfile

# %.bin: %.elf
# 	$(OBJCOPY) $< -O binary $@

# #While the elf file is great to have, and qemu is fine loading and running it,
# #Qemu assumes elf files are not kernels and so loads them differently (ie doesnt
# #pass boot args). Fun stuff.
# %.elf: %
# 	elfdump -e $@

# clean:
# 	rm -f $(OBJS)

# clobber: clean
# 	rm -f unix unix.bin

# install_h check:
# 	@cd sys; pwd; $(MAKE) $(TARGET)

all.prereq install.prereq def.prereq install_h.prereq clean.prereq:
	echo "Don't think any pre-reqs yet"

%.prereq:
	echo "Don't think any pre-reqs yet2"

# def: $(KMODS) $(XMODS) #XXX: config

