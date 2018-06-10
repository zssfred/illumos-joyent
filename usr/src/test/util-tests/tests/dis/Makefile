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
# Copyright 2017 Joyent, Inc.
#

include $(SRC)/Makefile.master

ROOTOPTPKG = $(ROOT)/opt/util-tests
TESTDIR = $(ROOTOPTPKG)/tests/dis
ARCHS = i386 sparc arm64

PROG = distest

ARM64_TESTS =			\
	tst.branches		\
	tst.data-imm		\
	tst.data-reg		\
	tst.load-store		\
	tst.regs		\
	tst.branch		\
	tst.addsub-carry	\
	tst.addsub-extreg	\
	tst.addsub-imm		\
	tst.addsub-shiftreg	\
	tst.bitfield		\
	tst.condcomp-imm	\
	tst.condcomp-reg	\
	tst.movwide-imm		\
	tst.extract		\
	tst.logical-imm		\
	tst.logical-shiftreg	\
	tst.ldst-reg-pair	\
	tst.ldst-literal	\
	tst.ldst-prfm		\
	tst.ldst-noalloc	\
	tst.dproc1		\
	tst.dproc2		\
	tst.condsel		\
	tst.dproc3		\
	tst.exception		\
	tst.system		\
	tst.ldst-exclusive	\
	tst.ldst-reg-imm-post	\
	tst.ldst-reg-imm-pre	\
	tst.ldst-reg-offset	\
	tst.ldst-reg-unpriv	\
	tst.ldst-reg-unscaled	\
	tst.ldst-reg-unsigned	\
	tst.ldst-simd		\
	tst.simd-across		\
	tst.simd-copy		\
	tst.simd-ext		\
	tst.simd-modimm		\
	tst.simd-pairwise	\
	tst.simd-scalarshift	\
	tst.simd-tbl		\
	tst.simd-trn


SPARC_TESTS = \
	tst.regs

I386_TESTS =		\
	32.adx 		\
	32.avx		\
	32.avx2		\
	32.avx512	\
	32.aes 		\
	32.bmi1 	\
	32.bmi2 	\
	32.f16c 	\
	32.fma-pd 	\
	32.fma-ps 	\
	32.fma-sd 	\
	32.fma-ss 	\
	32.lzcnt 	\
	32.movbe	\
	32.opmask	\
	32.pclmulqdq	\
	32.popcnt 	\
	32.sha		\
	32.sse-3	\
	32.sse-4.1 	\
	32.sse-4.2 	\
	32.ssse3 	\
	32.xsave 	\
	64.avx		\
	64.avx2		\
	64.avx512	\
	64.adx 		\
	64.aes 		\
	64.bmi1 	\
	64.bmi2 	\
	64.ept 		\
	64.f16c 	\
	64.fma-pd 	\
	64.fma-ps 	\
	64.fma-sd 	\
	64.fma-ss 	\
	64.lzcnt 	\
	64.movbe	\
	64.opmask	\
	64.pclmulqdq	\
	64.popcnt 	\
	64.random 	\
	64.sha		\
	64.sse-3	\
	64.sse-4.1 	\
	64.sse-4.2 	\
	64.ssse3 	\
	64.vmx 		\
	64.xsave 	\
	tst.cpuid	\
	tst.fence	\
	tst.msr		\
	tst.mwait 	\
	tst.random	\
	tst.smap	\
	tst.sep		\
	tst.tsc		\
	tst.vmx

I386_FILES = $(I386_TESTS:%=%.s) $(I386_TESTS:%=%.out)
ROOTI386 = $(I386_FILES:%=$(TESTDIR)/i386/%)

SPARC_FILES = $(SPARC_TESTS:%=%.s) $(SPARC_TESTS:%=%.out)
ROOTSPARC = $(SPARC_FILES:%=$(TESTDIR)/sparc/%)

ARM64_FILES = $(ARM64_TESTS:%=%.s) $(ARM64_TESTS:%=%.out)
ROOTARM64 = $(ARM64_FILES:%=$(TESTDIR)/arm64/%)

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/test/Makefile.com

ARCHDIRS = $(ARCHS:%=$(TESTDIR)/%)
CMDS = $(PROG:%=$(TESTDIR)/%)
$(CMDS) := FILEMODE = 0555

install: $(CMDS) $(ROOTI386) $(ROOTSPARC) $(ROOTARM64)

lint:

clobber: clean

clean:

$(CMDS) $(ROOTI386) $(ROOTSPARC) $(ROOTARM64): $(TESTDIR) $(ARCHDIRS)

$(TESTDIR) $(ARCHDIRS):
	$(INS.dir)

$(TESTDIR)/%: %
	$(INS.file)

$(TESTDIR)/%: %.ksh
	$(INS.rename)
