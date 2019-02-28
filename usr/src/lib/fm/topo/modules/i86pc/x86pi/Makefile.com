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
# Copyright (c) 2019, Joyent, Inc.
#
MODULE  = x86pi
ARCH    = i86pc
CLASS   = arch

TOPODIR         = ../../../../libtopo/common

UTILDIR         = ../../../common/pcibus
BRDIR           = ../../../common/hostbridge
USBDIR          = ../../../common/usb/common
UTILSRCS        = did.c did_hash.c did_props.c
X86PISRCS       = x86pi.c x86pi_bay.c x86pi_bboard.c x86pi_chassis.c \
                  x86pi_generic.c x86pi_hostbridge.c x86pi_subr.c
MODULESRCS      = $(X86PISRCS) $(UTILSRCS)
