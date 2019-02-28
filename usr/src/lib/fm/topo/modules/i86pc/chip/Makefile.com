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
MODULE = chip
ARCH = i86pc
CLASS = arch
MODULESRCS = chip.c chip_label.c chip_subr.c chip_amd.c chip_intel.c \
chip_serial.c chip_smbios.c

# not linted
SMATCH=off

