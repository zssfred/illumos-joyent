/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2018 Joyent, Inc.
 */

#include <libintl.h>
#include <fwflash/fwflash.h>

extern struct vrfyplugin *verifier;

char vendor[] = "HGST";

/*
 * Ultimately, we rely on the firmware verification logic that is baked into
 * libses (see enc_do_ucode()).  Thus, the only thing we do here is override
 * the default chunk size to what the vendor has indicated is the max.
 */
/*ARGSUSED*/
int
vendorvrfy(struct devicelist *dvp)
{
	verifier->chunksz = 4096;

	return (FWFLASH_SUCCESS);
}
