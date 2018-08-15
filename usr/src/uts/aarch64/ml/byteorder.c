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
 * Copyright (c) 2018, Joyent, Inc.
 */


#include <sys/types.h>
#include <sys/byteorder.h>

#ifdef _LITTLE_ENDIAN

uint64_t
htonll(uint64_t in)
{
	return BSWAP_64(in);
}

uint32_t
htonl(uint32_t in)
{
	return BSWAP_32(in);
}

uint16_t
htons(uint16_t in)
{
	return BSWAP_16(in);
}

uint64_t
ntohll(uint64_t in)
{
	return BSWAP_64(in);
}

uint32_t
ntohl(uint32_t in)
{
	return BSWAP_32(in);
}

uint16_t
ntohs(uint16_t in)
{
	return BSWAP_16(in);
}

#endif /* _LITTLE_ENDIAN */