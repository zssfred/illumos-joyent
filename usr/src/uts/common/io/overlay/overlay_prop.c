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
 * Copyright (c) 2014, Joyent, Inc.  All rights reserved.
 */

/*
 * Routines for manipulating property information structures.
 */

#include <sys/overlay_impl.h>

void
overlay_prop_set_name(overlay_prop_handle_t phdl, const char *name)
{
	overlay_ioc_propinfo_t *oip = (overlay_ioc_propinfo_t *)phdl;
	(void) strlcpy(oip->oipi_name, name, OVERLAY_PROP_NAMELEN);
}

void
overlay_prop_set_prot(overlay_prop_handle_t phdl, overlay_prop_prot_t prot)
{
	overlay_ioc_propinfo_t *oip = (overlay_ioc_propinfo_t *)phdl;
	oip->oipi_prot = prot;
}

void
overlay_prop_set_type(overlay_prop_handle_t phdl, overlay_prop_type_t type)
{
	overlay_ioc_propinfo_t *oip = (overlay_ioc_propinfo_t *)phdl;
	oip->oipi_type = type;
}

int
overlay_prop_set_default(overlay_prop_handle_t phdl, void *def, ssize_t len)
{
	overlay_ioc_propinfo_t *oip = (overlay_ioc_propinfo_t *)phdl;

	if (len > OVERLAY_PROP_SIZEMAX)
		return (E2BIG);

	bcopy(def, oip->oipi_default, len);
	oip->oipi_defsize = len;

	return (0);
}

void
overlay_prop_set_nodefault(overlay_prop_handle_t phdl)
{
	overlay_ioc_propinfo_t *oip = (overlay_ioc_propinfo_t *)phdl;
	oip->oipi_default[0] = '\0';
	oip->oipi_defsize = 0;
}

void
overlay_prop_set_range_uint16(overlay_prop_handle_t phdl, uint16_t min,
    uint16_t max)
{
}

void
overlay_prop_set_range_str(overlay_prop_handle_t phdl, const char *str)
{
}
