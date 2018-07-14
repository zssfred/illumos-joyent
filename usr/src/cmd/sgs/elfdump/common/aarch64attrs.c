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

#include <_libelf.h>
#include <stdio.h>
#include <strings.h>
#include <conv.h>
#include <msg.h>
#include <_elfdump.h>
#include <dwarf.h>

#include <sys/elf_AARCH64.h>

static uint_t
extract_uint32(const uchar_t *data, size_t *len)
{
	uint_t	r;
	uchar_t *p = (uchar_t *)&r;

	UL_ASSIGN_WORD(p, data + *len);

	*len += 4;

	return (r);
}
/*
 * The AARCH64 Specification as of ARMv8 does not currently have any public
 * build attributes (unlike 32 bit verisions of arm). However, it still supports
 * the .ARM.attributes section, so for now we'll just hex dump the contents.
 */
void
dump_aarch64_attributes(Cache *cache, Word shnum)
{
	int cnt;

	/* Iterate over sections in the cache */
	for (cnt = 1; cnt < shnum; cnt++) {

		/* Get the data buffer of the cache, and its size */
		Cache	*_cache = &cache[cnt];
		Shdr	*shdr = _cache->c_shdr;
		uchar_t	*data = (uchar_t *)_cache->c_data->d_buf;
		size_t	dsize = _cache->c_data->d_size;
		size_t len;

		/* Check each section's type, and if not attributes, move on */
		if (shdr->sh_type != SHT_AARCH64_ATTRIBUTES)
			continue;

		/* Display section name */
		dbg_print(0, MSG_ORIG(MSG_STR_EMPTY));
		dbg_print(0, MSG_INTL(MSG_ELF_SCN_ARMATTRS), _cache->c_name);

		/* Dump the hex in the section */
		while (len < dsize) {

			uint_t extracted = extract_uint32(data, &len);
			dbg_print(0, "%x ", extracted);

			/* After 8 int's print a new line */
			if ((len % (8 * 4)) == 0) {
				dbg_print(0, "\n");
			}
		}


	}
}
