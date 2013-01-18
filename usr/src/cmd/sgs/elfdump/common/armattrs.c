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

#include <sys/elf_ARM.h>

#define	ARM_TAG_TYPE_STRING	0x1
#define	ARM_TAG_TYPE_ULEB	0x2

#define	ARM_TAG_GET_TYPE(tag)						\
	(((tag == ARM_TAG_CPU_RAW_NAME) || (tag == ARM_TAG_CPU_NAME) ||	\
	(tag == ARM_TAG_COMPATIBILITY) ||				\
	(tag == ARM_TAG_ALSO_COMPATIBLE_WITH) ||			\
	(tag == ARM_TAG_CONFORMANCE)) ?					\
	ARM_TAG_TYPE_STRING : ARM_TAG_TYPE_ULEB)

static uint_t
extract_uint32(const uchar_t *data, size_t *len, int do_swap)
{
	uint_t	r;
	uchar_t *p = (uchar_t *)&r;

	if (do_swap)
		UL_ASSIGN_BSWAP_WORD(p, data + *len);
	else
		UL_ASSIGN_WORD(p, data + *len);

	*len += 4;

	return (r);
}

static void
dump_arm_attr_tag(uchar_t *data, size_t *len)
{
	uint_t		 stag;
	Conv_inv_buf_t	inv_buf;

	stag = (uint_t)uleb_extract(data, (uint64_t *)len);


	if (ARM_TAG_GET_TYPE(stag) == ARM_TAG_TYPE_ULEB) {
		uint32_t val = 0;

		val = uleb_extract(data, (uint64_t *)len);
		dbg_print(0, MSG_INTL(MSG_ARM_ATTR_VALUE),
		    conv_arm_tag(stag, 0, &inv_buf), val);
	} else {
		char *val = (char *)data + *len;

		*len += strlen(val) + 1;
		dbg_print(0, MSG_INTL(MSG_ARM_ATTR_STRVALUE),
		    conv_arm_tag(stag, 0, &inv_buf), val);
	}
}

static Boolean
dump_arm_attr_section(uchar_t *data, size_t *len, int do_swap)
{
	size_t  	init_len = *len;
	uint32_t	sec_size = extract_uint32(data, len, do_swap);
	char		*vendor = NULL;

	vendor = (char *)(data + *len);
	dbg_print(0, MSG_INTL(MSG_ARM_ATTR_VENDOR), vendor, sec_size);
	*len += strlen(vendor) + 1;

	if (strcmp(vendor, MSG_ORIG(MSG_ARM_ATTR_AEABI)) != 0) {
		dbg_print(0, MSG_ORIG(MSG_STR_EMPTY));
		*len = (init_len + sec_size);
		return (FALSE);
	}

	if (sec_size < 4) {
		dbg_print(0, MSG_INTL(MSG_ARM_ATTR_INVAL_SEC));
		*len = (init_len + sec_size);
		return (FALSE);
	}

	while ((*len - init_len) < sec_size) {
		uint_t		tag;
		uint32_t	tsize = 0;
		uchar_t		*end = NULL;
		Conv_inv_buf_t	inv_buf;
		size_t		orig_len = *len;

		tag = (uint_t)uleb_extract(data, (uint64_t *)len);
		tsize = extract_uint32(data, len, do_swap);

		end = data + orig_len + tsize;

		dbg_print(0, MSG_INTL(MSG_ARM_ATTR_TAG),
		    conv_arm_tag(tag, 0, &inv_buf), tsize);

		if (tag != ARM_TAG_FILE) {
			uint32_t specifier;

			while ((specifier = extract_uint32(data, len,
			    do_swap)) != 0) {
				if (tag == ARM_TAG_SYMBOL)
					dbg_print(0,
					    MSG_INTL(MSG_ARM_ATTR_SYMBOL_SPEC),
					    specifier);
				else
					dbg_print(0,
					    MSG_INTL(MSG_ARM_ATTR_SECT_SPEC),
					    specifier);
			}
		}

		while ((data + *len) < end)
			dump_arm_attr_tag(data, len);
	}

	return (TRUE);
}

/*
 * The .ARM.attributes section is of the form
 *
 * [byte:VERSION   # 'A'
 *   [ uint32:LENGTH string:VENDOR bytes:DATA ]
 *   [ uint32:LENGTH string:VENDOR bytes:DATA ]
 *   [ uint32:LENGTH string:VENDOR bytes:DATA ]...]
 *
 * Where only sub-sections of name "aeabi" are specified by the ABI and of
 * known content.
 *
 * Within an "aeabi" vendored section, are blocks, of one of the forms:
 *   [ ARM_TAG_FILE uint32:SIZE bytes:DATA ]
 *   [ ARM_TAG_SECTION uint32:SIZE uint32:SECNDX1,
 *     uint32:SECNDX2..., uint32:0, bytes:DATA ]
 *   [ ARM_TAG_SYMBOL uint32:SIZE uint32:SYMNDX1,
 *     uint32:SYMNBX2..., uint32:0, bytes:DATA ]
 *
 * The payload of each of this is a tag/value pair, where the value is either
 * a ULEB128 encoded integer, or a null terminated string (dependent on the
 * tag)
 */
void
dump_arm_attributes(Cache *cache, Word shnum, int do_swap)
{
	int cnt;

	for (cnt = 1; cnt < shnum; cnt++) {
		Cache	*_cache = &cache[cnt];
		Shdr	*shdr = _cache->c_shdr;
		uchar_t	*data = (uchar_t *)_cache->c_data->d_buf;
		size_t	dsize = _cache->c_data->d_size;
		size_t	len = 0;
		uchar_t	attrver = 0;

		if (shdr->sh_type != SHT_ARM_ATTRIBUTES)
			continue;

		dbg_print(0, MSG_ORIG(MSG_STR_EMPTY));
		dbg_print(0, MSG_INTL(MSG_ELF_SCN_ARMATTRS), _cache->c_name);

		attrver = *data++;
		dsize--;

		dbg_print(0, MSG_INTL(MSG_ARM_ATTR_VERSION), attrver,
		    (attrver != ARM_ATTR_VERSION) ?
		    MSG_INTL(MSG_ARM_ATTR_UNSUPPORTED) : "");

		if (attrver != ARM_ATTR_VERSION)
			return;

		while (dsize > 0) {
			if (dump_arm_attr_section(data, &len, do_swap) ==
			    FALSE)
				return;

			dsize -= len;
		}
	}
}
