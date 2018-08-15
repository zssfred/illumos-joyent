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

#ifndef _SYS_FDT_H
#define	_SYS_FDT_H

/*
 * Defines the structures used in the Flattened Device Tree format (fdt) +
 * functions used to initialize/parse them.
 *
 * This is used in armv8 to pass info about the system from the bootloader
 * to the kernel.
 *
 * This file is based on Devicetree Specification Release v0.2 (20 Dec. 2017),
 * and works for FDT version 16/17
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>

/*
 * The DTB (device tree blob) is a flat binary encoding of the device tree.
 * (hence Flattened Device Tree... not exactly sure why they use both acronyms)
 *
 * Regardless, it follows the format:
 *
 * 	fdt_header
 * 	(free space)
 * 	memory reservation block
 * 	(free space)
 * 	structure block
 * 	(free space)
 * 	strings block
 * 	(free space)
 *
 * Where free space is possibly included to align certain sections as required
 */


#define	FDT_MAGIC		0xd00dfeed
#define	FDT_LAST_COMP_VERSION	16 /* Last version supported by this parser */

typedef struct fdt_header {
	uint32_t	fdt_magic;
	uint32_t	fdt_totalsize;
	uint32_t	fdt_off_dt_struct;
	uint32_t	fdt_off_dt_strings;
	uint32_t	fdt_off_mem_rsvmap;
	uint32_t	fdt_version;
	uint32_t	fdt_last_comp_version;
	uint32_t	fdt_boot_cpuid_phys;
	uint32_t	fdt_size_dt_strings;
	uint32_t	fdt_size_dt_struct;
} fdt_header_t;

/*
 * The memory reservation portion of the device tree is a list of these entries,
 * specifying regions of memory that should not be touched by the kernel.
 *
 * XXX: i believe the list is null terminated.
 */
typedef struct fdt_reserve_entry {
	uint64_t	fdt_address;
	uint64_t	fdt_size;
} fdt_reserve_entry_t;

/*
 * The structure block is a flat tree with a sequence of tokens, followed by
 * data specified by the tokens. Below are defines for the tokens.
 *
 * The tree follows the format:
 *
 * (any number of FDT_TOKEN_NOP)
 * - FDT_TOKEN_BEGIN_NODE
 * 	- Nodes name as null-terminated string
 * 	- (zero padding to align to 4-bytes)
 * - For each property of the node:
 * 	- (any number of FDT_TOKEN_NOP)
 * 	- FDT_TOKEN_PROP
 * 		- [Property information]
 * 		- (zero padding to align to 4-bytes)
 * - Any child nodes, in this format
 * - (any number of FDT_TOKEN_NOP)
 * - FDT_TOKEN_END_NODE
 * - FDT_TOKEN_END
 *
 * Note: the byte after FDT_TOKEN_END has offset from beginning of the structure
 * block equal size_dt_struct field. () indicates optional
 *
 * [Property Information] is of the form:
 * 	1. A header containing two uint32's:
 * 		len - the length of the property's value
 * 		nameoff - the offset into the strings block where the property's
 * 			     name is stored (as null terminated string)
 *
 *      2. It's value - of length len in bytes.
 */
#define	FDT_TOKEN_BEGIN_NODE	0x00000001
#define	FDT_TOKEN_END_NODE	0x00000002
#define	FDT_TOKEN_PROP		0x00000003
#define	FDT_TOKEN_NOP		0x00000004
#define	FDT_TOKEN_END		0x00000009

typedef struct fdt_prop_header {
	uint32_t	fdt_len;
	uint32_t	fdt_nameoff;
} fdt_prop_header_t;

uintptr_t fdt_mem_resvmap_addr(fdt_header_t *);
uintptr_t fdt_strings_addr(fdt_header_t *);
uintptr_t fdt_struct_addr(fdt_header_t *);

char *fdt_string_at_off(fdt_header_t *, uint32_t);


// #define	ATAG_NONE	0x0
// #define	ATAG_CORE	0x54410001
// #define	ATAG_MEM	0x54410002
// #define	ATAG_VIDEOTEXT  0x54410003
// #define	ATAG_RAMDISK    0x54410004
// #define	ATAG_INITRD2    0x54420005
// #define	ATAG_SERIAL	0x54410006
// #define	ATAG_REVISION   0x54410007
// #define	ATAG_VIDEOLFB   0x54410008
// #define	ATAG_CMDLINE	0x54410009
// #define	ATAG_ILLUMOS_STATUS	0x726d0000
// #define	ATAG_ILLUMOS_MAPPING	0x726d0001

// typedef struct atag_header {
// 	uint32_t	ah_size;	/* size in 4 byte words */
// 	uint32_t	ah_tag;
// } atag_header_t;

// typedef struct atag_core {
// 	atag_header_t	ac_header;
// 	uint32_t	ac_flags;
// 	uint32_t	ac_pagesize;
// 	uint32_t	ac_rootdev;
// } atag_core_t;

// typedef struct atag_mem {
// 	atag_header_t	am_header;
// 	uint32_t	am_size;
// 	uint32_t	am_start;
// } atag_mem_t;

// typedef struct atag_ramdisk {
// 	atag_header_t	ar_header;
// 	uint32_t	ar_flags;
// 	uint32_t	ar_size;
// 	uint32_t	ar_start;
// } atag_ramdisk_t;

// typedef struct atag_initrd {
// 	atag_header_t	ai_header;
// 	uint32_t	ai_start;
// 	uint32_t	ai_size;
// } atag_initrd_t;

// typedef struct atag_serial {
// 	atag_header_t	as_header;
// 	uint32_t	as_low;
// 	uint32_t	as_high;
// } atag_serial_t;

// typedef struct atag_cmdline {
// 	atag_header_t	al_header;
// 	char		al_cmdline[1];
// } atag_cmdline_t;

// typedef struct atag_illumos_status {
// 	atag_header_t	ais_header;
// 	uint32_t	ais_version;
// 	uint32_t	ais_ptbase;
// 	uint32_t	ais_freemem;
// 	uint32_t	ais_freeused;
// 	uint32_t	ais_archive;
// 	uint32_t	ais_archivelen;
// 	uint32_t	ais_pt_arena;
// 	uint32_t	ais_pt_arena_max;
// 	uint32_t	ais_stext;
// 	uint32_t	ais_etext;
// 	uint32_t	ais_sdata;
// 	uint32_t	ais_edata;
// } atag_illumos_status_t;

// typedef struct atag_illumos_mapping {
// 	atag_header_t	aim_header;
// 	uint32_t	aim_paddr;
// 	uint32_t	aim_plen;
// 	uint32_t	aim_vaddr;
// 	uint32_t	aim_vlen;
// 	uint32_t	aim_mapflags;
// } atag_illumos_mapping_t;

// #define	ATAG_ILLUMOS_STATUS_SIZE	14
// #define	ATAG_ILLUMOS_MAPPING_SIZE	7
// #define	PF_NORELOC	0x08
// #define	PF_DEVICE	0x10
// #define	PF_LOADER	0x20

// extern atag_header_t *atag_next(atag_header_t *);
// extern const atag_header_t *atag_find(atag_header_t *, uint32_t);
// extern void atag_append(atag_header_t *, atag_header_t *);
// extern size_t atag_length(atag_header_t *);

#ifdef __cplusplus
}
#endif

#endif /* _SYS_ATAG_H */
