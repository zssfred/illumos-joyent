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

#if defined(_KERNEL)
#include <sys/types.h>
#include "reloc.h"
#else
#define	ELF_TARGET_AARCH64
#if defined(DO_RELOC_LIBLD)
#undef DO_RELOC_LIBLD
#define	DO_RELOC_LIBLD_AARCH64
#endif
#include <stdio.h>
#include "sgs.h"
#include <aarch64/machdep_aarch64.h>
#include "libld.h"
#include "reloc.h"
#include "conv.h"
#include "msg.h"
#endif

/*
 * We need to build this code differently when it is used for
 * cross linking:
 *	- Data alignment requirements can differ from those
 *		of the running system, so we can't access data
 *		in units larger than a byte
 *	- We have to include code to do byte swapping when the
 *		target and linker host use different byte ordering,
 *		but such code is a waste when running natively.
 */
#if !defined(DO_RELOC_LIBLD) || defined(__aarch64__)
#define	DORELOC_NATIVE
#endif


/*
 * For now, mark all relocations as unsupported until they come up.

 typedef struct {
	Xword	re_mask;	mask to apply to reloc (sparc only)
	Word	re_flags;	relocation attributes
	uchar_t	re_fsize;	field size (in bytes)
	uchar_t	re_bshift;	number of bits to shift (sparc only)
	uchar_t	re_sigbits;	number of significant bits
} Rel_entry;

 * Table Numbers referenced from ELF for the ARM 64-bit Architecture,
 * ARM IHI 0056C_beta, current through ABI release 1.0, issued 6th November 2013

 * XXX: ignore all checks for now...
 * XXX: Unsure about operand size, always using 8 for now.
 * XXX: Going to use re_bshift for right shift amount, and re_sigbits for left
 */
const Rel_entry reloc_table[R_AARCH64_NUM] = {
	/* Table 4-5 - Null relocations*/
	[R_AARCH64_NONE] =			{ 0, FLG_RE_NOTREL, 0, 0, 0 },
	[R_AARCH64_NONE_ALT] =			{ 0, FLG_RE_NOTREL, 0, 0, 0 },

	/* Table 4-6 - Static Data Relocations */
	/* XXX: i think these are pure replacements, so set mask as such */
	[R_AARCH64_ABS64] =			{ (Xword) 0xffffffffffffffffULL, FLG_RE_NOTREL, 8, 0, 0 },
	[R_AARCH64_ABS32] =			{ 0xffffffff, FLG_RE_NOTREL, 4, 0, 0 }, //XXX 4 seems to be right for this so need to go back to all of thse + doubble check size...
	[R_AARCH64_ABS16] =			{ 0xffff, FLG_RE_NOTREL, 2, 0, 0 },
	[R_AARCH64_PREL64] =			{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_PREL32] =			{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_PREL16] =			{ 0, FLG_RE_NOTSUP, 0, 0, 0 },

	/* Table 4-7: Group Relocations to create unsigned values or addresses */
	[R_AARCH64_MOVW_UABS_G0] =		{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_MOVW_UABS_G0_NC] =		{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_MOVW_UABS_G1] =		{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_MOVW_UABS_G1_NC] =		{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_MOVW_UABS_G2] =		{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_MOVW_UABS_G2_NC] =		{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_MOVW_UABS_G3] =		{ 0, FLG_RE_NOTSUP, 0, 0, 0 },

	/* Table 4-8: Group Relocations to create signed values */
	[R_AARCH64_MOVW_SABS_G0] =		{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_MOVW_SABS_G1] =		{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_MOVW_SABS_G2] =		{ 0, FLG_RE_NOTSUP, 0, 0, 0 },

	/* Table 4-9: Relocations for 19, 21 and 33 bit PC rel addresses */
	[R_AARCH64_LD_PREL_LO19] =		{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_ADR_PREL_LO21] =		{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_ADR_PREL_PG_HI21] =		{ (Xword) 0x1fffff000ULL, FLG_RE_PCPAGEREL, 8, 0, 0 },
	[R_AARCH64_ADR_PREL_PG_HI21_NC] =	{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_ADD_ABS_LO12_NC] =		{ 0xfff, FLG_RE_NOTREL, 4, 0, 10 },
	[R_AARCH64_LDST8_ABS_LO12_NC] =		{ 0xfff, FLG_RE_NOTREL, 4, 0, 10 },
	[R_AARCH64_LDST16_ABS_LO12_NC] =	{ 0xffe, FLG_RE_NOTREL, 4, 1, 10 },
	[R_AARCH64_LDST32_ABS_LO12_NC] =	{ 0xffc, FLG_RE_NOTREL, 4, 2, 10 },
	[R_AARCH64_LDST64_ABS_LO12_NC] =	{ 0xff8, FLG_RE_NOTREL, 4, 3, 10 },
	[R_AARCH64_LDST128_ABS_LO12_NC] =	{ 0, FLG_RE_NOTSUP, 0, 0, 0 },

	/* Table 4-10: Relocations for control-flow instructions */
	[R_AARCH64_TSTBR14] =			{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_CONDBR19] =			{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_JUMP26] =			{ 0x0ffffffc, FLG_RE_PCREL, 4, 2, 0 },
	[R_AARCH64_CALL26] =			{ 0x0ffffffc, FLG_RE_PCREL, 4, 2, 0 },

	/* Table 4-11 Group relocations to create PC-relative offsets inline */
	[R_AARCH64_MOVW_PREL_G0] =		{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_MOVW_PREL_G0_NC] =		{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_MOVW_PREL_G1] =		{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_MOVW_PREL_G1_NC] =		{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_MOVW_PREL_G2] =		{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_MOVW_PREL_G2_NC] =		{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_MOVW_PREL_G3] =		{ 0, FLG_RE_NOTSUP, 0, 0, 0 },

	/* Table 4-12 Group relocations to create GOT-relative offsets inline */
	[R_AARCH64_MOVW_GOTOFF_G0] =		{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_MOVW_GOTOFF_G0_NC] =		{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_MOVW_GOTOFF_G1] =		{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_MOVW_GOTOFF_G1_NC] =		{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_MOVW_GOTOFF_G2] =		{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_MOVW_GOTOFF_G2_NC] =		{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_MOVW_GOTOFF_G3] =		{ 0, FLG_RE_NOTSUP, 0, 0, 0 },

	/* Table 4-13: GOT-relative data relocations */
	[R_AARCH64_MOVW_GOTREL64] =		{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_MOVW_GOTREL32] =		{ 0, FLG_RE_NOTSUP, 0, 0, 0 },

	/* Table 4-14: GOT-relative instruction relocations */
	[R_AARCH64_GOT_LD_PREL19] =		{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_LD64_GOTOFF_LO15] =		{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_ADR_GOT_PAGE] =		{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_LD64_GOT_LO12_NC] =		{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_LD64_GOTPAGE_LO15] =		{ 0x7ff8, FLG_RE_GOTADD | FLG_RE_GOTPAGEREL, 4, 0, 7 },

	/* Table 4-15: General Dynamic TLS relocations */
	[R_AARCH64_TLSGD_ADR_PREL21] =		{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_TLSGD_ADR_PAGE21] =		{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_TLSGD_ADD_LO12_NC] =		{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_TLSGD_MOVW_G1] =		{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_TLSGD_MOVW_G0_NC] =		{ 0, FLG_RE_NOTSUP, 0, 0, 0 },

	/* Table 4-16: Local Dynamic TLS relocations */
	[R_AARCH64_TLSLD_ADR_PREL21] =		{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_TLSLD_ADR_PAGE21] =		{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_TLSLD_ADD_LO12_NC] =		{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_TLLGD_MOVW_G1] =		{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_TLSLD_MOVW_G0_NC] =		{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_TLSLD_LD_PREL19] =		{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_TLSLD_MOVW_DTPREL_G2] =	{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_TLSLD_MOVW_DTPREL_G1] =	{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_TLSLD_MOVW_DTPREL_G1_NC] =	{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_TLSLD_MOVW_DTPREL_G0] =	{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_TLSLD_MOVW_DTPREL_G0_NC] =	{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_TLSLD_ADD_DTPREL_HI12] =	{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_TLSLD_ADD_DTPREL_LO12] =	{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_TLSLD_ADD_DTPREL_LO12_NC] =	{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_TLSLD_LDST8_DTPREL_LO12] =	{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_TLSLD_LDST8_DTPREL_LO12_NC] = { 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_TLSLD_LDST16_DTPREL_LO12] =	{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_TLSLD_LDST16_DTPREL_LO12_NC] = { 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_TLSLD_LDST32_DTPREL_LO12] =	{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_TLSLD_LDST32_DTPREL_LO12_NC] = { 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_TLSLD_LDST64_DTPREL_LO12] =	{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_TLSLD_LDST64_DTPREL_LO12_NC] = { 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_TLSLD_LDST128_DTPREL_LO12] =	{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_TLSLD_LDST128_DTPREL_LO12_NC] = { 0, FLG_RE_NOTSUP, 0, 0, 0 },

	/* Tabble 4-17: Initial Exec TLS Relocations */
	[R_AARCH64_TLSIE_MOVW_GOTTPREL_G1] =	{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_TLSIE_MOVW_GOTTPREL_G0_NC] =	{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21] =	{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_TLSIE_LD64_GOTTPREL_LO12_NC] = { 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_TLSIE_LD_GOTTPREL_PREL19] =	{ 0, FLG_RE_NOTSUP, 0, 0, 0 },

	/* Table 4-18: Local Exec TLS */
	[R_AARCH64_TLSLE_MOVW_TPREL_G2] =	{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_TLSLE_MOVW_TPREL_G1] =	{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_TLSLE_MOVW_TPREL_G1_NC] =	{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_TLSLE_MOVW_TPREL_G0] =	{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_TLSLE_MOVW_TPREL_G0_NC] =	{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_TLSLE_ADD_TPREL_HI12] =	{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_TLSLE_ADD_TPREL_LO12] =	{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_TLSLE_ADD_TPREL_LO12_NC] =	{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_TLSLE_LDST8_TPREL_LO12] =	{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_TLSLE_LDST8_TPREL_LO12_NC] =	{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_TLSLE_LDST16_TPREL_LO12] =	{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_TLSLE_LDST16_TPREL_LO12_NC] = { 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_TLSLE_LDST32_TPREL_LO12] =	{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_TLSLE_LDST32_TPREL_LO12_NC] = { 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_TLSLE_LDST64_TPREL_LO12] =	{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_TLSLE_LDST64_TPREL_LO12_NC] = { 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_TLSLE_LDST128_TPREL_LO12] =	{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_TLSLE_LDST128_TPREL_LO12_NC] = { 0, FLG_RE_NOTSUP, 0, 0, 0 },

	/* Table 4-19: TLS Descriptor relocations  */
	[R_AARCH64_TLSDESC_LD_PREL19] =		{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_TLSDESC_ADR_PREL21] =	{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_TLSDESC_ADR_PAGE21] =	{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_TLSDESC_LD64_LO12] =		{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_TLSDESC_ADD_LO12] =		{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_TLSDESC_OFF_G1] =		{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_TLSDESC_OFF_G0_NC] =		{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_TLSDESC_LDR] =		{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_TLSDESC_ADD] =		{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_TLSDESC_CALL] =		{ 0, FLG_RE_NOTSUP, 0, 0, 0 },

	/* Table 4-20: Dynamic relocations */
	[R_AARCH64_COPY] =			{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_GLOB_DAT] =			{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_JUMP_SLOT] =			{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_RELATIVE] =			{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_TLS_DTPREL64] =		{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_TLS_DTPMOD64] =		{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_TLS_TPREL64] =		{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_TLSDESC] =			{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
	[R_AARCH64_TLS_IRELATIVE] =		{ 0, FLG_RE_NOTSUP, 0, 0, 0 },
};

/*
 * Write a single relocated value to its reference location We assume we wish
 * to add the relocation amount, value, to the value of the adress already
 * present at the offset.
 *
 *
 * NAME				VALUE	FIELD	CALCULATION		Bits
 * R_AARCH64_NONE		0/256 	none	none			none
 * R_AARCH64_ABS64		257	word64	S + A			[31:0]
 * R_AARCH64_ADR_PREL_PG_HI21	275	word64	Page(S+A) - Page(P)	[32:12]
 * R_AARCH64_ADD_ABS_LO12_NC	277	word64	S + A			[11:0]
 * R_AARCH64_JUMP26		282	word64	S + A - P		[27:2]
 * R_AARCH64_CALL26		283	word64	S + A - P		[27:2]
 * R_AARCH64_LD64_GOTPAGE_LO15	313	word64	G(GDAT(S+A)) -Page(GOT)	[14:3]
 *
 * R_AARCH64_LDST32_ABS_LO12_NC 285	word64	S + A			[11:3]
 *
 * These relocations are from tables 4-5 through 4-20 in ELF for the ARM 64-bit
 * Architecture (AARCH64), ARM IHI 0056C_beta, current through ABI release 1.0,
 * issued 6th November 2013.
 *
 * Relocation calculations:
 *
 * CALCULATION uses the following notation:
 *	S		address of the symbol
 *	A		addend of relocation
 *	P		address of the place being relocated
 *	X		result of operation, before any masking/bit selection
 *	Page(expr)	expr & ~0xfff (no matter what actual page size is)
 *	GOT		address of gloal offset table (must be 64 bit aligned)
 *	GDAT(S+A)	pointer-sized entry in got for addr S+A. relocated at
 *			    run time with R_AARCH64_GLOB_DAT(S+A)
 *	G(expr)		address of the GOT entry for expression expr
 *	Delta(S)	if S is a normal symbol, resolves to difference between
 *			    static link of S and execution address of S.
 *			if S is null (ELF symb index 0), same thing but using P
 *	Indirect(expr)	represents result of calling expr as a function.
 *
 * And for TLS relocations:
 *	GLDM(S)		a consecutive pair of pointer-sized entries in the GOT
 *			    for the load module index of the symbol S.
 *			    First entry will be relocated with R_TLS_DTPMOD(S)
 *			    second entry contains 0.
 *	GTLSIDX(S,A)	consecutive pair of pointer-sized entries in the got.
 *			    contains  a tls_index structure describing the thread
 *			    local variable located at offset A from the symbol S
 *			    First entry relocated with R_TLS_DTPMOD(S+A)
 *			    Second will with R_TLS_DTPREL(S+A)
 *	GTPREL(S+A)	pointer sized entry in got for offset from current thread
 *			    pointer of local variable at offset A from symbol S.
 *			    Will be relocated with TLS_TPREL(S+A)
 *	GTLSDESC(S+A)	represents consecutive pair of pointer-sized entries in
 *			    GOT which contain a tlsdesc struct describing the
 *			    thread local variable located at offset A from S.
 *			    The first entry holds a pointer o the variable's TLS
 *			    descriptor  resolver function and the second entry
 *			    holds a platform specific offset/pointer.
 *			    Both relocated with R_TLSDEC(S+A)
 *	LDM(S)		resolves to the load module index of symbol S
 *	DTPREL(S+A)	resolves to the offset from its module's TLS block of
 *			    the thread local variable located at offset A from S
 *	TPREL(S+A))	resolves to the offset from the current thread pointer
 *			    of the thread local var at offset A from S
 *	TLSDESC(S+A)	resolves to a contiguous pair of pointer-sized vlaues,
 *			    as created by GTLSDESC(S+A)
 *
 *
 * The calculations in the CALCULATION column are assumed to have been
 * performed before calling this function, except for inserting the appropriate
 * bits of the result (as shown by BITS column) into the instruction involving
 * relocation.
 */
#if defined(_KERNEL)
#define	lml	0		/* Needed by arglist of REL_ERR_* macros */
int
do_reloc_krtld(Word rtype, uchar_t *off, Xword *value, const char *sym,
    const char *file)
#elif defined(DO_RELOC_LIBLD)
int
do_reloc_ld(Rel_desc *rdesc, uchar_t *off, Xword *value,
    rel_desc_sname_func_t rel_desc_sname_func, const char *file,
    int bswap, void *lml)
#else
int //XXX HAD TO CHANGE uchar_t to Word
do_reloc_rtld(Word rtype, uchar_t *off, Xword *value,
    const char *sym, const char *file, void *lml)
#endif
{
	const Rel_entry *rep;
#ifdef DO_RELOC_LIBLD
#define	sym (*rel_desc_sname_func)(rdesc)
	Word 	rtype = rdesc->rel_rtype;
#endif
	Xword		base = 0, uvalue = 0;

	rep = &reloc_table[rtype];

	switch (rep->re_fsize) {
	case 8:
#if defined(DORELOC_NATIVE)
		base = *(Xword *)off;
#else
		if (bswap) {
			uchar_t *b_bytes = (uchar_t *)&base;
			UL_ASSIGN_BSWAP_XWORD(b_bytes, off);
		} else {
			uchar_t *b_bytes = (uchar_t *)&base;
			UL_ASSIGN_XWORD(b_bytes, off);
		}
#endif
		break;
	case 4:
#if defined(DORELOC_NATIVE)
		base = *(Word *)off;
#else
		if (bswap) {
			uchar_t *b_bytes = (uchar_t *)&base;
			UL_ASSIGN_BSWAP_WORD(b_bytes, off);
		} else {
			uchar_t *b_bytes = (uchar_t *)&base;
			UL_ASSIGN_WORD(b_bytes, off);
		}
#endif
		break;
	case 2:
#if defined(DORELOC_NATIVE)
		base = *(Half *)off;
#else
		if (bswap) {
			uchar_t *b_bytes = (uchar_t *)&base;
			UL_ASSIGN_BSWAP_HALF(b_bytes, off);
		} else {
			uchar_t *b_bytes = (uchar_t *)&base;
			UL_ASSIGN_HALF(b_bytes, off);
		}
#endif
		break;
	default:
		REL_ERR_UNSUPSZ(lml, file, sym, rtype, rep->re_fsize);
		return (0);
	}

	uvalue = *value;

	// printf("Type: %lld\n", rtype);
	// printf("Base: 0x%llx, Val: 0x%llx\n", base, uvalue);

	// printf("Mask: %llx\n", rep->re_mask);

	if (rep->re_mask != 0) {
		uvalue &= rep->re_mask;
	}

	switch (rtype) {
	case R_AARCH64_ADR_PREL_PG_HI21:
		/*
		 * ADRP immediates are encoded with LSBs at instruction[30:29]
		 * and MSBs at instructionp[23:5].
		 */
		uvalue >>= 12;
		Xword hibits = (uvalue & 0x1ffffc) >> 2;
		Xword lobits = uvalue & 0x3;
		uvalue = (lobits << 29) | (hibits << 5);

		/* zero out the base properly */
		base &= ~((0x3 << 29) | (0x1ffffc << 3));
		break;
	case R_AARCH64_LDST8_ABS_LO12_NC:
	case R_AARCH64_LDST16_ABS_LO12_NC:
	case R_AARCH64_LDST32_ABS_LO12_NC:
	case R_AARCH64_LDST64_ABS_LO12_NC:
		/*
		 * These relocations all need to zero out the entire immediate
		 * field, but dont write to all of it necessarily,
		 * so special case them for now.
		 */
		base &= ~(0x3ffc00);
		uvalue >>= rep->re_bshift;
		uvalue <<= rep->re_sigbits;
		break;
	default:
		if (rep->re_mask != 0) {
			/* zero out the base properly */
			base &= ~((rep->re_mask >> rep->re_bshift) << rep->re_sigbits);
		}
		uvalue >>= rep->re_bshift;
		uvalue <<= rep->re_sigbits;
		break;
	}

	base = base + uvalue;
	// printf("Result: 0x%llx, Val: 0x%llx\n", base, uvalue);

	switch (rep->re_fsize) {
	case 8:
#if defined(DORELOC_NATIVE)
		*(Xword *)off = (Xword)(base);
#else
		if (bswap) {
			uchar_t *b_bytes = (uchar_t *)&base;
			UL_ASSIGN_BSWAP_XWORD(off, b_bytes);
		} else {
			uchar_t *b_bytes = (uchar_t *)&base;
			UL_ASSIGN_XWORD(off, b_bytes);
		}
#endif
		break;

	case 4:
#if defined(DORELOC_NATIVE)
		*(Word *)off = (Word)(base);
#else
		if (bswap) {
			uchar_t *b_bytes = (uchar_t *)&base;
			UL_ASSIGN_BSWAP_WORD(off, b_bytes);
		} else {
			uchar_t *b_bytes = (uchar_t *)&base;
			UL_ASSIGN_WORD(off, b_bytes);
		}
#endif
		break;

	case 2:
#if defined(DORELOC_NATIVE)
		*(Half *)off = (Half)(base);
#else
		if (bswap) {
			uchar_t *b_bytes = (uchar_t *)&base;
			UL_ASSIGN_BSWAP_HALF(off, b_bytes);
		} else {
			uchar_t *b_bytes = (uchar_t *)&base;
			UL_ASSIGN_HALF(off, b_bytes);
		}
#endif
		break;
	}


	return (1);
#ifdef DO_RELOC_LIBLD
#undef sym
#endif
}
