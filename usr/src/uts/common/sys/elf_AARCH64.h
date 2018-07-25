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
 * Copyright 2013, Richard Lowe
 */

#ifndef _SYS_ELF_AARCH64_H
#define	_SYS_ELF_AARCH64_H

#ifdef __cplusplus
extern "C" {
#endif

#define	R_AARCH64_NONE			0
#define	R_AARCH64_NONE_ALT		256

/* XXXAARCH64: fill in 32 bit mode relocations */

/* 4.6.5: static data relocations */
#define	R_AARCH64_ABS64			257
#define	R_AARCH64_ABS32			258
#define	R_AARCH64_ABS16			259
#define	R_AARCH64_PREL64		260
#define	R_AARCH64_PREL32		261
#define	R_AARCH64_PREL16		262

/* 4.6.6: static aarch64 relocations */
/* Table 4-7 */
#define	R_AARCH64_MOVW_UABS_G0		263
#define	R_AARCH64_MOVW_UABS_G0_NC	264
#define	R_AARCH64_MOVW_UABS_G1		265
#define	R_AARCH64_MOVW_UABS_G1_NC	266
#define	R_AARCH64_MOVW_UABS_G2		267
#define	R_AARCH64_MOVW_UABS_G2_NC	268
#define	R_AARCH64_MOVW_UABS_G3		269
/* Table 4-8 */
#define	R_AARCH64_MOVW_SABS_G0		270
#define	R_AARCH64_MOVW_SABS_G1		271
#define	R_AARCH64_MOVW_SABS_G2		272
/* Table 4-9 */
#define	R_AARCH64_LD_PREL_LO19		273
#define	R_AARCH64_ADR_PREL_LO21		274
#define	R_AARCH64_ADR_PREL_PG_HI21	275
#define	R_AARCH64_ADR_PREL_PG_HI21_NC	276
#define	R_AARCH64_ADD_ABS_LO12_NC	277
#define	R_AARCH64_LDST8_ABS_LO12_NC	278
	/* Gap */
#define	R_AARCH64_LDST16_ABS_LO12_NC	284
#define	R_AARCH64_LDST32_ABS_LO12_NC	285
#define	R_AARCH64_LDST64_ABS_LO12_NC	286
	/* Gap */
#define	R_AARCH64_LDST128_ABS_LO12_NC	299
/* Table 4-10 */
#define	R_AARCH64_TSTBR14		279
#define	R_AARCH64_CONDBR19		280
	/* Gap */
#define	R_AARCH64_JUMP26		282
#define	R_AARCH64_CALL26		283
/* Table 4-11 */
#define	R_AARCH64_MOVW_PREL_G0		287
#define	R_AARCH64_MOVW_PREL_G0_NC	288
#define	R_AARCH64_MOVW_PREL_G1		289
#define	R_AARCH64_MOVW_PREL_G1_NC	290
#define	R_AARCH64_MOVW_PREL_G2		291
#define	R_AARCH64_MOVW_PREL_G2_NC	292
#define	R_AARCH64_MOVW_PREL_G3		293
/* Table 4-12 */
#define	R_AARCH64_MOVW_GOTOFF_G0	300
#define	R_AARCH64_MOVW_GOTOFF_G0_NC	301
#define	R_AARCH64_MOVW_GOTOFF_G1	302
#define	R_AARCH64_MOVW_GOTOFF_G1_NC	303
#define	R_AARCH64_MOVW_GOTOFF_G2	304
#define	R_AARCH64_MOVW_GOTOFF_G2_NC	305
#define	R_AARCH64_MOVW_GOTOFF_G3	306
/* Table 4-13 */
#define	R_AARCH64_MOVW_GOTREL64		307
#define	R_AARCH64_MOVW_GOTREL32		308
/* Table 4-14 */
#define	R_AARCH64_GOT_LD_PREL19		309
#define	R_AARCH64_LD64_GOTOFF_LO15	310
#define	R_AARCH64_ADR_GOT_PAGE		311
#define	R_AARCH64_LD64_GOT_LO12_NC	312
#define	R_AARCH64_LD64_GOTPAGE_LO15	313

/* 4.6.10: Thread Local Storage Relocations */
/* Table 4-15: General dynamic tls relocations */
#define	R_AARCH64_TLSGD_ADR_PREL21	512
#define	R_AARCH64_TLSGD_ADR_PAGE21	513
#define	R_AARCH64_TLSGD_ADD_LO12_NC	514
#define	R_AARCH64_TLSGD_MOVW_G1		515
#define	R_AARCH64_TLSGD_MOVW_G0_NC	516
/* Table 4-16: local dynamic tls relocations */
#define	R_AARCH64_TLSLD_ADR_PREL21		517
#define	R_AARCH64_TLSLD_ADR_PAGE21		518
#define	R_AARCH64_TLSLD_ADD_LO12_NC		519
#define	R_AARCH64_TLLGD_MOVW_G1			520
#define	R_AARCH64_TLSLD_MOVW_G0_NC		521
#define	R_AARCH64_TLSLD_LD_PREL19		522
#define	R_AARCH64_TLSLD_MOVW_DTPREL_G2		523
#define	R_AARCH64_TLSLD_MOVW_DTPREL_G1		524
#define	R_AARCH64_TLSLD_MOVW_DTPREL_G1_NC	525
#define	R_AARCH64_TLSLD_MOVW_DTPREL_G0		526
#define	R_AARCH64_TLSLD_MOVW_DTPREL_G0_NC	527
#define	R_AARCH64_TLSLD_ADD_DTPREL_HI12		528
#define	R_AARCH64_TLSLD_ADD_DTPREL_LO12		529
#define	R_AARCH64_TLSLD_ADD_DTPREL_LO12_NC	530
#define	R_AARCH64_TLSLD_LDST8_DTPREL_LO12	531
#define	R_AARCH64_TLSLD_LDST8_DTPREL_LO12_NC	532
#define	R_AARCH64_TLSLD_LDST16_DTPREL_LO12	533
#define	R_AARCH64_TLSLD_LDST16_DTPREL_LO12_NC	534
#define	R_AARCH64_TLSLD_LDST32_DTPREL_LO12	535
#define	R_AARCH64_TLSLD_LDST32_DTPREL_LO12_NC	536
#define	R_AARCH64_TLSLD_LDST64_DTPREL_LO12	537
#define	R_AARCH64_TLSLD_LDST64_DTPREL_LO12_NC	538
	/* Gap */
#define	R_AARCH64_TLSLD_LDST128_DTPREL_LO12	572
#define	R_AARCH64_TLSLD_LDST128_DTPREL_LO12_NC	573
/* Table 4-17: Initial Exec TLS relocations */
#define	R_AARCH64_TLSIE_MOVW_GOTTPREL_G1	539
#define	R_AARCH64_TLSIE_MOVW_GOTTPREL_G0_NC	540
#define	R_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21	541
#define	R_AARCH64_TLSIE_LD64_GOTTPREL_LO12_NC	542
#define	R_AARCH64_TLSIE_LD_GOTTPREL_PREL19	543
/* Table 4-18: Local exec TLS relocations */
#define	R_AARCH64_TLSLE_MOVW_TPREL_G2		544
#define	R_AARCH64_TLSLE_MOVW_TPREL_G1		545
#define	R_AARCH64_TLSLE_MOVW_TPREL_G1_NC	546
#define	R_AARCH64_TLSLE_MOVW_TPREL_G0		547
#define	R_AARCH64_TLSLE_MOVW_TPREL_G0_NC	548
#define	R_AARCH64_TLSLE_ADD_TPREL_HI12		549
#define	R_AARCH64_TLSLE_ADD_TPREL_LO12		550
#define	R_AARCH64_TLSLE_ADD_TPREL_LO12_NC	551
#define	R_AARCH64_TLSLE_LDST8_TPREL_LO12	552
#define	R_AARCH64_TLSLE_LDST8_TPREL_LO12_NC	553
#define	R_AARCH64_TLSLE_LDST16_TPREL_LO12	554
#define	R_AARCH64_TLSLE_LDST16_TPREL_LO12_NC	555
#define	R_AARCH64_TLSLE_LDST32_TPREL_LO12	556
#define	R_AARCH64_TLSLE_LDST32_TPREL_LO12_NC	557
#define	R_AARCH64_TLSLE_LDST64_TPREL_LO12	558
#define	R_AARCH64_TLSLE_LDST64_TPREL_LO12_NC	559
	/* Gap */
#define	R_AARCH64_TLSLE_LDST128_TPREL_LO12	570
#define	R_AARCH64_TLSLE_LDST128_TPREL_LO12_NC	571
/* Table 4-19: TLS descriptor relocations */
#define	R_AARCH64_TLSDESC_LD_PREL19		560
#define	R_AARCH64_TLSDESC_ADR_PREL21		561
#define	R_AARCH64_TLSDESC_ADR_PAGE21		562
#define	R_AARCH64_TLSDESC_LD64_LO12		563
#define	R_AARCH64_TLSDESC_ADD_LO12		564
#define	R_AARCH64_TLSDESC_OFF_G1		565
#define	R_AARCH64_TLSDESC_OFF_G0_NC		566
#define	R_AARCH64_TLSDESC_LDR			567
#define	R_AARCH64_TLSDESC_ADD			568
#define	R_AARCH64_TLSDESC_CALL			569
/* Table 4-20: Dynamic relocations */
#define	R_AARCH64_COPY				1024
#define	R_AARCH64_GLOB_DAT			1025
#define	R_AARCH64_JUMP_SLOT			1026
#define	R_AARCH64_RELATIVE			1027
#define	R_AARCH64_TLS_DTPREL64			1028
#define	R_AARCH64_TLS_DTPMOD64			1029
#define	R_AARCH64_TLS_TPREL64			1030
#define	R_AARCH64_TLSDESC			1031
#define	R_AARCH64_TLS_IRELATIVE			1032

#define	R_AARCH64_NUM				1033

//XXXAARCH64: max page size, google seems to say 64kb...
#define	ELF_AARCH64_MAXPGSZ	0x10000

/* AARCH64-specific section types */
#define	SHT_AARCH64_ATTRIBUTES		0x70000003

/* AARCH64-specific program headers */
#define	PT_AARCH64_ARCHEXT	0x70000000
#define	PT_AARCH64_UNWIND	0x70000001

//XXXAARCH64: comment out this until its an issue, cuz idk what they do
/*
 * There are consumers of this file that want to include elf defines for
 * all architectures.  This is a problem for the defines below, because
 * while they are architecture specific they have common names.  Hence to
 * prevent attempts to redefine these variables we'll check if any of
 * the other elf architecture header files have been included.  If
 * they have then we'll just stick with the existing definitions.
 */
#if !defined(_SYS_ELF_MACH_COMMON)
#define	_SYS_ELF_MACH_COMMON
#define	_SYS_ELF_MACH_AARCH64

#define	M_PLT_ENTSIZE	16	/* PLT entry size in bytes */
#define	M_PLT_INSSIZE	4	/* Size of each PLT insn */
#define	M_PLT_ALIGN	4	/* PLT is word aligned, since it's ARM code */

#define	M_PLT_XNumber	1	/* 1 reserved PLT entry, PLT[0] */
#define	M_PLT_RESERVSZ	20	/* plt[0] is 5 insns, rather than the usual 4, but 28 aligns weirdly so use 32 */

	/* XXXAARCH64: no idea on htis stuff :( */
#define	M_GOT_XNumber	3	/* 3 reserved got entries */
#define	M_GOT_XDYNAMIC	0	/* got[0] == _DYNAMIC */
#define	M_GOT_XLINKMAP	1	/* got[1] == link map */
#define	M_GOT_XRTLD	2	/* got[2] == rtbinder */
#define	M_GOT_ENTSIZE	8

#define	M_WORD_ALIGN	8
#endif

#ifdef __cplusplus
}
#endif

#endif /* _SYS_ELF_ARM_H */
