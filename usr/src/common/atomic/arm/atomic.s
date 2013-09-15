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
 * Copyright (c) 2013 Joyent, Inc.  All rights reserved.
 */

	.file	"atomic.s"

/*
 * Atomic Operatoins for 32-bit ARM. Note, that these require at least ARMv6K so
 * as to have access to the non-word size LDREX and STREX.
 */

#include <sys/asm_linkage.h>
#include <sys/atomic_impl.h>

/*
 * XXX We probably want some kind of backoff built in to these routines at some
 * point.
 */

#if defined(_KERNEL)
	/*
	 * Legacy kernel interfaces; they will go away (eventually).
	 */
	ANSI_PRAGMA_WEAK2(cas8,atomic_cas_8,function)
	ANSI_PRAGMA_WEAK2(cas32,atomic_cas_32,function)
	ANSI_PRAGMA_WEAK2(cas64,atomic_cas_64,function)
	ANSI_PRAGMA_WEAK2(caslong,atomic_cas_ulong,function)
	ANSI_PRAGMA_WEAK2(casptr,atomic_cas_ptr,function)
	ANSI_PRAGMA_WEAK2(atomic_and_long,atomic_and_ulong,function)
	ANSI_PRAGMA_WEAK2(atomic_or_long,atomic_or_ulong,function)
	ANSI_PRAGMA_WEAK2(swapl,atomic_swap_32,function)
#endif

	/*
	 * NOTE: If atomic_inc_8 and atomic_inc_8_nv are ever
	 * separated, you need to also edit the libc arm platform
	 * specific mapfile and remove the NODYNSORT attribute
	 * from atomic_inc_8_nv.
	 */
	ENTRY(atomic_inc_8)
	ALTENTRY(atomic_inc_8_nv)
	ALTENTRY(atomic_inc_uchar)
	ALTENTRY(atomic_inc_uchar_nv)
	mov	r1, #1
	b	atomic_add_8
	SET_SIZE(atomic_inc_uchar_nv)
	SET_SIZE(atomic_inc_uchar)
	SET_SIZE(atomic_inc_8_nv)
	SET_SIZE(atomic_inc_8)

	/*
	 * NOTE: If atomic_dec_8 and atomic_dec_8_nv are ever
	 * separated, you need to also edit the libc arm platform
	 * specific mapfile and remove the NODYNSORT attribute
	 * from atomic_dec_8_nv.
	 */
	ENTRY(atomic_dec_8)
	ALTENTRY(atomic_dec_8_nv)
	ALTENTRY(atomic_dec_uchar)
	ALTENTRY(atomic_dec_uchar_nv)
	mov	r1, #-1
	b	atomic_add_8
	SET_SIZE(atomic_dec_uchar_nv)
	SET_SIZE(atomic_dec_uchar)
	SET_SIZE(atomic_dec_8_nv)
	SET_SIZE(atomic_dec_8)

	/*
	 * NOTE: If atomic_add_8 and atomic_add_8_nv are ever
	 * separated, you need to also edit the libc arm platform
	 * specific mapfile and remove the NODYNSORT attribute
	 * from atomic_add_8_nv.
	 */
	ENTRY(atomic_add_8)
	ALTENTRY(atomic_add_8_nv)
	ALTENTRY(atomic_add_char)
	ALTENTRY(atomic_add_char_nv)
1:
	ldrexb	r2, [r0]
	add	r2, r1, r2
	strexb	r3, r2, [r0]
	cmp	r3, #0
	bne	1b
	mov	r0, r2
	bx	lr
	SET_SIZE(atomic_add_char_nv)
	SET_SIZE(atomic_add_char)
	SET_SIZE(atomic_add_8_nv)
	SET_SIZE(atomic_add_8)

	/*
	 * NOTE: If atomic_inc_16 and atomic_inc_16_nv are ever
	 * separated, you need to also edit the libc arm platform
	 * specific mapfile and remove the NODYNSORT attribute
	 * from atomic_inc_16_nv.
	 */
	ENTRY(atomic_inc_16)
	ALTENTRY(atomic_inc_16_nv)
	ALTENTRY(atomic_inc_ushort)
	ALTENTRY(atomic_inc_ushort_nv)
	mov	r1, #1
	b	atomic_add_16
	SET_SIZE(atomic_inc_ushort_nv)
	SET_SIZE(atomic_inc_ushort)
	SET_SIZE(atomic_inc_16_nv)
	SET_SIZE(atomic_inc_16)

	/*
	 * NOTE: If atomic_dec_16 and atomic_dec_16_nv are ever
	 * separated, you need to also edit the libc arm platform
	 * specific mapfile and remove the NODYNSORT attribute
	 * from atomic_dec_16_nv.
	 */
	ENTRY(atomic_dec_16)
	ALTENTRY(atomic_dec_16_nv)
	ALTENTRY(atomic_dec_ushort)
	ALTENTRY(atomic_dec_ushort_nv)
	mov	r1, #-1
	b	atomic_add_16
	SET_SIZE(atomic_dec_ushort_nv)
	SET_SIZE(atomic_dec_ushort)
	SET_SIZE(atomic_dec_16_nv)
	SET_SIZE(atomic_dec_16)

	/*
	 * NOTE: If atomic_add_16 and atomic_add_16_nv are ever
	 * separated, you need to also edit the libc arm platform
	 * specific mapfile and remove the NODYNSORT attribute
	 * from atomic_add_16_nv.
	 */
	ENTRY(atomic_add_16)
	ALTENTRY(atomic_add_16_nv)
	ALTENTRY(atomic_add_short)
	ALTENTRY(atomic_add_short_nv)
1:
	ldrexh	r2, [r0]
	add	r2, r1, r2
	strexh	r3, r2, [r0]
	cmp	r3, #0
	bne	1b
	mov	r0, r2
	bx	lr
	SET_SIZE(atomic_add_short_nv)
	SET_SIZE(atomic_add_short)
	SET_SIZE(atomic_add_16_nv)
	SET_SIZE(atomic_add_16)

	/*
	 * NOTE: If atomic_inc_32 and atomic_inc_32_nv are ever
	 * separated, you need to also edit the libc arm platform
	 * specific mapfile and remove the NODYNSORT attribute
	 * from atomic_inc_32_nv.
	 */
	ENTRY(atomic_inc_32)
	ALTENTRY(atomic_inc_32_nv)
	ALTENTRY(atomic_inc_uint)
	ALTENTRY(atomic_inc_uint_nv)
	ALTENTRY(atomic_inc_ulong)
	ALTENTRY(atomic_inc_ulong_nv)
	mov	r1, #1
	b	atomic_add_32
	SET_SIZE(atomic_inc_ulong_nv)
	SET_SIZE(atomic_inc_ulong)
	SET_SIZE(atomic_inc_uint_nv)
	SET_SIZE(atomic_inc_uint)
	SET_SIZE(atomic_inc_32_nv)
	SET_SIZE(atomic_inc_32)

	/*
	 * NOTE: If atomic_dec_32 and atomic_dec_32_nv are ever
	 * separated, you need to also edit the libc arm platform
	 * specific mapfile and remove the NODYNSORT attribute
	 * from atomic_dec_32_nv.
	 */
	ENTRY(atomic_dec_32)
	ALTENTRY(atomic_dec_32_nv)
	ALTENTRY(atomic_dec_uint)
	ALTENTRY(atomic_dec_uint_nv)
	ALTENTRY(atomic_dec_ulong)
	ALTENTRY(atomic_dec_ulong_nv)
	mov	r1, #-1
	b	atomic_add_32
	SET_SIZE(atomic_dec_ulong_nv)
	SET_SIZE(atomic_dec_ulong)
	SET_SIZE(atomic_dec_uint_nv)
	SET_SIZE(atomic_dec_uint)
	SET_SIZE(atomic_dec_32_nv)
	SET_SIZE(atomic_dec_32)

	/*
	 * NOTE: If atomic_add_32 and atomic_add_32_nv are ever
	 * separated, you need to also edit the libc arm platform
	 * specific mapfile and remove the NODYNSORT attribute
	 * from atomic_add_32_nv.
	 */
	ENTRY(atomic_add_32)
	ALTENTRY(atomic_add_32_nv)
	ALTENTRY(atomic_add_int)
	ALTENTRY(atomic_add_int_nv)
	ALTENTRY(atomic_add_ptr)
	ALTENTRY(atomic_add_ptr_nv)
	ALTENTRY(atomic_add_long)
	ALTENTRY(atomic_add_long_nv)
1:
	ldrex	r2, [r0]
	add	r2, r1, r2
	strex	r3, r2, [r0]
	cmp	r3, #0
	bne	1b
	mov	r0, r2
	bx	lr
	SET_SIZE(atomic_add_long_nv)
	SET_SIZE(atomic_add_long)
	SET_SIZE(atomic_add_ptr_nv)
	SET_SIZE(atomic_add_ptr)
	SET_SIZE(atomic_add_int_nv)
	SET_SIZE(atomic_add_int)
	SET_SIZE(atomic_add_32_nv)
	SET_SIZE(atomic_add_32)

	/*
	 * NOTE: If atomic_inc_64 and atomic_inc_64_nv are ever
	 * separated, you need to also edit the libc arm platform
	 * specific mapfile and remove the NODYNSORT attribute
	 * from atomic_inc_64_nv.
	 */
	ENTRY(atomic_inc_64)
	ALTENTRY(atomic_inc_64_nv)
	mov	r2, #1
	mov	r3, #0
	b	atomic_add_64
	SET_SIZE(atomic_inc_64_nv)
	SET_SIZE(atomic_inc_64)

	/*
	 * NOTE: If atomic_dec_64 and atomic_dec_64_nv are ever
	 * separated, you need to also edit the libc arm platform
	 * specific mapfile and remove the NODYNSORT attribute
	 * from atomic_dec_64_nv.
	 */
	ENTRY(atomic_dec_64)
	ALTENTRY(atomic_dec_64_nv)
	mov	r2, #-1
	mvn	r3, #0
	b	atomic_add_64
	SET_SIZE(atomic_dec_64_nv)
	SET_SIZE(atomic_dec_64)

	/*
	 * NOTE: If atomic_add_64 and atomic_add_64_nv are ever
	 * separated, you need to also edit the libc arm platform
	 * specific mapfile and remove the NODYNSORT attribute
	 * from atomic_add_64_nv.
	 */
	ENTRY(atomic_add_64)
	ALTENTRY(atomic_add_64_nv)
	push	{ r4, r5 }
1:
	ldrexd	r4, r5, [r0]
	adds	r4, r4, r2	
	adc	r5, r5, r3	
	strexd	r1, r4, r5, [r0]
	cmp	r1, #0
	bne	1b
	mov	r0, r4
	mov	r1, r5
	pop	{ r4, r5 }
	bx	lr
	SET_SIZE(atomic_add_64_nv)
	SET_SIZE(atomic_add_64)

	/*
	 * NOTE: If atomic_or_8 and atomic_or_8_nv are ever
	 * separated, you need to also edit the libc arm platform
	 * specific mapfile and remove the NODYNSORT attribute
	 * from atomic_or_8_nv.
	 */
	ENTRY(atomic_or_8)
	ALTENTRY(atomic_or_8_nv)
	ALTENTRY(atomic_or_uchar)
	ALTENTRY(atomic_or_uchar_nv)
1:
	ldrexb	r2, [r0]
	orr	r2, r1, r2
	strexb	r3, r2, [r0]
	cmp	r3, #0
	bne	1b
	mov	r0, r2
	bx	lr
	SET_SIZE(atomic_or_uchar_nv)
	SET_SIZE(atomic_or_uchar)
	SET_SIZE(atomic_or_8_nv)
	SET_SIZE(atomic_or_8)

	/*
	 * NOTE: If atomic_or_16 and atomic_or_16_nv are ever
	 * separated, you need to also edit the libc arm platform
	 * specific mapfile and remove the NODYNSORT attribute
	 * from atomic_or_16_nv.
	 */
	ENTRY(atomic_or_16)
	ALTENTRY(atomic_or_16_nv)
	ALTENTRY(atomic_or_ushort)
	ALTENTRY(atomic_or_ushort_nv)
1:
	ldrexh	r2, [r0]
	orr	r2, r1, r2
	strexh	r3, r2, [r0]
	cmp	r3, #0
	bne	1b
	mov	r0, r2
	bx	lr
	SET_SIZE(atomic_or_ushort_nv)
	SET_SIZE(atomic_or_ushort)
	SET_SIZE(atomic_or_16_nv)
	SET_SIZE(atomic_or_16)

	/*
	 * NOTE: If atomic_or_32 and atomic_or_32_nv are ever
	 * separated, you need to also edit the libc arm platform
	 * specific mapfile and remove the NODYNSORT attribute
	 * from atomic_or_32_nv.
	 */
	ENTRY(atomic_or_32)
	ALTENTRY(atomic_or_32_nv)
	ALTENTRY(atomic_or_uint)
	ALTENTRY(atomic_or_uint_nv)
	ALTENTRY(atomic_or_ulong)
	ALTENTRY(atomic_or_ulong_nv)
1:
	ldrex	r2, [r0]
	add	r2, r1, r2
	strex	r3, r2, [r0]
	cmp	r3, #0
	bne	1b
	mov	r0, r2
	bx	lr
	SET_SIZE(atomic_or_ulong_nv)
	SET_SIZE(atomic_or_ulong)
	SET_SIZE(atomic_or_uint_nv)
	SET_SIZE(atomic_or_uint)
	SET_SIZE(atomic_or_32_nv)
	SET_SIZE(atomic_or_32)

	/*
	 * NOTE: If atomic_or_64 and atomic_or_64_nv are ever
	 * separated, you need to also edit the libc arm platform
	 * specific mapfile and remove the NODYNSORT attribute
	 * from atomic_or_64_nv.
	 */
	ENTRY(atomic_or_64)
	ALTENTRY(atomic_or_64_nv)
	push	{ r4, r5 }
1:
	ldrexd	r4, r5, [r0]
	orr	r4, r4, r2	
	orr	r5, r5, r3	
	strexd	r1, r4, r5, [r0]
	cmp	r1, #0
	bne	1b
	mov	r0, r4
	mov	r1, r5
	pop	{ r4, r5 }
	bx	lr
	SET_SIZE(atomic_or_64_nv)
	SET_SIZE(atomic_or_64)

	/*
	 * NOTE: If atomic_and_8 and atomic_and_8_nv are ever
	 * separated, you need to also edit the libc arm platform
	 * specific mapfile and remove the NODYNSORT attribute
	 * from atomic_and_8_nv.
	 */
	ENTRY(atomic_and_8)
	ALTENTRY(atomic_and_8_nv)
	ALTENTRY(atomic_and_uchar)
	ALTENTRY(atomic_and_uchar_nv)
1:
	ldrexb	r2, [r0]
	and	r2, r1, r2
	strexb	r3, r2, [r0]
	cmp	r3, #0
	bne	1b
	mov	r0, r2
	bx	lr
	SET_SIZE(atomic_and_uchar)
	SET_SIZE(atomic_and_8_nv)
	SET_SIZE(atomic_and_8)

	/*
	 * NOTE: If atomic_and_16 and atomic_and_16_nv are ever
	 * separated, you need to also edit the libc arm platform
	 * specific mapfile and remove the NODYNSORT attribute
	 * from atomic_and_16_nv.
	 */
	ENTRY(atomic_and_16)
	ALTENTRY(atomic_and_16_nv)
	ALTENTRY(atomic_and_ushort)
	ALTENTRY(atomic_and_ushort_nv)
1:
	ldrexh	r2, [r0]
	and	r2, r1, r2
	strexh	r3, r2, [r0]
	cmp	r3, #0
	bne	1b
	mov	r0, r2
	bx	lr
	SET_SIZE(atomic_and_ushort_nv)
	SET_SIZE(atomic_and_ushort)
	SET_SIZE(atomic_and_16_nv)
	SET_SIZE(atomic_and_16)

	/*
	 * NOTE: If atomic_and_32 and atomic_and_32_nv are ever
	 * separated, you need to also edit the libc arm platform
	 * specific mapfile and remove the NODYNSORT attribute
	 * from atomic_and_32_nv.
	 */
	ENTRY(atomic_and_32)
	ALTENTRY(atomic_and_32_nv)
	ALTENTRY(atomic_and_uint)
	ALTENTRY(atomic_and_uint_nv)
	ALTENTRY(atomic_and_ulong)
	ALTENTRY(atomic_and_ulong_nv)
1:
	ldrex	r2, [r0]
	and	r2, r1, r2
	strex	r3, r2, [r0]
	cmp	r3, #0
	bne	1b
	mov	r0, r2
	bx	lr
	SET_SIZE(atomic_and_ulong_nv)
	SET_SIZE(atomic_and_ulong)
	SET_SIZE(atomic_and_uint_nv)
	SET_SIZE(atomic_and_uint)
	SET_SIZE(atomic_and_32_nv)
	SET_SIZE(atomic_and_32)

	/*
	 * NOTE: If atomic_and_64 and atomic_and_64_nv are ever
	 * separated, you need to also edit the libc arm platform
	 * specific mapfile and remove the NODYNSORT attribute
	 * from atomic_and_64_nv.
	 */
	ENTRY(atomic_and_64)
	ALTENTRY(atomic_and_64_nv)
	push	{ r4, r5 }
1:
	ldrexd	r4, r5, [r0]
	and	r4, r4, r2	
	and	r5, r5, r3	
	strexd	r1, r4, r5, [r0]
	cmp	r1, #0
	bne	1b
	mov	r0, r4
	mov	r1, r5
	pop	{ r4, r5 }
	bx	lr
	SET_SIZE(atomic_and_64_nv)
	SET_SIZE(atomic_and_64)

	ENTRY(atomic_cas_8)
	ALTENTRY(atomic_cas_uchar)
	push	{ r4 }
1:
	ldrexb	r3, [r0]
	cmp	r1, r3
	bne	2f			@ Compare failed, bail
	strexb	r4, r2, [r0]
	cmp	r4, #0			@ strexb failed, take another lap
	bne	1b
2:
	mov	r0, r3
	pop	{ r4 }
	bx	lr
	SET_SIZE(atomic_cas_uchar)
	SET_SIZE(atomic_cas_8)

	ENTRY(atomic_cas_16)
	ALTENTRY(atomic_cas_ushort)
	push	{ r4 }
1:
	ldrexh	r3, [r0]
	cmp	r1, r3
	bne	2f			@ Compare failed, bail
	strexh	r4, r2, [r0]
	cmp	r4, #0			@ strexb failed, take another lap
	bne	1b
2:
	mov	r0, r3
	pop	{ r4 }
	bx	lr
	SET_SIZE(atomic_cas_ushort)
	SET_SIZE(atomic_cas_16)

	ENTRY(atomic_cas_32)
	ALTENTRY(atomic_cas_uint)
	ALTENTRY(atomic_cas_ptr)
	ALTENTRY(atomic_cas_ulong)
	push	{ r4 }
1:
	ldrex	r3, [r0]
	cmp	r1, r3
	bne	2f			@ Compare failed, bail
	strex	r4, r2, [r0]
	cmp	r4, #0			@ strexb failed, take another lap
	bne	1b
2:
	mov	r0, r3
	pop	{ r4 }
	bx	lr
	SET_SIZE(atomic_cas_ulong)
	SET_SIZE(atomic_cas_ptr)
	SET_SIZE(atomic_cas_uint)
	SET_SIZE(atomic_cas_32)

	/*
	 * atomic_cas_64(uint64_t *target, uint64_t cmp, uint64_t newval);
	 *
	 * target is in r0
	 * cmp is in r2,r3
	 * newval is on the stack 
	 *
	 * Our register allocation:
	 * r0 - Always contains target
	 * r1 - Always used for the result of strexd
	 * r2, r3 - Always used for cmp
	 * r4, r5 - Always used for newval
	 * r6, r7 - Always used as the ldrexd target
	 *
	 * Note that sp points to newval when we enter. We push four values, so
	 * we need to add 16 when we load newval.
	 */
	ENTRY(atomic_cas_64)
	push	{ r4, r5, r6, r7 }
	ldrd	r4, [sp, #16]		@ load newval into memory
1:
	ldrexd	r6, r7, [r0]		@ load *target
	cmp	r6, r2
	bne	2f			@ bail if high word not equal
	cmp	r5, r3
	bne	2f			@ bail if low word not equal
	strexd	r1, r4, r5, [r0]	@ try to store *target
	cmp	r1, #0
	bne	1b			@ try again if store aborted
2:
	mov	r0, r6			@ ret low word of *target
	mov	r1, r7			@ ret high word of *target
	pop	{ r4, r5, r6, r7 }
	bx	lr
	SET_SIZE(atomic_cas_64)

	ENTRY(atomic_swap_8)
	ALTENTRY(atomic_swap_uchar)
1:
	ldrexb	r2, [r0]
	strexb	r3, r1, [r0]
	cmp	r3, #0
	bne	1b
	mov	r0, r2
	bx	lr
	SET_SIZE(atomic_swap_uchar)
	SET_SIZE(atomic_swap_8)

	ENTRY(atomic_swap_16)
	ALTENTRY(atomic_swap_ushort)
1:
	ldrexh	r2, [r0]
	strexh	r3, r1, [r0]
	cmp	r3, #0
	bne	1b
	mov	r0, r2
	bx	lr
	SET_SIZE(atomic_swap_ushort)
	SET_SIZE(atomic_swap_16)

	ENTRY(atomic_swap_32)
	ALTENTRY(atomic_swap_uint)
	ALTENTRY(atomic_swap_ptr)
	ALTENTRY(atomic_swap_ulong)
1:
	ldrex	r2, [r0]
	strex	r3, r1, [r0]
	cmp	r3, #0
	bne	1b
	mov	r0, r2
	bx	lr
	SET_SIZE(atomic_swap_ulong)
	SET_SIZE(atomic_swap_ptr)
	SET_SIZE(atomic_swap_uint)
	SET_SIZE(atomic_swap_32)

	ENTRY(atomic_swap_64)
	push	{ r4, r5 }
1:
	ldrexd	r4, r5, [r0]
	strexd	r1, r2, r3, [r0]
	cmp	r1, #0
	bne	1b
	mov	r0, r4
	mov	r1, r5
	pop	{ r4, r5 }
	bx	lr
	SET_SIZE(atomic_swap_64)

	ENTRY(atomic_set_long_excl)
	mov	r3, #1
	lsl	r1, r3, r1		@ bit to set
1:
	ldrex	r2, [r0]
	and	r3, r1, r2
	cmp	r3, r1			@ Check if the bit is set
	beq	2f
	orr	r2, r1, r2		@ Set the bit
	strex	r3, r1, [r0]
	cmp	r3, #0
	bne	1b
	mov	r0, #0
	bx	lr
2:
	mov	r0, #-1			@ bit already set
	bx	lr
	SET_SIZE(atomic_set_long_excl)

	ENTRY(atomic_clear_long_excl)
	mov	r3, #1
	lsl	r1, r3, r1
1:
	ldrex	r2, [r0]
	and	r3, r1, r2
	cmp	r3, r1
	bne	2f
	bic	r2, r1, r2
	strex	r3, r1, [r0]
	cmp	r3, #0
	bne	1b
	mov	r0, #0
	bx	lr
2:
	mov	r0, #-1
	bx	lr
	SET_SIZE(atomic_clear_long_excl)

#if !defined(_KERNEL)

	/*
	 * NOTE: membar_enter, membar_exit, membar_producer, and
	 * membar_consumer are identical routines.  We define them
	 * separately, instead of using ALTENTRY definitions to alias
	 * them together, so that DTrace and debuggers will see a unique
	 * address for them, allowing more accurate tracing.
	 */
	ENTRY(membar_enter)
	ARM_DMB_INSTR(r0)
	bx lr
	SET_SIZE(membar_enter)

	ENTRY(membar_exit)
	ARM_DMB_INSTR(r0)
	bx lr
	SET_SIZE(membar_exit)

	ENTRY(membar_producer)
	ARM_DMB_INSTR(r0)
	bx lr
	SET_SIZE(membar_producer)

	ENTRY(membar_consumer)
	ARM_DMB_INSTR(r0)
	bx lr
	SET_SIZE(membar_consumer)

#endif	/* !_KERNEL */
