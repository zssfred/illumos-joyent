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
 * Copyright 2013 Joyent, Inc.  All rights reserved.
 */

	.file	"cache.s"

/* XXXARM: rework cache/tlb maintenance functions to handle ARMv7 */

/*
 * Cache and memory barrier operations
 */

#include <sys/asm_linkage.h>

#if defined(lint) || defined(__lint)

void
aarch64_text_flush_range(caddr_t start, size_t len)

#else	/* __lint */

	/*
	 * Based on
	 * http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.den0024a/BABJDBHI.html
	 * 11.5
	 */

	//
	// X0 = base address
	// X1 = length (we assume the length is not 0)
	//
	ENTRY(aarch64_text_flush_range)
	// Calculate end of the region
	add x1, x1, x0                // Base Address + Length

	//
	// Clean the data cache by MVA
	//
	mrs x2, ctr_el0               // Read Cache Type Register

	// Get the minimun data cache line
	ubfx x4, x2, #16, #4          // Extract DminLine (log2 of the cache line)
	mov x3, #4                    // Dminline is the number of words (4 bytes)
	lsl x3, x3, x4                // X3 should contain the cache line
	sub x4, x3, #1                // get the mask for the cache line

	bic x4, x0, x4                // Aligned the base address of the region
	clean_data_cache:
	dc cvau, x4                   // Clean data cache line by VA to PoU
	add x4, x4, x3                // Next cache line
	cmp x4, x1                    // Is X4 (current cache line) smaller than the end
	                        // of the region
	b.lt clean_data_cache         // while (address < end_address)

	dsb ish                       // Ensure visibility of the data cleaned from cache

	//
	//Clean the instruction cache by VA
	//
	// Get the minimum instruction cache line (X2 contains ctr_el0)
	and x2, x2, #0xf             // Extract IminLine (log2 of the cache line)
	mov x3, #4                   // IminLine is the number of words (4 bytes)
	lsl x3, x3, x2               // X3 should contain the cache line
	sub x4, x3, #1               // Get the mask for the cache line

	bic x4, x0, x4               // Aligned the base address of the region
	clean_instruction_cache:
	ic ivau, x4                  // clean instruction cache line by va to pou
	add x4, x4, x3               // Next cache line
	cmp x4, x1                   // Is X4 (current cache line) smaller than the end
	                       // of the region
	b.lt clean_instruction_cache // while (address < end_address)

	dsb ish                      // Ensure completion of the invalidations
	isb                          // Synchronize the fetched instruction stream

	SET_SIZE(aarch64_text_flush_range)

#endif	/* __lint */
