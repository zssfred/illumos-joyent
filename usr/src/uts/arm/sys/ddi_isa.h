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

#ifndef _SYS_DDI_ISA_H
#define	_SYS_DDI_ISA_H

/*
 * ARM DDI Implementaion Functions
 */
#include <sys/isa_defs.h>
#include <sys/dditypes.h>
#include <sys/ndifm.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * XXX: There isn't a ton of symmetry between the intel and sparc ddi impl
 * portions. Rather than try and guess which one to use, we're going to leave
 * this empty until we have functions that we know we need implementations for.
 */

/*
 * This is a common subset of the ddi_acc_impl_t from sparc and intel. We've
 * defined it for now for the purposes of getting more of genunix building.
 */
typedef struct ddi_acc_impl {
	ddi_acc_hdl_t	ahi_common;

	uint8_t
		(*ahi_get8)(struct ddi_acc_impl *handle, uint8_t *addr);
	uint16_t
		(*ahi_get16)(struct ddi_acc_impl *handle, uint16_t *addr);
	uint32_t
		(*ahi_get32)(struct ddi_acc_impl *handle, uint32_t *addr);
	uint64_t
		(*ahi_get64)(struct ddi_acc_impl *handle, uint64_t *addr);

	void	(*ahi_put8)(struct ddi_acc_impl *handle, uint8_t *addr,
			uint8_t value);
	void	(*ahi_put16)(struct ddi_acc_impl *handle, uint16_t *addr,
			uint16_t value);
	void	(*ahi_put32)(struct ddi_acc_impl *handle, uint32_t *addr,
			uint32_t value);
	void	(*ahi_put64)(struct ddi_acc_impl *handle, uint64_t *addr,
			uint64_t value);

	void	(*ahi_rep_get8)(struct ddi_acc_impl *handle,
			uint8_t *host_addr, uint8_t *dev_addr,
			size_t repcount, uint_t flags);
	void	(*ahi_rep_get16)(struct ddi_acc_impl *handle,
			uint16_t *host_addr, uint16_t *dev_addr,
			size_t repcount, uint_t flags);
	void	(*ahi_rep_get32)(struct ddi_acc_impl *handle,
			uint32_t *host_addr, uint32_t *dev_addr,
			size_t repcount, uint_t flags);
	void	(*ahi_rep_get64)(struct ddi_acc_impl *handle,
			uint64_t *host_addr, uint64_t *dev_addr,
			size_t repcount, uint_t flags);

	void	(*ahi_rep_put8)(struct ddi_acc_impl *handle,
			uint8_t *host_addr, uint8_t *dev_addr,
			size_t repcount, uint_t flags);
	void	(*ahi_rep_put16)(struct ddi_acc_impl *handle,
			uint16_t *host_addr, uint16_t *dev_addr,
			size_t repcount, uint_t flags);
	void	(*ahi_rep_put32)(struct ddi_acc_impl *handle,
			uint32_t *host_addr, uint32_t *dev_addr,
			size_t repcount, uint_t flags);
	void	(*ahi_rep_put64)(struct ddi_acc_impl *handle,
			uint64_t *host_addr, uint64_t *dev_addr,
			size_t repcount, uint_t flags);

	int	(*ahi_fault_check)(struct ddi_acc_impl *handle);
	void	(*ahi_fault_notify)(struct ddi_acc_impl *handle);
	uint32_t	ahi_fault;
	ndi_err_t *ahi_err;
} ddi_acc_impl_t;


#ifdef __cplusplus
}
#endif

#endif /* _SYS_DDI_ISA_H */
