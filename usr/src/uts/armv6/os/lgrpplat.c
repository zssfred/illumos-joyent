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

/*
 * Locality group support for ARMv6
 *
 * The vast majority of ARMv6 machines are uniprocessor. There really isn't much
 * NUMA in these older chips -- and that's okay. importantly we're not going to
 * pretend that we actually have more than one locality group at this time. When
 * we reach the magical realm of fantasy future land of ARMv7 with its multiple
 * processors and likely numa layout, we'll take a more serious pass at all of
 * this. For now, we basically do the minimum that we need.
 */

#include <sys/lgrp.h>
#include <sys/memnode.h>

/* XXX Basically panic most functions until we implement them */
extern void bop_panic(const char *) __NORETURN;

/*
 * We only have a single ARM lgrp at this time.
 */
#define	NLGRP	1

/*
 * Static array to hold lgroup statistics and lgrps themselves
 */
static lgrp_t lgrp_space[NLGRP];
struct lgrp_stats lgrp_stats[NLGRP];

lgrp_t *
lgrp_plat_alloc(lgrp_id_t lgrpid)
{
	if (lgrpid != 0)
		return (NULL);

	return (&lgrp_space[0]);
}

/*
 * Configuration is not currently supported.
 */
void
lgrp_plat_config(lgrp_config_flag_t flag, uintptr_t arg)
{
	ASSERT(max_mem_nodes == 1);
}

lgrp_handle_t
lgrp_plat_cpu_to_hand(processorid_t id)
{
	ASSERT(max_mem_nodes == 1);
	return (LGRP_DEFAULT_HANDLE);
}

void
lgrp_plat_init(lgrp_init_stages_t stage)
{
	/*
	 * There isn't much to do in any other stage. Just make sure that we've
	 * set max_mem_nodes properly to 1.
	 */
	if (stage == LGRP_INIT_STAGE1) {
		max_mem_nodes = 1;
	}
}

/*
 * We have only one node in the system that's supported. Therefore there is no
 * lgrp latency in the traditional sense.
 */
int
lgrp_plat_latency(lgrp_handle_t from, lgrp_handle_t to)
{
	ASSERT(from == to);
	ASSERT(max_mem_nodes == 1);
	return (0);
}

int
lgrp_plat_max_lgrps(void)
{
	/* Only one lgrp is currently supported */
	return (1);
}

pgcnt_t
lgrp_plat_mem_size(lgrp_handle_t plathand, lgrp_mem_query_t query)
{
	bop_panic("lgrp_plat_mem_size");
}

lgrp_handle_t
lgrp_plat_pfn_to_hand(pfn_t pfn)
{
	ASSERT(max_mem_nodes == 1);
	return (LGRP_DEFAULT_HANDLE);
}

void
lgrp_plat_probe(void)
{
	ASSERT(max_mem_nodes == 1);
}

lgrp_handle_t
lgrp_plat_root_hand(void)
{
	return (LGRP_DEFAULT_HANDLE);
}
