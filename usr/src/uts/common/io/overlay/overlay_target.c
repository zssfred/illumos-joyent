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
 * Copyright (c) 2014 Joyent, Inc.
 */

/*
 * Overlay devices can operate in one of many modes. They may be a point to
 * point tunnel, they may be on a single multicast group, or they may have
 * dynamic destinations. All of these are programmed via varpd.
 *
 * XXX This all probably won't remain true.
 */

#include <sys/types.h>
#include <sys/ethernet.h>
#include <sys/kmem.h>

#include <sys/overlay_impl.h>

typedef enum overlay_target_mode {
	OVERLAY_TARGET_NONE = 0x0,
	OVERLAY_TARGET_POINT,
	OVERLAY_TARGET_DYNAMIC
} overlay_target_mode_t;

typedef struct overlay_target_point {
	uint8_t		otp_mac[ETHERADDRL];
	struct in6_addr	otp_ip;
	uint16_t	otp_port;
} overlay_target_point_t;

typedef struct overlay_target {
	overlay_target_mode_t	ott_mode;
	overlay_plugin_dest_t	ott_dest;
	overlay_target_point_t	ott_point;
} overlay_target_t;

static kmem_cache_t *overlay_target_cache;

void
overlay_target_init(void)
{
	overlay_target_cache = kmem_cache_create("overlay_target",
	    sizeof (overlay_target_t), 0, NULL, NULL, NULL, NULL, NULL, 0);
}

void
overlay_target_fini(void)
{
	kmem_cache_destroy(overlay_target_cache);
}

int
overlay_target_open(dev_t *devp, int flags, int otype, cred_t *credp)
{
	return (EPERM);
}

int
overlay_target_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rvalp)
{
	return (EPERM);
}

int
overlay_target_close(dev_t dev, int flags, int otype, cred_t *credp)
{
	return (EPERM);
}
