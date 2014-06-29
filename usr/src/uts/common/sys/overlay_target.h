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
 * Copyright (c) 2014 Joyent, Inc.  All rights reserved.
 */

#ifndef _OVERLAY_TARGET_H
#define	_OVERLAY_TARGET_H

/*
 * Overlay device varpd ioctl interface (/dev/overlay)
 */

#include <sys/types.h>
#include <sys/ethernet.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * What type of plugin is this? Is there a single destination or will there be
 * multiple destinations.
 */
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

#define	OVERLAY_TARG_IOCTL	(('o' << 24) | ('v' << 16) | ('t' << 8))

/*
 * Declare an association between a given varpd instance and a datalink.
 */
#define	OVERLAY_TARG_ASSOCIATE	(OVERLAY_TARG_IOCTL | 0x01)

typedef struct overlay_targ_associate {
	datalink_id_t		ota_linkid;
	uint32_t		ota_mode;
	uint64_t		ota_id;
	uint32_t		ota_provides;
	overlay_target_point_t	ota_point;
} overlay_targ_associate_t;

#ifdef __cplusplus
}
#endif

#endif /* _OVERLAY_TARGET_H */
