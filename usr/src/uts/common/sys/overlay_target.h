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
#include <netinet/in.h>
#include <sys/overlay_common.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct overlay_target_point {
	uint8_t		otp_mac[ETHERADDRL];
	struct in6_addr	otp_ip;
	uint16_t	otp_port;
} overlay_target_point_t;

#define	OVERLAY_TARG_IOCTL	(('o' << 24) | ('v' << 16) | ('t' << 8))

#define	OVERLAY_TARG_INFO	(OVERLAY_TARG_IOCTL | 0x01)

typedef enum overlay_targ_info_flags {
	OVERLAY_TARG_INFO_F_ACTIVE = 0x01,
	OVERLAY_TARG_INFO_F_DEGRADED = 0x02
} overlay_targ_info_flags_t;

/*
 * Get target information about an overlay device
 */
typedef struct overlay_targ_info {
	datalink_id_t		oti_linkid;
	uint32_t		oti_needs;
	uint64_t		oti_flags;
} overlay_targ_info_t;

/*
 * Declare an association between a given varpd instance and a datalink.
 */
#define	OVERLAY_TARG_ASSOCIATE	(OVERLAY_TARG_IOCTL | 0x02)

typedef struct overlay_targ_associate {
	datalink_id_t		ota_linkid;
	uint32_t		ota_mode;
	uint64_t		ota_id;
	uint32_t		ota_provides;
	overlay_target_point_t	ota_point;
} overlay_targ_associate_t;

/*
 * Remove an association from a device. If the device has already been started,
 * this implies OVERLAY_TARG_DEGRADE.
 */
#define	OVERLAY_TARG_DISASSOCIATE	(OVERLAY_TARG_IOCTL | 0x3)

/*
 * Tells the kernel that while a varpd instance still exists, it basically isn't
 * making any forward progress, so the device should consider itself degraded.
 */
#define	OVERLAY_TARG_DEGRADE	(OVERLAY_TARG_IOCTL | 0x4)

/*
 * Tells the kernel to remove the degraded status that it set on a device.
 */
#define	OVERLAY_TARG_RESTORE	(OVERLAY_TARG_IOCTL | 0x5)

typedef struct overlay_targ_id {
	datalink_id_t	otid_linkid;
} overlay_targ_id_t;

#ifdef __cplusplus
}
#endif

#endif /* _OVERLAY_TARGET_H */
