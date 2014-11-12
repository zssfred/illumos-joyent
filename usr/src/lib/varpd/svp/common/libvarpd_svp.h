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

#ifndef _LIBVARPD_SVP_H
#define	_LIBVARPD_SVP_H

/*
 * Implementation details of the SVP plugin and the SVP protocol.
 */

#include <netinet/in.h>
#include <sys/ethernet.h>
#include <thread.h>
#include <synch.h>
#include <libvarpd_provider.h>
#include <sys/avl.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Core implementation structure.
 */
typedef struct svp {
	overlay_plugin_dest_t	svp_dest;	/* RO */
	varpd_provider_handle_t	svp_hdl;	/* RO */
	mutex_t			svp_lock;
	char			*svp_host;
	uint16_t		svp_port;
	uint16_t		svp_uport;
	boolean_t		svp_huip;
	struct in6_addr		svp_uip;
} svp_t;

typedef struct svp_backend svp_backend_t;

/*
 * XXX Strawman backend APIs
 */
extern int svp_backend_get(const char *, svp_backend_t **);
extern void svp_backend_release(svp_backend_t *);

/*
 * SDC VXLAN Protocol Definitions
 */

typedef struct svp_req {
	uint16_t	svp_ver;
	uint16_t	svp_op;
	uint32_t	svp_size;
	uint64_t	svp_id;
	uint8_t		svp_data[];
} svp_req_t;

typedef enum svp_op {
	SVP_R_PING	= 0x01,
	SVP_R_PONG	= 0x02,
	SVP_R_VL2_REQ	= 0x03,
	SVP_R_VL2_ACK	= 0x04,
	SVP_R_VL3_REQ	= 0x05,
	SVP_R_VL3_ACK	= 0x06,
	SVP_R_BULK_REQ	= 0x07,
	SVP_R_BULK_ACK	= 0x08,
	SVP_R_LOG_REQ	= 0x09,
	SVP_R_LOG_ACK	= 0x0A,
	SVP_R_LOG_RM	= 0x0B,
	SVP_R_LOG_RACK	= 0x0C,
	SVP_R_SHOOTDOWN	= 0x0D,
} svp_op_t;

typedef enum svp_status {
	SVP_S_OK	= 0x00,	/* Everything OK */
	SVP_S_FATAL	= 0x01,	/* Fatal error, close connection */
	SVP_S_NOTFOUND	= 0x02,	/* Entry not found */
	SVP_S_BADL3TYPE	= 0x03,	/* Unknown svp_vl3_type_t */
	SVP_S_BADBULK	= 0x04,	/* Unknown svp_bulk_type_t */
	SVP_S_BADLOG	= 0x05,	/* Unknown svp_log_type_t */
	SVP_S_LOGAGIN	= 0x06	/* Nothing in the log yet */
} svp_status_t;

typedef struct svp_vl2_req {
	uint64_t	sl2r_vnetid;
	uint8_t		sl2r_mac[ETHERADDRL];
} svp_vl2_req_t;

typedef struct svp_vl2_ack {
	uint16_t	sl2a_status;
	uint16_t	sl2a_port;
	struct in6_addr	sl2a_addr;
} svp_vl2_ack_t;

typedef enum svp_vl3_type {
	SVP_VL3_IP	= 0x01,
	SVP_VL3_IPV6	= 0x02
} svp_vl3_type_t;

typedef struct svp_vl3_req {
	uint64_t	sl3r_vnetid;
	struct in6_addr	sl3r_ip;
	uint32_t	sl3r_type;
} svp_vl3_req_t;

typedef struct svp_vl3_ack {
	uint32_t	sl3a_status;
	uint8_t		sl3a_mac[ETHERADDRL];
	uint16_t	sl3a_uport;
	struct in6_addr	sl3a_uip;
} svp_vl3_ack_t;

typedef enum svp_bulk_type {
	SVP_BULK_VL2	= 0x01,
	SVP_BULK_VL3	= 0x02
} svp_bulk_type_t;

typedef struct svp_bulk_req {
	uint32_t	svbr_type;
} svp_bulk_req_t;

typedef struct svp_bulk_ack {
	uint32_t	svba_status;
	uint32_t	svba_type;
	uint8_t		svba_data[];
} svp_bulk_ack_t;

typedef enum svp_log_type {
	SVP_LOG_VL2	= 0x01,
	SVP_LOG_VL3	= 0x02
} svp_log_type_t;

typedef struct svp_log_req {
	uint32_t	svlr_type;
	uint32_t	svlr_count;
} svp_log_req_t;

typedef struct svp_log_vl2 {
	uint64_t	svl2_id;
	uint64_t	svl2_vnetid;
	uint8_t		svl2_mac[ETHERADDRL];
	uint8_t		svl2_pad[2];
} svp_log_vl2_t;

typedef struct svp_log_vl3 {
	uint64_t	svl3_id;
	uint64_t	svl3_vnetid;
	struct in6_addr	svl3_ip;
	uint8_t		svl3_mac[ETHERADDRL];
	uint8_t		svl3_pad[2];
} svp_log_vl3_t;

typedef struct svp_log_ack {
	uint32_t	svla_status;
	uint32_t	svla_type;
	uint8_t		svla_data[];
} svp_log_ack_t;

typedef struct svp_lrm_req {
	uint32_t	svrr_type;
	uint32_t	svrr_pad;
	uint64_t	svrr_ids[];
} svp_lrm_req_t;

typedef struct svp_lrm_ack {
	uint32_t	svra_status;
} svp_lrm_ack_t;

typedef struct svp_shootdown {
	uint64_t	svsd_vnetid;
	uint8_t		svsd_mac[ETHERADDRL];
	uint8_t		svsd_pad[2];
} svp_shootdown_t;

#ifdef __cplusplus
}
#endif

#endif /* _LIBVARPD_SVP_H */
