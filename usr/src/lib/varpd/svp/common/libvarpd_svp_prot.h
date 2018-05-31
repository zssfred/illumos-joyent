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
 * Copyright 2018 Joyent, Inc.
 */

#ifndef _LIBVARPD_SVP_PROT_H
#define	_LIBVARPD_SVP_PROT_H

/*
 * SVP protocol Definitions
 */

#include <sys/types.h>
#include <inttypes.h>
#include <sys/ethernet.h>
#include <netinet/in.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * SDC VXLAN Protocol Definitions
 */

#define	SVP_VERSION_ONE	1
#define	SVP_VERSION_TWO	2
/*
 * Bump this to 2.  Version 1 SVP is a subset of version 2, and can be
 * determined using an SVP_R_PING as part of connection establishment.
 * Version-2 specific changes will be highlighed (look for "v2").
 */
#define	SVP_CURRENT_VERSION	SVP_VERSION_TWO

typedef struct svp_req {
	uint16_t	svp_ver;
	uint16_t	svp_op;
	uint32_t	svp_size;
	uint32_t	svp_id;
	uint32_t	svp_crc32;
} svp_req_t;

/*
 * Unless specified, all message types function identically between v1 and v2
 * of SVP.
 */
typedef enum svp_op {
	SVP_R_UNKNOWN		= 0x00,
	SVP_R_PING		= 0x01,
	SVP_R_PONG		= 0x02,
	SVP_R_VL2_REQ		= 0x03,
	SVP_R_VL2_ACK		= 0x04,
	SVP_R_VL3_REQ		= 0x05,
	SVP_R_VL3_ACK		= 0x06,
	SVP_R_BULK_REQ		= 0x07,
	SVP_R_BULK_ACK		= 0x08,
	SVP_R_LOG_REQ		= 0x09,	/* v2 introduces new log type */
	SVP_R_LOG_ACK		= 0x0A, /* See svp_log_route_t */
	SVP_R_LOG_RM		= 0x0B,
	SVP_R_LOG_RM_ACK	= 0x0C,
	SVP_R_SHOOTDOWN		= 0x0D,
	SVP_R_ROUTE_REQ		= 0x0E,	/* v2 only */
	SVP_R_ROUTE_ACK		= 0x0F	/* v2 only */
} svp_op_t;

typedef enum svp_status {
	SVP_S_OK	= 0x00,	/* Everything OK */
	SVP_S_FATAL	= 0x01,	/* Fatal error, close connection */
	SVP_S_NOTFOUND	= 0x02,	/* Entry not found */
	SVP_S_BADL3TYPE	= 0x03,	/* Unknown svp_vl3_type_t */
	SVP_S_BADBULK	= 0x04	/* Unknown svp_bulk_type_t */
} svp_status_t;

/*
 * A client issues the SVP_R_VL2_REQ whenever it needs to perform a VL2->UL3
 * lookup. Requests have the following structure:
 */
typedef struct svp_vl2_req {
	uint8_t		sl2r_mac[ETHERADDRL];
	uint8_t		sl2r_pad[2];
	uint32_t	sl2r_vnetid;
} svp_vl2_req_t;

/*
 * This is the message a server uses to reply to the SVP_R_VL2_REQ.  If the
 * destination on the underlay is an IPv4 address, it should be encoded as an
 * IPv4-mapped IPv6 address.
 */
typedef struct svp_vl2_ack {
	uint16_t	sl2a_status;
	uint16_t	sl2a_port;
	uint8_t		sl2a_addr[16];
} svp_vl2_ack_t;


/*
 * A client issues the SVP_R_VL3_REQ request whenever it needs to perform a
 * VL3->VL2 lookup.  Note, that this also implicitly performs a VL2->UL3 lookup
 * as well. The sl3r_type member is used to indicate the kind of lookup type
 * that we're performing, eg. is it a L3 or L2.
 */
typedef enum svp_vl3_type {
	SVP_VL3_IP	= 0x01,
	SVP_VL3_IPV6	= 0x02
} svp_vl3_type_t;

typedef struct svp_vl3_req {
	uint8_t		sl3r_ip[16];
	uint32_t	sl3r_type;
	uint32_t	sl3r_vnetid;
} svp_vl3_req_t;

/*
 * This response, corresponding to the SVP_R_VL3_ACK, includes an answer to both
 * the VL3->VL2 and the VL2->UL3 requests.
 */
typedef struct svp_vl3_ack {
	uint32_t	sl3a_status;
	uint8_t		sl3a_mac[ETHERADDRL];
	uint16_t	sl3a_uport;
	uint8_t		sl3a_uip[16];
} svp_vl3_ack_t;

/*
 * SVP_R_BULK_REQ requests a bulk dump of data. Currently we have two kinds of
 * data tables that we need to dump: VL3->VL2 mappings and VL2->UL3 mappings.
 * The kind that we want is indicated using the svbr_type member.
 */
typedef enum svp_bulk_type {
	SVP_BULK_VL2	= 0x01,
	SVP_BULK_VL3	= 0x02
} svp_bulk_type_t;

typedef struct svp_bulk_req {
	uint32_t	svbr_type;
} svp_bulk_req_t;

/*
 * When replying to a bulk request (SVP_R_BULK_ACK), data is streamed back
 * across.  The format of the data is currently undefined and as we work on the
 * system, we'll get a better understanding of what this should look like. A
 * client may need to stream such a request to disk, or the format will need to
 * be in a streamable format that allows the client to construct data.
 */
typedef struct svp_bulk_ack {
	uint32_t	svba_status;
	uint32_t	svba_type;
	uint8_t		svba_data[];
} svp_bulk_ack_t;

/*
 * SVP_R_LOG_REQ requests a log entries from the specified log from the server.
 * The total number of bytes that the user is ready to receive is in svlr_count.
 * However, the server should not block for data if none is available and thus
 * may return less than svlr_count bytes back. We identify the IP address of the
 * underlay to use here explicitly.
 */
typedef struct svp_log_req {
	uint32_t	svlr_count;
	uint8_t		svlr_ip[16];
} svp_log_req_t;

/*
 * The server replies to a log request by sending a series of log entries.
 * These log entries may be a mixture of both vl2 and vl3 records. The reply is
 * a stream of bytes after the status message whose length is determined baseed
 * on the header itself. Each entry begins with a uint32_t that describes its
 * type and then is followed by the remaining data payload. The next entry
 * follows immediately which again begins with the uint32_t word that describes
 * what it should be.
 */
typedef enum svp_log_type {
	SVP_LOG_VL2	= 0x01,
	SVP_LOG_VL3	= 0x02,
	SVP_LOG_ROUTE	= 0x03	/* v2 only */
} svp_log_type_t;

typedef struct svp_log_vl2 {
	uint32_t	svl2_type;	/* Should be SVP_LOG_VL2 */
	uint8_t		svl2_id[16];	/* 16-byte UUID */
	uint8_t		svl2_mac[ETHERADDRL];
	uint8_t		svl2_pad[2];
	uint32_t	svl2_vnetid;
} svp_log_vl2_t;

typedef struct svp_log_vl3 {
	uint32_t	svl3_type;	/* Should be SVP_LOG_VL3 */
	uint8_t		svl3_id[16];	/* 16-byte UUID */
	uint8_t		svl3_ip[16];
	uint8_t		svl3_pad[2];
	uint16_t	svl3_vlan;
	uint32_t	svl3_vnetid;
} svp_log_vl3_t;

/*
 * This log entry only appears on v2 connections.
 */
typedef struct svp_log_route {
	uint32_t	svlr_type;	/* Should be SVP_LOG_ROUTE */
	uint8_t		svlr_id[16];	/* 16-byte UUID */
	uint32_t	svlr_src_vnetid;	/* Source VXLAN vnetid. */
	uint32_t	svlr_dst_vnetid;	/* Dest. VXLAN vnetid. */
	uint32_t	svlr_dcid;	/* Remote/dest Data Center ID. */
	uint8_t		svlr_srcip[16];	/* Source IP address base. */
	uint8_t		svlr_dstip[16];	/* Destination IP address base. */
	uint16_t	svlr_dst_vlan;	/* Source VLAN id. */
	uint16_t	svlr_src_vlan;	/* Destination VLAN id. */
	uint8_t		svlr_src_prefixlen;	/* Source IP prefix length. */
	uint8_t		svlr_dst_prefixlen;	/* Dest. IP prefix length. */
	uint16_t	svlr_pad;	/* So we can be aligned... */
} svp_log_route_t;

typedef struct svp_log_ack {
	uint32_t	svla_status;
	uint8_t		svla_data[];
} svp_log_ack_t;

/*
 * SVP_R_LOG_RM is used after the client successfully processes a series of the
 * log stream. It replies to tell the server that it can remove those IDs from
 * processing. The IDs used are the same IDs that were in the individual
 * SVP_R_LOG_ACK entries.
 */
typedef struct svp_lrm_req {
	uint32_t	svrr_count;
	uint8_t		svrr_ids[];
} svp_lrm_req_t;

/*
 * SVP_R_LOG_RM_ACK is used to indicate that a log entry has been successfully
 * deleted and at this point it makes sense to go and ask for another
 * SVP_R_LOG_REQ.
 */
typedef struct svp_lrm_ack {
	uint32_t	svra_status;
} svp_lrm_ack_t;

/*
 * A shootdown (SVP_R_SHOOTDOWN) is used by a CN to reply to another CN that it
 * sent an invalid entry that could not be processed. This should be a
 * relatively infrequent occurrence. Unlike the rest of the messages, there is
 * no reply to it. It's a single request to try and help get us out there. When
 * a node receives this, it will issue a conditional revocation ioctl, that
 * removes the entry if and only if, it matches the IP. That way if we've
 * already gotten an updated entry for this, we don't remove it again.
 */
typedef struct svp_shootdown {
	uint8_t		svsd_mac[ETHERADDRL];
	uint8_t		svsd_pad[2];
	uint32_t	svsd_vnetid;
} svp_shootdown_t;

/*
 * A route-request (SVP_R_ROUTE_REQ) queries the local SVP server to get a
 * far-remote (i.e. another Triton Data Center, nee. SDC) SVP server for
 * far-remote networks.  Modern overlay modules will request IP destinations
 * for remote-Triton networks, but they must know how to reach the
 * remote-Triton SVP server.
 *
 * NOTE: SVP_R_ROUTE_{REQ,ACK} are only present in SVP v2.
 */
typedef struct svp_route_req {
	uint32_t	srr_vnetid;	/* Requester's vnet ID. */
	uint16_t	srr_vlan;	/* Requester's VLAN ID. */
	uint16_t	srr_pad;	/* Zero on xmit, ignore on receipt. */
	uint8_t		srr_srcip[16];	/* VL3 Source IP. */
	uint8_t		srr_dstip[16];	/* VL3 Destination IP. */
} svp_route_req_t;

/*
 * The far-remote Triton Data Center will answer with the requisite information
 * to send overlay packets to the appropriate far-remote CNs.
 */
typedef struct svp_route_ack {
	uint32_t	sra_status;	/* Status. */
	uint32_t	sra_dcid;	/* Far-remote Data Center ID. */
	uint32_t	sra_vnetid;	/* Far-remote vnet ID. */
	uint16_t	sra_vlan;	/* Far-remote VLAN ID. */
	uint16_t	sra_port;	/* Destination UL3 port. */
	uint8_t		sra_ip[16];	/* Destination UL3 address. */
	uint8_t	sra_srcmac[ETHERADDRL];	/* Far-remote VL2 source. */
	uint8_t	sra_dstmac[ETHERADDRL];	/* Far-remote VL2 dest. */
	uint8_t		sra_src_pfx;	/* Far-remote VL3 source prefix */
	uint8_t		sra_dst_pfx;	/* Far-remote VL3 dest. prefix */
} svp_route_ack_t;

#ifdef __cplusplus
}
#endif

#endif /* _LIBVARPD_SVP_PROT_H */
