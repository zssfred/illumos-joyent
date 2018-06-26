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
 * Copyright 2018 Joyent, Inc.  All rights reserved.
 */

/*
 * Decode SVP (SmartDC VxLAN Protocol) packets
 */

#include <inttypes.h>
#include <sys/crc32.h>
#include <stdio.h>
#include <stdarg.h>
#include <libvarpd_svp_prot.h>
#include "snoop.h"

#define	UUID_SIZE 16

static uint32_t svp_crc32_tab[] = { CRC32_TABLE };

#define	NUM_BUFS 4
#define	BUF_LEN 64
static const char *
buf_printf(const char *fmt, ...)
{
	static char buf[NUM_BUFS][BUF_LEN];
	static size_t i = 0;
	char *bufp = buf[i++];
	va_list ap;

	va_start(ap, fmt);
	(void) vsnprintf(bufp, BUF_LEN, fmt, ap);
	va_end(ap);

	i %= NUM_BUFS;
	return (bufp);
}

#define	STR(x) case x: return(#x)
static const char *
svp_op_str(uint16_t op)
{
	switch (op) {
	STR(SVP_R_UNKNOWN);
	STR(SVP_R_PING);
	STR(SVP_R_PONG);
	STR(SVP_R_VL2_REQ);
	STR(SVP_R_VL2_ACK);
	STR(SVP_R_VL3_REQ);
	STR(SVP_R_VL3_ACK);
	STR(SVP_R_BULK_REQ);
	STR(SVP_R_BULK_ACK);
	STR(SVP_R_LOG_REQ);
	STR(SVP_R_LOG_ACK);
	STR(SVP_R_LOG_RM);
	STR(SVP_R_LOG_RM_ACK);
	STR(SVP_R_SHOOTDOWN);
	STR(SVP_R_ROUTE_REQ);
	STR(SVP_R_ROUTE_ACK);
	default:
		return (buf_printf("0x%hx", op));
	}
}

static const char *
svp_status_str(uint16_t status)
{
	switch (status) {
	STR(SVP_S_OK);
	STR(SVP_S_FATAL);
	STR(SVP_S_NOTFOUND);
	STR(SVP_S_BADL3TYPE);
	STR(SVP_S_BADBULK);
	default:
		return (buf_printf("0x%hx", status));
	}
}

static const char *
svp_vl3_type_str(uint32_t type)
{
	switch (type) {
	STR(SVP_VL3_IP);
	STR(SVP_VL3_IPV6);
	default:
		return (buf_printf("0x%x", type));
	}
}

static const char *
svp_bulk_type_str(uint32_t type)
{
	switch (type) {
	STR(SVP_BULK_VL2);
	STR(SVP_BULK_VL3);
	default:
		return (buf_printf("0x%x", type));
	}
}

static const char *
svp_log_type_str(uint32_t type)
{
	switch (type) {
	STR(SVP_LOG_VL2);
	STR(SVP_LOG_VL3);
	STR(SVP_LOG_ROUTE);
	default:
		return (buf_printf("0x%x", type));
	}
}
#undef STR

static const char *
svp_addr_str(void *addrp, uint8_t *prefixp)
{
	/* Include space for optional /ddd prefix length */
	static char buf[INET6_ADDRSTRLEN + 5];
	struct in_addr v4;
	int af = AF_INET6;

	if (IN6_IS_ADDR_V4MAPPED((struct in6_addr *)addrp)) {
		af = AF_INET;
		IN6_V4MAPPED_TO_INADDR((struct in6_addr *)addrp, &v4);
		addrp = &v4;
	}

	if (inet_ntop(af, addrp, buf, sizeof (buf)) == NULL) {
		uint8_t *p = addrp;
		size_t i;

		(void) strlcpy(buf, "0x", sizeof (buf));
		for (i = 0; i < 16; i++) {
			(void) snprintf(buf + 2 + i * 2,
			    sizeof (buf) - 2 - i * 2, "%02hhx", p[i]);
		}
	}

	if (prefixp != NULL && *prefixp != 128) {
		char buf2[5]; /* / + 3 digits + NUL */

		if (af == AF_INET)
			*prefixp -= 96;

		(void) snprintf(buf2, sizeof (buf2), "/%hhu", *prefixp);
		(void) strlcat(buf, buf2, sizeof (buf));
	}

	return (buf);
}

static const char *
svp_uuid_str(uint8_t *uuid)
{
	char *bufp = (char *)buf_printf("");
	char val[3];
	size_t i;

	for (i = 0; i < UUID_SIZE; i++) {
		(void) snprintf(val, sizeof (val), "%02hhx", uuid[i]);
		switch (i) {
		case 4:
		case 6:
		case 8:
		case 10:
			(void) strlcat(bufp, "-", BUF_LEN);
			break;
		}
		(void) strlcat(bufp, val, BUF_LEN);
	}
	return (bufp);
}

static boolean_t
svp_check_crc(char *data, int len)
{
	svp_req_t *req = (svp_req_t *)data;
	uint32_t save_crc = req->svp_crc32;
	uint32_t crc = -1U;

	req->svp_crc32 = 0;
	CRC32(crc, (uint8_t *)data, len, -1U, svp_crc32_tab);
	crc = ~crc;
	req->svp_crc32 = save_crc;

	return (ntohl(save_crc) == crc ? B_TRUE : B_FALSE);
}

static void
do_svp_vl2_req(void *data, int len)
{
	svp_vl2_req_t *vl2 = data;

	show_printf("MAC = %s", ether_ntoa((struct ether_addr *)vl2->sl2r_mac));
	show_printf("Virtual network id = %u", ntohl(vl2->sl2r_vnetid));
}

static void
do_svp_vl2_ack(void *data, int len)
{
	svp_vl2_ack_t *vl2a = data;

	show_printf("Status = %s", svp_status_str(ntohs(vl2a->sl2a_status)));
	show_printf("UL3 Address = %s", svp_addr_str(vl2a->sl2a_addr, NULL));
	show_printf("UL3 Port = %hu", ntohs(vl2a->sl2a_port));
}

static void
do_svp_vl3_req(void *data, int len)
{
	svp_vl3_req_t *req = data;

	show_printf("Vnet = %u", ntohl(req->sl3r_vnetid));
	show_printf("Type = %s", svp_vl3_type_str(ntohl(req->sl3r_type)));
	show_printf("VL3 Address = %s", svp_addr_str(req->sl3r_ip, NULL));
}

static void
do_svp_vl3_ack(void *data, int len)
{
	svp_vl3_ack_t *vl3a = data;

	show_printf("Status = %s", svp_status_str(ntohl(vl3a->sl3a_status)));
	show_printf("MAC = %s",
	    ether_ntoa((struct ether_addr *)vl3a->sl3a_mac));
	show_printf("UL3 Address = %s", svp_addr_str(vl3a->sl3a_uip, NULL));
	show_printf("UL3 Port = %hu", ntohs(vl3a->sl3a_uport));
}

static void
do_svp_bulk_req(void *data, int len)
{
	svp_bulk_req_t *req = data;

	if (len < sizeof (svp_bulk_req_t)) {
		show_printf("%s runt", svp_op_str(SVP_R_BULK_REQ));
		return;
	}

	show_printf("Type = %s", svp_bulk_type_str(ntohl(req->svbr_type)));
}

static void
do_svp_bulk_ack(void *data, int len)
{
	svp_bulk_ack_t *ack = data;
	uint32_t status;
	size_t i, n;

	show_printf("Status = %s", svp_status_str(status));
	show_printf("Type = %s", svp_bulk_type_str(ntohl(ack->svba_type)));

}

static void
do_svp_log_req(void *data, int len)
{
	svp_log_req_t *svlr = data;

	show_printf("Count = %u", ntohl(svlr->svlr_count));
	show_printf("Address = %s", svp_addr_str(svlr->svlr_ip, NULL));
}

static void
do_svp_log_ack(void *data, int len)
{
	svp_log_ack_t *ack = data;
	union {
		svp_log_vl2_t *vl2;
		svp_log_vl3_t *vl3;
		svp_log_route_t *vr;
		uint32_t	*vtype;
		void		*vd;
	} u = { .vd = (ack + 1) };
	uint32_t type;
	size_t total = 0, rlen = 0;
	uint8_t prefixlen;
	boolean_t is_host;

	show_printf("Status = %s", svp_status_str(ntohl(ack->svla_status)));
	len -= sizeof (*ack);

	while (len > 0) {
		if (len < sizeof (uint32_t)) {
			show_printf("    Trailing runt");
			break;
		}

		type = ntohl(*u.vtype);

		switch (type) {
		case SVP_LOG_VL2:
			rlen = sizeof (svp_log_vl2_t);
			break;
		case SVP_LOG_VL3:
			rlen = sizeof (svp_log_vl3_t);
			break;
		case SVP_LOG_ROUTE:
			rlen = sizeof (svp_log_route_t);
			break;
		default:
			/*
			 * If we don't know the type, we cannot determine
			 * the size of the record, so we cannot continue past
			 * this.
			 */
			show_printf("Log %-4s: Log type = 0x%x",
			    buf_printf("%zu", ++total), type);
			return;
		}

		if (len < rlen) {
			show_printf("Log %-4s %s runt",
			    buf_printf("%zu", ++total), svp_log_type_str(type));
			return;
		}

		/* These are the same in all three records */
		show_printf("Log %-4s Log type = %s",
		    buf_printf("%zu", ++total), svp_log_type_str(type));
		show_printf("%8s UUID = %s", "", svp_uuid_str(u.vl2->svl2_id));

		switch (type) {
		case SVP_LOG_VL2:
			show_printf("%8s MAC = %s", "",
			    ether_ntoa((struct ether_addr *)u.vl2->svl2_mac));
			show_printf("%8s Vnet = %u", "",
			    ntohl(u.vl2->svl2_vnetid));
			u.vl2++;
			break;
		case SVP_LOG_VL3:
			show_printf("%8s VLAN = %hu", "",
			    ntohs(u.vl3->svl3_vlan));
			show_printf("%8s Address = %s", "",
			    svp_addr_str(u.vl3->svl3_ip, NULL));
			show_printf("%8s Vnet = %u", "",
			    ntohl(u.vl3->svl3_vnetid));
			u.vl3++;
			break;
		case SVP_LOG_ROUTE:
			show_printf("%8s Source Vnet = %u", "",
			    ntohl(u.vr->svlr_src_vnetid));
			show_printf("%8s Source VLAN = %hu", "",
			    ntohs(u.vr->svlr_src_vlan));

			prefixlen = u.vr->svlr_src_prefixlen;
			is_host = prefixlen == 128 ? B_TRUE : B_FALSE;
			show_printf("%8s Source %s = %s", "",
			    is_host ? "address" : "subnet",
			    svp_addr_str(u.vr->svlr_srcip, &prefixlen));
			show_printf("%8s Destination DC id = %u", "",
			    ntohl(u.vr->svlr_dcid));
			show_printf("%8s Destination Vnet = %u", "",
			    ntohl(u.vr->svlr_dst_vnetid));
			show_printf("%8s Destination VLAN = %hu", "",
			    ntohs(u.vr->svlr_dst_vlan));

			prefixlen = u.vr->svlr_dst_prefixlen;
			is_host = prefixlen == 128 ? B_TRUE : B_FALSE;
			show_printf("%8s Destination %s = %s", "",
			    is_host ? "address" : "subnet",
			    svp_addr_str(u.vr->svlr_dstip, &prefixlen));
			u.vr++;
			break;
		}

		len -= rlen;
		show_space();
	}
	show_printf("Total log records = %zu", total);
}

static void
do_svp_lrm_req(void *data, int len)
{
	svp_lrm_req_t *req = data;
	size_t expected_sz = sizeof (*req);
	size_t i, n;

	n = ntohl(req->svrr_count);

	/* IDs are 16-byte UUIDs */
	expected_sz += n * UUID_SIZE;
	show_printf("ID Count = %u%s", n,
	    (len == expected_sz) ? "" : buf_printf(" (size mismatch)"));
	if (len != expected_sz)
		return;

	for (i = 0; i < n; i++) {
		show_printf("%-4s %s", (i == 0) ? "IDs:" : "",
		    svp_uuid_str(&req->svrr_ids[UUID_SIZE * i]));
	}
}

static void
do_svp_lrm_ack(void *data, int len)
{
	svp_lrm_ack_t *ack = data;

	show_printf("Status = %s", svp_status_str(ntohl(ack->svra_status)));
}

static void
do_svp_shootdown(void *data, int len)
{
	svp_shootdown_t *sd = data;

	show_printf("Vnet = %u", ntohl(sd->svsd_vnetid));
	show_printf("MAC Address = %s",
	    ether_ntoa((struct ether_addr *)sd->svsd_mac));
}

static void
do_svp_route_req(void *data, int len)
{
	svp_route_req_t *req = data;

	show_printf("Vnet = %u", ntohl(req->srr_vnetid));
	show_printf("VLAN = %hu", ntohs(req->srr_vlan));
	show_printf("Source Address = %s", svp_addr_str(req->srr_srcip, NULL));
	show_printf("Destination Address = %s", svp_addr_str(req->srr_dstip,
	    NULL));
}

static void
do_svp_route_ack(void *data, int len)
{
	svp_route_ack_t *ack = data;

	show_printf("Status = %s", svp_status_str(ntohl(ack->sra_status)));
	show_printf("Remote DC Id = %u", ntohl(ack->sra_dcid));
	show_printf("Remote Vnet = %u", ntohl(ack->sra_vnetid));
	show_printf("Remote VLAN = %hu", ntohs(ack->sra_vlan));
	show_printf("Remote UL3 Address = %s", svp_addr_str(ack->sra_ip, NULL));
	show_printf("Remote UL3 Port = %hu", ntohs(ack->sra_port));
	show_printf("Source MAC Address = %s",
	    ether_ntoa((struct ether_addr *)ack->sra_srcmac));
	show_printf("Destination MAC Address = %s",
	    ether_ntoa((struct ether_addr *)ack->sra_dstmac));
	show_printf("Source IP Prefix = %hhu", ack->sra_src_pfx);
	show_printf("Destination IP Prefix = %hhu", ack->sra_dst_pfx);
}

static struct svp_len_tbl {
	uint16_t slt_op;
	size_t	slt_len;
} svp_len_tbl[] = {
	{ SVP_R_UNKNOWN,	0 },
	{ SVP_R_PING,		0 },
	{ SVP_R_PONG,		0 },
	{ SVP_R_VL2_REQ,	sizeof (svp_vl2_req_t) },
	{ SVP_R_VL2_ACK,	sizeof (svp_vl2_ack_t) },
	{ SVP_R_VL3_REQ,	sizeof (svp_vl3_req_t) },
	{ SVP_R_VL3_ACK,	sizeof (svp_vl3_ack_t) },
	{ SVP_R_BULK_REQ,	sizeof (svp_bulk_req_t) },
	{ SVP_R_BULK_ACK,	sizeof (svp_bulk_ack_t) },
	{ SVP_R_LOG_REQ,	sizeof (svp_log_req_t) },
	{ SVP_R_LOG_ACK,	0 },
	{ SVP_R_LOG_RM,		sizeof (svp_lrm_req_t) },
	{ SVP_R_LOG_RM_ACK,	sizeof (svp_lrm_ack_t) },
	{ SVP_R_SHOOTDOWN,	sizeof (svp_shootdown_t) },
	{ SVP_R_ROUTE_REQ,	sizeof (svp_route_req_t) },
	{ SVP_R_ROUTE_ACK,	sizeof (svp_route_ack_t) }
};

static boolean_t
svp_check_runt(uint16_t op, int len)
{
	if (op > SVP_R_ROUTE_ACK)
		return (B_FALSE);

	if (len < svp_len_tbl[op].slt_len) {
		show_printf("%s Runt", svp_op_str(op));
		show_space();
		return (B_TRUE);
	}
	return (B_FALSE);
}

int
interpret_svp(int flags, char *data, int fraglen)
{
	svp_req_t *req = (svp_req_t *)data;
	boolean_t crc_ok;

	if (fraglen < sizeof (svp_req_t)) {
		if (flags & F_SUM)
			(void) snprintf(get_sum_line(), MAXLINE,
			    "SVP RUNT");
		if (flags & F_DTAIL)
			show_header("SVP RUNT:  ", "Short packet", fraglen);

		return (fraglen);
	}

	crc_ok = svp_check_crc(data, fraglen);

	if (flags & F_SUM) {
		(void) snprintf(get_sum_line(), MAXLINE,
		    "SVP V=%hu OP=%s ID=%u%s", ntohs(req->svp_ver),
		    svp_op_str(ntohs(req->svp_op)),
		    ntohl(req->svp_id), crc_ok ? "" : " (BAD CRC)");
	}

	if (flags & F_DTAIL) {
		uint16_t op = ntohs(req->svp_op);

		show_header("SVP:    ", "SVP Header", sizeof (svp_req_t));
		show_space();
		show_printf("Version = %hu", ntohs(req->svp_ver));
		show_printf("Op = %s", svp_op_str(op));
		show_printf("Packet length = %u bytes%s", ntohl(req->svp_size),
		    (ntohl(req->svp_size) == fraglen - sizeof (*req)) ?
		    "" : " (mismatch)");
		show_printf("Id = %u", ntohl(req->svp_id));
		show_printf("CRC = %x%s", ntohl(req->svp_crc32),
		    crc_ok ? "" : " (bad)");
		show_space();

		req++;
		fraglen -= sizeof (*req);

		if (svp_check_runt(op, fraglen))
			return (fraglen);

		switch (op) {
		case SVP_R_VL2_REQ:
			do_svp_vl2_req(req, fraglen);
			break;
		case SVP_R_VL2_ACK:
			do_svp_vl2_ack(req, fraglen);
			break;
		case SVP_R_VL3_REQ:
			do_svp_vl3_req(req, fraglen);
			break;
		case SVP_R_VL3_ACK:
			do_svp_vl3_ack(req, fraglen);
			break;
		case SVP_R_BULK_REQ:
			do_svp_bulk_req(req, fraglen);
			break;
		case SVP_R_BULK_ACK:
			do_svp_bulk_ack(req, fraglen);
			break;
		case SVP_R_LOG_REQ:
			do_svp_log_req(req, fraglen);
			break;
		case SVP_R_LOG_ACK:
			do_svp_log_ack(req, fraglen);
			break;
		case SVP_R_LOG_RM:
			do_svp_lrm_req(req, fraglen);
			break;
		case SVP_R_LOG_RM_ACK:
			do_svp_lrm_ack(req, fraglen);
			break;
		case SVP_R_SHOOTDOWN:
			do_svp_shootdown(req, fraglen);
			break;
		case SVP_R_ROUTE_REQ:
			do_svp_route_req(req, fraglen);
			break;
		case SVP_R_ROUTE_ACK:
			do_svp_route_ack(req, fraglen);
			break;
		}

		show_space();
	}

	return (0);
}
