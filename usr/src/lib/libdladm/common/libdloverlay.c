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

#include <libdladm_impl.h>
#include <libdllink.h>
#include <libdloverlay.h>
#include <sys/dld.h>
#include <sys/overlay.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>

dladm_status_t
dladm_overlay_create(dladm_handle_t handle, const char *name,
    const char *encap, uint64_t vid, uint32_t flags)
{
	int ret;
	dladm_status_t status;
	datalink_id_t linkid;
	overlay_ioc_create_t oic;

	status = dladm_create_datalink_id(handle, name, DATALINK_CLASS_OVERLAY,
	    DL_ETHER, flags, &linkid);
	if (status != DLADM_STATUS_OK)
		return (status);

	bzero(&oic, sizeof (oic));
	oic.oic_linkid = linkid;
	oic.oic_vnetid = vid;
	(void) strlcpy(oic.oic_encap, encap, MAXLINKNAMELEN);

	status = DLADM_STATUS_OK;
	ret = ioctl(dladm_dld_fd(handle), OVERLAY_IOC_CREATE, &oic);
	if (ret != 0) {
		/* XXX We need to have private errors here */
		status = dladm_errno2status(errno);
	}

	if (status != DLADM_STATUS_OK)
		(void) dladm_destroy_datalink_id(handle, linkid, flags);

	return (status);
}

dladm_status_t
dladm_overlay_delete(dladm_handle_t handle, datalink_id_t linkid)
{
	dladm_status_t status;
	datalink_class_t class;
	overlay_ioc_delete_t oid;
	int ret;
	uint32_t flags;

	if (dladm_datalink_id2info(handle, linkid, &flags, &class, NULL,
	    NULL, 0) != DLADM_STATUS_OK)
		return (DLADM_STATUS_BADARG);

	if (class != DATALINK_CLASS_OVERLAY)
		return (DLADM_STATUS_BADARG);

	oid.oid_linkid = linkid;
	status = DLADM_STATUS_OK;
	ret = ioctl(dladm_dld_fd(handle), OVERLAY_IOC_DELETE, &oid);
	if (ret != 0)
		status = dladm_errno2status(errno);

	if (status == DLADM_STATUS_OK)
		(void) dladm_destroy_datalink_id(handle, linkid,
		    flags);

	return (status);
}

static void
dladm_overlay_print_prop(const overlay_ioc_propinfo_t *oipi, const void *buf,
    const uint32_t bufsize)
{
	const struct in6_addr *ipv6;
	struct in_addr ip;
	char strbuf[INET6_ADDRSTRLEN];

	switch (oipi->oipi_type) {
	case OVERLAY_PROP_T_INT:
		if (bufsize > 8) {
			printf("%s: <INT E2BIG>\n");
		} else if (bufsize > 4) {
			const int64_t *val = buf;
			printf("%s: %lld\n", oipi->oipi_name, *val);
		} else if (bufsize > 2) {
			const int32_t *val = buf;
			printf("%s: %ld\n", oipi->oipi_name, *val);
		} else if (bufsize > 1) {
			const int16_t *val = buf;
			printf("%s: %d\n", oipi->oipi_name, *val);
		} else {
			const int8_t *val = buf;
			printf("%s: %d\n", oipi->oipi_name, *val);
		}
		break;
	case OVERLAY_PROP_T_UINT:
		if (bufsize > 8) {
			printf("%s: <INT E2BIG>\n");
		} else if (bufsize > 4) {
			const uint64_t *val = buf;
			printf("%s: %lld\n", oipi->oipi_name, *val);
		} else if (bufsize > 2) {
			const uint32_t *val = buf;
			printf("%s: %ld\n", oipi->oipi_name, *val);
		} else if (bufsize > 1) {
			const uint16_t *val = buf;
			printf("%s: %d\n", oipi->oipi_name, *val);
		} else {
			const uint8_t *val = buf;
			printf("%s: %d\n", oipi->oipi_name, *val);
		}
		break;
	case OVERLAY_PROP_T_STRING:
		printf("%s: %s\n", oipi->oipi_name, (const char *)buf);
		break;
	case OVERLAY_PROP_T_IP:
		if (bufsize != sizeof (struct in6_addr)) {
			printf("%s: <malformed IP>\n", oipi->oipi_name);
			return;
		}

		ipv6 = buf;
		if (IN6_IS_ADDR_V4MAPPED(ipv6)) {
			IN6_V4MAPPED_TO_INADDR(ipv6, &ip);
			if (inet_ntop(AF_INET, &ip, strbuf,
			    sizeof (strbuf)) == NULL) {
				printf("%s: malformed ip\n", oipi->oipi_name);
				return;
			}
		} else {
			if (inet_ntop(AF_INET6, ipv6, strbuf,
			    sizeof (strbuf)) == NULL) {
				printf("%s: malformed ip\n", oipi->oipi_name);
				return;
			}
		}
		printf("%s: %s\n", oipi->oipi_name, strbuf);
		break;
	default:
		printf("%s: <unkonwn type>\n", oipi->oipi_name);
	}
}

dladm_status_t
dladm_overlay_show(dladm_handle_t handle, datalink_id_t linkid)
{
	int ret, i;
	dladm_status_t status;
	datalink_class_t class;
	overlay_ioc_nprops_t oin;
	overlay_ioc_propinfo_t oipi;
	overlay_ioc_prop_t oip;

	if (dladm_datalink_id2info(handle, linkid, NULL, &class, NULL,
	    NULL, 0) != DLADM_STATUS_OK)
		return (DLADM_STATUS_BADARG);

	if (class != DATALINK_CLASS_OVERLAY)
		return (DLADM_STATUS_BADARG);

	oin.oipn_linkid = linkid;
	status = DLADM_STATUS_OK;
	ret = ioctl(dladm_dld_fd(handle), OVERLAY_IOC_NPROPS, &oin);
	if (ret != 0) {
		fprintf(stderr, "failed to get NPROPS\n");
		return (dladm_errno2status(errno));
	}

	for (i = 0; i < oin.oipn_nprops; i++) {
		bzero(&oipi, sizeof (overlay_ioc_propinfo_t));
		bzero(&oip, sizeof (overlay_ioc_prop_t));
		oipi.oipi_linkid = linkid;
		oipi.oipi_id = i;
		ret = ioctl(dladm_dld_fd(handle), OVERLAY_IOC_PROPINFO, &oipi);
		if (ret != 0) {
			fprintf(stderr, "failed to get propinfo %d\n", i);
			return (dladm_errno2status(errno));
		}

		oip.oip_linkid = linkid;
		oip.oip_id = i;
		ret = ioctl(dladm_dld_fd(handle), OVERLAY_IOC_GETPROP, &oip);
		if (ret != 0) {
			fprintf(stderr, "failed to get prop %s\n",
			    oipi.oipi_name);
			return (dladm_errno2status(errno));
		}
		dladm_overlay_print_prop(&oipi, oip.oip_value, oip.oip_size);
	}

	return (DLADM_STATUS_OK);
}
