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
#include <stdlib.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <limits.h>

static dladm_status_t
dladm_overlay_parse_prop(overlay_ioc_propinfo_t *infop,
    overlay_ioc_prop_t *prop, const char *val)
{
	int ret;
	int64_t ival;
	uint64_t uval;
	char *eptr;
	struct in6_addr ipv6;
	struct in_addr ip;

	switch (infop->oipi_type) {
	case OVERLAY_PROP_T_INT:
		errno = 0;
		ival = strtol(val, &eptr, 10);
		if ((ival == 0 && errno == EINVAL) ||
		    ((ival == LONG_MAX || ival == LONG_MIN) &&
		    errno == ERANGE))
			return (DLADM_STATUS_BADARG);
		bcopy(&ival, prop->oip_value, sizeof (int64_t));
		prop->oip_size = sizeof (int64_t);
		break;
	case OVERLAY_PROP_T_UINT:
		errno = 0;
		uval = strtol(val, &eptr, 10);
		if ((uval == 0 && errno == EINVAL) ||
		    (uval == ULONG_MAX && errno == ERANGE))
			return (DLADM_STATUS_BADARG);
		bcopy(&uval, prop->oip_value, sizeof (uint64_t));
		prop->oip_size = sizeof (uint64_t);
		break;
	case OVERLAY_PROP_T_STRING:
		ret = strlcpy((char *)prop->oip_value, val,
		    OVERLAY_PROP_SIZEMAX);
		if (ret >= OVERLAY_PROP_SIZEMAX)
			return (DLADM_STATUS_BADARG);
		prop->oip_size = ret + 1;
		break;
	case OVERLAY_PROP_T_IP:
		/*
		 * Always try to parse the IP as an IPv6 address. If that fails,
		 * try to interpret it as an IPv4 address and transform it into
		 * an IPv6 mapped IPv4 address.
		 */
		if (inet_pton(AF_INET6, val, &ipv6) != 1) {
			if (inet_pton(AF_INET, val, &ip) != 1)
				return (DLADM_STATUS_BADARG);

			IN6_INADDR_TO_V4MAPPED(&ip, &ipv6);
		}
		bcopy(&ipv6, prop->oip_value, sizeof (struct in6_addr));
		prop->oip_size = sizeof (struct in6_addr);
		break;
	default:
		abort();
	}

	return (DLADM_STATUS_OK);
}

dladm_status_t
dladm_overlay_setprop(dladm_handle_t handle, datalink_id_t linkid,
    const char *name, char *const *valp, uint_t cnt)
{
	int			ret;
	dladm_status_t		status;
	overlay_ioc_propinfo_t	info;
	overlay_ioc_prop_t	prop;

	if (linkid == DATALINK_INVALID_LINKID ||
	    name == NULL || valp == NULL || cnt != 1)
		return (DLADM_STATUS_BADARG);

	bzero(&info, sizeof (overlay_ioc_propinfo_t));
	info.oipi_linkid = linkid;
	info.oipi_id = -1;
	if (strlcpy(info.oipi_name, name, OVERLAY_PROP_NAMELEN) >=
	    OVERLAY_PROP_NAMELEN)
		return (DLADM_STATUS_BADARG);

	status = DLADM_STATUS_OK;
	ret = ioctl(dladm_dld_fd(handle), OVERLAY_IOC_PROPINFO, &info);
	if (ret != 0)
		status = dladm_errno2status(errno);

	if (ret != DLADM_STATUS_OK)
		return (status);

	prop.oip_linkid = linkid;
	prop.oip_id = info.oipi_id;
	prop.oip_name[0] = '\0';
	if ((ret = dladm_overlay_parse_prop(&info, &prop, valp[0])) !=
	    DLADM_STATUS_OK)
		return (ret);

	status = DLADM_STATUS_OK;
	ret = ioctl(dladm_dld_fd(handle), OVERLAY_IOC_SETPROP, &prop);
	if (ret != 0)
		status = dladm_errno2status(errno);

	return (ret);
}

/*
 * Tell the user about any unset required properties.
 * XXX libraries shouldn't do this. Should be a dladm_arg_list_t returned to
 * dladm(1M)
 */
static int
dladm_overlay_activate_cb(dladm_handle_t handle, datalink_id_t linkid,
    overlay_ioc_propinfo_t *infop, void *arg)
{
	overlay_ioc_prop_t prop;

	if ((infop->oipi_prot & OVERLAY_PROP_PERM_REQ) == 0)
		return (DLADM_WALK_CONTINUE);

	bzero(&prop, sizeof (overlay_ioc_prop_t));
	if (dladm_overlay_get_prop(handle, linkid, infop, &prop) !=
	    DLADM_STATUS_OK)
		return (DLADM_WALK_CONTINUE);

	if (prop.oip_size == 0)
		fprintf(stderr, "unset required propety: %s\n",
		    infop->oipi_name);

	return (DLADM_WALK_CONTINUE);
}

dladm_status_t
dladm_overlay_create(dladm_handle_t handle, const char *name,
    const char *encap, const char *search, uint64_t vid,
    dladm_arg_list_t *props, uint32_t flags)
{
	int ret, i;
	dladm_status_t status;
	datalink_id_t linkid;
	overlay_ioc_create_t oic;
	overlay_ioc_activate_t oia;

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

	if (status != DLADM_STATUS_OK) {
		(void) dladm_destroy_datalink_id(handle, linkid, flags);
		return (status);
	}

	for (i = 0; props != NULL && i < props->al_count; i++) {
		dladm_arg_info_t	*aip = &props->al_info[i];

		ret = dladm_overlay_setprop(handle, linkid, aip->ai_name,
		    aip->ai_val, aip->ai_count);
		if (ret != DLADM_STATUS_OK) {
			/* XXX */
			fprintf(stderr, "failed to set property %s\n",
			    aip->ai_name);
			(void) dladm_overlay_delete(handle, linkid);
			return (status);
		}
	}

	bzero(&oia, sizeof (oia));
	oia.oia_linkid = linkid;
	ret = ioctl(dladm_dld_fd(handle), OVERLAY_IOC_ACTIVATE, &oia);
	if (ret != 0) {
		/* XXX We need to have private errors here */
		dladm_overlay_walk_prop(handle, linkid,
		    dladm_overlay_activate_cb, NULL);
		status = dladm_errno2status(errno);
	}

	if (status != DLADM_STATUS_OK)
		(void) dladm_overlay_delete(handle, linkid);

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

dladm_status_t
dladm_overlay_get_prop(dladm_handle_t handle, datalink_id_t linkid,
    overlay_ioc_propinfo_t *infop, overlay_ioc_prop_t *oip)
{
	int ret;

	bzero(oip, sizeof (overlay_ioc_prop_t));
	oip->oip_linkid = linkid;
	oip->oip_id = infop->oipi_id;
	ret = ioctl(dladm_dld_fd(handle), OVERLAY_IOC_GETPROP, oip);
	if (ret != 0) {
		return (dladm_errno2status(errno));
	}

	return (DLADM_STATUS_OK);
}

dladm_status_t
dladm_overlay_walk_prop(dladm_handle_t handle, datalink_id_t linkid,
    dladm_prop_f func, void *arg)
{
	int i, ret;
	dladm_status_t status;
	datalink_class_t class;
	overlay_ioc_nprops_t oin;
	overlay_ioc_propinfo_t oipi;

	if (dladm_datalink_id2info(handle, linkid, NULL, &class, NULL,
	    NULL, 0) != DLADM_STATUS_OK)
		return (DLADM_STATUS_BADARG);

	if (class != DATALINK_CLASS_OVERLAY)
		return (DLADM_STATUS_BADARG);

	bzero(&oin, sizeof (overlay_ioc_nprops_t));
	status = DLADM_STATUS_OK;
	oin.oipn_linkid = linkid;
	ret = ioctl(dladm_dld_fd(handle), OVERLAY_IOC_NPROPS, &oin);
	if (ret != 0) {
		return (dladm_errno2status(errno));
	}

	for (i = 0; i < oin.oipn_nprops; i++) {
		bzero(&oipi, sizeof (overlay_ioc_propinfo_t));
		oipi.oipi_linkid = linkid;
		oipi.oipi_id = i;
		ret = ioctl(dladm_dld_fd(handle), OVERLAY_IOC_PROPINFO, &oipi);
		if (ret != 0) {
			fprintf(stderr, "failed to get propinfo %d\n", i);
			return (dladm_errno2status(errno));
		}
		ret = func(handle, linkid, &oipi, arg);
		if (ret == DLADM_WALK_TERMINATE)
			break;
	}

	return (DLADM_STATUS_OK);
}
