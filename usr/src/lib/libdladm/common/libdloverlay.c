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
#include <libvarpd_client.h>

#define	VARPD_PROPERTY_NAME	"varpd/id"

static const char *dladm_overlay_doorpath = "/tmp/overlay.door";
typedef struct dladm_overlay_propinfo {
	boolean_t dop_isvarpd;
	union {
		overlay_ioc_propinfo_t *dop_overlay;
		varpd_client_prop_handle_t dop_varpd;
	} dop_un;
} dladm_overlay_propinfo_t;

dladm_status_t
dladm_overlay_prop_info(dladm_overlay_propinfo_handle_t phdl,
    const char **namep, uint_t *typep, uint_t *protp, const void **defp,
    uint32_t *sizep, const mac_propval_range_t **possp)
{
	dladm_overlay_propinfo_t *infop = (dladm_overlay_propinfo_t *)phdl;
	overlay_ioc_propinfo_t *oinfop = infop->dop_un.dop_overlay;

	if (infop->dop_isvarpd == B_FALSE) {
		if (namep != NULL)
			*namep = oinfop->oipi_name;
		if (typep != NULL)
			*typep = oinfop->oipi_type;
		if (protp != NULL)
			*protp = oinfop->oipi_prot;
		if (defp != NULL)
			*defp = oinfop->oipi_default;
		if (sizep != NULL)
			*sizep = oinfop->oipi_defsize;
		if (possp != NULL)
			*possp = (const mac_propval_range_t *)oinfop->oipi_poss;

	} else {
		int ret;
		ret = libvarpd_c_prop_info(infop->dop_un.dop_varpd, namep,
		    typep, protp, defp, sizep, possp);
		if (ret != 0)
			return (dladm_errno2status(ret));

	}

	return (DLADM_STATUS_OK);
}

static dladm_status_t
dladm_overlay_parse_prop(overlay_prop_type_t type, void *buf, uint32_t *sizep,
    const char *val)
{
	int ret;
	int64_t ival;
	uint64_t uval;
	char *eptr;
	struct in6_addr ipv6;
	struct in_addr ip;

	switch (type) {
	case OVERLAY_PROP_T_INT:
		errno = 0;
		ival = strtol(val, &eptr, 10);
		if ((ival == 0 && errno == EINVAL) ||
		    ((ival == LONG_MAX || ival == LONG_MIN) &&
		    errno == ERANGE))
			return (DLADM_STATUS_BADARG);
		bcopy(&ival, buf, sizeof (int64_t));
		*sizep = sizeof (int64_t);
		break;
	case OVERLAY_PROP_T_UINT:
		errno = 0;
		uval = strtol(val, &eptr, 10);
		if ((uval == 0 && errno == EINVAL) ||
		    (uval == ULONG_MAX && errno == ERANGE))
			return (DLADM_STATUS_BADARG);
		bcopy(&uval, buf, sizeof (uint64_t));
		*sizep = sizeof (uint64_t);
		break;
	case OVERLAY_PROP_T_STRING:
		ret = strlcpy((char *)buf, val, OVERLAY_PROP_SIZEMAX);
		if (ret >= OVERLAY_PROP_SIZEMAX)
			return (DLADM_STATUS_BADARG);
		*sizep = ret + 1;
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
		bcopy(&ipv6, buf, sizeof (struct in6_addr));
		*sizep = sizeof (struct in6_addr);
		break;
	default:
		abort();
	}

	return (DLADM_STATUS_OK);
}

dladm_status_t
dladm_overlay_varpd_setprop(dladm_handle_t handle, varpd_client_handle_t chdl,
    uint64_t inst, const char *name, char *const *valp, uint_t cnt)
{
	int ret;
	uint32_t size;
	uint8_t buf[LIBVARPD_PROP_SIZEMAX];
	varpd_client_prop_handle_t phdl;
	uint_t type;
	dladm_status_t status;

	if ((ret = libvarpd_c_prop_handle_alloc(chdl, inst, &phdl)) != 0)
		return (dladm_errno2status(ret));

	if ((ret = libvarpd_c_prop_info_fill_by_name(phdl, name)) != 0) {
		libvarpd_c_prop_handle_free(phdl);
		return (dladm_errno2status(ret));
	}

	if ((ret = libvarpd_c_prop_info(phdl, NULL, &type, NULL, NULL, NULL,
	    NULL)) != 0) {
		libvarpd_c_prop_handle_free(phdl);
		return (dladm_errno2status(ret));
	}

	if ((status = dladm_overlay_parse_prop(type, buf, &size, valp[0])) !=
	    DLADM_STATUS_OK) {
		libvarpd_c_prop_handle_free(phdl);
		return (dladm_errno2status(ret));
	}

	status = DLADM_STATUS_OK;
	ret = libvarpd_c_prop_set(phdl, buf, size);
	libvarpd_c_prop_handle_free(phdl);

	return (dladm_errno2status(ret));
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
	if ((ret = dladm_overlay_parse_prop(info.oipi_type, prop.oip_value,
	    &prop.oip_size, valp[0])) != DLADM_STATUS_OK)
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
    dladm_overlay_propinfo_handle_t phdl, void *arg)
{
	dladm_status_t status;
	uint8_t buf[DLADM_OVERLAY_PROP_SIZEMAX];
	uint_t prot;
	size_t size;
	const char *name;

	if ((status = dladm_overlay_prop_info(phdl, &name, NULL, &prot, NULL,
	    NULL, NULL)) != DLADM_STATUS_OK)
		return (status);

	if ((prot & OVERLAY_PROP_PERM_REQ) == 0)
		return (DLADM_WALK_CONTINUE);

	if (dladm_overlay_get_prop(handle, linkid, phdl, buf, &size) !=
	    DLADM_STATUS_OK)
		return (DLADM_WALK_CONTINUE);

	if (size == 0)
		fprintf(stderr, "unset required propety: %s\n", name);

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
	size_t slen;
	varpd_client_handle_t vch;
	uint64_t id;

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

	slen = strlen(search);
	for (i = 0; props != NULL && i < props->al_count; i++) {
		dladm_arg_info_t	*aip = &props->al_info[i];

		/*
		 * If it's a property for the search plugin, eg. it has the
		 * prefix '<search>/', then we don't set the property on the
		 * overlay device and instead set it on the varpd instance.
		 */
		if (strncmp(aip->ai_name, search, slen) == 0 &&
		    aip->ai_name[slen] == '/')
			continue;
		status = dladm_overlay_setprop(handle, linkid, aip->ai_name,
		    aip->ai_val, aip->ai_count);
		if (status != DLADM_STATUS_OK) {
			/* XXX */
			fprintf(stderr, "failed to set property %s\n",
			    aip->ai_name);
			(void) dladm_overlay_delete(handle, linkid);
			return (status);
		}
	}

	if ((ret = libvarpd_c_create(&vch, dladm_overlay_doorpath)) != 0) {
		fprintf(stderr, "failed to create libvarpd handle: %d\n", ret);
		(void) dladm_overlay_delete(handle, linkid);
		return (dladm_errno2status(ret));
	}

	if ((ret = libvarpd_c_instance_create(vch, linkid, search,
	    &id)) != 0) {
		fprintf(stderr, "failed to create varpd instance: %d\n", ret);
		libvarpd_c_destroy(vch);
		(void) dladm_overlay_delete(handle, linkid);
		return (dladm_errno2status(ret));
	}

	for (i = 0; props != NULL && i < props->al_count; i++) {
		dladm_arg_info_t	*aip = &props->al_info[i];

		/*
		 * Skip arguments we've processed already.
		 */
		if (strncmp(aip->ai_name, search, slen) != 0)
			continue;

		if (aip->ai_name[slen] != '/')
			continue;

		ret = dladm_overlay_varpd_setprop(handle, vch, id, aip->ai_name,
		    aip->ai_val, aip->ai_count);
		if (ret != 0) {
			fprintf(stderr, "failed to set varpd prop: %s\n",
			    aip->ai_name);
			/* XXX Need to clean up instance, but... */
			libvarpd_c_destroy(vch);
			(void) dladm_overlay_delete(handle, linkid);
			return (dladm_errno2status(ret));
		}
	}

	if ((ret = libvarpd_c_instance_activate(vch, id)) != 0) {
		fprintf(stderr, "failed to activate varpd instance: %d\n", ret);
		/* XXX Need to clean up instance, but we don't support that */
		libvarpd_c_destroy(vch);
		(void) dladm_overlay_delete(handle, linkid);
		return (dladm_errno2status(ret));

	}

	bzero(&oia, sizeof (oia));
	oia.oia_linkid = linkid;
	status = DLADM_STATUS_OK;
	ret = ioctl(dladm_dld_fd(handle), OVERLAY_IOC_ACTIVATE, &oia);
	if (ret != 0) {
		/* XXX We need to have private errors here */
		ret = errno;
		fprintf(stderr, "failed to activate %d\n", ret);
		dladm_overlay_walk_prop(handle, linkid,
		    dladm_overlay_activate_cb, NULL);
		status = dladm_errno2status(ret);
		/* XXX Clean up varpd instance */
	}

	libvarpd_c_destroy(vch);
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
    dladm_overlay_propinfo_handle_t infohdl, void *buf, size_t *sizep)
{
	int ret;
	overlay_ioc_prop_t oip;
	dladm_overlay_propinfo_t *infop = (dladm_overlay_propinfo_t *)infohdl;

	/* XXX Better errno */
	if (*sizep < DLADM_OVERLAY_PROP_SIZEMAX)
		return (dladm_errno2status(ERANGE));

	if (infop->dop_isvarpd == B_FALSE) {
		bzero(&oip, sizeof (overlay_ioc_prop_t));
		oip.oip_linkid = linkid;
		oip.oip_id = infop->dop_un.dop_overlay->oipi_id;
		ret = ioctl(dladm_dld_fd(handle), OVERLAY_IOC_GETPROP, &oip);
		if (ret != 0)
			return (dladm_errno2status(errno));
		bcopy(oip.oip_value, buf, DLADM_OVERLAY_PROP_SIZEMAX);
		*sizep = oip.oip_size;
	} else {
		uint32_t size = *sizep;

		ret = libvarpd_c_prop_get(infop->dop_un.dop_varpd, buf, &size);
		if (ret != 0)
			return (dladm_errno2status(errno));
		*sizep = size;
	}

	return (DLADM_STATUS_OK);
}

static dladm_status_t
dladm_overlay_walk_varpd_prop(dladm_handle_t handle, datalink_id_t linkid,
    uint64_t varpdid, dladm_overlay_prop_f func, void *arg)
{
	int ret, i;
	varpd_client_handle_t chdl;
	varpd_client_prop_handle_t phdl;
	uint_t nprops;
	dladm_status_t status;

	if ((ret = libvarpd_c_create(&chdl, dladm_overlay_doorpath)) != 0)
		return (dladm_errno2status(ret));

	if ((ret = libvarpd_c_prop_handle_alloc(chdl, varpdid, &phdl)) != 0) {
		libvarpd_c_destroy(chdl);
		return (dladm_errno2status(ret));
	}

	if ((ret = libvarpd_c_prop_nprops(chdl, varpdid, &nprops)) != 0) {
		libvarpd_c_prop_handle_free(phdl);
		libvarpd_c_destroy(chdl);
		return (dladm_errno2status(ret));
	}

	status = DLADM_STATUS_OK;
	for (i = 0; i < nprops; i++) {
		dladm_overlay_propinfo_t dop;

		bzero(&dop, sizeof (dop));
		dop.dop_isvarpd = B_TRUE;
		dop.dop_un.dop_varpd = phdl;

		if ((ret = libvarpd_c_prop_info_fill(phdl, i)) != 0) {
			status = dladm_errno2status(ret);
			break;
		}

		ret = func(handle, linkid,
		    (dladm_overlay_propinfo_handle_t)&dop, arg);
		if (ret == DLADM_WALK_TERMINATE)
			break;
	}

	libvarpd_c_prop_handle_free(phdl);
	libvarpd_c_destroy(chdl);

	return (status);
}

dladm_status_t
dladm_overlay_walk_prop(dladm_handle_t handle, datalink_id_t linkid,
    dladm_overlay_prop_f func, void *arg)
{
	int i, ret;
	dladm_status_t status;
	datalink_class_t class;
	overlay_ioc_nprops_t oin;
	overlay_ioc_propinfo_t oipi;
	dladm_overlay_propinfo_t dop;
	uint64_t varpdid = UINT64_MAX;

	if (dladm_datalink_id2info(handle, linkid, NULL, &class, NULL,
	    NULL, 0) != DLADM_STATUS_OK)
		return (DLADM_STATUS_BADARG);

	if (class != DATALINK_CLASS_OVERLAY)
		return (DLADM_STATUS_BADARG);

	bzero(&oin, sizeof (overlay_ioc_nprops_t));
	status = DLADM_STATUS_OK;
	oin.oipn_linkid = linkid;
	ret = ioctl(dladm_dld_fd(handle), OVERLAY_IOC_NPROPS, &oin);
	if (ret != 0)
		return (dladm_errno2status(errno));

	for (i = 0; i < oin.oipn_nprops; i++) {
		bzero(&dop, sizeof (dladm_overlay_propinfo_t));
		bzero(&oipi, sizeof (overlay_ioc_propinfo_t));
		oipi.oipi_linkid = linkid;
		oipi.oipi_id = i;
		ret = ioctl(dladm_dld_fd(handle), OVERLAY_IOC_PROPINFO, &oipi);
		if (ret != 0) {
			fprintf(stderr, "failed to get propinfo %d\n", i);
			return (dladm_errno2status(errno));
		}

		dop.dop_isvarpd = B_FALSE;
		dop.dop_un.dop_overlay = &oipi;
		ret = func(handle, linkid,
		    (dladm_overlay_propinfo_handle_t)&dop, arg);
		if (ret == DLADM_WALK_TERMINATE)
			break;

		if (strcmp(oipi.oipi_name, VARPD_PROPERTY_NAME) == 0) {
			uint8_t buf[DLADM_OVERLAY_PROP_SIZEMAX];
			size_t bufsize = sizeof (buf);
			uint64_t *vp;

			if ((status = dladm_overlay_get_prop(handle, linkid,
			    (dladm_overlay_propinfo_handle_t)&dop, buf,
			    &bufsize)) != DLADM_STATUS_OK)
				continue;

			vp = (uint64_t *)buf;
			varpdid = *vp;
		}
	}

	/* Should this really be possible? */
	if (varpdid == UINT64_MAX)
		return (DLADM_STATUS_OK);

	return (dladm_overlay_walk_varpd_prop(handle, linkid, varpdid, func,
	    arg));
}
