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

/*
 * varpd client interfaces
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <umem.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <door.h>

#include <libvarpd_impl.h>

typedef struct varpd_client {
	int vcl_doorfd;
} varpd_client_t;

typedef struct varpd_client_prop_info {
	varpd_client_t		*vcprop_client;
	uint64_t		vcprop_instance;
	uint_t			vcprop_propid;
	uint_t			vcprop_type;
	uint_t			vcprop_prot;
	uint32_t		vcprop_defsize;
	uint32_t		vcprop_psize;
	char			vcprop_name[LIBVARPD_PROP_NAMELEN];
	uint8_t			vcprop_default[LIBVARPD_PROP_SIZEMAX];
	uint8_t			vcprop_poss[LIBVARPD_PROP_SIZEMAX];
} varpd_client_prop_info_t;

static int
libvarpd_c_door_call(varpd_client_t *client, varpd_client_arg_t *argp)
{
	int ret;
	door_arg_t darg;

	darg.data_ptr = (char *)argp;
	darg.data_size = sizeof (varpd_client_arg_t);
	darg.desc_ptr = NULL;
	darg.desc_num = 0;
	darg.rbuf = (char *)argp;
	darg.rsize = sizeof (varpd_client_arg_t);

	do {
		ret = door_call(client->vcl_doorfd, &darg);
	} while (ret != 0 && errno == EINTR);
	if (ret != 0) {
		switch (errno) {
		case E2BIG:
		case EFAULT:
		case EINVAL:
		case ENOTSUP:
		case EOVERFLOW:
		case ENFILE:
			abort();
		}
		ret = errno;
	}

	return (ret);
}

int
libvarpd_c_create(varpd_client_handle_t *chpp, const char *doorname)
{
	varpd_client_t *client;

	client = umem_alloc(sizeof (varpd_client_t), UMEM_DEFAULT);
	if (client == NULL)
		return (ENOMEM);

	client->vcl_doorfd = open(doorname, O_RDWR);
	if (client->vcl_doorfd < 0) {
		int ret = errno;
		umem_free(client, sizeof (varpd_client_t));
		return (ret);
	}

	*chpp = (varpd_client_handle_t)client;
	return (0);
}

int
libvarpd_c_destroy(varpd_client_handle_t chp)
{
	varpd_client_t *client = (varpd_client_t *)chp;
	if (close(client->vcl_doorfd) != 0)
		abort();

	umem_free(chp, sizeof (varpd_client_handle_t));
	return (0);
}

int
libvarpd_c_instance_create(varpd_client_handle_t chp, datalink_id_t linkid,
    const char *search, uint64_t *cidp)
{
	int ret;
	varpd_client_t *client = (varpd_client_t *)chp;
	varpd_client_arg_t carg;
	varpd_client_create_arg_t *cap = &carg.vca_un.vca_create;

	if (strlen(search) >= LIBVARPD_PROP_NAMELEN)
		return (EINVAL);
	carg.vca_command = VARPD_CLIENT_CREATE;
	carg.vca_errno = 0;
	cap->vcca_linkid = linkid;
	(void) strlcpy(cap->vcca_plugin, search, LIBVARPD_PROP_NAMELEN);

	ret = libvarpd_c_door_call(client, &carg);
	if (ret != 0)
		return (ret);

	if (carg.vca_errno != 0)
		return (carg.vca_errno);

	*cidp = cap->vcca_id;

	return (0);
}

int
libvarpd_c_instance_activate(varpd_client_handle_t chp, uint64_t cid)
{
	int ret;
	varpd_client_t *client = (varpd_client_t *)chp;
	varpd_client_arg_t carg;
	varpd_client_instance_arg_t *vciap = &carg.vca_un.vca_instance;

	carg.vca_command = VARPD_CLIENT_ACTIVATE;
	carg.vca_errno = 0;
	vciap->vcia_id = cid;

	ret = libvarpd_c_door_call(client, &carg);
	if (ret != 0)
		return (ret);

	if (carg.vca_errno != 0)
		return (carg.vca_errno);

	return (0);
}

int
libvarpd_c_instance_destroy(varpd_client_handle_t chp, uint64_t cid)
{
	int ret;
	varpd_client_t *client = (varpd_client_t *)chp;
	varpd_client_arg_t carg;
	varpd_client_instance_arg_t *vciap = &carg.vca_un.vca_instance;

	carg.vca_command = VARPD_CLIENT_DESTROY;
	carg.vca_errno = 0;
	vciap->vcia_id = cid;

	ret = libvarpd_c_door_call(client, &carg);
	if (ret != 0)
		return (ret);

	if (carg.vca_errno != 0)
		return (carg.vca_errno);

	return (0);
}

int
libvarpd_c_prop_nprops(varpd_client_handle_t chp, uint64_t cid, uint_t *nprops)
{
	int ret;
	varpd_client_t *client = (varpd_client_t *)chp;
	varpd_client_arg_t carg;
	varpd_client_nprops_arg_t *vcnap = &carg.vca_un.vca_nprops;

	carg.vca_command = VARPD_CLIENT_NPROPS;
	carg.vca_errno = 0;
	vcnap->vcna_id = cid;
	vcnap->vcna_nprops = 0;

	ret = libvarpd_c_door_call(client, &carg);
	if (ret != 0)
		return (ret);

	if (carg.vca_errno != 0)
		return (carg.vca_errno);
	*nprops = vcnap->vcna_nprops;
	return (0);
}

int
libvarpd_c_prop_handle_alloc(varpd_client_handle_t chp, uint64_t cid,
    varpd_client_prop_handle_t *phdlp)
{
	varpd_client_prop_info_t *infop;

	infop = umem_alloc(sizeof (varpd_client_prop_info_t), UMEM_DEFAULT);
	if (infop == NULL)
		return (ENOMEM);

	bzero(infop, sizeof (varpd_client_prop_info_t));
	infop->vcprop_client = (varpd_client_t *)chp;
	infop->vcprop_instance = cid;
	infop->vcprop_propid = UINT_MAX;
	*phdlp = (varpd_client_prop_handle_t)infop;
	return (0);
}

void
libvarpd_c_prop_handle_free(varpd_client_prop_handle_t phdl)
{
	umem_free(phdl, sizeof (varpd_client_prop_info_t));
	phdl = NULL;
}

static void
libvarpd_c_prop_info_from_door(varpd_client_prop_info_t *infop,
    const varpd_client_propinfo_arg_t *vcfap)
{
	infop->vcprop_propid = vcfap->vcfa_propid;
	infop->vcprop_type = vcfap->vcfa_type;
	infop->vcprop_prot = vcfap->vcfa_prot;
	infop->vcprop_defsize = vcfap->vcfa_defsize;
	infop->vcprop_psize = vcfap->vcfa_psize;
	bcopy(vcfap->vcfa_name, infop->vcprop_name, LIBVARPD_PROP_NAMELEN);
	bcopy(vcfap->vcfa_default, infop->vcprop_default,
	    LIBVARPD_PROP_SIZEMAX);
	bcopy(vcfap->vcfa_poss, infop->vcprop_poss, LIBVARPD_PROP_SIZEMAX);
}

int
libvarpd_c_prop_info_fill_by_name(varpd_client_prop_handle_t phdl,
    const char *name)
{
	int ret;
	varpd_client_arg_t carg;
	varpd_client_propinfo_arg_t *vcfap = &carg.vca_un.vca_info;
	varpd_client_prop_info_t *infop = (varpd_client_prop_info_t *)phdl;

	if (strlen(name) >= LIBVARPD_PROP_NAMELEN)
		return (EINVAL);
	bzero(&carg, sizeof (varpd_client_arg_t));
	carg.vca_command = VARPD_CLIENT_PROPINFO;
	carg.vca_errno = 0;
	vcfap->vcfa_id = infop->vcprop_instance;
	vcfap->vcfa_propid = UINT_MAX;
	(void) strlcpy(vcfap->vcfa_name, name, LIBVARPD_PROP_NAMELEN);

	ret = libvarpd_c_door_call(infop->vcprop_client, &carg);
	if (ret != 0)
		return (ret);

	if (carg.vca_errno != 0)
		return (carg.vca_errno);

	libvarpd_c_prop_info_from_door(infop, vcfap);
	return (0);
}

int
libvarpd_c_prop_info_fill(varpd_client_prop_handle_t phdl, uint_t propid)
{
	int ret;
	varpd_client_arg_t carg;
	varpd_client_propinfo_arg_t *vcfap = &carg.vca_un.vca_info;
	varpd_client_prop_info_t *infop = (varpd_client_prop_info_t *)phdl;

	bzero(&carg, sizeof (varpd_client_arg_t));
	carg.vca_command = VARPD_CLIENT_PROPINFO;
	carg.vca_errno = 0;
	vcfap->vcfa_id = infop->vcprop_instance;
	vcfap->vcfa_propid = propid;

	ret = libvarpd_c_door_call(infop->vcprop_client, &carg);
	if (ret != 0)
		return (ret);

	if (carg.vca_errno != 0)
		return (carg.vca_errno);

	libvarpd_c_prop_info_from_door(infop, vcfap);
	return (0);
}

int
libvarpd_c_prop_info(varpd_client_prop_handle_t phdl, const char **namep,
    uint_t *typep, uint_t *protp, const void **defp, uint32_t *sizep,
    const mac_propval_range_t **possp)
{
	varpd_client_prop_info_t *infop = (varpd_client_prop_info_t *)phdl;
	if (infop->vcprop_propid == UINT_MAX)
		return (EINVAL);

	if (namep != NULL)
		*namep = infop->vcprop_name;
	if (typep != NULL)
		*typep = infop->vcprop_type;
	if (protp != NULL)
		*protp = infop->vcprop_prot;
	if (defp != NULL)
		*defp = infop->vcprop_default;
	if (sizep != NULL)
		*sizep = infop->vcprop_psize;
	if (possp != NULL)
		*possp = (const mac_propval_range_t *)infop->vcprop_poss;
	return (0);
}

int
libvarpd_c_prop_get(varpd_client_prop_handle_t phdl, void *buf, uint32_t *len)
{
	int ret;
	varpd_client_arg_t carg;
	varpd_client_prop_arg_t *vcpap = &carg.vca_un.vca_prop;
	varpd_client_prop_info_t *infop = (varpd_client_prop_info_t *)phdl;

	if (len == NULL || buf == NULL || infop->vcprop_propid == UINT_MAX)
		return (EINVAL);
	if (*len < LIBVARPD_PROP_SIZEMAX)
		return (EOVERFLOW);

	bzero(&carg, sizeof (varpd_client_arg_t));
	carg.vca_command = VARPD_CLIENT_GETPROP;
	carg.vca_errno = 0;
	vcpap->vcpa_id = infop->vcprop_instance;
	vcpap->vcpa_propid = infop->vcprop_propid;

	ret = libvarpd_c_door_call(infop->vcprop_client, &carg);
	if (ret != 0)
		return (ret);

	if (carg.vca_errno != 0)
		return (carg.vca_errno);

	/*
	 * XXX We should really abort, as the server shouldn't send bad input,
	 * but a library really shouldn't kill the client. Therefore we have a
	 * shitty, shitty, error case.
	 */
	if (vcpap->vcpa_bufsize > LIBVARPD_PROP_SIZEMAX)
		return (E2BIG);

	bcopy(vcpap->vcpa_buf, buf, vcpap->vcpa_bufsize);
	*len = vcpap->vcpa_bufsize;
	return (0);
}

int
libvarpd_c_prop_set(varpd_client_prop_handle_t phdl, const void *buf,
    uint32_t len)
{
	int ret;
	varpd_client_arg_t carg;
	varpd_client_prop_arg_t *vcpap = &carg.vca_un.vca_prop;
	varpd_client_prop_info_t *infop = (varpd_client_prop_info_t *)phdl;

	if (len == NULL || buf == NULL || infop->vcprop_propid == UINT_MAX)
		return (EINVAL);
	if (len > LIBVARPD_PROP_SIZEMAX)
		return (EOVERFLOW);

	carg.vca_command = VARPD_CLIENT_SETPROP;
	carg.vca_errno = 0;
	vcpap->vcpa_id = infop->vcprop_instance;
	vcpap->vcpa_propid = infop->vcprop_propid;
	vcpap->vcpa_bufsize = len;
	bcopy(buf, vcpap->vcpa_buf, len);

	ret = libvarpd_c_door_call(infop->vcprop_client, &carg);
	if (ret != 0)
		return (ret);

	if (carg.vca_errno != 0)
		return (carg.vca_errno);

	return (0);
}
