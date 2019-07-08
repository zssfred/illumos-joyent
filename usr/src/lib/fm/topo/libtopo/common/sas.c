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
 * Copyright 2019 Joyent, Inc.
 */

/*
 * The sas FMRI scheme is intended to be used in conjuction with a
 * digraph-based topology to represent a SAS fabric.
 *
 * There are four types of vertices in the topology:
 *
 * initiator
 * ---------
 * An initiator is a device on the SAS fabric that originates SCSI commands.
 * Typically this is a SAS host-bus adapter (HBA) which can be built onto the
 * system board or be part of a PCIe add-in card.
 *
 * XXX - add description of initiator node properties
 *
 * port
 * ----
 * A port is a logical construct that represents a grouping of one or more
 * PHYs.  A port with one PHY is known as a narrow port.  An example of a
 * narrow port would be the connection from an expander to a target device.
 * A port with more than one PHY is known as a wide port.  A typical example
 * of a wide port would be the connection from an initiator to an exander
 * (typically 4 or 8 PHYs wide).
 *
 * XXX - add description of port node properties
 *
 * target
 * ------
 * A target (or end-device) represents the device that is receiving
 * SCSI commands from the an initiator.   Examples include disks and SSDs as
 * well as SMP and SES management devices.  SES and SMP targets would
 * be connected to an expander.  Disk/SSD targets can be connected to an
 * expander or directly attached (via a narrow port) to an initiator.
 *
 * XXX - add description of target node properties
 *
 * XXX - It'd be really cool if we could check for a ZFS pool config and
 * try to match the target to a leaf vdev and include the zfs-scheme FMRI of
 * that vdev as a property on this node.
 *
 * XXX - Similarly, for disks/ssd's it'd be cool if we could a match the
 * target to a disk node in the hc-scheme topology and also add the
 * hc-scheme FMRI of that disk as a property on this node.  This one would
 * have to be a dynamic (propmethod) property because we'd need to walk
 * the hc-schem tree, which may not have been built when we're enumerating.
 *
 * expander
 * --------
 * An expander acts as both a port multiplexer and expander routing signals
 * between one or more initiators and one or more targets or possibly a
 * second layer of downstream expanders, depending on the size of the fabric.
 * The SAS specification optionally allows for up to two levels of expanders
 * between the initiator(s) and target(s).
 *
 * XXX - add description of expander node properties
 *
 * Version 0 sas FMRI scheme
 * -------------------------
 * The resource in the sas FMRI scheme doesn't represent a discrete component
 * like the hc or svc schemes.  Rather, the resource represents a unique
 * path from a given initiator to a given target.  Hence, the first two
 * node/instance pairs are always an initiator and port and last two pairs
 * are always a port and a target. In between there may be one or two sets
 * of expander and port pairs.
 *
 * e.g.
 * sas:///initiator=<inst>/<port>=<inst>/.../port=<inst>/target=<inst>
 *
 * Node instance numbers are based on the local SAS address of the underlying
 * component.  Each initiator, expander and target will have a unique[1] SAS
 * address.  And each port from an initiator or to a target will also have a
 * unique SAS address.  However, expander ports are not individually
 * addressed.  If the expander port is attached, the instance number shall
 * be the SAS address of the attached device.  If the expander port is not
 * attached, the instance number shall be the SAS address of the expander,
 * itself.
 *
 * [1] The SAS address will be unique within a given SAS fabric (domain)
 *
 * The nvlist representation of the FMRI consists of two nvpairs:
 *
 * name               type                   value
 * ----               ----                   -----
 * sas-fmri-version   DATA_TYPE_UINT8        0
 * sas-path           DATA_TYPE_NVLIST_ARRAY see below
 *
 * sas-path is an array of nvlists where each nvlist contains the following
 * nvpairs:
 *
 * name               type                   value
 * ----               ----                   -----
 * sas-name           DATA_TYPE_STRING       (initiator|port|expander|target)
 * sas-id             DATA_TYPE_UINT64       SAS address (see above)
 *
 * XXX - what, if anything, should we put in the FMRI authority?
 */
#include <libnvpair.h>
#include <fm/topo_mod.h>

#include <sys/fm/protocol.h>
#include <sys/types.h>

#include <topo_digraph.h>
#include <topo_sas.h>
#include <topo_method.h>
#include <topo_subr.h>
#include "sas.h"

static int sas_fmri_nvl2str(topo_mod_t *, tnode_t *, topo_version_t,
    nvlist_t *, nvlist_t **);
static int sas_fmri_str2nvl(topo_mod_t *, tnode_t *, topo_version_t,
    nvlist_t *, nvlist_t **);
static int sas_fmri_create(topo_mod_t *, tnode_t *, topo_version_t,
    nvlist_t *, nvlist_t **);

static const topo_method_t sas_methods[] = {
	{ TOPO_METH_NVL2STR, TOPO_METH_NVL2STR_DESC, TOPO_METH_NVL2STR_VERSION,
	    TOPO_STABILITY_INTERNAL, sas_fmri_nvl2str },
	{ TOPO_METH_STR2NVL, TOPO_METH_STR2NVL_DESC, TOPO_METH_STR2NVL_VERSION,
	    TOPO_STABILITY_INTERNAL, sas_fmri_str2nvl },
	{ TOPO_METH_FMRI, TOPO_METH_FMRI_DESC, TOPO_METH_FMRI_VERSION,
	    TOPO_STABILITY_INTERNAL, sas_fmri_create },
	{ NULL }
};

static int sas_enum(topo_mod_t *, tnode_t *, const char *, topo_instance_t,
    topo_instance_t, void *, void *);
static void sas_release(topo_mod_t *, tnode_t *);

static const topo_modops_t sas_ops =
	{ sas_enum, sas_release };

static const topo_modinfo_t sas_info =
	{ "sas", FM_FMRI_SCHEME_SAS, SAS_VERSION, &sas_ops };

int
sas_init(topo_mod_t *mod, topo_version_t version)
{
	if (getenv("TOPOSASDEBUG"))
		topo_mod_setdebug(mod);
	topo_mod_dprintf(mod, "initializing sas builtin\n");

	if (version != SAS_VERSION)
		return (topo_mod_seterrno(mod, EMOD_VER_NEW));

	if (topo_mod_register(mod, &sas_info, TOPO_VERSION) != 0) {
		topo_mod_dprintf(mod, "failed to register sas_info: "
		    "%s\n", topo_mod_errmsg(mod));
		return (-1);
	}

	return (0);
}

void
sas_fini(topo_mod_t *mod)
{
	topo_mod_unregister(mod);
}

static topo_vertex_t *
sas_create_vertex(topo_mod_t *mod, const char *name, topo_instance_t inst)
{
	topo_vertex_t *vtx;
	tnode_t *tn;
	topo_pgroup_info_t pgi;
	int err;

	pgi.tpi_namestab = TOPO_STABILITY_PRIVATE;
	pgi.tpi_datastab = TOPO_STABILITY_PRIVATE;
	pgi.tpi_version = TOPO_VERSION;
	if (strcmp(name, TOPO_VTX_EXPANDER) == 0)
		pgi.tpi_name = TOPO_PGROUP_EXPANDER;
	else if (strcmp(name, TOPO_VTX_INITIATOR) == 0)
		pgi.tpi_name = TOPO_PGROUP_INITIATOR;
	else if (strcmp(name, TOPO_VTX_PORT) == 0)
		pgi.tpi_name = TOPO_PGROUP_SASPORT;
	else if (strcmp(name, TOPO_VTX_TARGET) == 0)
		pgi.tpi_name = TOPO_PGROUP_TARGET;
	else {
		topo_mod_dprintf(mod, "invalid vertex name: %s", name);
		return (NULL);
	}

	if ((vtx = topo_vertex_new(mod, name, inst)) == NULL) {
		topo_mod_dprintf(mod, "failed to create vertex: "
		    "%s=%" PRIx64 "", name, inst);
		return (NULL);
	}
	tn = topo_vertex_node(vtx);

	if (topo_pgroup_create(tn, &pgi, &err) != 0) {
		topo_mod_dprintf(mod, "failed to create %s propgroup on "
		    "%s=%" PRIx64 ": %s", pgi.tpi_name, name, inst,
		    topo_strerror(err));
	}
	return (vtx);
}

/*ARGSUSED*/
static int
sas_enum(topo_mod_t *mod, tnode_t *rnode, const char *name,
    topo_instance_t min, topo_instance_t max, void *notused1, void *notused2)
{
	if (topo_method_register(mod, rnode, sas_methods) != 0) {
		topo_mod_dprintf(mod, "failed to register scheme methods");
		/* errno set */
		return (-1);
	}

	/*
	 * XXX - this code simply hardcodes a minimal topology in order to
	 * facilitate early unit testing of the topo_digraph code.  This
	 * will be replaced by proper code that will discover and dynamically
	 * enumerate the SAS fabric(s).
	 */
	topo_vertex_t *ini, *ini_p1, *exp_in1, *exp, *exp_out1, *exp_out2,
	    *tgt1_p1, *tgt2_p1, *tgt1, *tgt2;
	uint64_t ini_addr = 0x5003048023567a00;
	uint64_t exp_addr = 0x500304801861347f;
	uint64_t tg1_addr = 0x5000cca2531b1025;
	uint64_t tg2_addr = 0x5000cca2531a41b9;

	if ((ini = sas_create_vertex(mod, TOPO_VTX_INITIATOR, ini_addr)) ==
	    NULL)
		return (-1);
	if ((ini_p1 = sas_create_vertex(mod, TOPO_VTX_PORT, ini_addr)) == NULL)
		return (-1);
	if (topo_edge_new(mod, ini, ini_p1) != 0)
		return (-1);

	if ((exp_in1 = sas_create_vertex(mod, TOPO_VTX_PORT, ini_addr)) ==
	    NULL)
		return (-1);
	if (topo_edge_new(mod, ini_p1, exp_in1) != 0)
		return (-1);

	if ((exp = sas_create_vertex(mod, TOPO_VTX_EXPANDER, exp_addr)) ==
	    NULL)
		return (-1);
	if (topo_edge_new(mod, exp_in1, exp) != 0)
		return (-1);

	if ((exp_out1 = sas_create_vertex(mod, TOPO_VTX_PORT, tg1_addr)) ==
	    NULL)
		return (-1);
	if (topo_edge_new(mod, exp, exp_out1) != 0)
		return (-1);

	if ((tgt1_p1 = sas_create_vertex(mod, TOPO_VTX_PORT, tg1_addr)) ==
	    NULL)
		return (-1);
	if (topo_edge_new(mod, exp_out1, tgt1_p1) != 0)
		return (-1);

	if ((tgt1 = sas_create_vertex(mod, TOPO_VTX_TARGET, tg1_addr)) == NULL)
		return (-1);
	if (topo_edge_new(mod, tgt1_p1, tgt1) != 0)
		return (-1);

	if ((exp_out2 = sas_create_vertex(mod, TOPO_VTX_PORT, tg2_addr)) ==
	    NULL)
		return (-1);
	if (topo_edge_new(mod, exp, exp_out2) != 0)
		return (-1);

	if ((tgt2_p1 = sas_create_vertex(mod, TOPO_VTX_PORT, tg2_addr)) ==
	    NULL)
		return (-1);
	if (topo_edge_new(mod, exp_out2, tgt2_p1) != 0)
		return (-1);

	if ((tgt2 = sas_create_vertex(mod, TOPO_VTX_TARGET, tg2_addr)) == NULL)
		return (-1);
	if (topo_edge_new(mod, tgt2_p1, tgt2) != 0)
		return (-1);

	return (0);
}

static void
sas_release(topo_mod_t *mod, tnode_t *node)
{
	topo_method_unregister_all(mod, node);
}

/*
 * XXX still need to implement the two methods below
 */

/*ARGSUSED*/
static int
sas_fmri_create(topo_mod_t *mod, tnode_t *node, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	if (version > TOPO_METH_FMRI_VERSION)
		return (topo_mod_seterrno(mod, EMOD_VER_NEW));

	return (-1);
}

static ssize_t
fmri_bufsz(nvlist_t *nvl)
{
	nvlist_t **paths;
	uint_t nelem;
	ssize_t bufsz = 0;

	bufsz += snprintf(NULL, 0, "sas://");
	if (nvlist_lookup_nvlist_array(nvl, FM_FMRI_SAS_PATH, &paths,
	    &nelem) != 0) {
		return (0);
	}

	for (uint_t i = 0; i < nelem; i++) {
		char *sasname;
		uint64_t sasaddr;

		if (nvlist_lookup_string(paths[i], FM_FMRI_SAS_NAME,
		    &sasname) != 0 ||
		    nvlist_lookup_uint64(paths[i], FM_FMRI_SAS_ADDR,
		    &sasaddr) != 0) {
			return (0);
		}
		bufsz += snprintf(NULL, 0, "/%s=%" PRIx64 "", sasname,
		    sasaddr);
	}
	return (bufsz);
}

/*ARGSUSED*/
static int
sas_fmri_nvl2str(topo_mod_t *mod, tnode_t *node, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	uint8_t scheme_vers;
	nvlist_t *outnvl;
	nvlist_t **paths;
	uint_t nelem;
	ssize_t bufsz, end = 0;
	char *buf;

	if (version > TOPO_METH_NVL2STR_VERSION)
		return (topo_mod_seterrno(mod, EMOD_VER_NEW));

	if (nvlist_lookup_uint8(in, FM_FMRI_SAS_VERSION, &scheme_vers) != 0 ||
	    scheme_vers != FM_SAS_SCHEME_VERSION) {
		return (topo_mod_seterrno(mod, EMOD_FMRI_NVL));
	}

	/*
	 * Get size of buffer needed to hold the string representation of the
	 * FMRI.
	 */
	if ((bufsz = fmri_bufsz(in)) == 0) {
		return (topo_mod_seterrno(mod, EMOD_FMRI_MALFORM));
	}

	if ((buf = topo_mod_zalloc(mod, bufsz)) == NULL) {
		return (topo_mod_seterrno(mod, EMOD_NOMEM));
	}

	/*
	 * We've already successfully done these nvlist lookups in fmri_bufsz()
	 * so we don't worry about checking retvals this time around.
	 */
	end += sprintf(buf, "sas://");
	(void) nvlist_lookup_nvlist_array(in, FM_FMRI_SAS_PATH, &paths,
	    &nelem);
	for (uint_t i = 0; i < nelem; i++) {
		char *sasname;
		uint64_t sasaddr;

		(void) nvlist_lookup_string(paths[i], FM_FMRI_SAS_NAME,
		    &sasname);
		(void) nvlist_lookup_uint64(paths[i], FM_FMRI_SAS_ADDR,
		    &sasaddr);
		end += sprintf(buf + end, "/%s=%" PRIx64 "", sasname,
		    sasaddr);
	}

	if (topo_mod_nvalloc(mod, &outnvl, NV_UNIQUE_NAME) != 0) {
		topo_mod_free(mod, buf, bufsz);
		return (topo_mod_seterrno(mod, EMOD_FMRI_NVL));
	}
	if (nvlist_add_string(outnvl, "fmri-string", buf) != 0) {
		nvlist_free(outnvl);
		topo_mod_free(mod, buf, bufsz);
		return (topo_mod_seterrno(mod, EMOD_FMRI_NVL));
	}
	topo_mod_free(mod, buf, bufsz);
	*out = outnvl;

	return (0);
}

/*ARGSUSED*/
static int
sas_fmri_str2nvl(topo_mod_t *mod, tnode_t *node, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	char *fmristr, *tmp, *lastpair;
	char *sasname;
	nvlist_t *fmri = NULL, **sas_path = NULL;
	uint_t npairs = 0, i = 0;

	if (version > TOPO_METH_STR2NVL_VERSION)
		return (topo_mod_seterrno(mod, EMOD_VER_NEW));

	if (nvlist_lookup_string(in, "fmri-string", &fmristr) != 0)
		return (topo_mod_seterrno(mod, EMOD_METHOD_INVAL));

	if (strncmp(fmristr, "sas:///", 7) != 0)
		return (topo_mod_seterrno(mod, EMOD_FMRI_MALFORM));

	if (topo_mod_nvalloc(mod, &fmri, NV_UNIQUE_NAME) != 0) {
		/* errno set */
		return (-1);
	}
	if (nvlist_add_string(fmri, FM_FMRI_SCHEME,
	    FM_FMRI_SCHEME_SAS) != 0 ||
	    nvlist_add_uint8(fmri, FM_FMRI_SAS_VERSION,
	    FM_SAS_SCHEME_VERSION) != 0) {
		(void) topo_mod_seterrno(mod, EMOD_NOMEM);
		goto err;
	}

	/*
	 * Count the number of "=" chars after the "sas:///" portion of the
	 * FMRI to determine how big the sas-path array needs to be.
	 */
	tmp = topo_mod_strdup(mod, fmristr + 7);
	(void) strtok_r(tmp, "=", &lastpair);
	while (strtok_r(NULL, "=", &lastpair) != NULL)
		npairs++;

	topo_mod_strfree(mod, tmp);

	if ((sas_path = topo_mod_zalloc(mod, npairs + sizeof (nvlist_t *))) ==
	    NULL) {
		(void) topo_mod_seterrno(mod, EMOD_NOMEM);
		goto err;
	}

	sasname = fmristr + 7;
	while (i < npairs) {
		nvlist_t *pathcomp;
		uint64_t sasaddr;
		char *end, *addrstr, *estr;

		if (topo_mod_nvalloc(mod, &pathcomp, NV_UNIQUE_NAME) != 0) {
			(void) topo_mod_seterrno(mod, EMOD_NOMEM);
			goto err;
		}
		if ((end = strchr(sasname, '=')) == NULL) {
			(void) topo_mod_seterrno(mod, EMOD_FMRI_MALFORM);
			goto err;
		}
		*end = '\0';

		addrstr = end + 1;

		/*
		 * If this is the last pair, then addrstr will already be
		 * nul-terminated.
		 */
		if (i < (npairs - 1)) {
			if ((end = strchr(addrstr, '/')) == NULL) {
				(void) topo_mod_seterrno(mod,
				    EMOD_FMRI_MALFORM);
				goto err;
			}
			*end = '\0';
		}

		/*
		 * Convert addrstr to a uint64_t
		 */
		errno = 0;
		sasaddr = strtoull(addrstr, &estr, 16);
		if (errno != 0 || *estr != '\0') {
			(void) topo_mod_seterrno(mod, EMOD_FMRI_MALFORM);
			goto err;
		}

		/*
		 * Add both nvpairs to the nvlist and then add the nvlist to
		 * the sas-path nvlist array.
		 */
		if (nvlist_add_string(pathcomp, FM_FMRI_SAS_NAME, sasname) !=
		    0 ||
		    nvlist_add_uint64(pathcomp, FM_FMRI_SAS_ADDR, sasaddr) !=
		    0) {
			(void) topo_mod_seterrno(mod, EMOD_NOMEM);
			goto err;
		}
		sas_path[i++] = pathcomp;
		sasname = end + 1;
	}
	if (nvlist_add_nvlist_array(fmri, FM_FMRI_SAS_PATH, sas_path,
	    npairs) != 0) {
		(void) topo_mod_seterrno(mod, EMOD_NOMEM);
		goto err;
	}
	*out = fmri;

	return (0);
err:
	topo_mod_dprintf(mod, "sas_fmri_str2nvl failed: %s",
	    topo_strerror(topo_mod_errno(mod)));
	if (sas_path != NULL) {
		for (i = 0; i < npairs; i++)
			nvlist_free(sas_path[i]);

		topo_mod_free(mod, sas_path, npairs + sizeof (nvlist_t *));
	}
	nvlist_free(fmri);
	return (-1);
}
