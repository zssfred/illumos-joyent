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

/*ARGSUSED*/
static int
sas_fmri_create(topo_mod_t *mod, tnode_t *node, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	if (version > TOPO_METH_FMRI_VERSION)
		return (topo_mod_seterrno(mod, EMOD_VER_NEW));

	return (0);
}


/*ARGSUSED*/
static int
sas_enum(topo_mod_t *mod, tnode_t *pnode, const char *name,
    topo_instance_t min, topo_instance_t max, void *notused1, void *notused2)
{
	topo_vertex_t *vi1, *vp1, *vp2, *vp3, *ve1, *vp4, *vt1;

	/* (void) topo_method_register(mod, pnode, sas_methods); */
	if ((vi1 = topo_vertex_new(mod, TOPO_VTX_INITIATOR, 11111)) == NULL)
		return (-1);
	if ((vp1 = topo_vertex_new(mod, TOPO_VTX_PORT, 11111)) == NULL)
		return (-1);
	if (topo_edge_new(mod, vi1, vp1) != 0)
		return (-1);

	if ((vp2 = topo_vertex_new(mod, TOPO_VTX_PORT, 22222)) == NULL)
		return (-1);
	if (topo_edge_new(mod, vp1, vp2) != 0)
		return (-1);

	if ((ve1 = topo_vertex_new(mod, TOPO_VTX_EXPANDER, 22222)) == NULL)
		return (-1);
	if (topo_edge_new(mod, vp2, ve1) != 0)
		return (-1);

	if ((vp3 = topo_vertex_new(mod, TOPO_VTX_PORT, 3333)) == NULL)
		return (-1);
	if (topo_edge_new(mod, ve1, vp3) != 0)
		return (-1);

	if ((vp4 = topo_vertex_new(mod, TOPO_VTX_PORT, 33333)) == NULL)
		return (-1);
	if (topo_edge_new(mod, vp3, vp4) != 0)
		return (-1);

	if ((vt1 = topo_vertex_new(mod, TOPO_VTX_TARGET, 44444)) == NULL)
		return (-1);
	if (topo_edge_new(mod, vp4, vt1) != 0)
		return (-1);

	return (0);
}

static void
sas_release(topo_mod_t *mod, tnode_t *node)
{
	topo_method_unregister_all(mod, node);
}

/*ARGSUSED*/
static int
sas_fmri_nvl2str(topo_mod_t *mod, tnode_t *node, topo_version_t version,
    nvlist_t *nvl, nvlist_t **out)
{
	uint8_t scheme_version;

	if (version > TOPO_METH_NVL2STR_VERSION)
		return (topo_mod_seterrno(mod, EMOD_VER_NEW));

	if (nvlist_lookup_uint8(nvl, FM_VERSION, &scheme_version) != 0 ||
	    scheme_version > FM_SAS_SCHEME_VERSION)
		return (topo_mod_seterrno(mod, EMOD_FMRI_NVL));

	return (0);
}

/*ARGSUSED*/
static int
sas_fmri_str2nvl(topo_mod_t *mod, tnode_t *node, topo_version_t version,
    nvlist_t *nvl, nvlist_t **out)
{
	uint8_t scheme_version;

	if (version > TOPO_METH_STR2NVL_VERSION)
		return (topo_mod_seterrno(mod, EMOD_VER_NEW));

	if (nvlist_lookup_uint8(nvl, FM_VERSION, &scheme_version) != 0 ||
	    scheme_version > FM_SAS_SCHEME_VERSION)
		return (topo_mod_seterrno(mod, EMOD_FMRI_NVL));

	return (0);
}
