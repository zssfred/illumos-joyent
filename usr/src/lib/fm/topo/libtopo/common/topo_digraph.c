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
 * XXX add comment
 */

#include <libtopo.h>
#include <sys/fm/protocol.h>

#include <topo_digraph.h>
#define	__STDC_FORMAT_MACROS
#include <inttypes.h>

topo_digraph_t *
topo_digraph_get(topo_hdl_t *thp, const char *scheme)
{
	topo_digraph_t *tdg;

	for (tdg = topo_list_next(&thp->th_digraphs); tdg != NULL;
	    tdg = topo_list_next(tdg)) {
		if (strcmp(scheme, tdg->tdg_scheme) == 0)
			return (tdg);
	}
	return (NULL);
}

static topo_digraph_t *
find_digraph(topo_mod_t *mod)
{
	return (topo_digraph_get(mod->tm_hdl, mod->tm_info->tmi_scheme));
}

topo_digraph_t *
topo_digraph_new(topo_hdl_t *thp, topo_mod_t *mod, const char *scheme)
{
	topo_digraph_t *tdg;
	tnode_t *tn = NULL;

	if ((tdg = topo_mod_zalloc(mod, sizeof (topo_digraph_t))) == NULL) {
		(void) topo_hdl_seterrno(thp, ETOPO_NOMEM);
		return (NULL);
	}

	tdg->tdg_mod = mod;

	if ((tdg->tdg_scheme = topo_mod_strdup(mod, scheme)) == NULL) {
		(void) topo_hdl_seterrno(thp, ETOPO_NOMEM);
		goto err;
	}

	/*
	 * For digraph topologies, the "root" node, which gets passed in to
	 * the scheme module's enum method is not part of the actual graph
	 * structure per-se.
	 * Its purpose is simply to provide a place on which to register the
	 * scheme-specific methods.  Client code then invokes these methods via
	 * the topo_fmri_* interfaces.
	 */
	if ((tn = topo_mod_zalloc(mod, sizeof (tnode_t))) == NULL)
		goto err;

	tn->tn_state = TOPO_NODE_ROOT | TOPO_NODE_INIT;
	tn->tn_name = (char *)scheme;
	tn->tn_instance = 0;
	tn->tn_enum = mod;
	tn->tn_hdl = thp;
	topo_node_hold(tn);

	tdg->tdg_rootnode = tn;

	(void) pthread_mutex_init(&tdg->tdg_lock, NULL);

	return (tdg);
err:
	topo_mod_free(mod, tdg, sizeof (topo_digraph_t));
	return (NULL);
}

void
topo_digraph_destroy(topo_digraph_t *tdg)
{
	topo_mod_t *mod;

	if (tdg == NULL)
		return;

	mod = tdg->tdg_mod;
	(void) pthread_mutex_destroy(&tdg->tdg_lock);
	topo_mod_strfree(mod, (char *)tdg->tdg_scheme);
	topo_mod_free(mod, tdg, sizeof (topo_digraph_t));
}

topo_vertex_t *
topo_vertex_new(topo_mod_t *mod, const char *name, topo_instance_t inst)
{
	tnode_t *tn = NULL;
	topo_vertex_t *vtx = NULL;
	topo_digraph_t *tdg;

	topo_mod_dprintf(mod, "Creating vertex %s=%" PRIx64 "", name, inst);
	if ((tdg = find_digraph(mod)) == NULL) {
		return (NULL);
	}
	if ((vtx = topo_mod_zalloc(mod, sizeof (topo_vertex_t))) == NULL ||
	    (tn = topo_mod_zalloc(mod, sizeof (tnode_t))) == NULL) {
		(void) topo_mod_seterrno(mod, EMOD_NOMEM);
		goto err;
	}
	if ((tn->tn_name = topo_mod_strdup(mod, name)) == NULL) {
		(void) topo_mod_seterrno(mod, EMOD_NOMEM);
		goto err;
	}
	tn->tn_enum = mod;
	tn->tn_hdl = mod->tm_hdl;
	tn->tn_instance = inst;
	/*
	 * Adding the TOPO_NODE_ROOT state to the node has the effect of
	 * preventing topo_node_destroy() from trying to clean up the parent
	 * node's node hash, which is only necessary in tree topologies.
	 */
	tn->tn_state = TOPO_NODE_ROOT | TOPO_NODE_BOUND;
	vtx->tvt_node = tn;
	topo_node_hold(tn);

	/* Bump the refcnt on the module that's creating this vertex. */
	topo_mod_hold(mod);

	(void) pthread_mutex_lock(&tdg->tdg_lock);
	topo_list_append(&tdg->tdg_vertices, vtx);
	tdg->tdg_nvertices++;
	(void) pthread_mutex_unlock(&tdg->tdg_lock);

	return (vtx);
err:
	topo_mod_dprintf(mod, "failed to add create vertex %s=%" PRIx64 "(%s)",
	    name, inst, topo_strerror(topo_mod_errno(mod)));
	topo_mod_free(mod, tn, sizeof (tnode_t));
	topo_mod_free(mod, vtx, sizeof (topo_vertex_t));
	return (NULL);
}

tnode_t *
topo_vertex_node(topo_vertex_t *vtx)
{
	return (vtx->tvt_node);
}

/*
 * Convenience interface for deallocating a topo_vertex_t
 */
void
topo_vertex_destroy(topo_mod_t *mod, topo_vertex_t *vtx)
{
	topo_edge_t *edge;

	topo_node_unbind(vtx->tvt_node);

	edge = topo_list_next(&vtx->tvt_incoming);
	while (edge != NULL) {
		topo_edge_t *tmp = edge;

		edge = topo_list_next(edge);
		topo_mod_free(mod, tmp, sizeof (topo_edge_t));
	}

	edge = topo_list_next(&vtx->tvt_outgoing);
	while (edge != NULL) {
		topo_edge_t *tmp = edge;

		edge = topo_list_next(edge);
		topo_mod_free(mod, tmp, sizeof (topo_edge_t));
	}

	topo_mod_free(mod, vtx, sizeof (topo_vertex_t));
}

int
topo_vertex_iter(topo_hdl_t *thp, topo_digraph_t *tdg,
    int (*func)(topo_hdl_t *, topo_vertex_t *, boolean_t, void *), void *arg)
{
	uint_t n = 0;

	for (topo_vertex_t *vtx = topo_list_next(&tdg->tdg_vertices);
	    vtx != NULL; vtx = topo_list_next(vtx), n++) {
		int ret;
		boolean_t last_vtx = B_FALSE;

		if (n == (tdg->tdg_nvertices - 1))
			last_vtx = B_TRUE;

		ret = func(thp, vtx, last_vtx, arg);

		switch (ret) {
		case (TOPO_WALK_NEXT):
			continue;
		case (TOPO_WALK_TERMINATE):
			goto out;
		case (TOPO_WALK_ERR):
			/* FALLTHRU */
		default:
			return (-1);
		}
	}
out:
	return (0);
}

int
topo_edge_new(topo_mod_t *mod, topo_vertex_t *from, topo_vertex_t *to)
{
	topo_digraph_t *tdg;
	topo_edge_t *e_from = NULL, *e_to = NULL;

	topo_mod_dprintf(mod, "Adding edge from vertex %s=%" PRIx64 " to "
	    "%s=%" PRIx64"", topo_node_name(from->tvt_node),
	    topo_node_instance(from->tvt_node),
	    topo_node_name(to->tvt_node), topo_node_instance(to->tvt_node));

	if ((tdg = find_digraph(mod)) == NULL) {
		return (-1);
	}
	if ((e_from = topo_mod_zalloc(mod, sizeof (topo_edge_t))) == NULL ||
	    (e_to = topo_mod_zalloc(mod, sizeof (topo_edge_t))) == NULL) {
		topo_mod_free(mod, e_from, sizeof (topo_edge_t));
		topo_mod_free(mod, e_to, sizeof (topo_edge_t));
		return (topo_mod_seterrno(mod, EMOD_NOMEM));
	}
	e_from->tve_vertex = from;
	e_to->tve_vertex = to;

	(void) pthread_mutex_lock(&tdg->tdg_lock);
	topo_list_append(&from->tvt_outgoing, e_to);
	from->tvt_noutgoing++;
	topo_list_append(&to->tvt_incoming, e_from);
	tdg->tdg_nedges++;
	(void) pthread_mutex_unlock(&tdg->tdg_lock);

	return (0);
}

int
topo_edge_iter(topo_hdl_t *thp, topo_vertex_t *vtx,
    int (*func)(topo_hdl_t *, topo_edge_t *, boolean_t, void *), void *arg)
{
	uint_t n = 0;

	for (topo_edge_t *edge = topo_list_next(&vtx->tvt_outgoing);
	    edge != NULL; edge = topo_list_next(edge), n++) {
		int ret;
		boolean_t last_edge = B_FALSE;

		if (n == (vtx->tvt_noutgoing - 1))
			last_edge = B_TRUE;

		ret = func(thp, edge, last_edge, arg);

		switch (ret) {
		case (TOPO_WALK_NEXT):
			continue;
		case (TOPO_WALK_TERMINATE):
			break;
		case (TOPO_WALK_ERR):
			/* FALLTHRU */
		default:
			return (-1);
		}
	}
	return (0);
}

/*
 * Convenience interface for deallocating a topo_path_t
 */
void
topo_path_destroy(topo_hdl_t *thp, topo_path_t *path)
{
	topo_path_component_t *pathcomp;

	if (path == NULL)
		return;

	topo_hdl_strfree(thp, (char *)path->tsp_fmristr);
	nvlist_free(path->tsp_fmri);

	pathcomp = topo_list_next(&path->tsp_components);
	while (pathcomp != NULL) {
		topo_path_component_t *tmp = pathcomp;

		pathcomp = topo_list_next(pathcomp);
		topo_hdl_free(thp, tmp, sizeof (topo_path_component_t));
	}

	topo_hdl_free(thp, path, sizeof (topo_path_t));
}

/*
 * This just wraps topo_path_t so that visit_vertex() can build a linked list
 * path paths.
 */
struct digraph_path
{
	topo_list_t	dgp_link;
	topo_path_t	*dgp_path;
};

static int
visit_vertex(topo_hdl_t *thp, topo_vertex_t *vtx, topo_vertex_t *to,
    topo_list_t *all_paths, char *curr_path, uint_t *npaths)
{
	struct digraph_path *pathnode = NULL;
	topo_path_t *path = NULL;
	topo_path_component_t *pathcomp = NULL;
	nvlist_t *fmri = NULL;
	char *pathstr;
	int err;

	(void) asprintf(&pathstr, "%s/%s=%" PRIx64"",
	    curr_path,
	    topo_node_name(vtx->tvt_node),
	    topo_node_instance(vtx->tvt_node));

	if (vtx == to) {
		(*npaths)++;
		pathnode = topo_hdl_zalloc(thp, sizeof (struct digraph_path));

		if ((path = topo_hdl_zalloc(thp, sizeof (topo_path_t))) ==
		    NULL ||
		    (path->tsp_fmristr = topo_hdl_strdup(thp, pathstr)) ==
		    NULL ||
		    (pathcomp = topo_hdl_zalloc(thp,
		    sizeof (topo_path_component_t))) == NULL) {
			(void) topo_hdl_seterrno(thp, ETOPO_NOMEM);
			goto err;
		}

		pathcomp->tspc_vertex = vtx;
		topo_list_append(&path->tsp_components, pathcomp);
		if (topo_fmri_str2nvl(thp, pathstr, &fmri, &err) != 0) {
			/* errno set */
			goto err;
		}
		path->tsp_fmri = fmri;
		pathnode->dgp_path = path;

		topo_list_append(all_paths, pathnode);
		free(pathstr);
		return (0);
	}

	for (topo_edge_t *edge = topo_list_next(&vtx->tvt_outgoing);
	    edge != NULL; edge = topo_list_next(edge)) {

		if (visit_vertex(thp, edge->tve_vertex, to, all_paths, pathstr,
		    npaths) != 0)
			goto err;
	}
	free(pathstr);

	return (0);
err:
	topo_hdl_free(thp, pathnode, sizeof (struct digraph_path));
	topo_path_destroy(thp, path);
	return (-1);
}

/*
 * On success, populates the "paths" parameter with an array of
 * topo_saspath_t structs representing all paths from the "from" vertex to the
 * "to" vertex.  The caller is responsible for freeing this array.  Also, on
 * success, returns the the number of paths found.  If no paths are found, 0
 * is returned.
 *
 * On error, -1 is returned.
 */
int
topo_digraph_paths(topo_hdl_t *thp, topo_digraph_t *tdg, topo_vertex_t *from,
    topo_vertex_t *to, topo_path_t ***paths)
{
	topo_list_t all_paths = { 0 };
	char *curr_path;
	struct digraph_path *path;
	uint_t i, npaths = 0;
	int ret;

	ret = asprintf(&curr_path, "sas://%s=%s/%s=%" PRIx64"",
	    FM_FMRI_SAS_TYPE, FM_FMRI_SAS_TYPE_PATH,
	    topo_node_name(from->tvt_node),
	    topo_node_instance(from->tvt_node));

	if (ret == -1)
		return (topo_hdl_seterrno(thp, ETOPO_NOMEM));

	for (topo_edge_t *edge = topo_list_next(&from->tvt_outgoing);
	    edge != NULL; edge = topo_list_next(edge)) {

		ret = visit_vertex(thp, edge->tve_vertex, to, &all_paths,
		    curr_path, &npaths);
		if (ret != 0) {
			/* errno set */
			free(curr_path);
			goto err;
		}

	}
	free(curr_path);

	/*
	 * No paths were found between the "from" and "to" vertices, so
	 * we're done here.
	 */
	if (npaths == 0)
		return (0);

	*paths = topo_hdl_zalloc(thp, npaths * sizeof (topo_path_t *));
	if (*paths == NULL) {
		(void) topo_hdl_seterrno(thp, ETOPO_NOMEM);
		goto err;
	}

	for (i = 0, path = topo_list_next(&all_paths); path != NULL;
	    i++, path = topo_list_next(path)) {

		*((*paths) + i) = path->dgp_path;
	}
	return (npaths);
err:
	/* XXX add code to free all_paths list */
	topo_dprintf(thp, TOPO_DBG_ERR, "%s: failed (%s)", __func__,
	    topo_hdl_errmsg(thp));
	return (-1);
}

static void
tdg_xml_nvstring(FILE *fp, const char *pad, const char *name,
    const char *value)
{
	(void) fprintf(fp, "%s<%s %s='%s' %s='%s' %s='%s' />\n", pad,
	    TDG_XML_NVPAIR, TDG_XML_NAME, name, TDG_XML_TYPE, TDG_XML_STRING,
	    TDG_XML_VALUE, value);
}

static void
tdg_xml_nvlist(FILE *fp, const char *pad, const char *name)
{
	(void) fprintf(fp, "%s<%s %s='%s' %s='%s'>\n", pad,
	    TDG_XML_NVPAIR, TDG_XML_NAME, name, TDG_XML_TYPE, TDG_XML_NVLIST);
}

static void
tdg_xml_nvuint8(FILE *fp, const char *pad, const char *name,
    const uint8_t value)
{
	(void) fprintf(fp, "%s<%s %s='%s' %s='%s' %s='%u' />\n", pad,
	    TDG_XML_NVPAIR, TDG_XML_NAME, name, TDG_XML_TYPE, TDG_XML_UINT8,
	    TDG_XML_VALUE, value);
}

static void
tdg_xml_nvint8(FILE *fp, const char *pad, const char *name,
    const uint8_t value)
{
	(void) fprintf(fp, "%s<%s %s='%s' %s='%s' %s='%d' />\n", pad,
	    TDG_XML_NVPAIR, TDG_XML_NAME, name, TDG_XML_TYPE, TDG_XML_INT8,
	    TDG_XML_VALUE, value);
}

static void
tdg_xml_nvuint16(FILE *fp, const char *pad, const char *name,
    const uint8_t value)
{
	(void) fprintf(fp, "%s<%s %s='%s' %s='%s' %s='%u' />\n", pad,
	    TDG_XML_NVPAIR, TDG_XML_NAME, name, TDG_XML_TYPE, TDG_XML_UINT16,
	    TDG_XML_VALUE, value);
}

static void
tdg_xml_nvint16(FILE *fp, const char *pad, const char *name,
    const uint8_t value)
{
	(void) fprintf(fp, "%s<%s %s='%s' %s='%s' %s='%d' />\n", pad,
	    TDG_XML_NVPAIR, TDG_XML_NAME, name, TDG_XML_TYPE, TDG_XML_INT16,
	    TDG_XML_VALUE, value);
}

static void
tdg_xml_nvuint32(FILE *fp, const char *pad, const char *name,
    const uint32_t value)
{
	(void) fprintf(fp, "%s<%s %s='%s' %s='%s' %s='%u' />\n", pad,
	    TDG_XML_NVPAIR, TDG_XML_NAME, name, TDG_XML_TYPE, TDG_XML_UINT32,
	    TDG_XML_VALUE, value);
}

static void
tdg_xml_nvint32(FILE *fp, const char *pad, const char *name,
    const int32_t value)
{
	(void) fprintf(fp, "%s<%s %s='%s' %s='%s' %s='%d' />\n", pad,
	    TDG_XML_NVPAIR, TDG_XML_NAME, name, TDG_XML_TYPE, TDG_XML_UINT32,
	    TDG_XML_VALUE, value);
}

static void
tdg_xml_nvuint64(FILE *fp, const char *pad, const char *name,
    const uint64_t value)
{
	(void) fprintf(fp, "%s<%s %s='%s' %s='%s' %s='%" PRIx64 "' />\n", pad,
	    TDG_XML_NVPAIR, TDG_XML_NAME, name, TDG_XML_TYPE, TDG_XML_UINT64,
	    TDG_XML_VALUE, value);
}

static void
tdg_xml_nvint64(FILE *fp, const char *pad, const char *name,
    const uint64_t value)
{
	(void) fprintf(fp, "%s<%s %s='%s' %s='%s' %s='%" PRIi64 "' />\n", pad,
	    TDG_XML_NVPAIR, TDG_XML_NAME, name, TDG_XML_TYPE, TDG_XML_UINT64,
	    TDG_XML_VALUE, value);
}

static void
tdg_xml_nvdbl(FILE *fp, const char *pad, const char *name,
    const double value)
{
	(void) fprintf(fp, "%s<%s %s='%s' %s='%s' %s='%lf' />\n", pad,
	    TDG_XML_NVPAIR, TDG_XML_NAME, name, TDG_XML_TYPE, TDG_XML_UINT64,
	    TDG_XML_VALUE, value);
}

static void
tdg_xml_nvarray(FILE *fp, const char *pad, const char *name, const char *type,
    const uint_t nelem)
{
	(void) fprintf(fp, "%s<%s %s='%s' %s='%s' %s='%u'>\n", pad,
	    TDG_XML_NVPAIR, TDG_XML_NAME, name, TDG_XML_TYPE, type,
	    TDG_XML_NELEM, nelem);
}

static int
serialize_edge(topo_hdl_t *thp, topo_edge_t *edge, boolean_t last_edge,
    void *arg)
{
	nvlist_t *fmri = NULL;
	char *fmristr;
	int err;
	tnode_t *tn;
	FILE *fp = (FILE *)arg;

	tn = topo_vertex_node(edge->tve_vertex);
	if (topo_node_resource(tn, &fmri, &err) != 0 ||
	    topo_fmri_nvl2str(thp, fmri, &fmristr, &err) != 0) {
		nvlist_free(fmri);
		return (TOPO_WALK_ERR);
	}
	nvlist_free(fmri);

	(void) fprintf(fp, "%s<%s %s='%s' />\n", TDG_XML_PAD4, TDG_XML_NVPAIR,
	    TDG_XML_VALUE, fmristr);
	topo_hdl_strfree(thp, fmristr);

	return (TOPO_WALK_NEXT);
}

static int
serialize_nvpair(FILE *fp, const char *pad, const char *pname, nvpair_t *nvp)
{
	data_type_t type = nvpair_type(nvp);

	switch (type) {
		case DATA_TYPE_INT8: {
			int8_t val;

			if (nvpair_value_int8(nvp, &val) != 0)
				return (-1);

			tdg_xml_nvint8(fp, pad, pname, val);
			break;
		}
		case DATA_TYPE_UINT8: {
			uint8_t val;

			if (nvpair_value_uint8(nvp, &val) != 0)
				return (-1);

			tdg_xml_nvuint8(fp, pad, pname, val);
			break;
		}
		case DATA_TYPE_INT16: {
			int16_t val;

			if (nvpair_value_int16(nvp, &val) != 0)
				return (-1);

			tdg_xml_nvint16(fp, pad, pname, val);
			break;
		}
		case DATA_TYPE_UINT16: {
			uint16_t val;

			if (nvpair_value_uint16(nvp, &val) != 0)
				return (-1);

			tdg_xml_nvuint16(fp, pad, pname, val);
			break;
		}
		case DATA_TYPE_INT32: {
			int32_t val;

			if (nvpair_value_int32(nvp, &val) != 0)
				return (-1);

			tdg_xml_nvint32(fp, pad, pname, val);
			break;
		}
		case DATA_TYPE_UINT32: {
			uint32_t val;

			if (nvpair_value_uint32(nvp, &val) != 0)
				return (-1);

			tdg_xml_nvuint32(fp, pad, pname, val);
			break;
		}
		case DATA_TYPE_INT64: {
			int64_t val;

			if (nvpair_value_int64(nvp, &val) != 0)
				return (-1);

			tdg_xml_nvint64(fp, pad, pname, val);
			break;
		}
		case DATA_TYPE_UINT64: {
			uint64_t val;

			if (nvpair_value_uint64(nvp, &val) != 0)
				return (-1);

			tdg_xml_nvuint64(fp, pad, pname, val);
			break;
		}
		case DATA_TYPE_DOUBLE: {
			double val;

			if (nvpair_value_double(nvp, &val) != 0)
				return (-1);

			tdg_xml_nvdbl(fp, pad, pname, val);
			break;
		}
		case DATA_TYPE_STRING: {
			char *val;

			if (nvpair_value_string(nvp, &val) != 0)
				return (-1);

			tdg_xml_nvstring(fp, pad, pname, val);
			break;
		}
		case DATA_TYPE_NVLIST: {
			nvlist_t *nvl;
			nvpair_t *elem = NULL;
			char *newpad;

			if (nvpair_value_nvlist(nvp, &nvl) != 0)
				return (-1);
			tdg_xml_nvlist(fp, pad, pname);

			if (asprintf(&newpad, "  %s", pad) < 0)
				return (-1);

			(void) fprintf(fp, "%s<%s>\n", newpad, TDG_XML_NVLIST);

			while ((elem = nvlist_next_nvpair(nvl, elem)) != NULL) {
				char *nvname = nvpair_name(elem);

				if (serialize_nvpair(fp, newpad, nvname,
				    elem) != 0) {
					free(newpad);
					return (-1);
				}
			}
			free(newpad);

			(void) fprintf(fp, "%s  </%s>\n", pad, TDG_XML_NVLIST);
			(void) fprintf(fp, "%s</%s> <!-- %s -->\n", pad,
			    TDG_XML_NVPAIR, pname);
			break;
		}
		case DATA_TYPE_INT32_ARRAY: {
			uint_t nelems;
			int32_t *val;

			if (nvpair_value_int32_array(nvp, &val, &nelems) != 0)
				return (-1);

			tdg_xml_nvarray(fp, pad, pname, TDG_XML_INT32_ARR,
			    nelems);
			for (uint_t i; i < nelems; i++) {
				(void) fprintf(fp, "%s  <%s %s='%d' />\n", pad,
				    TDG_XML_NVPAIR, TDG_XML_VALUE, val[i]);
			}
			(void) fprintf(fp, "%s  </%s>\n", pad, TDG_XML_NVPAIR);
			break;
		}
		case DATA_TYPE_UINT32_ARRAY: {
			uint_t nelems;
			uint32_t *val;

			if (nvpair_value_uint32_array(nvp, &val, &nelems) != 0)
				return (-1);

			tdg_xml_nvarray(fp, pad, pname, TDG_XML_UINT32_ARR,
			    nelems);
			for (uint_t i; i < nelems; i++) {
				(void) fprintf(fp, "%s  <%s %s='%u' />\n", pad,
				    TDG_XML_NVPAIR, TDG_XML_VALUE, val[i]);
			}
			(void) fprintf(fp, "%s  </%s>\n", pad, TDG_XML_NVPAIR);
			break;
		}
		case DATA_TYPE_INT64_ARRAY: {
			uint_t nelems;
			int64_t *val;

			if (nvpair_value_int64_array(nvp, &val, &nelems) != 0)
				return (-1);

			tdg_xml_nvarray(fp, pad, pname, TDG_XML_INT64_ARR,
			    nelems);
			for (uint_t i; i < nelems; i++) {
				(void) fprintf(fp, "%s  <%s %s='%" PRIi64
				    "' />\n", pad, TDG_XML_NVPAIR,
				    TDG_XML_VALUE, val[i]);
			}
			(void) fprintf(fp, "%s  </%s>\n", pad, TDG_XML_NVPAIR);
			break;
		}
		case DATA_TYPE_UINT64_ARRAY: {
			uint_t nelems;
			uint64_t *val;

			if (nvpair_value_uint64_array(nvp, &val, &nelems) != 0)
				return (-1);

			tdg_xml_nvarray(fp, pad, pname, TDG_XML_UINT64_ARR,
			    nelems);
			for (uint_t i; i < nelems; i++) {
				(void) fprintf(fp, "%s  <%s %s='%" PRIx64
				    "' />\n", pad, TDG_XML_NVPAIR,
				    TDG_XML_VALUE, val[i]);
			}
			(void) fprintf(fp, "%s  </%s>\n", pad, TDG_XML_NVPAIR);
			break;
		}
		case DATA_TYPE_STRING_ARRAY: {
			uint_t nelems;
			char **val;

			if (nvpair_value_string_array(nvp, &val, &nelems) != 0)
				return (-1);

			tdg_xml_nvarray(fp, pad, pname, TDG_XML_STRING_ARR,
			    nelems);
			for (uint_t i; i < nelems; i++) {
				(void) fprintf(fp, "%s  <%s %s='%s' />\n", pad,
				    TDG_XML_NVPAIR, TDG_XML_VALUE, val[i]);
			}
			(void) fprintf(fp, "%s  </%s>\n", pad, TDG_XML_NVPAIR);
			break;
		}
		case DATA_TYPE_NVLIST_ARRAY: {
			uint_t nelems;
			nvlist_t **val;

			if (nvpair_value_nvlist_array(nvp, &val, &nelems) != 0)
				return (-1);

			tdg_xml_nvarray(fp, pad, pname, TDG_XML_NVLIST_ARR,
			    nelems);
			for (uint_t i; i < nelems; i++) {
				nvpair_t *elem = NULL;
				char *newpad;

				(void) fprintf(fp, "%s  <%s>\n", pad,
				    TDG_XML_NVLIST);

				if (asprintf(&newpad, "  %s", pad) < 0)
					return (-1);

				while ((elem = nvlist_next_nvpair(val[i],
				    elem)) != NULL) {
					char *nvname = nvpair_name(elem);

					if (serialize_nvpair(fp, newpad,
					    nvname, elem) != 0) {
						free(newpad);
						return (-1);
					}
				}
				free(newpad);

				(void) fprintf(fp, "%s  </%s>\n", pad,
				    TDG_XML_NVLIST);
			}
			(void) fprintf(fp, "%s  </%s>\n", pad, TDG_XML_NVPAIR);
			break;
		}
		default:
			(void) fprintf(fp, "Invalid nvpair data type: %d\n",
			    type);
			return (-1);
	}
	return (0);
}

static int
serialize_pgroups(topo_hdl_t *thp, FILE *fp, tnode_t *tn)
{
	topo_pgroup_t *pg;
	uint_t npgs = 0;

	for (pg = topo_list_next(&tn->tn_pgroups); pg != NULL;
	    pg = topo_list_next(pg)) {

		npgs++;
	}

	tdg_xml_nvarray(fp, TDG_XML_PAD2, TDG_XML_PGROUPS, TDG_XML_NVLIST_ARR,
	    npgs);

	for (pg = topo_list_next(&tn->tn_pgroups); pg != NULL;
	    pg = topo_list_next(pg)) {

		topo_proplist_t *pvl;
		uint_t nprops = 0;

		(void) fprintf(fp, "%s<%s>\n", TDG_XML_PAD4, TDG_XML_NVLIST);
		tdg_xml_nvstring(fp, TDG_XML_PAD4, TOPO_PROP_GROUP_NAME,
		    pg->tpg_info->tpi_name);
		tdg_xml_nvstring(fp, TDG_XML_PAD4, TOPO_PROP_GROUP_DSTAB,
		    topo_stability2name(pg->tpg_info->tpi_datastab));
		tdg_xml_nvstring(fp, TDG_XML_PAD4, TOPO_PROP_GROUP_NSTAB,
		    topo_stability2name(pg->tpg_info->tpi_namestab));
		tdg_xml_nvuint32(fp, TDG_XML_PAD4, TOPO_PROP_GROUP_VERSION,
		    pg->tpg_info->tpi_version);

		for (pvl = topo_list_next(&pg->tpg_pvals); pvl != NULL;
		    pvl = topo_list_next(pvl))
			nprops++;

		tdg_xml_nvarray(fp, TDG_XML_PAD4, TDG_XML_PVALS,
		    TDG_XML_NVLIST_ARR, nprops);

		for (pvl = topo_list_next(&pg->tpg_pvals); pvl != NULL;
		    pvl = topo_list_next(pvl)) {

			topo_propval_t *pv = pvl->tp_pval;
			nvpair_t *nvp;

			(void) fprintf(fp, "%s<%s>\n", TDG_XML_PAD6,
			    TDG_XML_NVLIST);
			tdg_xml_nvstring(fp, TDG_XML_PAD6, TDG_XML_NAME,
			    pv->tp_name);
			tdg_xml_nvuint32(fp, TDG_XML_PAD6, TDG_XML_TYPE,
			    pv->tp_type);

			if (nvlist_lookup_nvpair(pv->tp_val, TOPO_PROP_VAL_VAL,
			    &nvp) != 0 ||
			    serialize_nvpair(fp, TDG_XML_PAD6, pv->tp_name,
			    nvp) != 0) {
				return (-1);
			}
			(void) fprintf(fp, "%s</%s>\n", TDG_XML_PAD6,
			    TDG_XML_NVLIST);
		}

		(void) fprintf(fp, "%s</%s> <!-- %s -->\n", TDG_XML_PAD4,
		    TDG_XML_NVPAIR, TDG_XML_PVALS);
		(void) fprintf(fp, "%s</%s>\n", TDG_XML_PAD4, TDG_XML_NVLIST);
	}
	(void) fprintf(fp, "%s</%s> <!-- %s -->\n", TDG_XML_PAD2,
	    TDG_XML_NVPAIR, TDG_XML_PGROUPS);

	return (0);
}

static int
serialize_vertex(topo_hdl_t *thp, topo_vertex_t *vtx, boolean_t last_vtx,
    void *arg)
{
	nvlist_t *fmri = NULL;
	char *fmristr;
	tnode_t *tn;
	int err;
	FILE *fp = (FILE *)arg;

	tn = topo_vertex_node(vtx);
	if (topo_node_resource(tn, &fmri, &err) != 0 ||
	    topo_fmri_nvl2str(thp, fmri, &fmristr, &err) != 0) {
		nvlist_free(fmri);
		return (TOPO_WALK_ERR);
	}

	nvlist_free(fmri);

	(void) fprintf(fp, "%s<%s>\n", TDG_XML_PAD2, TDG_XML_NVLIST);
	tdg_xml_nvstring(fp, TDG_XML_PAD2, TDG_XML_FMRI, fmristr);
	topo_hdl_strfree(thp, fmristr);

	tdg_xml_nvstring(fp, TDG_XML_PAD2, TDG_XML_NAME, topo_node_name(tn));
	tdg_xml_nvuint64(fp, TDG_XML_PAD2, TDG_XML_INSTANCE,
	    topo_node_instance(tn));

	if (serialize_pgroups(thp, fp, tn) != 0)
		return (TOPO_WALK_ERR);

	if (vtx->tvt_noutgoing != 0) {
		tdg_xml_nvarray(fp, TDG_XML_PAD2, TDG_XML_OUTEDGES,
		    TDG_XML_STRING_ARR, vtx->tvt_noutgoing);

		if (topo_edge_iter(thp, vtx, serialize_edge, fp) != 0) {
			(void) fprintf(fp, "\nfailed to iterate edges on %s=%"
			    PRIx64 "\n", topo_node_name(tn),
			    topo_node_instance(tn));
			return (TOPO_WALK_ERR);
		}
		(void) fprintf(fp, "%s</%s> <!-- %s -->\n", TDG_XML_PAD2,
		    TDG_XML_NVPAIR, TDG_XML_OUTEDGES);
	}
	(void) fprintf(fp, "%s</%s>\n\n", TDG_XML_PAD2, TDG_XML_NVLIST);

	return (TOPO_WALK_NEXT);
}

/*
 * This function takes a topo_digraph_t and serializes in an XML schema which
 * describes an nvlist representation of a directed graph topology.  The nvlist
 * has the following schema:
 *
 * vertices: nvlist-array
 *     fmri: string
 *     name: string
 *     instance: uint64
 *     property-groups: nvlist-array
 *         property-group-name: string
 *         property-group-name-stability: string
 *         property-group-data-stability: string
 *         property-group-version: uint32
 *         property-values: nvlist-array
 *           . . .
 *     outgoing-edges: string-array
 *     . . .
 */
int
topo_digraph_serialize(topo_hdl_t *thp, topo_digraph_t *tdg, FILE *fp)
{
	(void) fprintf(fp, "<?xml version=\"1.0\"?>\n");
	(void) fprintf(fp, "<%s>\n", TDG_XML_NVLIST);

	tdg_xml_nvarray(fp, "", TDG_XML_VERTICES, TDG_XML_NVLIST_ARR,
	    tdg->tdg_nvertices);

	if (topo_vertex_iter(thp, tdg, serialize_vertex, fp) != 0) {
		(void) fprintf(fp, "\nfailed to iterate vertices\n");
		return (-1);
	}

	(void) fprintf(fp, "</%s> <!-- %s -->\n", TDG_XML_NVPAIR,
	    TDG_XML_VERTICES);
	(void) fprintf(fp, "</%s>\n", TDG_XML_NVLIST);

	return (0);
}

/*
 * This function takes a buffer containing XML data describing an nvlist
 * representation of a directed graph topology.  This data is deserialized back
 * to an nvlist and that nvlist is then processed to rehydrate the original
 * directed graph.
 */
topo_digraph_t *
topo_digraph_deserialize(topo_hdl_t *thp, const char *xml, size_t sz)
{
	/* XXX - need to implement */
	return (NULL);
}
