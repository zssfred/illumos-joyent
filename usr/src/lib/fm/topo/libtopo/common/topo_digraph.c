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

/*
 * XXX maybe it would be better to just pass in a pointer to the digraph to
 * the modules enum entry point in one of the void* params?
 */
static topo_digraph_t *
find_digraph(topo_mod_t *mod)
{
	return (topo_digraph_get(mod->tm_hdl, mod->tm_info->tmi_scheme));
}

topo_digraph_t *
topo_digraph_new(topo_hdl_t *thp, topo_mod_t *mod, const char *scheme)
{
	topo_digraph_t *tdg;

	if ((tdg = topo_mod_zalloc(mod, sizeof (topo_digraph_t))) == NULL) {
		(void) topo_hdl_seterrno(thp, ETOPO_NOMEM);
		return (NULL);
	}

	tdg->tdg_mod = mod;

	if ((tdg->tdg_scheme = topo_mod_strdup(mod, scheme)) == NULL) {
		(void) topo_hdl_seterrno(thp, ETOPO_NOMEM);
		goto err;
	}

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

	topo_mod_dprintf(mod, "Creating vertex %s=%" PRIu64 "", name, inst);
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

	pthread_mutex_lock(&tdg->tdg_lock);
	topo_list_append(&tdg->tdg_vertices, vtx);
	tdg->tdg_nvertices++;
	pthread_mutex_unlock(&tdg->tdg_lock);

	return (vtx);
err:
	topo_mod_dprintf(mod, "failed to add create vertex %s=%" PRIu64 "(%s)",
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

void
topo_vertex_destroy(topo_mod_t *mod, topo_vertex_t *vtx)
{
	topo_edge_t *edge;

	topo_node_unbind(vtx->tvt_node);

	for (edge = topo_list_next(&vtx->tvt_incoming); edge != NULL;
	    edge = topo_list_next(edge)) {
		topo_mod_free(mod, edge, sizeof (topo_edge_t));
	}
	for (edge = topo_list_next(&vtx->tvt_outgoing); edge != NULL;
	    edge = topo_list_next(edge)) {
		topo_mod_free(mod, edge, sizeof (topo_edge_t));
	}

	topo_mod_free(mod, vtx, sizeof (topo_vertex_t));
}

int
topo_vertex_iter(topo_hdl_t *thp, topo_digraph_t *tdg,
    int (*func)(topo_hdl_t *, topo_vertex_t *, void *), void *arg)
{
	for (topo_vertex_t *vtx = topo_list_next(&tdg->tdg_vertices);
	    vtx != NULL; vtx = topo_list_next(vtx)) {
		int ret;

		ret = func(thp, vtx, arg);

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

int
topo_edge_new(topo_mod_t *mod, topo_vertex_t *from, topo_vertex_t *to)
{
	topo_digraph_t *tdg;
	topo_edge_t *e_from = NULL, *e_to = NULL;

	topo_mod_dprintf(mod, "Adding edge from vertex %s=%" PRIu64 " to "
	    "%s=%" PRIu64"", topo_node_name(from->tvt_node),
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

	pthread_mutex_lock(&tdg->tdg_lock);
	topo_list_append(&from->tvt_outgoing, e_to);
	topo_list_append(&to->tvt_incoming, e_from);
	tdg->tdg_nedges++;
	pthread_mutex_unlock(&tdg->tdg_lock);

	return (0);
}

int
topo_edge_iter(topo_hdl_t *thp, topo_vertex_t *vtx,
    int (*func)(topo_hdl_t *, topo_edge_t *, void *), void *arg)
{
	for (topo_edge_t *edge = topo_list_next(&vtx->tvt_outgoing);
	    edge != NULL; edge = topo_list_next(edge)) {
		int ret;

		ret = func(thp, edge, arg);

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

struct digraph_path
{
	topo_list_t	dgp_link;
	char		*dgp_path;
};

static int
visit_vertex(topo_hdl_t *thp, topo_vertex_t *vtx, topo_vertex_t *to,
    topo_list_t *all_paths, char *curr_path, uint_t *npaths)
{
	struct digraph_path *path;
	char *pathstr;

	asprintf(&pathstr, "%s/%s=%" PRIu64"",
	    curr_path,
	    topo_node_name(vtx->tvt_node),
	    topo_node_instance(vtx->tvt_node));

	if (vtx == to) {
		(*npaths)++;
		path = topo_hdl_zalloc(thp, sizeof (struct digraph_path));
		path->dgp_path = topo_hdl_strdup(thp, pathstr);
		topo_list_append(all_paths, path);
		free(pathstr);
		return (0);
	}

	for (topo_edge_t *edge = topo_list_next(&vtx->tvt_outgoing);
	    edge != NULL; edge = topo_list_next(edge)) {

		visit_vertex(thp, edge->tve_vertex, to, all_paths, pathstr,
		    npaths);
	}
	free(pathstr);

	return (0);
}

/*
 * On success, populates the "paths" parameter with an array of "sas" scheme
 * FMRI's (as strings) representing all paths from the "from" vertex to the
 * "to" vertex.  The caller is responsible for freeing this array.  Also, on
 * success, returns the the number of paths found.  If no paths are found, 0
 * is returned.
 *
 * On error, -1 is returned.
 */
int
topo_digraph_paths(topo_hdl_t *thp, topo_digraph_t *tdg, topo_vertex_t *from,
    topo_vertex_t *to, char ***paths)
{
	topo_list_t all_paths = { 0 };
	char *curr_path;
	struct digraph_path *path;
	uint_t i, npaths = 0;

	asprintf(&curr_path, "sas:///%s=%" PRIu64"",
	    topo_node_name(from->tvt_node),
	    topo_node_instance(from->tvt_node));

	for (topo_edge_t *edge = topo_list_next(&from->tvt_outgoing);
	    edge != NULL; edge = topo_list_next(edge)) {

		visit_vertex(thp, edge->tve_vertex, to, &all_paths, curr_path,
		    &npaths);
	}
	free(curr_path);

	if (npaths == 0)
		return (0);

	*paths = calloc(npaths, sizeof (char *));
	for (i = 0, path = topo_list_next(&all_paths); path != NULL;
	    i++, path = topo_list_next(path)) {

		*paths[i] = path->dgp_path;
	}

	return (npaths);
}
