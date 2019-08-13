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

#ifndef _TOPO_DIGRAPH_H
#define	_TOPO_DIGRAPH_H

#include <fm/topo_mod.h>

#include <topo_list.h>
#include <topo_prop.h>
#include <topo_method.h>
#include <topo_alloc.h>
#include <topo_error.h>
#include <topo_file.h>
#include <topo_module.h>
#include <topo_string.h>
#include <topo_subr.h>
#include <topo_tree.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * List of property names used when serializing a topo_digraph_t to JSON.
 * When deserializing a JSON representation of a topo_digraph_t, the JSON is
 * first converted to an nvlist representation and then that nvlist is
 * processed to produce a topo_digraph_t.  These property names are also
 * used as the nvpair names in that intermidiate nvlist.
 */
#define	TDG_XML_FMRI		"fmri"
#define	TDG_XML_SCHEME		"fmri-scheme"
#define	TDG_XML_NAME		"name"
#define	TDG_XML_NELEM		"nelem"
#define	TDG_XML_NVLIST		"nvlist"
#define	TDG_XML_NVLIST_ARR	"nvlist-array"
#define	TDG_XML_NVPAIR		"nvpair"
#define	TDG_XML_INSTANCE	"instance"
#define	TDG_XML_INT8		"int8"
#define	TDG_XML_INT16		"int16"
#define	TDG_XML_INT32		"int32"
#define	TDG_XML_INT32_ARR	"int32-array"
#define	TDG_XML_INT64		"int64"
#define	TDG_XML_INT64_ARR	"int64-array"
#define	TDG_XML_PGROUPS		"property-groups"
#define	TDG_XML_PVALS		"property-values"
#define	TDG_XML_OUTEDGES	"outgoing-edges"
#define	TDG_XML_STRING		"string"
#define	TDG_XML_STRING_ARR	"string-array"
#define	TDG_XML_TYPE		"type"
#define	TDG_XML_UINT8		"uint8"
#define	TDG_XML_UINT16		"uint16"
#define	TDG_XML_UINT32		"uint32"
#define	TDG_XML_UINT32_ARR	"uint32-array"
#define	TDG_XML_UINT64		"uint64"
#define	TDG_XML_UINT64_ARR	"uint64-array"
#define	TDG_XML_VALUE		"value"
#define	TDG_XML_VERTICES	"vertices"

#define	TDG_XML_PAD2		"  "
#define	TDG_XML_PAD4		"    "
#define	TDG_XML_PAD6		"      "

struct topo_digraph
{
	topo_list_t	tdg_list;		/* next/prev pointers */
	pthread_mutex_t	tdg_lock;
	const char	*tdg_scheme;		/* FMRI scheme */
	topo_mod_t	*tdg_mod;		/* builtin enumerator mod */
	tnode_t		*tdg_rootnode;		/* see topo_digraph_new() */
	topo_list_t	tdg_vertices;		/* adjacency list */
	uint_t		tdg_nvertices;		/* total num of vertices */
	uint_t		tdg_nedges;		/* total num of edges */
};

struct topo_vertex
{
	topo_list_t	tvt_list;		/* next/prev pointers */
	tnode_t		*tvt_node;
	topo_list_t	tvt_incoming;
	topo_list_t	tvt_outgoing;
	uint_t		tvt_noutgoing;		/* total num outgoing edges */
};

struct topo_edge
{
	topo_list_t	tve_list;		/* next/prev pointers */
	topo_vertex_t	*tve_vertex;
};

#ifdef __cplusplus
}
#endif

#endif	/* _TOPO_DIGRAPH_H */
