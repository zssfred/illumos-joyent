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
#include <topo_digraph_xml.h>

#define	__STDC_FORMAT_MACROS
#include <inttypes.h>

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
