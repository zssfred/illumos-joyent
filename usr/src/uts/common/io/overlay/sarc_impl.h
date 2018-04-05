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
 * Copyright 2018, Joyent, Inc.
 */

#ifndef _SARC_IMPL_H
#define	_SARC_IMPL_H

#include <sys/debug.h>
#include <sys/sarc.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	SARC_NUM_LISTS	4	/* MRU, MFU, ghost MRU, ghost MFU */
#define	SARC_LIST_MASK	0x3
#define	SARC_MIN_C	10	/* Largely arbitrary minimum size */

typedef struct sarc_list {
	list_t	sal_list;
	size_t	sal_len;	/* # of entries in list */
} sarc_list_t;

struct sarc {
	sarc_ops_t	sarc_ops;		/* RO */
	size_t		sarc_link_off;		/* RO */
	size_t		sarc_tag_off;		/* RO */
	size_t		sarc_nbuckets;		/* RO */
	size_t		sarc_c;
	size_t		sarc_p;
	size_t		sarc_elsize;
	sarc_list_t	sarc_list[SARC_NUM_LISTS];	/* MRU, MFU, etc */
	sarc_list_t	sarc_bucket[];			/* hash buckets */
};

#define	SARC_LIST(_sarc, _lnk) \
	(&(_sarc)->sarc_list[(_lnk)->sal_flags & SARC_LIST_MASK])

#ifdef lint
extern sarc_link_t *obj_to_link(sarc_t *, void *);
extern void *link_to_obj(sarc_t *, sarc_link_t *);
extern void *obj_to_tag(sarc_t *, void *);
#else
#define	obj_to_link(_s, _o)	\
	((sarc_link_t *)(((char *)(_o)) + (_s)->sarc_link_off))
#define	link_to_obj(_s, _l)	\
	((void *)(((char *)(_l)) - (_s)->sarc_link_off))
#define	obj_to_tag(_s, _o)	\
	((void *)(((char *)(_o)) + (_s)->sarc_tag_off))
#endif

#ifdef __cplusplus
}
#endif

#endif /* _SARC_IMPL_H */
