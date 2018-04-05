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

#ifndef _SARC_H
#define	_SARC_H

/*
 * SARC - A simplified implementation of the ARC algorithm for caches.
 *
 * This implements a cache that uses the adaptive replacement cache algorithm
 * to manage the contents of the cache.  Like the original description of the
 * ARC algorithm, it assumes each entry is fixed size.  Unlike the original
 * description of the cache, it allows references to be held to entries,
 * possibly beyond the lifetime of the entry in the cache.  Evicted entries
 * that are still refheld at the time of eviction from the cache do not get
 * counted towards it's size.  While the ZFS ARC merely looks for the next
 * suitable entry when evicting refheld entries, it has mechanisms to also
 * slow down the rate at which new data is added to the ZFS ARC.  Adding
 * such mechanisms to this implementation would add additional complexity
 * for any consumers.  Instead, it is dependent upon the user to only
 * keep refheld entries for short periods of time to prevent the cache
 * size from growing excessively large.  This implementation also does not
 * currently implement any locking, so users must serialize access to any
 * use of a given sarc_t with a mutex -- even lookup routines can cause
 * movement of entries amongst the various lists that are maintined, so
 * something such as rwlock would not work correctly.
 */

#include <sys/list.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum sarc_flag {
	SARC_MRU =	0x00,
	SARC_MFU =	0x01,
	SARC_GMRU =	0x02,
	SARC_GMFU =	0x03,

	SARC_F_DEAD =	0x04,
} sarc_flag_t;

typedef struct sarc_link {
	list_node_t	sal_hash_link;	/* Hash chain bucket */
	list_node_t	sal_list_link;	/* MRU, MFU, etc. list link */
	uint_t		sal_refcnt;
	sarc_flag_t	sal_flags;
} sarc_link_t;

struct sarc;
typedef struct sarc sarc_t;

typedef struct sarc_ops {
	uint64_t	(*sao_hash)(const void *);
	int		(*sao_cmp)(const void *, const void *);
	void		(*sao_dtor)(void *);
	boolean_t	(*sao_fetch)(void *);
	void		(*sao_evict)(void *);
} sarc_ops_t;

/*
 * The ARC algorithm maintains a cache of at most c items (divided into a
 * MRU and MFU lists). The proportion of MRU:MFU entries can vary over time
 * based on access patterns.  ARC utilizes a ghost cache (also of c items
 * split between MRU and MFU) to detect changes in access patterns and
 * adjust the split between MRU and MFU items.
 *
 * The expectation is that an entry being cached can itself be divided into
 * some small identifying portion (that includes at least the hash tag) and
 * the data being cached.   When a cache item moves to a ghost list, the
 * evict operation is called on the entry to indicate the data portion can be
 * freed while retaining the identifying portion of the entry.  When an entry
 * on the ghost list moves back into the cache, the fetch op is called on the
 * entry to reload the data that was released by the earlier evict operation.
 *
 * If the amount of data in an entry is small relative to the identifying
 * information, there may not be much benefit in releasing any memory during
 * an evict call.  Two conveinence functions (sarc_noevict() and sarc_nofetch())
 * are provided for such instances.  These functions are effectively no-ops.
 * When used, the ghost lists become more corporal and act effectively as a
 * second level cache (also c sized), but does not otherwise effect the
 * operation of the ARC algorithm.  It should be noted in such an instance the
 * actual size of the cache will be 2c instead of c.
 */
extern void sarc_noevict(void *);
extern boolean_t sarc_nofetch(void *);

/*
 * int sarc_create(sarcp, c, hsize, ops, objsize, link_off, tag_off, km_flags)
 *
 * sarcp	Contains newly allocated sarc_t instance
 * c		Number of items the cache can hold
 * ops		The functions that operate on entry for hashing, comparison, etc
 * objsize	The size of each entry
 * link_off	The offset of sarc_link_t within each entry
 * tag_off	The offset of the tag field within each entry
 * km_flags	The flags used when allocating the new sarc_t instance
 *
 * On success, sarc_create returns 0.  On failure, sarc_create can return:
 * EINVAL	A parameter was not valid
 * ENOMEM	No memory was available
 */
extern int sarc_create(sarc_t **, size_t, size_t, const sarc_ops_t *, size_t,
    size_t, size_t, int);

/* Destroys a sarc_t instance */
extern void sarc_destroy(sarc_t *);

/*
 * Add an entry into the given cache.
 *
 * Returns:
 *	0	Success
 *	EINVAL	sarc_flag_t contained an invalid value
 *	EEXIST	Entry already exists
 */
extern int sarc_insert(sarc_t *, void *);

/*
 * Lookup an entry in the cache with the given tag.  If found, the refheld
 * object is returned. sarc_rele() should be called to release the reference.
 * If not found, NULL is retured.
 */
extern void *sarc_lookup(sarc_t *, const void *);

/*
 * Remove an entry from the cache.  If the reference count is > 0, the dtor
 * function call is deferred until the reference count is 0.  Once
 * sarc_remove() is called on an entry, it is no longer returned in any
 * lookup request, irrespective of its reference count.  Such an entry is also
 * then ignored in any cache sizing calculations (such as when entries are
 * moved between MRU, MFU, etc lists or when an entry is removed to make room
 * for newer entries).
 */
extern void sarc_remove(sarc_t *, void *);

/*
 * Increment the reference count of an entry in the cache.  As lookups always
 * return a refheld entry (when an entry is found), this is only needed to
 * add additional holds on an entry are needed.
 */
extern void sarc_hold(sarc_t *, void *);

/*
 * Decrement the reference count of an entry in the cache.  This should be
 * called for anything returned by sarc_lookup() to release the hold added
 * by the lookup function.
 */
extern void sarc_rele(sarc_t *, void *);

extern void *sarc_first(sarc_t *);
extern void *sarc_next(sarc_t *, void *);

/*
 * Adjust the size of the cache.   May result in large amounts of entries
 * being evicted at once.  May return EINVAL if the new size is below
 * SARC_MIN_C (10).
 */
extern int sarc_adjust_c(sarc_t *, size_t);

#ifdef __cplusplus
}
#endif

#endif /* _SARC_H */
