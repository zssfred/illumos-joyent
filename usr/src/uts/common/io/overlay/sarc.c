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

#include <sys/debug.h>
#include <sys/errno.h>
#include <sys/sysmacros.h>
#ifdef _KERNEL
#include <sys/types.h>
#else
#include <stddef.h>
#include <stdint.h>
#endif

/*
 * XXX: Until this code is integrated, it can be useful to be able to
 * build this on it's own for testing, etc. on PIs that predate when
 * the __unused macro was added.  If/once this code is integrated into
 * illumos-joyent, this check can be removed.
 */
#ifndef __unused
#define	__unused __attribute__((unused))
#endif

#ifdef _KERNEL
#include <sys/kmem.h>
#define	ZALLOC		kmem_zalloc
#define	FREE		kmem_free
#else
#include <umem.h>
#define	ZALLOC		umem_zalloc
#define	FREE		umem_free
#endif

#include "sarc_impl.h"

/*
 * The *_overflow functions mimic the gcc/clang intrinsic functions.  Once
 * we are using a newer compiler version to that includes these as intrisnics,
 * these can be replaced with those versions.
 */
static int
uadd_overflow(const size_t a, const size_t b, size_t *sump)
{
	*sump = a + b;
	if (*sump < a || *sump < b)
		return (1);
	return (0);
}

#define	MUL_NO_OVERFLOW ((size_t)1 << (sizeof (size_t) * 4))

static int
umul_overflow(const size_t a, const size_t b, size_t *cp)
{
	*cp = a * b;

	if ((a >= MUL_NO_OVERFLOW || b >= MUL_NO_OVERFLOW) &&
	    a != 0 && b != 0 && SIZE_MAX / a < b)
		return (1);

	return (0);
}

void
sarc_noevict(void *entry __unused)
{
}

boolean_t
sarc_nofetch(void *entry __unused)
{
	return (B_TRUE);
}

int
sarc_create(sarc_t **sp, size_t c, size_t hsize, const sarc_ops_t *ops,
    size_t obj_size, size_t link_off, size_t tag_off, int kmflags)
{
	sarc_t *sarc;
	sarc_list_t *bucket;
	size_t len = 0;
	size_t i;

	if (c < SARC_MIN_C)
		return (EINVAL);

	/* XXX: Maybe return EOVERFLOW instead? */
	if (umul_overflow(sizeof (sarc_list_t), hsize, &len))
		return (EINVAL);
	if (uadd_overflow(sizeof (*sarc), len, &len))
		return (EINVAL);

	if ((sarc = ZALLOC(len, kmflags)) == NULL)
		return (ENOMEM);

	sarc->sarc_ops = *ops;
	sarc->sarc_c = c;
	sarc->sarc_p = c / 2;
	sarc->sarc_nbuckets = hsize;
	sarc->sarc_link_off = link_off;
	sarc->sarc_tag_off = tag_off;
	sarc->sarc_elsize = obj_size;

	for (i = 0, bucket = sarc->sarc_bucket; i < hsize; i++, bucket++) {
		list_create(&bucket->sal_list, obj_size, offsetof(sarc_link_t,
		    sal_hash_link));
	}

	for (i = 0; i < SARC_NUM_LISTS; i++) {
		list_create(&sarc->sarc_list[i].sal_list, obj_size,
		    offsetof(sarc_link_t, sal_list_link));
	}

	*sp = sarc;
	return (0);
}

void
sarc_destroy(sarc_t *s)
{
	list_t *l;
	sarc_link_t *lnk;
	void *obj;
	size_t i, len;

	if (s == NULL)
		return;

	/* If creation succeeded, this calculation cannot overflow */
	len = sizeof (*s) + s->sarc_nbuckets * sizeof (sarc_list_t);

	for (i = 0; i < SARC_NUM_LISTS; i++) {
		l = &s->sarc_list[i].sal_list;
		for (;;) {
			if ((lnk = list_remove_head(l)) == NULL)
				break;
		}
	}

	for (i = 0; i < s->sarc_nbuckets; i++) {
		l = &s->sarc_bucket[i].sal_list;
		for (;;) {
			if ((lnk = list_remove_head(l)) == NULL)
				break;
			ASSERT0(lnk->sal_refcnt);
			obj = link_to_obj(s, lnk);
			s->sarc_ops.sao_dtor(obj);
		}
	}

	FREE(s, len);
}

static void
sarc_delete(sarc_t *s, sarc_link_t *lp)
{
	void *op = link_to_obj(s, lp);
	void *tp = obj_to_tag(s, op);
	uint_t n = s->sarc_ops.sao_hash(tp) % s->sarc_nbuckets;

	ASSERT3U(s->sarc_bucket[n].sal_len, >, 0);
	ASSERT(!list_is_empty(&s->sarc_bucket[n].sal_list));
	ASSERT(!list_link_active(&lp->sal_list_link));
	ASSERT(list_link_active(&lp->sal_hash_link));

	list_remove(&s->sarc_bucket[n].sal_list, lp);
	s->sarc_bucket[n].sal_len--;
	s->sarc_ops.sao_dtor(op);
}

static sarc_link_t *
sarc_lru_remove(sarc_t *s, sarc_flag_t list)
{
	sarc_link_t *lp;

	ASSERT3S(list, >=, SARC_MRU);
	ASSERT3S(list, <=, SARC_GMFU);

	if ((lp = list_remove_tail(&s->sarc_list[list].sal_list)) != NULL)
		s->sarc_list[list].sal_len--;

	return (lp);
}

static void
sarc_add(sarc_t *s, sarc_link_t *lp, sarc_flag_t which)
{
	sarc_list_t *slst;

	ASSERT3S(which & ~SARC_LIST_MASK, ==, 0);
	ASSERT(!list_link_active(&lp->sal_list_link));

	slst = &s->sarc_list[which];
	lp->sal_flags &= ~SARC_LIST_MASK;
	lp->sal_flags |= which;
	list_insert_head(&slst->sal_list, lp);
	slst->sal_len++;
}

/*
 * Evict an entry from the cache (MRU, MFU) and move it to the respective
 * ghost list (MRU -> ghost MRU or MFU -> ghost MFU) to make room for a new
 * entry.  This is the REPLACE procedure from the ARC paper where
 * from_gmfu == (xt in B2)
 */
static void
sarc_evict(sarc_t *s, boolean_t from_gmfu)
{
	sarc_link_t *lp;
	sarc_flag_t dst;
	size_t mru_len = s->sarc_list[SARC_MRU].sal_len;

	if ((mru_len > 0) && ((mru_len > s->sarc_p) ||
	    (from_gmfu && mru_len == s->sarc_p))) {
		lp = sarc_lru_remove(s, SARC_MRU);
		dst = SARC_GMRU;
	} else {
		lp = sarc_lru_remove(s, SARC_MFU);
		dst = SARC_GMFU;
	}

	s->sarc_ops.sao_evict(link_to_obj(s, lp));
	sarc_add(s, lp, dst);
}

static sarc_link_t *
sarc_hash_lookup(sarc_t *s, const void *tp, sarc_list_t **lpp)
{
	uint_t n = s->sarc_ops.sao_hash(tp) % s->sarc_nbuckets;
	sarc_link_t *lp;
	sarc_list_t *bucket = &s->sarc_bucket[n];
	list_t *l = &bucket->sal_list;
	void *cmp;

	if (lpp != NULL)
		*lpp = bucket;

	for (lp = list_head(l); lp != NULL; lp = list_next(l, lp)) {
		cmp = obj_to_tag(s, link_to_obj(s, lp));

		if (s->sarc_ops.sao_cmp(cmp, tp) == 0 &&
		    !(lp->sal_flags & SARC_F_DEAD))
			return (lp);
	}

	return (NULL);
}

int
sarc_insert(sarc_t *s, void *obj)
{
	sarc_link_t *lp = obj_to_link(s, obj);
	sarc_link_t *evict_lp = NULL;
	sarc_list_t *bucket;
	size_t mru_total;
	size_t mfu_total;

	/* Make sure there's no duplicates */
	if (sarc_hash_lookup(s, obj_to_tag(s, obj), &bucket) != NULL)
		return (EEXIST);

	list_link_init(&lp->sal_hash_link);
	list_link_init(&lp->sal_list_link);
	lp->sal_refcnt = 0;
	lp->sal_flags = 0;

	list_insert_tail(&bucket->sal_list, lp);
	bucket->sal_len++;

	/* New entries always get put on the MRU */
	lp->sal_flags = SARC_MRU;

	mru_total = s->sarc_list[SARC_MRU].sal_len +
	    s->sarc_list[SARC_GMRU].sal_len;
	mfu_total = s->sarc_list[SARC_MFU].sal_len +
	    s->sarc_list[SARC_GMFU].sal_len;

	if (mru_total == s->sarc_c) {
		if (s->sarc_list[SARC_MRU].sal_len < s->sarc_c) {
			evict_lp = sarc_lru_remove(s, SARC_GMRU);
			sarc_evict(s, B_FALSE);
		} else {
			evict_lp = sarc_lru_remove(s, SARC_MRU);
		}
	} else if ((mru_total < s->sarc_c) &&
	    (mru_total + mfu_total >= s->sarc_c)) {
		evict_lp = sarc_lru_remove(s, SARC_GMFU);
		sarc_evict(s, B_FALSE);
	}

	if (evict_lp != NULL) {
		if (evict_lp->sal_refcnt > 0) {
			evict_lp->sal_flags |= SARC_F_DEAD;
		} else {
			sarc_delete(s, evict_lp);
		}
	}

	/* New entries always go on the MRU */
	sarc_add(s, lp, SARC_MRU);
	return (0);
}

void *
sarc_lookup(sarc_t *s, const void *tp)
{
	sarc_link_t *lp;
	sarc_list_t *src;
	void *obj;
	size_t gmfu_len, gmru_len, ratio;
	boolean_t from_ghost = B_FALSE;
	boolean_t from_gmfu = B_FALSE;

	if ((lp = sarc_hash_lookup(s, tp, NULL)) == NULL)
		return (NULL);

	obj = link_to_obj(s, lp);
	src = SARC_LIST(s, lp);
	gmfu_len = s->sarc_list[SARC_GMFU].sal_len;
	gmru_len = s->sarc_list[SARC_GMRU].sal_len;

	/*
	 * If an entry has been found, it means it's been accessed
	 * at least once, so it gets put at the head of the MFU list
	 */
	switch (lp->sal_flags & SARC_LIST_MASK) {
	case SARC_MFU:
		/*
		 * While we'll end up removing the entry from the MFU and
		 * then readding it back to the MFU, we want it moved to
		 * the head of the MFU from whereever it's current position
		 * is, so we cannot return early.
		 */
	case SARC_MRU:
		from_ghost = B_FALSE;
		break;
	case SARC_GMRU:
		/*
		 * If we have a ghost MRU hit, we want to bias
		 * towards more MRU, so adjust p accordingly
		 */
		if ((ratio = gmfu_len / gmru_len) == 0)
			ratio = 1;
		s->sarc_p = MIN(s->sarc_p + ratio, s->sarc_c);
		from_ghost = B_TRUE;
		break;
	case SARC_GMFU:
		/*
		 * Simlarly, if there's a ghost MFU hit, we want to
		 * bias towards more MFU, so adjust p accordingly
		 */
		if ((ratio = gmru_len / gmfu_len) == 0)
			ratio = 1;
		s->sarc_p = (s->sarc_p >= ratio) ? s->sarc_p - ratio : 0;
		from_ghost = B_TRUE;
		from_gmfu = B_TRUE;
		break;
	}

	/* Remove from its current list */
	ASSERT3U(src->sal_len, >, 0);
	ASSERT(!list_is_empty(&src->sal_list));
	list_remove(&src->sal_list, lp);
	src->sal_len--;

	if (from_ghost) {
		/*
		 * If we cannot fetch the data for a ghost entry, we don't
		 * want to put it on the MRU list.  Instead just put it back
		 * at the front of the list it was on.
		 */
		if (!s->sarc_ops.sao_fetch(obj)) {
			list_insert_head(&src->sal_list, lp);
			src->sal_len++;
			return (obj);
		}

		/*
		 * We have entries on the ghost list, it means the cache
		 * (MRU, MFU) is full.  Bump something down to the ghost
		 * list so we can move entry back into the cache.
		 */
		sarc_evict(s, from_gmfu);
	}

	sarc_add(s, lp, SARC_MFU);
	return (obj);
}

/*
 * Move the most recent entry in one of the ghost lists onto the tail of
 * which and fetch.  If which is a ghost list, this is a no-op.  Returns
 * B_TRUE if it was able to successfully resurrect an item, B_FALSE
 * otherwise.
 */
static boolean_t
sarc_resurrect(sarc_t *s, sarc_flag_t which)
{
	sarc_list_t *ghost_list, *dst;
	sarc_link_t *exghost;

	ASSERT3U(which & ~SARC_LIST_MASK, ==, 0);

	dst = &s->sarc_list[which];
	switch (which) {
	case SARC_MRU:
		ghost_list = &s->sarc_list[SARC_GMRU];
		break;
	case SARC_MFU:
		ghost_list = &s->sarc_list[SARC_GMFU];
		break;
	default:
		return (B_FALSE);
	}
	if (ghost_list->sal_len == 0)
		return (B_FALSE);

	exghost = list_remove_head(&ghost_list->sal_list);
	if (!s->sarc_ops.sao_fetch(link_to_obj(s, exghost))) {
		/* If we cannot fetch for some reason, just put it back */
		list_insert_head(&ghost_list->sal_list, exghost);
		return (B_FALSE);
	}
	ghost_list->sal_len--;

	exghost->sal_flags &= ~SARC_LIST_MASK;
	exghost->sal_flags |= which;
	list_insert_tail(&dst->sal_list, exghost);
	dst->sal_len++;

	return (B_TRUE);
}

void
sarc_remove(sarc_t *s, void *op)
{
	sarc_link_t *lp = obj_to_link(s, op);
	sarc_list_t *lst = SARC_LIST(s, lp);

	ASSERT(!list_is_empty(&lst->sal_list));
	ASSERT3U(lst->sal_len, >, 0);
	list_remove(&lst->sal_list, lp);
	lst->sal_len--;

	/*
	 * For similar reasons as when we resize, if we're removing something
	 * from the MRU or MFU list, we want to move an entry from the
	 * respective ghost list so the ghost MRU:ghost MFU ratio (used to
	 * determine how aggressively p is adjusted on ghost hits) stays
	 * correct.  Since we're removing a single item, there's not much
	 * we can do if we can't fetch the ghost item, so ignore the return
	 * value.
	 */
	(void) sarc_resurrect(s, lp->sal_flags & SARC_LIST_MASK);

	if (lp->sal_refcnt > 0) {
		lp->sal_flags |= SARC_F_DEAD;
	} else {
		sarc_delete(s, lp);
	}
}

void
sarc_hold(sarc_t *s, void *op)
{
	sarc_link_t *lp = obj_to_link(s, op);

	++lp->sal_refcnt;
}

void
sarc_rele(sarc_t *s, void *op)
{
	sarc_link_t *lp = obj_to_link(s, op);

	ASSERT3U(lp->sal_refcnt, >, 0);

	if (--lp->sal_refcnt == 0 && (lp->sal_flags & SARC_F_DEAD))
		sarc_remove(s, op);
}

int
sarc_adjust_c(sarc_t *s, size_t new_c)
{
	sarc_link_t *lp = NULL;
	size_t new_p = 0;
	size_t mfu_tgt_len = 0;

	/*
	 * The original ARC paper doesn't cover this.  The most obvious
	 * thing seems to scale p by the same ratio of old_c:new_c, and
	 * if new_c < old_c, evict / delete entries as appropriate
	 */
	if (new_c < SARC_MIN_C)
		return (EINVAL);

	if (new_c == s->sarc_c)
		return (0);

	/*
	 * new_p = p * (new_c/old_c).  Since we can't easily
	 * use floating point if we're in the kernel, we try to
	 * order the operations to preserve as much accuracy as
	 * possible.  It does mean if new_c * p > SIZE_MAX, we
	 * will fail the resize, however since the kernel is
	 * 64-bit, that means new_c * p would be > 2^64 for
	 * us to fail, so that seems unlikely to be legitimate.
	 *
	 * Since we are using integer math to resize p in proportion to the
	 * change in c, it is possible the new value could result in a value
	 * one less than if floating point + rounding was done (due to
	 * truncation instead of rounding with integer division).  At the
	 * moment, it doesn't seem like this should be a significant concern
	 * as the value is p is constantly adjusted based on the access pattern
	 * (i.e. hit rate) of the ghost caches.  If the value of p is off, it
	 * should converge to the current 'correct' (best might be a better
	 * description) value of p.  It should be expected that resizing the
	 * cache is a somewhat disruptive operation in that it can lead to a
	 * potentially large amount of cache eviction.
	 */
	if (umul_overflow(s->sarc_p, new_c, &new_p))
		return (EOVERFLOW);
	new_p /= s->sarc_c;
	mfu_tgt_len = new_c - new_p;

	if (new_c > s->sarc_c) {
		/*
		 * When increasing the size of the cache, we could just
		 * update c and p, and leave the existing entries as is.
		 * However, the ARC algorithm (at least as explained by
		 * Megiddo and Modha) seems to implicitly assume that
		 * if the ghost lists are populated, then their respective
		 * real lists are 'full'.  Not having this seems like it
		 * could distort the ideal value of p.  As such we want to
		 * move as many entries from the ghost lists back into the
		 * MFU and MRU caches as we can to keep adjustments to p
		 * from being overly aggressive.
		 */
		while (s->sarc_list[SARC_MRU].sal_len < new_p) {
			if (!sarc_resurrect(s, SARC_MRU))
				break;
		}

		while (s->sarc_list[SARC_MFU].sal_len < mfu_tgt_len) {
			if (!sarc_resurrect(s, SARC_MFU))
				break;
		}
	} else {
		/*
		 * Move enough stuff from the MRU and MFU lists onto their
		 * respective ghost lists.  Since p is the desired size of
		 * the MRU list, c - p is the size of the MFU.  However,
		 * the number of entries for a given list and it's ghost
		 * counter part should also be <= c.  This means:
		 *	p	Current maximum size of MRU
		 *	c - p	Current maximum size of MFU
		 *	c - p	Current maximum size of ghost MRU
		 *	p	Current maximum size of ghost MFU
		 *
		 * Thus the new size of the ghost MRU is == mfu_tgt_len and
		 * the new new size of the ghost MFU is p.  As we move entries
		 * around, these limits might be exceeded (e.g. we may move
		 * more than new_c - new_p entries from the MRU to the
		 * ghost MFU, but only for the duration of the resize
		 * operation -- everything should be within limits once we're
		 * done.
		 */
		while (s->sarc_list[SARC_MRU].sal_len > new_p) {
			if ((lp = sarc_lru_remove(s, SARC_MRU)) == NULL)
				break;
			s->sarc_ops.sao_evict(link_to_obj(s, lp));
			sarc_add(s, lp, SARC_GMRU);
		}
		while (s->sarc_list[SARC_GMRU].sal_len > mfu_tgt_len) {
			if ((lp = sarc_lru_remove(s, SARC_GMRU)) != NULL) {
				if (lp->sal_refcnt > 0)
					lp->sal_flags |= SARC_F_DEAD;
				else
					sarc_delete(s, lp);
			} else {
				break;
			}
		}

		while (s->sarc_list[SARC_MFU].sal_len > mfu_tgt_len) {
			if ((lp = sarc_lru_remove(s, SARC_MFU)) == NULL)
				break;
			s->sarc_ops.sao_evict(link_to_obj(s, lp));
			sarc_add(s, lp, SARC_GMFU);
		}
		while (s->sarc_list[SARC_GMFU].sal_len > new_p) {
			if ((lp = sarc_lru_remove(s, SARC_GMFU)) != NULL) {
				if (lp->sal_refcnt > 0)
					lp->sal_flags |= SARC_F_DEAD;
				else
					sarc_delete(s, lp);
			} else {
				break;
			}
		}
	}

	s->sarc_c = new_c;
	s->sarc_p = new_p;
	return (0);
}

void *
sarc_first(sarc_t *s)
{
	sarc_link_t *lp = NULL;

	for (int i = 0; i < SARC_NUM_LISTS; i++) {
		sarc_list_t *slp = &s->sarc_list[i];

		if ((lp = list_head(&slp->sal_list)) == NULL)
			continue;

		while (lp != NULL && ((lp->sal_flags & SARC_F_DEAD) != 0))
			lp = list_next(&slp->sal_list, lp);

		if (lp != NULL) {
			++lp->sal_refcnt;
			return (link_to_obj(s, lp));
		}
	}

	return (lp);
}

void *
sarc_next(sarc_t *s, void *op)
{
	sarc_link_t *lp;
	int which;

	lp = obj_to_link(s, op);
	which = lp->sal_flags & SARC_LIST_MASK;

	while (which < SARC_NUM_LISTS) {
		sarc_list_t *slp = &s->sarc_list[which++];

		while ((lp = list_next(&slp->sal_list, lp)) != NULL) {
			if (!(lp->sal_flags & SARC_F_DEAD))
				goto done;
		}
	}

done:
	sarc_rele(s, op);
	if (lp == NULL)
		return (NULL);

	++lp->sal_refcnt;

	return (link_to_obj(s, lp));
}
