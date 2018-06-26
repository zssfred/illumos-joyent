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
 * Copyright 2018 Joyent, Inc.
 */

/*
 * Overlay device target cache management
 *
 * For more information, see the big theory statement in
 * uts/common/io/overlay/overlay.c
 */

#include <inet/ip.h>
#include <inet/ip6.h>
#include <sys/types.h>
#include <sys/ethernet.h>
#include <sys/kmem.h>
#include <sys/policy.h>
#include <sys/sysmacros.h>
#include <sys/stream.h>
#include <sys/strsun.h>
#include <sys/strsubr.h>
#include <sys/mac_provider.h>
#include <sys/mac_client.h>
#include <sys/mac_client_priv.h>
#include <sys/vlan.h>
#include <sys/crc32.h>
#include <sys/cred.h>
#include <sys/file.h>
#include <sys/errno.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#include <sys/overlay_impl.h>
#include <sys/sdt.h>

#define	OVERLAY_DROP(mp, reason) \
    DTRACE_PROBE2(overlay__drop, mblk_t *, mp, char *, reason)

/*
 * This is total straw man, but at least it's a prime number. Here we're
 * going to have to go through and do a lot of evaluation and understanding as
 * to how these target caches should grow and shrink, as well as, memory
 * pressure and evictions. This just gives us a starting point that'll be 'good
 * enough', until it's not.
 */
#define	OVERLAY_HSIZE	823

/*
 * The default size of each target cache.  This is also a complete strawman
 * whose value could change as we gain better operational experience with
 * overlay routing.
 */
#define	OVERLAY_CACHE_SIZE	512

/*
 * We use this data structure to keep track of what requests have been actively
 * allocated to a given instance so we know what to put back on the pending
 * list.
 */
typedef struct overlay_target_hdl {
	minor_t oth_minor;		/* RO */
	zoneid_t oth_zoneid;		/* RO */
	int oth_oflags;			/* RO */
	list_node_t oth_link;		/* overlay_target_lock */
	kmutex_t oth_lock;
	list_t	oth_outstanding;	/* oth_lock */
} overlay_target_hdl_t;

typedef int (*overlay_target_copyin_f)(const void *, void **, size_t *, int);
typedef int (*overlay_target_ioctl_f)(overlay_target_hdl_t *, void *);
typedef int (*overlay_target_copyout_f)(void *, void *, size_t, int);

typedef struct overlay_target_ioctl {
	int		oti_cmd;	/* ioctl id */
	boolean_t	oti_write;	/* ioctl requires FWRITE */
	boolean_t	oti_ncopyout;	/* copyout data? */
	overlay_target_copyin_f oti_copyin;	/* copyin func */
	overlay_target_ioctl_f oti_func; /* function to call */
	overlay_target_copyout_f oti_copyout;	/* copyin func */
	size_t		oti_size;	/* size of user level structure */
} overlay_target_ioctl_t;

static kmem_cache_t *overlay_target_cache;
static kmem_cache_t *overlay_entry_cache;
static id_space_t *overlay_thdl_idspace;
static void *overlay_thdl_state;

/*
 * When we support overlay devices in the NGZ, then all of these need to become
 * zone aware, by plugging into the netstack engine and becoming per-netstack
 * data.
 */
static list_t overlay_thdl_list;
static kmutex_t overlay_target_lock;
static kcondvar_t overlay_target_condvar;
static list_t overlay_target_list;
static boolean_t overlay_target_excl;

/*
 * Outstanding data per hash table entry.
 */
static int overlay_ent_size = 128 * 1024;

/* ARGSUSED */
static int
overlay_target_cache_constructor(void *buf, void *arg, int kmflgs)
{
	overlay_target_t *ott = buf;

	mutex_init(&ott->ott_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&ott->ott_cond, NULL, CV_DRIVER, NULL);
	return (0);
}

/* ARGSUSED */
static void
overlay_target_cache_destructor(void *buf, void *arg)
{
	overlay_target_t *ott = buf;

	cv_destroy(&ott->ott_cond);
	mutex_destroy(&ott->ott_lock);
}

/* ARGSUSED */
static int
overlay_entry_cache_constructor(void *buf, void *arg, int kmflgs)
{
	overlay_target_entry_t *ote = buf;

	bzero(ote, sizeof (overlay_target_entry_t));
	mutex_init(&ote->ote_lock, NULL, MUTEX_DRIVER, NULL);
	return (0);
}

/* ARGSUSED */
static void
overlay_entry_cache_destructor(void *buf, void *arg)
{
	overlay_target_entry_t *ote = buf;

	mutex_destroy(&ote->ote_lock);
}

static uint64_t
overlay_mac_hash(const void *v)
{
	const overlay_target_mac_t *m = v;

	uint32_t crc;
	CRC32(crc, m->otm_mac, ETHERADDRL, -1U, crc32_table);
	CRC32(crc, &m->otm_dcid, sizeof (uint32_t), crc, crc32_table);
	return (crc);
}

static int
overlay_mac_cmp(const void *a, const void *b)
{
	const overlay_target_mac_t *l = a;
	const overlay_target_mac_t *r = b;

	if (l->otm_dcid != r->otm_dcid)
		return (1);
	return (bcmp(l->otm_mac, r->otm_mac, ETHERADDRL) != 0);
}

static uint64_t
overlay_ip_hash(const void *v)
{
	const overlay_target_vl3_t *vl3 = v;

	uint32_t crc;
	CRC32(crc, &vl3->otvl3_src, sizeof (vl3->otvl3_src), -1U, crc32_table);
	CRC32(crc, &vl3->otvl3_dst, sizeof (vl3->otvl3_dst), crc, crc32_table);
	CRC32(crc, &vl3->otvl3_src_vlan, sizeof (vl3->otvl3_src_vlan), crc,
	    crc32_table);
	return (crc);
}

static int
overlay_ip_cmp(const void *a, const void *b)
{
	const overlay_target_vl3_t *l = a;
	const overlay_target_vl3_t *r = b;

	if (l->otvl3_src_vlan != r->otvl3_src_vlan)
		return (1);
	if (!IN6_ARE_ADDR_EQUAL(&l->otvl3_src, &r->otvl3_src))
		return (1);
	if (!IN6_ARE_ADDR_EQUAL(&l->otvl3_dst, &r->otvl3_dst))
		return (1);
	return (0);
}

static void
overlay_target_entry_dtor(void *arg)
{
	overlay_target_entry_t *ote = arg;

	ote->ote_flags = 0;
	bzero(&ote->ote_u, sizeof (ote->ote_u));
	ote->ote_ott = NULL;
	ote->ote_odd = NULL;
	freemsgchain(ote->ote_chead);
	ote->ote_chead = ote->ote_ctail = NULL;
	ote->ote_mbsize = 0;
	ote->ote_vtime = 0;
	kmem_cache_free(overlay_entry_cache, ote);
}

static void
overlay_target_entry_l2sarc_dtor(void *arg)
{
	overlay_target_entry_t *ote = arg;
	overlay_target_t *ott = ote->ote_ott;

	ASSERT(MUTEX_HELD(&ott->ott_lock));
	ASSERT3S((ote->ote_flags & OVERLAY_ENTRY_F_VL3), ==, 0);

	avl_remove(&ott->ott_u.ott_dyn.ott_tree, ote);
	overlay_target_entry_dtor(ote);
}

static void
overlay_target_entry_l3sarc_dtor(void *arg)
{
	overlay_target_entry_t *ote = arg;
	overlay_target_t *ott = ote->ote_ott;

	ASSERT(MUTEX_HELD(&ott->ott_lock));
	ASSERT3S((ote->ote_flags & OVERLAY_ENTRY_F_VL3), ==,
	    OVERLAY_ENTRY_F_VL3);

	avl_remove(&ott->ott_u.ott_dyn.ott_l3tree, ote);
	overlay_target_entry_dtor(ote);
}

static int
overlay_mac_avl(const void *a, const void *b)
{
	const overlay_target_entry_t *le = a;
	const overlay_target_entry_t *re = b;
	const overlay_target_mac_t *lm = &le->ote_u.ote_vl2.otvl2_mac;
	const overlay_target_mac_t *rm = &re->ote_u.ote_vl2.otvl2_mac;
	int i;

	/* Order by DCID, then MAC */
	if (lm->otm_dcid < rm->otm_dcid)
		return (-1);
	if (lm->otm_dcid > rm->otm_dcid)
		return (1);

	for (i = 0; i < ETHERADDRL; i++) {
		if (lm->otm_mac[i] > rm->otm_mac[i])
			return (1);
		else if (lm->otm_mac[i] < rm->otm_mac[i])
			return (-1);
	}
	return (0);
}

static int
overlay_ip_avl(const void *a, const void *b)
{
	const overlay_target_entry_t *l = a;
	const overlay_target_entry_t *r = b;
	const overlay_target_vl3_t *l_vl3 = &l->ote_u.ote_vl3;
	const overlay_target_vl3_t *r_vl3 = &r->ote_u.ote_vl3;
	int ret;

	if ((ret = memcmp(&l_vl3->otvl3_src, &r_vl3->otvl3_src,
	    sizeof (l_vl3->otvl3_src))) != 0)
		return (ret < 0 ? -1 : 1);
	if ((ret = memcmp(&l_vl3->otvl3_dst, &r_vl3->otvl3_dst,
	    sizeof (l_vl3->otvl3_dst))) != 0)
		return (ret < 0 ? -1 : 1);
	if (l_vl3->otvl3_src_vlan < r_vl3->otvl3_src_vlan)
		return (-1);
	if (l_vl3->otvl3_src_vlan > r_vl3->otvl3_src_vlan)
		return (1);
	return (0);
}

void
overlay_target_init(void)
{
	int ret;
	ret = ddi_soft_state_init(&overlay_thdl_state,
	    sizeof (overlay_target_hdl_t), 1);
	VERIFY(ret == 0);
	overlay_target_cache = kmem_cache_create("overlay_target",
	    sizeof (overlay_target_t), 0, overlay_target_cache_constructor,
	    overlay_target_cache_destructor, NULL, NULL, NULL, 0);
	overlay_entry_cache = kmem_cache_create("overlay_entry",
	    sizeof (overlay_target_entry_t), 0, overlay_entry_cache_constructor,
	    overlay_entry_cache_destructor, NULL, NULL, NULL, 0);
	mutex_init(&overlay_target_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&overlay_target_condvar, NULL, CV_DRIVER, NULL);
	list_create(&overlay_target_list, sizeof (overlay_target_entry_t),
	    offsetof(overlay_target_entry_t, ote_qlink));
	list_create(&overlay_thdl_list, sizeof (overlay_target_hdl_t),
	    offsetof(overlay_target_hdl_t, oth_link));
	overlay_thdl_idspace = id_space_create("overlay_target_minors",
	    1, INT32_MAX);
}

void
overlay_target_fini(void)
{
	id_space_destroy(overlay_thdl_idspace);
	list_destroy(&overlay_thdl_list);
	list_destroy(&overlay_target_list);
	cv_destroy(&overlay_target_condvar);
	mutex_destroy(&overlay_target_lock);
	kmem_cache_destroy(overlay_entry_cache);
	kmem_cache_destroy(overlay_target_cache);
	ddi_soft_state_fini(&overlay_thdl_state);
}

void
overlay_target_free(overlay_dev_t *odd)
{
	if (odd->odd_target == NULL)
		return;

	if (odd->odd_target->ott_mode == OVERLAY_TARGET_DYNAMIC) {
		mutex_enter(&odd->odd_target->ott_lock);
		/*
		 * Our VL3 AVL tree and hashtable contain the same elements.
		 * Additionally, when an entry is removed from the sarc cache,
		 * the entry is removed from the corresponding AVL tree.
		 * Deleting the sarc cache will destroy any remaining entries,
		 * so all we need to do is destroy the sarc caches.
		 */
		sarc_destroy(odd->odd_target->ott_u.ott_dyn.ott_dhash);
		sarc_destroy(odd->odd_target->ott_u.ott_dyn.ott_l3dhash);
		ASSERT(avl_is_empty(&odd->odd_target->ott_u.ott_dyn.ott_tree));
		ASSERT(avl_is_empty(
		    &odd->odd_target->ott_u.ott_dyn.ott_l3tree));
		mutex_exit(&odd->odd_target->ott_lock);
	}

	ASSERT(odd->odd_target->ott_ocount == 0);
	kmem_cache_free(overlay_target_cache, odd->odd_target);
}

int
overlay_target_busy()
{
	int ret;

	mutex_enter(&overlay_target_lock);
	ret = !list_is_empty(&overlay_thdl_list);
	mutex_exit(&overlay_target_lock);

	return (ret);
}

static void
overlay_target_queue(overlay_target_entry_t *entry)
{
	mutex_enter(&overlay_target_lock);
	mutex_enter(&entry->ote_ott->ott_lock);
	if (entry->ote_ott->ott_flags & OVERLAY_T_TEARDOWN) {
		mutex_exit(&entry->ote_ott->ott_lock);
		mutex_exit(&overlay_target_lock);
		return;
	}
	entry->ote_ott->ott_ocount++;
	mutex_exit(&entry->ote_ott->ott_lock);
	list_insert_tail(&overlay_target_list, entry);
	cv_signal(&overlay_target_condvar);
	mutex_exit(&overlay_target_lock);
}

void
overlay_target_quiesce(overlay_target_t *ott)
{
	if (ott == NULL)
		return;
	mutex_enter(&ott->ott_lock);
	ott->ott_flags |= OVERLAY_T_TEARDOWN;
	while (ott->ott_ocount != 0)
		cv_wait(&ott->ott_cond, &ott->ott_lock);
	mutex_exit(&ott->ott_lock);
}

/*
 * Write the VL3 src/dst IP from the packet in mp into src and dst.  If the
 * addresses are IPv4 addresses, they are written as mapped addresses.
 */
static int
overlay_get_vl3_ips(mblk_t *mp, struct in6_addr *src, struct in6_addr *dst)
{
	uint16_t sap;

#if 1
	/* Temporary until mblk helpers are integrated */
	struct ether_vlan_header *eth = (struct ether_vlan_header *)mp->b_rptr;
	ipha_t *iphp = (ipha_t *)(eth + 1);
	ip6_t *ip6hp = (ip6_t *)(eth + 1);
	size_t mlen = MBLKL(mp);

	if (mlen < sizeof (struct ether_vlan_header))
		return (EINVAL);
	mlen -= sizeof (struct ether_vlan_header);

	/* We currently don't support routing on untagged vlans */
	if ((sap = ntohs(eth->ether_tpid)) != ETHERTYPE_VLAN)
		return (EINVAL);

	sap = ntohs(eth->ether_type);
	if (mlen == 0) {
		if ((mp = mp->b_cont) == NULL)
			return (EINVAL);
		mlen = MBLKL(mp);
		iphp = (ipha_t *)mp->b_rptr;
		ip6hp = (ip6_t *)mp->b_rptr;
	}

	switch (sap) {
	case ETHERTYPE_IP:
		if (mlen < sizeof (ipha_t))
			return (EINVAL);
		ASSERT3U(IPH_HDR_VERSION(iphp), ==, IPV4_VERSION);
		IN6_IPADDR_TO_V4MAPPED(iphp->ipha_src, src);
		IN6_IPADDR_TO_V4MAPPED(iphp->ipha_dst, dst);
		break;
	case ETHERTYPE_IPV6:
		if (mlen < sizeof (ip6_t))
			return (EINVAL);
		ASSERT3U(IPH_HDR_VERSION(iphp), ==, IPV6_VERSION);
		bcopy(&ip6hp->ip6_src, src, sizeof (*src));
		bcopy(&ip6hp->ip6_dst, dst, sizeof (*dst));
		break;
	default:
		return (EINVAL);
	}

	return (0);
#else
	size_t soff, doff;
	uint32_t v4s, v4d;
	int i;

	if (!mblk_read_uint16(mp, offsetof(struct ether_header, ether_type),
	    &sap))
		return (EINVAL);

	if (sap == ETHERTYPE_VLAN) {
		if (!mblk_read_uint16(mp,
		    offsetof(struct ether_vlan_header, ether_type), &sap))
			return (EINVAL);
		soff = doff = sizeof (struct ether_vlan_header);
	} else {
		soff = doff = sizeof (struct ether_header);
	}

	switch (sap) {
	case ETHERTYPE_IP:
		soff += offsetof(ipha_t, ipha_src);
		doff += offsetof(ipha_t, ipha_dst);

		if (!mblk_read_uint32(mp, soff, &v4s) ||
		    !mblk_read_uint32(mp, doff, &v4d))
			return (EINVAL);
		IN6_IPADDR_TO_V4MAPPED(&v4s, src);
		IN6_IPADDR_TO_V4MAPPED(&v4d, dst);
		break;
	case ETHERTYPE_IPV6:
		soff += offsetof(ip6_t, ip6_src);
		doff += offsetof(ip6_6, ip6_dst);

		for (i = 0; i < 4; i++) {
			if (!mblk_read_uint32(mp, soff, &src->s6_addr32[i]) ||
			    !mblk_read_uint32(mp, doff, &dst->s6_addr32[i]))
				return (EINVAL);
			soff += sizeof (uint32_t);
			doff += sizeof (uint32_t);
		}
		break;
	default:
		return (EINVAL);
	}

	return (0);
#endif
}

static int
overlay_route(overlay_dev_t *odd, mblk_t *mp,
    const overlay_target_route_t *route, const overlay_target_mac_t *dst_mac)
{
	uint16_t tci;

	if (MBLKL(mp) >= sizeof (struct ether_vlan_header)) {
		struct ether_vlan_header *evh;

		evh = (struct ether_vlan_header *)mp->b_rptr;
		tci = ntohs(evh->ether_tci);

		/*
		 * Today we require all encapsulated frames to be vlan tagged.
		 * If this is relaxed in the future, we will need to allow for
		 * insertion and removal of the vlan tag as appropriate here.
		 */
		if (ntohs(evh->ether_tpid) != ETHERTYPE_VLAN) {
			OVERLAY_DROP(mp, "not vlan tagged");
			return (OVERLAY_TARGET_DROP);
		}

		tci &= ~(VLAN_ID_MASK);
		tci |= route->otr_vlan;
		evh->ether_tci = htons(tci);
		bcopy(dst_mac->otm_mac, &evh->ether_dhost, ETHERADDRL);
		bcopy(route->otr_srcmac, &evh->ether_shost, ETHERADDRL);
		return (OVERLAY_TARGET_OK);
	}

#if 1
	/* Temporary until mblk helpers are integrated */
	OVERLAY_DROP(mp, "ethernet header split between mblks");
	return (OVERLAY_TARGET_DROP);
#else
	size_t off;

	off = offsetof(struct ether_vlan_header, ether_tpid);
	if (!mblk_read_uint16(mp, off, &tci)) {
		OVERLAY_DROP(mp, "cannot read tpid");
		return (OVERLAY_TARGET_DROP);
	}

	tci = ntohs(evh->ether_tci);
	tci &= ~(VLAN_ID_MASK);
	tci |= route->otr_vlan;

	if (!mblk_write_uint16(mp, off, tci)) {
		OVERLAY_DROP(mp, "cannot set routed destination vlan");
		return (OVERLAY_TARGET_DROP);
	}

	for (int i = 0; i < ETHERADDRL; i++) {
		if (!mblk_write_uint8(mp, i, dst_msc->otm_mac[i]) ||
		    !mblk_write_uint8(mp, i + ETHERADDRL,
		    route->otr_srcmac[i])) {
			OVERLAY_DROP(mp, "cannot set routed macs");
			return (OVERLAY_TARGET_DROP);
		}
	}

	return (OVERLAY_TARGET_OK);
#endif
}

static int
overlay_target_try_queue(overlay_target_entry_t *entry, mblk_t *mp)
{
	size_t mlen = msgsize(mp);

	ASSERT(MUTEX_HELD(&entry->ote_lock));

	if (mlen + entry->ote_mbsize > overlay_ent_size) {
		OVERLAY_DROP(mp, "target queue full");
		return (OVERLAY_TARGET_DROP);
	}

	if (entry->ote_ctail != NULL) {
		ASSERT(entry->ote_ctail->b_next == NULL);
		entry->ote_ctail->b_next = mp;
		entry->ote_ctail = mp;
	} else {
		entry->ote_chead = mp;
		entry->ote_ctail = mp;
	}
	entry->ote_mbsize += mlen;
	if ((entry->ote_flags & OVERLAY_ENTRY_F_PENDING) == 0) {
		entry->ote_flags |= OVERLAY_ENTRY_F_PENDING;
		overlay_target_queue(entry);
	}
	return (OVERLAY_TARGET_ASYNC);
}

static int
overlay_route_lookup_vl2(overlay_target_entry_t *vl3e,
    overlay_target_entry_t *vl2e, uint64_t *vidp, struct sockaddr_in6 *v6,
    socklen_t *slenp, mblk_t *mp)
{
	overlay_target_vl2_t *vl2p;
	int ret;

	ASSERT(MUTEX_HELD(&vl3e->ote_lock));

	if (vl2e == NULL) {
		vl3e->ote_flags &= ~OVERLAY_ENTRY_F_VALID;
		return (overlay_target_try_queue(vl3e, mp));
	}

	mutex_enter(&vl2e->ote_lock);
	if (vl2e->ote_flags & (OVERLAY_ENTRY_F_DROP | OVERLAY_ENTRY_F_ROUTER)) {
		overlay_target_entry_flags_t flags = vl2e->ote_flags;

		mutex_exit(&vl2e->ote_lock);

		if (flags & OVERLAY_ENTRY_F_DROP) {
			OVERLAY_DROP(mp, "VL2 target marked drop");
		} else {
			OVERLAY_DROP(mp, "VL2 target is overlay router");
		}

		return (OVERLAY_TARGET_DROP);
	}

	/*
	 * If the route is missing queue on the VL3 entry so a VL3->UL3
	 * lookup is done (to get the route data).
	 */
	if ((vl2e->ote_flags & OVERLAY_ENTRY_F_HAS_ROUTE) == 0) {
		mutex_exit(&vl2e->ote_lock);

		vl3e->ote_flags &= ~OVERLAY_ENTRY_F_VALID;
		return (overlay_target_try_queue(vl3e, mp));
	}

	/*
	 * If the VL2 target point is missing, we try to be a bit (though
	 * hopefully not too) clever.  We can always queue on the VL3 entry
	 * which will trigger a VL3->UL3 lookup request (as it is effectively
	 * a superset of the VL2->UL3 lookup).  However, if we know we already
	 * have an outstanding VL3->UL3 request, we queue on the VL2 entry and
	 * avoid doing another redundant lookup.  We can also queue on the VL2
	 * entry when it is a local (same vnet, same DC) destination -- we
	 * currently cannot generate VL2->UL3 lookups for remote destinations,
	 * only same vnet, same DC.  Queueing on the VL2 entry also allows
	 * instances on the same vlan as the queued VL2 entry to piggy back on
	 * the lookup request and avoid a redundant lookup.  However if the
	 * VL2 entry is remote, we have to do a VL3->UL3 lookup.
	 */
	if ((vl2e->ote_flags & OVERLAY_ENTRY_F_VALID) == 0) {
		overlay_target_entry_t *queue_e;

		if ((vl2e->ote_flags & OVERLAY_ENTRY_F_PENDING) == 0 &&
		    vl2e->ote_u.ote_vl2.otvl2_mac.otm_dcid !=
		    vl2e->ote_odd->odd_dcid) {
			queue_e = vl3e;
		} else {
			queue_e = vl2e;
		}

		ret = overlay_target_try_queue(queue_e, mp);
		mutex_exit(&vl2e->ote_lock);
		return (ret);
	}

	ASSERT(vl2e->ote_flags & OVERLAY_ENTRY_F_VALID);

	vl2p = &vl2e->ote_u.ote_vl2;

	*vidp = vl2p->otvl2_route.otr_vnet;
	bcopy(&vl2p->otvl2_dest.otp_ip, &v6->sin6_addr,
	    sizeof (struct in6_addr));
	v6->sin6_port = htons(vl2p->otvl2_dest.otp_port);
	*slenp = sizeof (struct sockaddr_in6);

	ret = overlay_route(vl2e->ote_odd, mp, &vl2p->otvl2_route,
	    &vl2p->otvl2_mac);
	mutex_exit(&vl2e->ote_lock);

	return (ret);
}

static int
overlay_route_lookup(overlay_dev_t *odd, mblk_t *mp, uint16_t vlan,
    struct sockaddr *sock, socklen_t *slenp, uint64_t *vidp)
{
	overlay_target_t *ott = odd->odd_target;
	overlay_target_entry_t *entry, *vl2_entry = NULL;
	struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)sock;
	overlay_target_vl3_t vl3 = { 0 };
	int ret = OVERLAY_TARGET_DROP;

	/* overlay_target_lookup() should have set this */
	ASSERT3U(v6->sin6_family, ==, AF_INET6);

	/* We should only be called for dynamic endpoints */
	ASSERT3U(ott->ott_mode, ==, OVERLAY_TARGET_DYNAMIC);

	vl3.otvl3_src_vlan = vlan;
	if ((ret = overlay_get_vl3_ips(mp, &vl3.otvl3_src, &vl3.otvl3_dst))
	    != OVERLAY_TARGET_OK) {
		OVERLAY_DROP(mp, "could not read VL3 src/dst IPs");
		return (OVERLAY_TARGET_DROP);
	}

	mutex_enter(&ott->ott_lock);
	entry = sarc_lookup(ott->ott_u.ott_dyn.ott_l3dhash, &vl3);
	if (entry == NULL) {
		if ((entry = kmem_cache_alloc(overlay_entry_cache,
		    KM_NOSLEEP | KM_NORMALPRI)) == NULL) {
			mutex_exit(&ott->ott_lock);
			OVERLAY_DROP(mp, "failed VL3 target entry allocation");
			return (OVERLAY_TARGET_DROP);
		}

		bcopy(&vl3, &entry->ote_u.ote_vl3, sizeof (vl3));
		entry->ote_flags = OVERLAY_ENTRY_F_VL3;

		entry->ote_chead = entry->ote_ctail = mp;
		entry->ote_mbsize = msgsize(mp);
		entry->ote_flags |= OVERLAY_ENTRY_F_PENDING;

		entry->ote_ott = ott;
		entry->ote_odd = odd;

		sarc_insert(ott->ott_u.ott_dyn.ott_l3dhash, entry);
		avl_add(&ott->ott_u.ott_dyn.ott_l3tree, entry);
		mutex_exit(&ott->ott_lock);
		overlay_target_queue(entry);
		return (OVERLAY_TARGET_ASYNC);
	}
	sarc_hold(ott->ott_u.ott_dyn.ott_l3dhash, entry);
	mutex_enter(&entry->ote_lock);

	/*
	 * A bit ugly, but if we need the VL2 entry, we want to look it up
	 * while we still hold ott_lock.
	 */
	if ((entry->ote_flags &
	    (OVERLAY_ENTRY_F_DROP|OVERLAY_ENTRY_F_ROUTER|
	    OVERLAY_ENTRY_F_VALID)) == OVERLAY_ENTRY_F_VALID) {
		vl2_entry = sarc_lookup(ott->ott_u.ott_dyn.ott_dhash,
		    &entry->ote_u.ote_vl3.otvl3_vl2);
		if (vl2_entry != NULL)
			sarc_hold(ott->ott_u.ott_dyn.ott_dhash, vl2_entry);
	}
	mutex_exit(&ott->ott_lock);

	ASSERT(entry->ote_flags & OVERLAY_ENTRY_F_VL3);

	if (entry->ote_flags & OVERLAY_ENTRY_F_DROP) {
		OVERLAY_DROP(mp, "VL3 target entry marked drop");
		ret = OVERLAY_TARGET_DROP;
	} else if (entry->ote_flags & OVERLAY_ENTRY_F_ROUTER) {
		/*
		 * XXX: A packet with a dst IP of an overlay router.
		 * Maybe generate an ICMP reply?  For now, we drop.
		 */
		OVERLAY_DROP(mp, "VL3 target entry is router");
		ret = OVERLAY_TARGET_DROP;
	} else if ((entry->ote_flags & OVERLAY_ENTRY_F_VALID) == 0) {
		ret = overlay_target_try_queue(entry, mp);
	} else {
		ret = overlay_route_lookup_vl2(entry, vl2_entry, vidp, v6,
		    slenp, mp);
	}
	mutex_exit(&entry->ote_lock);

	mutex_enter(&ott->ott_lock);
	sarc_rele(ott->ott_u.ott_dyn.ott_l3dhash, entry);
	if (vl2_entry != NULL)
		sarc_rele(ott->ott_u.ott_dyn.ott_dhash, vl2_entry);
	mutex_exit(&ott->ott_lock);
	return (ret);
}

/*
 * This function assumes that the destination mode is OVERLAY_PLUGIN_D_IP |
 * OVERLAY_PLUGIN_D_PORT. As we don't have an implementation of anything else at
 * this time, say for NVGRE, we drop all packets that match this.
 */
int
overlay_target_lookup(overlay_dev_t *odd, mblk_t *mp, struct sockaddr *sock,
    socklen_t *slenp, uint64_t *vidp)
{
	int ret;
	struct sockaddr_in6 *v6;
	overlay_target_t *ott;
	overlay_target_entry_t *entry;
	mac_header_info_t mhi;
	overlay_target_mac_t omac;

	ASSERT(odd->odd_target != NULL);

	/* Default to our local vid, routing may change this if necessary */
	*vidp = odd->odd_vid;

	/*
	 * At this point, the overlay device is in a mux which means that it's
	 * been activated. At this point, parts of the target, such as the mode
	 * and the destination are now read-only and we don't have to worry
	 * about synchronization for them.
	 */
	ott = odd->odd_target;
	if (ott->ott_dest != (OVERLAY_PLUGIN_D_IP | OVERLAY_PLUGIN_D_PORT)) {
		OVERLAY_DROP(mp, "plugin doesn't support IP or port");
		return (OVERLAY_TARGET_DROP);
	}

	v6 = (struct sockaddr_in6 *)sock;
	bzero(v6, sizeof (struct sockaddr_in6));
	v6->sin6_family = AF_INET6;

	if (ott->ott_mode == OVERLAY_TARGET_POINT) {
		mutex_enter(&ott->ott_lock);
		bcopy(&ott->ott_u.ott_point.otp_ip, &v6->sin6_addr,
		    sizeof (struct in6_addr));
		v6->sin6_port = htons(ott->ott_u.ott_point.otp_port);
		mutex_exit(&ott->ott_lock);
		*slenp = sizeof (struct sockaddr_in6);

		return (OVERLAY_TARGET_OK);
	}

	ASSERT(ott->ott_mode == OVERLAY_TARGET_DYNAMIC);

	if (mac_vlan_header_info(odd->odd_mh, mp, &mhi) != 0) {
		OVERLAY_DROP(mp, "could not read vlan header");
		return (OVERLAY_TARGET_DROP);
	}

	omac.otm_dcid = odd->odd_dcid;
	bcopy(mhi.mhi_daddr, omac.otm_mac, ETHERADDRL);

	mutex_enter(&ott->ott_lock);
	entry = sarc_lookup(ott->ott_u.ott_dyn.ott_dhash, &omac);
	if (entry == NULL) {
		overlay_target_vl2_t *vl2p;

		entry = kmem_cache_alloc(overlay_entry_cache,
		    KM_NOSLEEP | KM_NORMALPRI);
		if (entry == NULL) {
			mutex_exit(&ott->ott_lock);
			OVERLAY_DROP(mp, "VL2 target entry allocation failed");
			return (OVERLAY_TARGET_DROP);
		}

		vl2p = &entry->ote_u.ote_vl2;
		bcopy(mhi.mhi_daddr, vl2p->otvl2_mac.otm_mac, ETHERADDRL);
		vl2p->otvl2_mac.otm_dcid = odd->odd_dcid;
		vl2p->otvl2_route.otr_vnet = odd->odd_vid;
		vl2p->otvl2_route.otr_vlan = VLAN_ID(mhi.mhi_tci);

		entry->ote_chead = entry->ote_ctail = mp;
		entry->ote_mbsize = msgsize(mp);
		entry->ote_flags |= OVERLAY_ENTRY_F_PENDING;

		entry->ote_ott = ott;
		entry->ote_odd = odd;

		sarc_insert(ott->ott_u.ott_dyn.ott_dhash, entry);
		avl_add(&ott->ott_u.ott_dyn.ott_tree, entry);
		mutex_exit(&ott->ott_lock);
		overlay_target_queue(entry);
		return (OVERLAY_TARGET_ASYNC);
	}
	sarc_hold(ott->ott_u.ott_dyn.ott_dhash, entry);
	mutex_exit(&ott->ott_lock);

	mutex_enter(&entry->ote_lock);
	if (entry->ote_flags & OVERLAY_ENTRY_F_DROP) {
		OVERLAY_DROP(mp, "VL2 target marked drop");
		ret = OVERLAY_TARGET_DROP;
	} else if (entry->ote_flags & OVERLAY_ENTRY_F_ROUTER) {
		if (mhi.mhi_bindsap == ETHERTYPE_ARP) {
			/*
			 * Send unicast ARP requests to varpd for processing.
			 * We will eventually need something similar for IPv6.
			 */
			ret = overlay_target_try_queue(entry, mp);
		} else {
			ret = overlay_route_lookup(odd, mp,
			    VLAN_ID(mhi.mhi_tci), sock, slenp, vidp);
		}
	} else if (entry->ote_flags & OVERLAY_ENTRY_F_VALID) {
		overlay_target_point_t *otp = &entry->ote_u.ote_vl2.otvl2_dest;

		bcopy(&otp->otp_ip, &v6->sin6_addr, sizeof (struct in6_addr));
		v6->sin6_port = htons(otp->otp_port);
		*slenp = sizeof (struct sockaddr_in6);
		ret = OVERLAY_TARGET_OK;
	} else {
		ret = overlay_target_try_queue(entry, mp);
	}
	mutex_exit(&entry->ote_lock);

	mutex_enter(&ott->ott_lock);
	sarc_rele(ott->ott_u.ott_dyn.ott_dhash, entry);
	mutex_exit(&ott->ott_lock);

	return (ret);
}

/* ARGSUSED */
static int
overlay_target_info(overlay_target_hdl_t *thdl, void *arg)
{
	overlay_dev_t *odd;
	overlay_targ_info_t *oti = arg;

	odd = overlay_hold_by_dlid(oti->oti_linkid);
	if (odd == NULL)
		return (ENOENT);

	mutex_enter(&odd->odd_lock);
	oti->oti_flags = 0;
	oti->oti_needs = odd->odd_plugin->ovp_dest;
	if (odd->odd_flags & OVERLAY_F_DEGRADED)
		oti->oti_flags |= OVERLAY_TARG_INFO_F_DEGRADED;
	if (odd->odd_flags & OVERLAY_F_ACTIVATED)
		oti->oti_flags |= OVERLAY_TARG_INFO_F_ACTIVE;
	oti->oti_vnetid = odd->odd_vid;
	oti->oti_dcid = odd->odd_dcid;
	mutex_exit(&odd->odd_lock);
	overlay_hold_rele(odd);
	return (0);
}

static sarc_ops_t overlay_sarc_l2_ops = {
	.sao_hash = overlay_mac_hash,
	.sao_cmp = overlay_mac_cmp,
	.sao_dtor = overlay_target_entry_l2sarc_dtor,
	.sao_fetch = sarc_nofetch,
	.sao_evict = sarc_noevict
};

static sarc_ops_t overlay_sarc_l3_ops = {
	.sao_hash = overlay_ip_hash,
	.sao_cmp = overlay_ip_cmp,
	.sao_dtor = overlay_target_entry_l3sarc_dtor,
	.sao_fetch = sarc_nofetch,
	.sao_evict = sarc_noevict
};

/* ARGSUSED */
static int
overlay_target_associate(overlay_target_hdl_t *thdl, void *arg)
{
	overlay_dev_t *odd;
	overlay_target_t *ott;
	overlay_targ_associate_t *ota = arg;

	odd = overlay_hold_by_dlid(ota->ota_linkid);
	if (odd == NULL)
		return (ENOENT);

	if (ota->ota_id == 0) {
		overlay_hold_rele(odd);
		return (EINVAL);
	}

	if (ota->ota_mode != OVERLAY_TARGET_POINT &&
	    ota->ota_mode != OVERLAY_TARGET_DYNAMIC) {
		overlay_hold_rele(odd);
		return (EINVAL);
	}

	if (ota->ota_provides != odd->odd_plugin->ovp_dest) {
		overlay_hold_rele(odd);
		return (EINVAL);
	}

	if (ota->ota_mode == OVERLAY_TARGET_POINT) {
		if (ota->ota_provides & OVERLAY_PLUGIN_D_IP) {
			if (IN6_IS_ADDR_UNSPECIFIED(&ota->ota_point.otp_ip) ||
			    IN6_IS_ADDR_V4COMPAT(&ota->ota_point.otp_ip) ||
			    IN6_IS_ADDR_V4MAPPED_ANY(&ota->ota_point.otp_ip)) {
				overlay_hold_rele(odd);
				return (EINVAL);
			}
		}

		if (ota->ota_provides & OVERLAY_PLUGIN_D_PORT) {
			if (ota->ota_point.otp_port == 0) {
				overlay_hold_rele(odd);
				return (EINVAL);
			}
		}
	}

	ott = kmem_cache_alloc(overlay_target_cache, KM_SLEEP);
	ott->ott_flags = 0;
	ott->ott_ocount = 0;
	ott->ott_mode = ota->ota_mode;
	ott->ott_dest = ota->ota_provides;
	ott->ott_id = ota->ota_id;

	if (ott->ott_mode == OVERLAY_TARGET_POINT) {
		bcopy(&ota->ota_point, &ott->ott_u.ott_point,
		    sizeof (overlay_target_point_t));
	} else {
		int ret;

		ret = sarc_create(&ott->ott_u.ott_dyn.ott_dhash,
		    OVERLAY_CACHE_SIZE, OVERLAY_HSIZE, &overlay_sarc_l2_ops,
		    sizeof (overlay_target_entry_t),
		    offsetof(overlay_target_entry_t, ote_reflink),
		    offsetof(overlay_target_entry_t, ote_u.ote_vl2.otvl2_mac),
		    KM_SLEEP);
		if (ret != 0) {
			mutex_exit(&odd->odd_lock);
			kmem_cache_free(overlay_target_cache, ott);
			overlay_hold_rele(odd);
			return (ret);
		}

		ret = sarc_create(&ott->ott_u.ott_dyn.ott_l3dhash,
		    OVERLAY_CACHE_SIZE, OVERLAY_HSIZE, &overlay_sarc_l3_ops,
		    sizeof (overlay_target_entry_t),
		    offsetof(overlay_target_entry_t, ote_reflink),
		    offsetof(overlay_target_entry_t, ote_u.ote_vl3), KM_SLEEP);
		if (ret != 0) {
			mutex_exit(&odd->odd_lock);
			sarc_destroy(ott->ott_u.ott_dyn.ott_dhash);
			kmem_cache_free(overlay_target_cache, ott);
			overlay_hold_rele(odd);
			return (ret);
		}

		avl_create(&ott->ott_u.ott_dyn.ott_tree, overlay_mac_avl,
		    sizeof (overlay_target_entry_t),
		    offsetof(overlay_target_entry_t, ote_avllink));
		avl_create(&ott->ott_u.ott_dyn.ott_l3tree, overlay_ip_avl,
		    sizeof (overlay_target_entry_t),
		    offsetof(overlay_target_entry_t, ote_avllink));
	}
	mutex_enter(&odd->odd_lock);
	if (odd->odd_flags & OVERLAY_F_VARPD) {
		mutex_exit(&odd->odd_lock);
		kmem_cache_free(overlay_target_cache, ott);
		overlay_hold_rele(odd);
		return (EEXIST);
	}

	odd->odd_flags |= OVERLAY_F_VARPD;
	odd->odd_target = ott;
	mutex_exit(&odd->odd_lock);

	overlay_hold_rele(odd);


	return (0);
}


/* ARGSUSED */
static int
overlay_target_degrade(overlay_target_hdl_t *thdl, void *arg)
{
	overlay_dev_t *odd;
	overlay_targ_degrade_t *otd = arg;

	odd = overlay_hold_by_dlid(otd->otd_linkid);
	if (odd == NULL)
		return (ENOENT);

	overlay_fm_degrade(odd, otd->otd_buf);
	overlay_hold_rele(odd);
	return (0);
}

/* ARGSUSED */
static int
overlay_target_restore(overlay_target_hdl_t *thdl, void *arg)
{
	overlay_dev_t *odd;
	overlay_targ_id_t *otid = arg;

	odd = overlay_hold_by_dlid(otid->otid_linkid);
	if (odd == NULL)
		return (ENOENT);

	overlay_fm_restore(odd);
	overlay_hold_rele(odd);
	return (0);
}

/* ARGSUSED */
static int
overlay_target_disassociate(overlay_target_hdl_t *thdl, void *arg)
{
	overlay_dev_t *odd;
	overlay_targ_id_t *otid = arg;

	odd = overlay_hold_by_dlid(otid->otid_linkid);
	if (odd == NULL)
		return (ENOENT);

	mutex_enter(&odd->odd_lock);
	odd->odd_flags &= ~OVERLAY_F_VARPD;
	mutex_exit(&odd->odd_lock);

	overlay_hold_rele(odd);
	return (0);

}

static int
overlay_target_lookup_request(overlay_target_hdl_t *thdl, void *arg)
{
	overlay_targ_lookup_t *otl = arg;
	overlay_target_entry_t *entry;
	clock_t ret, timeout;
	mac_header_info_t mhi;

	timeout = ddi_get_lbolt() + drv_usectohz(MICROSEC);
again:
	mutex_enter(&overlay_target_lock);
	while (list_is_empty(&overlay_target_list)) {
		ret = cv_timedwait(&overlay_target_condvar,
		    &overlay_target_lock, timeout);
		if (ret == -1) {
			mutex_exit(&overlay_target_lock);
			return (ETIME);
		}
	}
	entry = list_remove_head(&overlay_target_list);
	mutex_exit(&overlay_target_lock);
	mutex_enter(&entry->ote_lock);
	/*
	 * Router entries may send lookups to varpd even when valid.  For
	 * example, illumos systems will send unicast ARP queries to cached
	 * entries (including the router mac address).  To answer those, we
	 * need to forward on the query to varpd.  IPv6 will eventually
	 * need something similar for ND requests.
	 */
	if ((entry->ote_flags &
	    (OVERLAY_ENTRY_F_VALID|OVERLAY_ENTRY_F_ROUTER)) ==
	    OVERLAY_ENTRY_F_VALID) {
		ASSERT(entry->ote_chead == NULL);
		mutex_exit(&entry->ote_lock);
		goto again;
	}
	ASSERT(entry->ote_chead != NULL);

	/*
	 * If we have a bogon that doesn't have a valid mac header, drop it and
	 * try again.
	 */
	if (mac_vlan_header_info(entry->ote_odd->odd_mh, entry->ote_chead,
	    &mhi) != 0) {
		boolean_t queue = B_FALSE;
		mblk_t *mp = entry->ote_chead;
		entry->ote_chead = mp->b_next;
		mp->b_next = NULL;
		if (entry->ote_ctail == mp)
			entry->ote_ctail = entry->ote_chead;
		entry->ote_mbsize -= msgsize(mp);
		if (entry->ote_chead != NULL)
			queue = B_TRUE;
		mutex_exit(&entry->ote_lock);
		if (queue == B_TRUE)
			overlay_target_queue(entry);
		freemsg(mp);
		goto again;
	}

	otl->otl_dlid = entry->ote_odd->odd_linkid;
	otl->otl_reqid = (uintptr_t)entry;
	otl->otl_varpdid = entry->ote_ott->ott_id;
	otl->otl_vnetid = entry->ote_odd->odd_vid;

	otl->otl_hdrsize = mhi.mhi_hdrsize;
	otl->otl_pktsize = msgsize(entry->ote_chead) - otl->otl_hdrsize;
	if (entry->ote_flags & OVERLAY_ENTRY_F_VL3) {
		overlay_targ_l3_t *l3p = &otl->otl_addru.otlu_l3;

		otl->otl_l3req = B_TRUE;
		bcopy(&entry->ote_u.ote_vl3.otvl3_src, &l3p->otl3_srcip,
		    sizeof (struct in6_addr));
		bcopy(&entry->ote_u.ote_vl3.otvl3_dst, &l3p->otl3_dstip,
		    sizeof (struct in6_addr));
	} else {
		overlay_targ_l2_t *l2p = &otl->otl_addru.otlu_l2;

		otl->otl_l3req = B_FALSE;
		bcopy(mhi.mhi_daddr, l2p->otl2_dstaddr, ETHERADDRL);
		bcopy(mhi.mhi_saddr, l2p->otl2_srcaddr, ETHERADDRL);
		l2p->otl2_dsttype = mhi.mhi_dsttype;
		l2p->otl2_sap = mhi.mhi_bindsap;
	}
	otl->otl_vlan = VLAN_ID(mhi.mhi_tci);
	mutex_exit(&entry->ote_lock);

	mutex_enter(&thdl->oth_lock);
	list_insert_tail(&thdl->oth_outstanding, entry);
	mutex_exit(&thdl->oth_lock);

	return (0);
}

static void
overlay_target_lookup_respond_vl3(const overlay_targ_resp_t *otr,
    overlay_target_entry_t *entry)
{
	overlay_target_entry_t *shared = NULL;
	overlay_target_entry_t *vl2_entry;
	overlay_target_t *ott = entry->ote_ott;
	sarc_t *mhash = ott->ott_u.ott_dyn.ott_dhash;
	hrtime_t now = gethrtime();

	ASSERT(MUTEX_HELD(&entry->ote_lock));
	ASSERT(entry->ote_flags & OVERLAY_ENTRY_F_VL3);

	/*
	 * A cross-{vlan,dc,vnet} packet with a destination VL3 of an overlay
	 * router IP.  For now we drop these.
	 */
	if (entry->ote_flags & OVERLAY_ENTRY_F_ROUTER) {
		entry->ote_flags &= ~OVERLAY_ENTRY_F_PENDING;
		entry->ote_flags |= OVERLAY_ENTRY_F_DROP;
		return;
	}

	bcopy(&otr->otr_mac, &entry->ote_u.ote_vl3.otvl3_vl2,
	   sizeof (overlay_target_mac_t));

	mutex_enter(&ott->ott_lock);
	if ((shared = sarc_lookup(mhash, &otr->otr_mac)) != NULL)
		sarc_hold(mhash, shared);
	mutex_exit(&ott->ott_lock);

	/*
	 * Once we have the VL2 destination, we need to see if we already
	 * have an existing VL2 entry we can reuse.  If not, we create a
	 * fully-formed (i.e. valid) VL2 entry that we add to the cache.
	 */
	if (shared == NULL) {
		vl2_entry = kmem_cache_alloc(overlay_entry_cache,
		    KM_NOSLEEP | KM_NORMALPRI);
		if (vl2_entry == NULL) {
			/*
			 * If we can't allocate a VL2 entry for the VL3
			 * destination, we just give up for now and drain
			 * any queued packets.  New packets will retry this
			 * allocation, so if the memory pressure lets up, we
			 * should recover.
			 */
			freemsgchain(entry->ote_chead);
			entry->ote_chead = entry->ote_ctail = NULL;
			return;
		}

		vl2_entry->ote_ott = ott;
		vl2_entry->ote_odd = entry->ote_odd;

		bcopy(&otr->otr_answer, &vl2_entry->ote_u.ote_vl2.otvl2_dest,
		    sizeof (overlay_target_point_t));
		bcopy(&otr->otr_mac, &vl2_entry->ote_u.ote_vl2.otvl2_mac,
		    sizeof (overlay_target_mac_t));
		bcopy(&otr->otr_route, &vl2_entry->ote_u.ote_vl2.otvl2_route,
		    sizeof (overlay_target_route_t));
		vl2_entry->ote_flags =
		    OVERLAY_ENTRY_F_HAS_ROUTE | OVERLAY_ENTRY_F_VALID;
		vl2_entry->ote_vtime = entry->ote_vtime = now;

		mutex_enter(&ott->ott_lock);
		if ((shared = sarc_lookup(mhash, &otr->otr_mac)) != NULL) {
			overlay_target_entry_dtor(vl2_entry);
			kmem_cache_free(overlay_entry_cache, vl2_entry);
			sarc_hold(mhash, shared);

			vl2_entry = shared;
		} else {
			sarc_insert(mhash, vl2_entry);
			avl_add(&ott->ott_u.ott_dyn.ott_tree, vl2_entry);
			sarc_hold(mhash, vl2_entry);
		}
		mutex_exit(&ott->ott_lock);
	} else {
		vl2_entry = shared;
	}

	mutex_enter(&vl2_entry->ote_lock);
	if ((vl2_entry->ote_flags & (OVERLAY_ENTRY_F_HAS_ROUTE)) == 0) {
		bcopy(&otr->otr_route, &vl2_entry->ote_u.ote_vl2.otvl2_route,
		    sizeof (overlay_target_route_t));
		vl2_entry->ote_flags |= OVERLAY_ENTRY_F_HAS_ROUTE;
	}

	/*
	 * Update the VL2 entry if it doesn't have a valid destination. This
	 * can lead to a slightly strange corner case where an entry is both
	 * valid and pending (if there is still an outstanding VL2 request).
	 * In such a case, the VL2 response will just overwrite the destination
	 * with the same results and clear the pending flag.
	 */
	if ((vl2_entry->ote_flags & (OVERLAY_ENTRY_F_VALID)) == 0) {
		bcopy(&otr->otr_answer, &vl2_entry->ote_u.ote_vl2.otvl2_dest,
		    sizeof (overlay_target_point_t));
		vl2_entry->ote_vtime = gethrtime();
		vl2_entry->ote_flags |= OVERLAY_ENTRY_F_VALID;
	}
	mutex_exit(&vl2_entry->ote_lock);
}

static int
overlay_target_lookup_respond(overlay_target_hdl_t *thdl, void *arg)
{
	const overlay_targ_resp_t *otr = arg;
	overlay_target_entry_t *entry;
	mblk_t *mp;

	mutex_enter(&thdl->oth_lock);
	for (entry = list_head(&thdl->oth_outstanding); entry != NULL;
	    entry = list_next(&thdl->oth_outstanding, entry)) {
		if ((uintptr_t)entry == otr->otr_reqid)
			break;
	}

	if (entry == NULL) {
		mutex_exit(&thdl->oth_lock);
		return (EINVAL);
	}
	list_remove(&thdl->oth_outstanding, entry);
	mutex_exit(&thdl->oth_lock);

	mutex_enter(&entry->ote_lock);

	/*
	 * If we ever support a protocol that uses MAC addresses as the UL
	 * destination address, this check should probably include checking
	 * that otp_mac is also all zeros.
	 */
	if (IN6_IS_ADDR_UNSPECIFIED(&otr->otr_answer.otp_ip) &&
	    otr->otr_answer.otp_port == 0)
		entry->ote_flags |= OVERLAY_ENTRY_F_ROUTER;

	if ((entry->ote_flags & OVERLAY_ENTRY_F_VL3) == 0) {
		bcopy(&otr->otr_answer, &entry->ote_u.ote_vl2.otvl2_dest,
		    sizeof (overlay_target_point_t));
		entry->ote_vtime = gethrtime();
	} else {
		overlay_target_lookup_respond_vl3(otr, entry);
	}

	entry->ote_flags &= ~OVERLAY_ENTRY_F_PENDING;
	entry->ote_flags |= OVERLAY_ENTRY_F_VALID;

	mp = entry->ote_chead;
	entry->ote_chead = NULL;
	entry->ote_ctail = NULL;
	entry->ote_mbsize = 0;
	mutex_exit(&entry->ote_lock);

	/*
	 * For now do an in-situ drain.  For VL3 entries, if we re-use
	 * and existing VL2 entry, it is possible the VL2 lookup is still
	 * pending (though should be rare).  In such instances, the packets
	 * queued on the VL3 entry will get queued on the VL2 entry until
	 * the VL2 entry is resolved.
	 */
	mp = overlay_m_tx(entry->ote_odd, mp);
	freemsgchain(mp);

	mutex_enter(&entry->ote_ott->ott_lock);
	entry->ote_ott->ott_ocount--;
	cv_signal(&entry->ote_ott->ott_cond);
	mutex_exit(&entry->ote_ott->ott_lock);

	return (0);
}

static int
overlay_target_lookup_drop(overlay_target_hdl_t *thdl, void *arg)
{
	const overlay_targ_resp_t *otr = arg;
	overlay_target_entry_t *entry;
	mblk_t *mp;
	boolean_t queue = B_FALSE;

	mutex_enter(&thdl->oth_lock);
	for (entry = list_head(&thdl->oth_outstanding); entry != NULL;
	    entry = list_next(&thdl->oth_outstanding, entry)) {
		if ((uintptr_t)entry == otr->otr_reqid)
			break;
	}

	if (entry == NULL) {
		mutex_exit(&thdl->oth_lock);
		return (EINVAL);
	}
	list_remove(&thdl->oth_outstanding, entry);
	mutex_exit(&thdl->oth_lock);

	mutex_enter(&entry->ote_lock);

	/* Safeguard against a confused varpd */
	if (entry->ote_flags & OVERLAY_ENTRY_F_VALID) {
		entry->ote_flags &= ~OVERLAY_ENTRY_F_PENDING;
		DTRACE_PROBE1(overlay__target__valid__drop,
		    overlay_target_entry_t *, entry);
		mutex_exit(&entry->ote_lock);
		goto done;
	}

	mp = entry->ote_chead;
	if (mp != NULL) {
		entry->ote_chead = mp->b_next;
		mp->b_next = NULL;
		if (entry->ote_ctail == mp)
			entry->ote_ctail = entry->ote_chead;
		entry->ote_mbsize -= msgsize(mp);
	}
	if (entry->ote_chead != NULL) {
		queue = B_TRUE;
		entry->ote_flags |= OVERLAY_ENTRY_F_PENDING;
	} else {
		entry->ote_flags &= ~OVERLAY_ENTRY_F_PENDING;
	}
	mutex_exit(&entry->ote_lock);

	if (queue == B_TRUE)
		overlay_target_queue(entry);
	freemsg(mp);

done:
	mutex_enter(&entry->ote_ott->ott_lock);
	entry->ote_ott->ott_ocount--;
	cv_signal(&entry->ote_ott->ott_cond);
	mutex_exit(&entry->ote_ott->ott_lock);

	return (0);
}

/* ARGSUSED */
static int
overlay_target_pkt_copyin(const void *ubuf, void **outp, size_t *bsize,
    int flags)
{
	overlay_targ_pkt_t *pkt;
	overlay_targ_pkt32_t *pkt32;

	pkt = kmem_alloc(sizeof (overlay_targ_pkt_t), KM_SLEEP);
	*outp = pkt;
	*bsize = sizeof (overlay_targ_pkt_t);
	if (ddi_model_convert_from(flags & FMODELS) == DDI_MODEL_ILP32) {
		uintptr_t addr;

		if (ddi_copyin(ubuf, pkt, sizeof (overlay_targ_pkt32_t),
		    flags & FKIOCTL) != 0) {
			kmem_free(pkt, *bsize);
			return (EFAULT);
		}
		pkt32 = (overlay_targ_pkt32_t *)pkt;
		addr = pkt32->otp_buf;
		pkt->otp_buf = (void *)addr;
	} else {
		if (ddi_copyin(ubuf, pkt, *bsize, flags & FKIOCTL) != 0) {
			kmem_free(pkt, *bsize);
			return (EFAULT);
		}
	}
	return (0);
}

static int
overlay_target_pkt_copyout(void *ubuf, void *buf, size_t bufsize,
    int flags)
{
	if (ddi_model_convert_from(flags & FMODELS) == DDI_MODEL_ILP32) {
		overlay_targ_pkt_t *pkt = buf;
		overlay_targ_pkt32_t *pkt32 = buf;
		uintptr_t addr = (uintptr_t)pkt->otp_buf;
		pkt32->otp_buf = (caddr32_t)addr;
		if (ddi_copyout(buf, ubuf, sizeof (overlay_targ_pkt32_t),
		    flags & FKIOCTL) != 0)
			return (EFAULT);
	} else {
		if (ddi_copyout(buf, ubuf, bufsize, flags & FKIOCTL) != 0)
			return (EFAULT);
	}
	return (0);
}

static int
overlay_target_packet(overlay_target_hdl_t *thdl, void *arg)
{
	overlay_targ_pkt_t *pkt = arg;
	overlay_target_entry_t *entry;
	mblk_t *mp;
	size_t mlen;
	size_t boff;

	mutex_enter(&thdl->oth_lock);
	for (entry = list_head(&thdl->oth_outstanding); entry != NULL;
	    entry = list_next(&thdl->oth_outstanding, entry)) {
		if ((uintptr_t)entry == pkt->otp_reqid)
			break;
	}

	if (entry == NULL) {
		mutex_exit(&thdl->oth_lock);
		return (EINVAL);
	}
	mutex_enter(&entry->ote_lock);
	mutex_exit(&thdl->oth_lock);
	mp = entry->ote_chead;
	/* Protect against a rogue varpd */
	if (mp == NULL) {
		mutex_exit(&entry->ote_lock);
		return (EINVAL);
	}
	mlen = MIN(msgsize(mp), pkt->otp_size);
	pkt->otp_size = mlen;
	boff = 0;
	while (mlen > 0) {
		size_t wlen = MIN(MBLKL(mp), mlen);
		if (ddi_copyout(mp->b_rptr,
		    (void *)((uintptr_t)pkt->otp_buf + boff),
		    wlen, 0) != 0) {
			mutex_exit(&entry->ote_lock);
			return (EFAULT);
		}
		mlen -= wlen;
		boff += wlen;
		mp = mp->b_cont;
	}
	mutex_exit(&entry->ote_lock);
	return (0);
}

static int
overlay_target_inject(overlay_target_hdl_t *thdl, void *arg)
{
	overlay_targ_pkt_t *pkt = arg;
	overlay_target_entry_t *entry;
	overlay_dev_t *odd;
	mblk_t *mp;

	if (pkt->otp_size > ETHERMAX + VLAN_TAGSZ)
		return (EINVAL);

	mp = allocb(pkt->otp_size, 0);
	if (mp == NULL)
		return (ENOMEM);

	if (ddi_copyin(pkt->otp_buf, mp->b_rptr, pkt->otp_size, 0) != 0) {
		freeb(mp);
		return (EFAULT);
	}
	mp->b_wptr += pkt->otp_size;

	if (pkt->otp_linkid != UINT64_MAX) {
		odd = overlay_hold_by_dlid(pkt->otp_linkid);
		if (odd == NULL) {
			freeb(mp);
			return (ENOENT);
		}
	} else {
		mutex_enter(&thdl->oth_lock);
		for (entry = list_head(&thdl->oth_outstanding); entry != NULL;
		    entry = list_next(&thdl->oth_outstanding, entry)) {
			if ((uintptr_t)entry == pkt->otp_reqid)
				break;
		}

		if (entry == NULL) {
			mutex_exit(&thdl->oth_lock);
			freeb(mp);
			return (ENOENT);
		}
		odd = entry->ote_odd;
		mutex_exit(&thdl->oth_lock);
	}

	mutex_enter(&odd->odd_lock);
	overlay_io_start(odd, OVERLAY_F_IN_RX);
	mutex_exit(&odd->odd_lock);

	mac_rx(odd->odd_mh, NULL, mp);

	mutex_enter(&odd->odd_lock);
	overlay_io_done(odd, OVERLAY_F_IN_RX);
	mutex_exit(&odd->odd_lock);

	return (0);
}

static int
overlay_target_resend(overlay_target_hdl_t *thdl, void *arg)
{
	overlay_targ_pkt_t *pkt = arg;
	overlay_target_entry_t *entry;
	overlay_dev_t *odd;
	mblk_t *mp;

	if (pkt->otp_size > ETHERMAX + VLAN_TAGSZ)
		return (EINVAL);

	mp = allocb(pkt->otp_size, 0);
	if (mp == NULL)
		return (ENOMEM);

	if (ddi_copyin(pkt->otp_buf, mp->b_rptr, pkt->otp_size, 0) != 0) {
		freeb(mp);
		return (EFAULT);
	}
	mp->b_wptr += pkt->otp_size;

	if (pkt->otp_linkid != UINT64_MAX) {
		odd = overlay_hold_by_dlid(pkt->otp_linkid);
		if (odd == NULL) {
			freeb(mp);
			return (ENOENT);
		}
	} else {
		mutex_enter(&thdl->oth_lock);
		for (entry = list_head(&thdl->oth_outstanding); entry != NULL;
		    entry = list_next(&thdl->oth_outstanding, entry)) {
			if ((uintptr_t)entry == pkt->otp_reqid)
				break;
		}

		if (entry == NULL) {
			mutex_exit(&thdl->oth_lock);
			freeb(mp);
			return (ENOENT);
		}
		odd = entry->ote_odd;
		mutex_exit(&thdl->oth_lock);
	}

	mp = overlay_m_tx(odd, mp);
	freemsgchain(mp);

	return (0);
}

typedef struct overlay_targ_list_int {
	boolean_t	otli_count;
	uint32_t	otli_cur;
	uint32_t	otli_nents;
	uint32_t	otli_ents[];
} overlay_targ_list_int_t;

static int
overlay_target_list_copyin(const void *ubuf, void **outp, size_t *bsize,
    int flags)
{
	overlay_targ_list_t n;
	overlay_targ_list_int_t *otl;

	if (ddi_copyin(ubuf, &n, sizeof (overlay_targ_list_t),
	    flags & FKIOCTL) != 0)
		return (EFAULT);

	/*
	 */
	if (n.otl_nents >= INT32_MAX / sizeof (uint32_t))
		return (EINVAL);
	*bsize = sizeof (overlay_targ_list_int_t) +
	    sizeof (uint32_t) * n.otl_nents;
	otl = kmem_zalloc(*bsize, KM_SLEEP);
	otl->otli_cur = 0;
	otl->otli_nents = n.otl_nents;
	if (otl->otli_nents != 0) {
		otl->otli_count = B_FALSE;
		if (ddi_copyin((void *)((uintptr_t)ubuf +
		    offsetof(overlay_targ_list_t, otl_ents)),
		    otl->otli_ents, n.otl_nents * sizeof (uint32_t),
		    flags & FKIOCTL) != 0) {
			kmem_free(otl, *bsize);
			return (EFAULT);
		}
	} else {
		otl->otli_count = B_TRUE;
	}

	*outp = otl;
	return (0);
}

static int
overlay_target_ioctl_list_cb(overlay_dev_t *odd, void *arg)
{
	overlay_targ_list_int_t *otl = arg;

	if (otl->otli_cur < otl->otli_nents)
		otl->otli_ents[otl->otli_cur] = odd->odd_linkid;
	otl->otli_cur++;
	return (0);
}

/* ARGSUSED */
static int
overlay_target_ioctl_list(overlay_target_hdl_t *thdl, void *arg)
{
	overlay_dev_iter(overlay_target_ioctl_list_cb, arg);
	return (0);
}

/* ARGSUSED */
static int
overlay_target_list_copyout(void *ubuf, void *buf, size_t bufsize, int flags)
{
	overlay_targ_list_int_t *otl = buf;

	if (ddi_copyout(&otl->otli_cur, ubuf, sizeof (uint32_t),
	    flags & FKIOCTL) != 0)
		return (EFAULT);

	if (otl->otli_count == B_FALSE) {
		if (ddi_copyout(otl->otli_ents,
		    (void *)((uintptr_t)ubuf +
		    offsetof(overlay_targ_list_t, otl_ents)),
		    sizeof (uint32_t) * otl->otli_nents,
		    flags & FKIOCTL) != 0)
			return (EFAULT);
	}
	return (0);
}

/* ARGSUSED */
static int
overlay_target_cache_get(overlay_target_hdl_t *thdl, void *arg)
{
	int ret = 0;
	overlay_dev_t *odd;
	overlay_target_t *ott;
	overlay_targ_cache_t *otc = arg;

	odd = overlay_hold_by_dlid(otc->otc_linkid);
	if (odd == NULL)
		return (ENOENT);

	mutex_enter(&odd->odd_lock);
	if (!(odd->odd_flags & OVERLAY_F_VARPD)) {
		mutex_exit(&odd->odd_lock);
		overlay_hold_rele(odd);
		return (ENXIO);
	}
	ott = odd->odd_target;
	if (ott->ott_mode != OVERLAY_TARGET_POINT &&
	    ott->ott_mode != OVERLAY_TARGET_DYNAMIC) {
		mutex_exit(&odd->odd_lock);
		overlay_hold_rele(odd);
		return (ENOTSUP);
	}
	mutex_enter(&ott->ott_lock);
	mutex_exit(&odd->odd_lock);

	if (ott->ott_mode == OVERLAY_TARGET_POINT) {
		otc->otc_entry.otce_flags = 0;
		bcopy(&ott->ott_u.ott_point, &otc->otc_entry.otce_dest,
		    sizeof (overlay_target_point_t));
	} else {
		overlay_target_entry_t *ote;

		if ((ote = sarc_lookup(ott->ott_u.ott_dyn.ott_dhash,
		    &otc->otc_entry.otce_mac)) == NULL) {
			ret = ENOENT;
			goto done;
		}

		mutex_enter(&ote->ote_lock);
		if ((ote->ote_flags & OVERLAY_ENTRY_F_VALID_MASK) != 0) {
			if (ote->ote_flags & OVERLAY_ENTRY_F_DROP) {
				otc->otc_entry.otce_flags =
				    OVERLAY_TARGET_CACHE_DROP;
			} else if (ote->ote_flags & OVERLAY_ENTRY_F_ROUTER) {
				otc->otc_entry.otce_flags =
				    OVERLAY_TARGET_CACHE_ROUTER;
			} else {
				otc->otc_entry.otce_flags = 0;
				bcopy(&ote->ote_u.ote_vl2.otvl2_dest,
				    &otc->otc_entry.otce_dest,
				    sizeof (overlay_target_point_t));
			}
			ret = 0;
		} else {
			ret = ENOENT;
		}
		mutex_exit(&ote->ote_lock);
	}

done:
	mutex_exit(&ott->ott_lock);
	overlay_hold_rele(odd);

	return (ret);
}

/* ARGSUSED */
static int
overlay_target_cache_set(overlay_target_hdl_t *thdl, void *arg)
{
	overlay_dev_t *odd;
	overlay_target_t *ott;
	overlay_target_entry_t *ote, *new = NULL;
	overlay_targ_cache_t *otc = arg;
	mblk_t *mp = NULL;

	if (otc->otc_entry.otce_flags &
	    ~(OVERLAY_TARGET_CACHE_DROP | OVERLAY_TARGET_CACHE_ROUTER))
		return (EINVAL);

	if (otc->otc_entry.otce_flags ==
	    (OVERLAY_TARGET_CACHE_DROP | OVERLAY_TARGET_CACHE_ROUTER))
		return (EINVAL);

	odd = overlay_hold_by_dlid(otc->otc_linkid);
	if (odd == NULL)
		return (ENOENT);

	/*
	 * Optimistically create the new entry.  If not needed, we'll free it.
	 * We shouldn't be calling this ioctl rapidly enough that any potential
	 * alloc/free churn should cause a problem.
	 */
	new = kmem_cache_alloc(overlay_entry_cache, KM_SLEEP);
	bcopy(&otc->otc_entry.otce_mac, &new->ote_u.ote_vl2.otvl2_mac,
	    sizeof (overlay_target_mac_t));

	mutex_enter(&odd->odd_lock);
	if (!(odd->odd_flags & OVERLAY_F_VARPD)) {
		mutex_exit(&odd->odd_lock);
		overlay_hold_rele(odd);
		overlay_target_entry_dtor(new);
		return (ENXIO);
	}
	ott = odd->odd_target;
	if (ott->ott_mode != OVERLAY_TARGET_DYNAMIC) {
		mutex_exit(&odd->odd_lock);
		overlay_hold_rele(odd);
		overlay_target_entry_dtor(new);
		return (ENOTSUP);
	}

	new->ote_ott = ott;
	new->ote_odd = odd;

	mutex_enter(&ott->ott_lock);
	mutex_exit(&odd->odd_lock);

	if ((ote = sarc_lookup(ott->ott_u.ott_dyn.ott_dhash,
	    &otc->otc_entry.otce_mac)) == NULL)
		ote = new;

	mutex_enter(&ote->ote_lock);
	if (otc->otc_entry.otce_flags & OVERLAY_TARGET_CACHE_DROP) {
		ote->ote_flags |= OVERLAY_ENTRY_F_DROP;
	} else {
		ote->ote_flags |= OVERLAY_ENTRY_F_VALID;
		if (otc->otc_entry.otce_flags & OVERLAY_TARGET_CACHE_ROUTER)
			ote->ote_flags |= OVERLAY_ENTRY_F_ROUTER;
		bcopy(&otc->otc_entry.otce_dest, &ote->ote_u.ote_vl2.otvl2_dest,
		    sizeof (overlay_target_point_t));
		mp = ote->ote_chead;
		ote->ote_chead = NULL;
		ote->ote_ctail = NULL;
		ote->ote_mbsize = 0;
		ote->ote_vtime = gethrtime();
	}

	if (ote == new) {
		sarc_insert(ott->ott_u.ott_dyn.ott_dhash, ote);
		avl_add(&ott->ott_u.ott_dyn.ott_tree, ote);
	}
	mutex_exit(&ote->ote_lock);
	mutex_exit(&ott->ott_lock);

	if (mp != NULL) {
		mp = overlay_m_tx(ote->ote_odd, mp);
		freemsgchain(mp);
	}

	overlay_hold_rele(odd);

	if (ote != new)
		overlay_target_entry_dtor(new);

	return (0);
}

/* ARGSUSED */
static int
overlay_target_cache_remove(overlay_target_hdl_t *thdl, void *arg)
{
	int ret = 0;
	overlay_dev_t *odd;
	overlay_target_t *ott;
	overlay_target_entry_t *ote;
	overlay_targ_cache_t *otc = arg;

	odd = overlay_hold_by_dlid(otc->otc_linkid);
	if (odd == NULL)
		return (ENOENT);

	mutex_enter(&odd->odd_lock);
	if (!(odd->odd_flags & OVERLAY_F_VARPD)) {
		mutex_exit(&odd->odd_lock);
		overlay_hold_rele(odd);
		return (ENXIO);
	}
	ott = odd->odd_target;
	if (ott->ott_mode != OVERLAY_TARGET_DYNAMIC) {
		mutex_exit(&odd->odd_lock);
		overlay_hold_rele(odd);
		return (ENOTSUP);
	}
	mutex_enter(&ott->ott_lock);
	mutex_exit(&odd->odd_lock);

	if (otc->otc_entry.otce_mac.otm_dcid == 0)
		otc->otc_entry.otce_mac.otm_dcid = odd->odd_dcid;

	ote = sarc_lookup(ott->ott_u.ott_dyn.ott_dhash,
	    &otc->otc_entry.otce_mac);
	if (ote != NULL) {
		mutex_enter(&ote->ote_lock);
		ote->ote_flags &= ~OVERLAY_ENTRY_F_VALID_MASK;
		mutex_exit(&ote->ote_lock);
		ret = 0;
	} else {
		ret = ENOENT;
	}

	mutex_exit(&ott->ott_lock);
	overlay_hold_rele(odd);

	return (ret);
}

/* ARGSUSED */
static int
overlay_target_cache_flush(overlay_target_hdl_t *thdl, void *arg)
{
	avl_tree_t *avl;
	overlay_dev_t *odd;
	overlay_target_t *ott;
	overlay_target_entry_t *ote;
	overlay_targ_cache_t *otc = arg;

	odd = overlay_hold_by_dlid(otc->otc_linkid);
	if (odd == NULL)
		return (ENOENT);

	mutex_enter(&odd->odd_lock);
	if (!(odd->odd_flags & OVERLAY_F_VARPD)) {
		mutex_exit(&odd->odd_lock);
		overlay_hold_rele(odd);
		return (ENXIO);
	}
	ott = odd->odd_target;
	if (ott->ott_mode != OVERLAY_TARGET_DYNAMIC) {
		mutex_exit(&odd->odd_lock);
		overlay_hold_rele(odd);
		return (ENOTSUP);
	}
	mutex_enter(&ott->ott_lock);
	mutex_exit(&odd->odd_lock);
	avl = &ott->ott_u.ott_dyn.ott_tree;

	for (ote = avl_first(avl); ote != NULL; ote = AVL_NEXT(avl, ote)) {
		mutex_enter(&ote->ote_lock);
		ote->ote_flags &= ~OVERLAY_ENTRY_F_VALID_MASK;
		mutex_exit(&ote->ote_lock);
	}

	avl = &ott->ott_u.ott_dyn.ott_l3tree;
	for (ote = avl_first(avl); ote != NULL; ote = AVL_NEXT(avl, ote)) {
		mutex_enter(&ote->ote_lock);
		ote->ote_flags &= ~OVERLAY_ENTRY_F_VALID_MASK;
		mutex_exit(&ote->ote_lock);
	}

	mutex_exit(&ott->ott_lock);
	overlay_hold_rele(odd);

	return (0);
}

static int
overlay_target_cache_iter_copyin(const void *ubuf, void **outp, size_t *bsize,
    int flags)
{
	overlay_targ_cache_iter_t base, *iter;

	if (ddi_copyin(ubuf, &base, sizeof (overlay_targ_cache_iter_t),
	    flags & FKIOCTL) != 0)
		return (EFAULT);

	if (base.otci_count > OVERLAY_TARGET_ITER_MAX)
		return (E2BIG);

	if (base.otci_count == 0)
		return (EINVAL);

	*bsize = sizeof (overlay_targ_cache_iter_t) +
	    base.otci_count * sizeof (overlay_targ_cache_entry_t);
	iter = kmem_alloc(*bsize, KM_SLEEP);
	bcopy(&base, iter, sizeof (overlay_targ_cache_iter_t));
	*outp = iter;

	return (0);
}

typedef struct overlay_targ_cache_marker {
	overlay_target_mac_t otcm_mac;
	uint16_t	otcm_done;
} overlay_targ_cache_marker_t __aligned(8);
CTASSERT(sizeof (overlay_targ_cache_marker_t) == 2 * sizeof (uint64_t));

/* ARGSUSED */
static int
overlay_target_cache_iter(overlay_target_hdl_t *thdl, void *arg)
{
	overlay_dev_t *odd;
	overlay_target_t *ott;
	overlay_target_entry_t lookup, *ent;
	overlay_targ_cache_marker_t *mark;
	avl_index_t where;
	avl_tree_t *avl;
	uint16_t written = 0;

	overlay_targ_cache_iter_t *iter = arg;
	mark = (void *)&iter->otci_marker;

	if (mark->otcm_done != 0) {
		iter->otci_count = 0;
		return (0);
	}

	odd = overlay_hold_by_dlid(iter->otci_linkid);
	if (odd == NULL)
		return (ENOENT);

	mutex_enter(&odd->odd_lock);
	if (!(odd->odd_flags & OVERLAY_F_VARPD)) {
		mutex_exit(&odd->odd_lock);
		overlay_hold_rele(odd);
		return (ENXIO);
	}
	ott = odd->odd_target;
	if (ott->ott_mode != OVERLAY_TARGET_DYNAMIC &&
	    ott->ott_mode != OVERLAY_TARGET_POINT) {
		mutex_exit(&odd->odd_lock);
		overlay_hold_rele(odd);
		return (ENOTSUP);
	}

	/*
	 * Holding this lock across the entire iteration probably isn't very
	 * good. We should perhaps add an r/w lock for the avl tree. But we'll
	 * wait until we now it's necessary before we do more.
	 */
	mutex_enter(&ott->ott_lock);
	mutex_exit(&odd->odd_lock);

	if (ott->ott_mode == OVERLAY_TARGET_POINT) {
		overlay_targ_cache_entry_t *out = &iter->otci_ents[0];
		bzero(&out->otce_mac, sizeof (out->otce_mac));
		out->otce_flags = 0;
		bcopy(&ott->ott_u.ott_point, &out->otce_dest,
		    sizeof (overlay_target_point_t));
		written++;
		mark->otcm_done = 1;
	}

	avl = &ott->ott_u.ott_dyn.ott_tree;
	lookup.ote_u.ote_vl2.otvl2_mac.otm_dcid = odd->odd_dcid;
	bcopy(&mark->otcm_mac, &lookup.ote_u.ote_vl2.otvl2_mac,
	    sizeof (mark->otcm_mac));
	ent = avl_find(avl, &lookup, &where);

	/*
	 * NULL ent means that the entry does not exist, so we want to start
	 * with the closest node in the tree. This means that we implicitly rely
	 * on the tree's order and the first node will be the mac 00:00:00:00:00
	 * and the last will be ff:ff:ff:ff:ff:ff.
	 */
	if (ent == NULL) {
		ent = avl_nearest(avl, where, AVL_AFTER);
		if (ent == NULL) {
			mark->otcm_done = 1;
			goto done;
		}
	}

	for (; ent != NULL && written < iter->otci_count;
	    ent = AVL_NEXT(avl, ent)) {
		overlay_targ_cache_entry_t *out = &iter->otci_ents[written];
		mutex_enter(&ent->ote_lock);
		if ((ent->ote_flags & OVERLAY_ENTRY_F_VALID_MASK) == 0) {
			mutex_exit(&ent->ote_lock);
			continue;
		}
		bcopy(&ent->ote_u.ote_vl2.otvl2_mac, &out->otce_mac,
		    sizeof (out->otce_mac));
		out->otce_flags = 0;
		if (ent->ote_flags & OVERLAY_ENTRY_F_DROP)
			out->otce_flags |= OVERLAY_TARGET_CACHE_DROP;
		if (ent->ote_flags & OVERLAY_ENTRY_F_VALID)
			bcopy(&ent->ote_u.ote_vl2.otvl2_dest, &out->otce_dest,
			    sizeof (overlay_target_point_t));
		written++;
		mutex_exit(&ent->ote_lock);
	}

	if (ent != NULL) {
		bcopy(&ent->ote_u.ote_vl2.otvl2_mac, &mark->otcm_mac,
		    sizeof (mark->otcm_mac));
	} else {
		mark->otcm_done = 1;
	}

done:
	iter->otci_count = written;
	mutex_exit(&ott->ott_lock);
	overlay_hold_rele(odd);

	return (0);
}

/* ARGSUSED */
static int
overlay_target_cache_iter_copyout(void *ubuf, void *buf, size_t bufsize,
    int flags)
{
	size_t outsize;
	const overlay_targ_cache_iter_t *iter = buf;

	outsize = sizeof (overlay_targ_cache_iter_t) +
	    iter->otci_count * sizeof (overlay_targ_cache_entry_t);

	if (ddi_copyout(buf, ubuf, outsize, flags & FKIOCTL) != 0)
		return (EFAULT);

	return (0);
}

/* ARGSUSED */
static int
overlay_target_cache_remove_net(overlay_target_hdl_t *thdl, void *arg)
{
	overlay_targ_cache_net_t *otcn = arg;
	overlay_targ_cache_net_entry_t *otcne = &otcn->otcn_entry;
	overlay_dev_t *odd = NULL;
	overlay_target_t *ott = NULL;
	overlay_target_entry_t *ote = NULL, *ote_next = NULL;
	avl_tree_t *avl = NULL;
	avl_index_t where = { 0 };
	overlay_target_vl3_t cmp = { 0 };

	odd = overlay_hold_by_dlid(otcn->otcn_linkid);
	if (odd == NULL)
		return (ENOENT);

	cmp.otvl3_src_vlan = otcne->otcne_vlan;

	/*
	 * A bit ugly, but as explained below, these need to be the network
	 * addresses for the src/dst subnets.
	 */
	cmp.otvl3_src._S6_un._S6_u32[0] = otcne->otcne_src._S6_un._S6_u32[0] &
	    IN6_MASK_FROM_PREFIX(0, otcne->otcne_src_prefixlen);
	cmp.otvl3_src._S6_un._S6_u32[1] = otcne->otcne_src._S6_un._S6_u32[1] &
	    IN6_MASK_FROM_PREFIX(1, otcne->otcne_src_prefixlen);
	cmp.otvl3_src._S6_un._S6_u32[2] = otcne->otcne_src._S6_un._S6_u32[2] &
	    IN6_MASK_FROM_PREFIX(2, otcne->otcne_src_prefixlen);
	cmp.otvl3_src._S6_un._S6_u32[3] = otcne->otcne_src._S6_un._S6_u32[3] &
	    IN6_MASK_FROM_PREFIX(3, otcne->otcne_src_prefixlen);

	cmp.otvl3_dst._S6_un._S6_u32[0] = otcne->otcne_dst._S6_un._S6_u32[0] &
	    IN6_MASK_FROM_PREFIX(0, otcne->otcne_dst_prefixlen);
	cmp.otvl3_dst._S6_un._S6_u32[1] = otcne->otcne_dst._S6_un._S6_u32[1] &
	    IN6_MASK_FROM_PREFIX(1, otcne->otcne_dst_prefixlen);
	cmp.otvl3_dst._S6_un._S6_u32[2] = otcne->otcne_dst._S6_un._S6_u32[2] &
	    IN6_MASK_FROM_PREFIX(2, otcne->otcne_dst_prefixlen);
	cmp.otvl3_dst._S6_un._S6_u32[3] = otcne->otcne_dst._S6_un._S6_u32[3] &
	    IN6_MASK_FROM_PREFIX(3, otcne->otcne_dst_prefixlen);

	mutex_enter(&odd->odd_lock);
	if (!(odd->odd_flags & OVERLAY_F_VARPD)) {
		mutex_exit(&odd->odd_lock);
		overlay_hold_rele(odd);
		return (ENXIO);
	}
	ott = odd->odd_target;
	if (ott->ott_mode != OVERLAY_TARGET_DYNAMIC) {
		mutex_exit(&odd->odd_lock);
		overlay_hold_rele(odd);
		return (ENOTSUP);
	}
	mutex_enter(&ott->ott_lock);
	mutex_exit(&odd->odd_lock);
	avl = &ott->ott_u.ott_dyn.ott_l3tree;

	/*
	 * For deleting all the entries between two networks, we first locate
	 * the entry just before the given net addresses.  VL3 target entries
	 * are sorted by <src ip, dst ip, src vlan>, so the subnet address
	 * (i.e. 192.168.1.0) will always sort before any addresses within
	 * the subnet.  Therefore, the entry just before where the subnet
	 * addresses would go the entry that immediately preceeds any
	 * potential matching entries (note that we should never actually
	 * have the subnet addresses stored as target entries as that would
	 * not make any sense).  We find the entry immediately before where
	 * any potential entries are (or if NULL, that means any potential
	 * matches would be the first entries when sorted), then start
	 * iterating through the subsequent entries until we either exhaust
	 * all our entries, or find an entry no longer in range.  The latter
	 * indicating we've iterated all potential matches.
	 */

	/*
	 * Find where the network address would be in the tree, but should
	 * never actually see them in the tree.
	 */
	VERIFY3P(avl_find(avl, &cmp, &where), ==, NULL);

	ote = avl_nearest(avl, where, AVL_BEFORE);
	if (ote == NULL)
		ote = avl_first(avl);
	else
		ote = AVL_NEXT(avl, ote);

#define	IN_RANGE(_ote, _otcne)						\
    (IN6_ARE_PREFIXEDADDR_EQUAL(&(_ote)->ote_u.ote_vl3.otvl3_src,	\
    &(_otcne)->otcne_src, (_otcne)->otcne_src_prefixlen) &&		\
    IN6_ARE_PREFIXEDADDR_EQUAL(&(_ote)->ote_u.ote_vl3.otvl3_dst,	\
    &(_otcne)->otcne_dst, (_otcne)->otcne_dst_prefixlen) &&		\
    (_ote)->ote_u.ote_vl3.otvl3_src_vlan == (_otcne)->otcne_vlan)

	while (ote != NULL && IN_RANGE(ote, otcne)) {
		ote_next = AVL_NEXT(avl, ote);
		sarc_remove(ott->ott_u.ott_dyn.ott_l3dhash, ote);
		ote = ote_next;
	}

#undef	IN_RANGE

	mutex_exit(&ott->ott_lock);
	overlay_hold_rele(odd);
	return (0);
}

static overlay_target_ioctl_t overlay_target_ioctab[] = {
	{ OVERLAY_TARG_INFO, B_TRUE, B_TRUE,
		NULL, overlay_target_info,
		NULL, sizeof (overlay_targ_info_t)	},
	{ OVERLAY_TARG_ASSOCIATE, B_TRUE, B_FALSE,
		NULL, overlay_target_associate,
		NULL, sizeof (overlay_targ_associate_t)	},
	{ OVERLAY_TARG_DISASSOCIATE, B_TRUE, B_FALSE,
		NULL, overlay_target_disassociate,
		NULL, sizeof (overlay_targ_id_t)	},
	{ OVERLAY_TARG_DEGRADE, B_TRUE, B_FALSE,
		NULL, overlay_target_degrade,
		NULL, sizeof (overlay_targ_degrade_t)	},
	{ OVERLAY_TARG_RESTORE, B_TRUE, B_FALSE,
		NULL, overlay_target_restore,
		NULL, sizeof (overlay_targ_id_t)	},
	{ OVERLAY_TARG_LOOKUP, B_FALSE, B_TRUE,
		NULL, overlay_target_lookup_request,
		NULL, sizeof (overlay_targ_lookup_t)	},
	{ OVERLAY_TARG_RESPOND, B_TRUE, B_FALSE,
		NULL, overlay_target_lookup_respond,
		NULL, sizeof (overlay_targ_resp_t)	},
	{ OVERLAY_TARG_DROP, B_TRUE, B_FALSE,
		NULL, overlay_target_lookup_drop,
		NULL, sizeof (overlay_targ_resp_t)	},
	{ OVERLAY_TARG_PKT, B_TRUE, B_TRUE,
		overlay_target_pkt_copyin,
		overlay_target_packet,
		overlay_target_pkt_copyout,
		sizeof (overlay_targ_pkt_t)		},
	{ OVERLAY_TARG_INJECT, B_TRUE, B_FALSE,
		overlay_target_pkt_copyin,
		overlay_target_inject,
		NULL, sizeof (overlay_targ_pkt_t)	},
	{ OVERLAY_TARG_RESEND, B_TRUE, B_FALSE,
		overlay_target_pkt_copyin,
		overlay_target_resend,
		NULL, sizeof (overlay_targ_pkt_t)	},
	{ OVERLAY_TARG_LIST, B_FALSE, B_TRUE,
		overlay_target_list_copyin,
		overlay_target_ioctl_list,
		overlay_target_list_copyout,
		sizeof (overlay_targ_list_t)		},
	{ OVERLAY_TARG_CACHE_GET, B_FALSE, B_TRUE,
		NULL, overlay_target_cache_get,
		NULL, sizeof (overlay_targ_cache_t)	},
	{ OVERLAY_TARG_CACHE_SET, B_TRUE, B_TRUE,
		NULL, overlay_target_cache_set,
		NULL, sizeof (overlay_targ_cache_t)	},
	{ OVERLAY_TARG_CACHE_REMOVE, B_TRUE, B_TRUE,
		NULL, overlay_target_cache_remove,
		NULL, sizeof (overlay_targ_cache_t)	},
	{ OVERLAY_TARG_CACHE_FLUSH, B_TRUE, B_TRUE,
		NULL, overlay_target_cache_flush,
		NULL, sizeof (overlay_targ_cache_t)	},
	{ OVERLAY_TARG_CACHE_ITER, B_FALSE, B_TRUE,
		overlay_target_cache_iter_copyin,
		overlay_target_cache_iter,
		overlay_target_cache_iter_copyout,
		sizeof (overlay_targ_cache_iter_t)		},
	{ OVERLAY_TARG_CACHE_REMOVE_NET, B_TRUE, B_TRUE,
		NULL, overlay_target_cache_remove_net,
		NULL, sizeof (overlay_targ_cache_net_t)	},
	{ 0 }
};

int
overlay_target_open(dev_t *devp, int flags, int otype, cred_t *credp)
{
	minor_t mid;
	overlay_target_hdl_t *thdl;

	if (secpolicy_dl_config(credp) != 0)
		return (EPERM);

	if (getminor(*devp) != 0)
		return (ENXIO);

	if (otype & OTYP_BLK)
		return (EINVAL);

	if (flags & ~(FREAD | FWRITE | FEXCL))
		return (EINVAL);

	if ((flags & FWRITE) &&
	    !(flags & FEXCL))
		return (EINVAL);

	if (!(flags & FREAD) && !(flags & FWRITE))
		return (EINVAL);

	if (crgetzoneid(credp) != GLOBAL_ZONEID)
		return (EPERM);

	mid = id_alloc(overlay_thdl_idspace);
	if (ddi_soft_state_zalloc(overlay_thdl_state, mid) != 0) {
		id_free(overlay_thdl_idspace, mid);
		return (ENXIO);
	}

	thdl = ddi_get_soft_state(overlay_thdl_state, mid);
	VERIFY(thdl != NULL);
	thdl->oth_minor = mid;
	thdl->oth_zoneid = crgetzoneid(credp);
	thdl->oth_oflags = flags;
	mutex_init(&thdl->oth_lock, NULL, MUTEX_DRIVER, NULL);
	list_create(&thdl->oth_outstanding, sizeof (overlay_target_entry_t),
	    offsetof(overlay_target_entry_t, ote_qlink));
	*devp = makedevice(getmajor(*devp), mid);

	mutex_enter(&overlay_target_lock);
	if ((flags & FEXCL) && overlay_target_excl == B_TRUE) {
		mutex_exit(&overlay_target_lock);
		list_destroy(&thdl->oth_outstanding);
		mutex_destroy(&thdl->oth_lock);
		ddi_soft_state_free(overlay_thdl_state, mid);
		id_free(overlay_thdl_idspace, mid);
		return (EEXIST);
	} else if ((flags & FEXCL) != 0) {
		VERIFY(overlay_target_excl == B_FALSE);
		overlay_target_excl = B_TRUE;
	}
	list_insert_tail(&overlay_thdl_list, thdl);
	mutex_exit(&overlay_target_lock);

	return (0);
}

/* ARGSUSED */
int
overlay_target_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rvalp)
{
	overlay_target_ioctl_t *ioc;
	overlay_target_hdl_t *thdl;

	if (secpolicy_dl_config(credp) != 0)
		return (EPERM);

	if ((thdl = ddi_get_soft_state(overlay_thdl_state,
	    getminor(dev))) == NULL)
		return (ENXIO);

	for (ioc = &overlay_target_ioctab[0]; ioc->oti_cmd != 0; ioc++) {
		int ret;
		caddr_t buf;
		size_t bufsize;

		if (ioc->oti_cmd != cmd)
			continue;

		if (ioc->oti_write == B_TRUE && !(mode & FWRITE))
			return (EBADF);

		if (ioc->oti_copyin == NULL) {
			bufsize = ioc->oti_size;
			buf = kmem_alloc(bufsize, KM_SLEEP);
			if (ddi_copyin((void *)(uintptr_t)arg, buf, bufsize,
			    mode & FKIOCTL) != 0) {
				kmem_free(buf, bufsize);
				return (EFAULT);
			}
		} else {
			if ((ret = ioc->oti_copyin((void *)(uintptr_t)arg,
			    (void **)&buf, &bufsize, mode)) != 0)
				return (ret);
		}

		ret = ioc->oti_func(thdl, buf);
		if (ret == 0 && ioc->oti_size != 0 &&
		    ioc->oti_ncopyout == B_TRUE) {
			if (ioc->oti_copyout == NULL) {
				if (ddi_copyout(buf, (void *)(uintptr_t)arg,
				    bufsize, mode & FKIOCTL) != 0)
					ret = EFAULT;
			} else {
				ret = ioc->oti_copyout((void *)(uintptr_t)arg,
				    buf, bufsize, mode);
			}
		}

		kmem_free(buf, bufsize);
		return (ret);
	}

	return (ENOTTY);
}

/* ARGSUSED */
int
overlay_target_close(dev_t dev, int flags, int otype, cred_t *credp)
{
	overlay_target_hdl_t *thdl;
	overlay_target_entry_t *entry;
	minor_t mid = getminor(dev);

	if ((thdl = ddi_get_soft_state(overlay_thdl_state, mid)) == NULL)
		return (ENXIO);

	mutex_enter(&overlay_target_lock);
	list_remove(&overlay_thdl_list, thdl);
	mutex_enter(&thdl->oth_lock);
	while ((entry = list_remove_head(&thdl->oth_outstanding)) != NULL)
		list_insert_tail(&overlay_target_list, entry);
	cv_signal(&overlay_target_condvar);
	mutex_exit(&thdl->oth_lock);
	if ((thdl->oth_oflags & FEXCL) != 0) {
		VERIFY(overlay_target_excl == B_TRUE);
		overlay_target_excl = B_FALSE;
	}
	mutex_exit(&overlay_target_lock);

	list_destroy(&thdl->oth_outstanding);
	mutex_destroy(&thdl->oth_lock);
	mid = thdl->oth_minor;
	ddi_soft_state_free(overlay_thdl_state, mid);
	id_free(overlay_thdl_idspace, mid);

	return (0);
}
