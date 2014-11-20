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
 * Copyright (c) 2014 Joyent, Inc.
 */

/*
 * This file encapsulates all of the logic for dealing with a given remote host
 * that is being used to service requests. Multiple different overlay devices
 * all share the same single device here.
 */

#include <umem.h>
#include <strings.h>
#include <string.h>
#include <stddef.h>
#include <thread.h>
#include <synch.h>
#include <assert.h>
#include <sys/socket.h>
#include <netdb.h>

#include <libvarpd_provider.h>
#include <libvarpd_svp.h>

mutex_t svp_remote_lock = DEFAULTMUTEX;
avl_tree_t svp_remote_tree;

static void
svp_remote_mkfmamsg(svp_remote_t *srp, svp_degrade_state_t state, char *buf,
    size_t buflen)
{
	switch (state) {
	case SVP_RD_DNS_FAIL:
		(void) snprintf(buf, buflen, "failed to resolve or find "
		    "entries for hostname %s", srp->sr_hostname);
		break;
	case SVP_RD_REMOTE_FAIL:
		(void) snprintf(buf, buflen, "cannot reach any remote peers");
		break;
	default:
		abort();
	}
}

static int
svp_remote_comparator(const void *l, const void *r)
{
	int ret;
	const svp_remote_t *lr = l, *rr = r;

	ret = strcmp(lr->sr_hostname, rr->sr_hostname);
	if (ret > 0)
		return (1);
	else if (ret < 0)
		return (-1);
	else
		return (0);
}

int
svp_remote_init(void)
{
	avl_create(&svp_remote_tree, svp_remote_comparator,
	    sizeof (svp_remote_t), offsetof(svp_remote_t, sr_gnode));
	return (0);
}

void
svp_remote_fini(void)
{
	avl_destroy(&svp_remote_tree);
}

static void
svp_remote_destroy(svp_remote_t *srp)
{
	size_t len;

	/*
	 * XXX Clean up DNS related information, eg. make sure we're not in the
	 * queue. Likely need a flag cv...
	 */

	if (mutex_destroy(&srp->sr_lock) != 0)
		abort();

	if (srp->sr_addrinfo != NULL)
		freeaddrinfo(srp->sr_addrinfo);
	len = strlen(srp->sr_hostname) + 1;
	umem_free(srp->sr_hostname, len);
	umem_free(srp, sizeof (svp_remote_t));
}

static int
svp_remote_create(const char *host, svp_remote_t **outp)
{
	size_t hlen;
	svp_remote_t *remote;

	assert(MUTEX_HELD(&svp_remote_lock));

	remote = umem_zalloc(sizeof (svp_remote_t), UMEM_DEFAULT);
	if (remote == NULL) {
		mutex_unlock(&svp_remote_lock);
		return (ENOMEM);
	}
	hlen = strlen(host) + 1;
	remote->sr_hostname = umem_alloc(hlen, UMEM_DEFAULT);
	if (remote->sr_hostname == NULL) {
		umem_free(remote, sizeof (svp_remote_t));
		mutex_unlock(&svp_remote_lock);
		return (ENOMEM);
	}
	if (mutex_init(&remote->sr_lock, USYNC_THREAD, NULL) != 0)
		abort();
	avl_create(&remote->sr_tree, svp_comparator, sizeof (svp_t),
	    offsetof(svp_t, svp_rlink));
	(void) strlcpy(remote->sr_hostname, host, hlen);
	remote->sr_count = 1;

	*outp = remote;
	return (0);
}

int
svp_remote_find(char *host, svp_remote_t **outp)
{
	int ret;
	svp_remote_t lookup, *remote;

	lookup.sr_hostname = host;
	mutex_lock(&svp_remote_lock);
	remote = avl_find(&svp_remote_tree, &lookup, NULL);
	if (remote != NULL) {
		assert(remote->sr_count > 0);
		remote->sr_count++;
		*outp = remote;
		mutex_unlock(&svp_remote_lock);
		return (0);
	}

	if ((ret = svp_remote_create(host, outp)) != 0) {
		mutex_unlock(&svp_remote_lock);
		return (ret);
	}

	avl_add(&svp_remote_tree, *outp);
	mutex_unlock(&svp_remote_lock);

	/* Make sure DNS is up to date */
	svp_host_queue(*outp);

	return (0);
}

void
svp_remote_release(svp_remote_t *srp)
{
	mutex_lock(&svp_remote_lock);
	mutex_lock(&srp->sr_lock);
	srp->sr_count--;
	if (srp->sr_count != 0) {
		mutex_unlock(&srp->sr_lock);
		mutex_unlock(&svp_remote_lock);
		return;
	}
	mutex_unlock(&srp->sr_lock);

	avl_remove(&svp_remote_tree, srp);
	mutex_unlock(&svp_remote_lock);
	svp_remote_destroy(srp);
}

int
svp_remote_attach(svp_remote_t *srp, svp_t *svp)
{
	svp_t check;
	avl_index_t where;

	mutex_lock(&srp->sr_lock);
	if (svp->svp_remote != NULL)
		abort();

	/*
	 * We require everything except shootdowns
	 */
	if (svp->svp_cb.scb_vl2_lookup == NULL)
		abort();
	if (svp->svp_cb.scb_vl3_lookup == NULL)
		abort();
	if (svp->svp_cb.scb_vl2_invalidate == NULL)
		abort();
	if (svp->svp_cb.scb_vl3_inject == NULL)
		abort();

	check.svp_vid = svp->svp_vid;
	if (avl_find(&srp->sr_tree, &check, &where) != NULL)
		abort();
	avl_insert(&srp->sr_tree, svp, where);
	svp->svp_remote = srp;
	mutex_unlock(&srp->sr_lock);

	return (0);
}

void
svp_remote_detach(svp_t *svp)
{
	svp_t *lookup;
	svp_remote_t *srp = svp->svp_remote;

	if (srp == NULL)
		abort();

	mutex_lock(&srp->sr_lock);
	lookup = avl_find(&srp->sr_tree, svp, NULL);
	if (lookup == NULL || lookup != svp)
		abort();
	avl_remove(&srp->sr_tree, svp);
	svp->svp_remote = NULL;
	mutex_unlock(&srp->sr_lock);
	svp_remote_release(srp);
}

void
svp_remote_vl2_lookup(svp_t *svp, const uint8_t *mac, void *arg)
{
	svp->svp_cb.scb_vl2_lookup(svp, SVP_S_NOTFOUND, NULL, NULL, arg);
}

void
svp_remote_vl3_lookup(svp_t *svp, const struct sockaddr *addr, void *arg)
{
	if (addr->sa_family != AF_INET && addr->sa_family != AF_INET6)
		abort();

	svp->svp_cb.scb_vl3_lookup(svp, SVP_S_NOTFOUND, NULL, NULL, NULL, arg);
}

void
svp_remote_dns_timer(port_event_t *pe, void *unused)
{
	svp_remote_t *s;
	mutex_lock(&svp_remote_lock);
	for (s = avl_first(&svp_remote_tree); s != NULL;
	    s = AVL_NEXT(&svp_remote_tree, s)) {
		svp_host_queue(s);
	}
	mutex_unlock(&svp_remote_lock);
}

void
svp_remote_resolved(svp_remote_t *srp, struct addrinfo *newaddrs)
{
	struct addrinfo *a;
	svp_conn_t *scp, *prev;
	int ngen;

	mutex_lock(&srp->sr_lock);
	srp->sr_gen++;
	ngen = srp->sr_gen;
	mutex_unlock(&srp->sr_lock);

	for (a = newaddrs; a != NULL; a = a->ai_next) {
		struct in6_addr in6;
		struct in6_addr *addrp;

		if (a->ai_family != AF_INET && a->ai_family != AF_INET6)
			abort();

		if (a->ai_family == AF_INET) {
			struct sockaddr_in *v4;
			v4 = (struct sockaddr_in *)a->ai_addr;
			addrp = &in6;
			IN6_INADDR_TO_V4MAPPED(&v4->sin_addr, addrp);
		} else {
			struct sockaddr_in6 *v6;
			v6 = (struct sockaddr_in6 *)a->ai_addr;
			addrp = &v6->sin6_addr;
		}

		mutex_lock(&srp->sr_lock);
		for (scp = srp->sr_conns; scp != NULL; scp = scp->sc_next) {
			mutex_lock(&scp->sc_lock);
			if (bcmp(addrp, &scp->sc_addr,
			    sizeof (struct in6_addr)) == 0) {
				scp->sc_gen = ngen;
				mutex_unlock(&scp->sc_lock);
				break;
			}
			mutex_unlock(&scp->sc_lock);
		}
		if (scp == NULL)
			svp_remote_conn_create(srp, addrp);
		mutex_unlock(&srp->sr_lock);
	}

	mutex_lock(&srp->sr_lock);
	prev = NULL;
	scp = srp->sr_conns;
	while (scp != NULL) {
		mutex_lock(&scp->sc_lock);
		if (scp->sc_gen != ngen) {
			svp_conn_t *d = scp;
			if (prev == NULL)
				srp->sr_conns = scp->sc_next;
			else
				prev->sc_next = scp->sc_next;
			scp = scp->sc_next;
			mutex_unlock(&scp->sc_lock);
			svp_remote_conn_destroy(srp, d);
			continue;
		}
		mutex_unlock(&scp->sc_lock);

		prev = scp;
	}
	mutex_unlock(&srp->sr_lock);
}

void
svp_remote_degrade(svp_remote_t *srp, svp_degrade_state_t flag)
{
	int sf, nf;
	char buf[256];

	if (flag == SVP_RD_ALL || flag == 0)
		abort();

	mutex_lock(&srp->sr_lock);
	if ((flag & srp->sr_degrade) != 0) {
		mutex_unlock(&srp->sr_lock);
		return;
	}

	sf = ffs(srp->sr_degrade);
	nf = ffs(flag);
	srp->sr_degrade |= flag;
	if (sf == 0 || sf > nf) {
		svp_t *svp;
		svp_remote_mkfmamsg(srp, flag, buf, sizeof (buf));

		for (svp = avl_first(&srp->sr_tree); svp != NULL;
		    svp = AVL_NEXT(&srp->sr_tree, svp)) {
			libvarpd_fma_degrade(svp->svp_hdl, buf);
		}
	}
	mutex_unlock(&srp->sr_lock);
}

void
svp_remote_restore(svp_remote_t *srp, svp_degrade_state_t flag)
{
	int sf, nf;
	mutex_lock(&srp->sr_lock);
	sf = ffs(srp->sr_degrade);
	if ((srp->sr_degrade & flag) != flag)
		abort();
	srp->sr_degrade &= ~flag;
	nf = ffs(srp->sr_degrade);

	/*
	 * If we're now empty, restore the device. If we still are degraded, but
	 * we now have a higher base than we used to, change the message.
	 */
	if (srp->sr_degrade == 0) {
		svp_t *svp;
		for (svp = avl_first(&srp->sr_tree); svp != NULL;
		    svp = AVL_NEXT(&srp->sr_tree, svp)) {
			libvarpd_fma_restore(svp->svp_hdl);
		}
	} else if (nf != sf) {
		svp_t *svp;
		char buf[256];

		svp_remote_mkfmamsg(srp, 1U << (nf - 1), buf, sizeof (buf));
		for (svp = avl_first(&srp->sr_tree); svp != NULL;
		    svp = AVL_NEXT(&srp->sr_tree, svp)) {
			libvarpd_fma_degrade(svp->svp_hdl, buf);
		}
	}
	mutex_unlock(&srp->sr_lock);
}
