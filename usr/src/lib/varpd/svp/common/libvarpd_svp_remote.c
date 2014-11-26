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

static mutex_t svp_remote_lock = DEFAULTMUTEX;
static avl_tree_t svp_remote_tree;
static svp_timer_t svp_dns_timer;
static int svp_dns_timer_rate = 30;	/* seconds */

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
		(void) snprintf(buf, buflen, "unkonwn error state: %d", state);
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

	if (lr->sr_rport > rr->sr_rport)
		return (1);
	else if (lr->sr_rport < rr->sr_rport)
		return (-1);
	else
		return (0);
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
		libvarpd_panic("failed to destroy mutex sr_lock");

	if (srp->sr_addrinfo != NULL)
		freeaddrinfo(srp->sr_addrinfo);
	len = strlen(srp->sr_hostname) + 1;
	umem_free(srp->sr_hostname, len);
	umem_free(srp, sizeof (svp_remote_t));
}

static int
svp_remote_create(const char *host, uint16_t port, svp_remote_t **outp)
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
	remote->sr_rport = port;
	if (mutex_init(&remote->sr_lock, USYNC_THREAD, NULL) != 0)
		libvarpd_panic("failed to create mutex sr_lock");
	list_create(&remote->sr_conns, sizeof (svp_conn_t),
	    offsetof(svp_conn_t, sc_rlist));
	list_create(&remote->sr_dconns, sizeof (svp_conn_t),
	    offsetof(svp_conn_t, sc_rlist));
	avl_create(&remote->sr_tree, svp_comparator, sizeof (svp_t),
	    offsetof(svp_t, svp_rlink));
	(void) strlcpy(remote->sr_hostname, host, hlen);
	remote->sr_count = 1;

	*outp = remote;
	return (0);
}

int
svp_remote_find(char *host, uint16_t port, svp_remote_t **outp)
{
	int ret;
	svp_remote_t lookup, *remote;

	lookup.sr_hostname = host;
	lookup.sr_rport = port;
	mutex_lock(&svp_remote_lock);
	remote = avl_find(&svp_remote_tree, &lookup, NULL);
	if (remote != NULL) {
		assert(remote->sr_count > 0);
		remote->sr_count++;
		*outp = remote;
		mutex_unlock(&svp_remote_lock);
		return (0);
	}

	if ((ret = svp_remote_create(host, port, outp)) != 0) {
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
		libvarpd_panic("failed to create mutex sr_lock");

	/*
	 * We require everything except shootdowns
	 */
	if (svp->svp_cb.scb_vl2_lookup == NULL)
		libvarpd_panic("missing callback scb_vl2_lookup");
	if (svp->svp_cb.scb_vl3_lookup == NULL)
		libvarpd_panic("missing callback scb_vl3_lookup");
	if (svp->svp_cb.scb_vl2_invalidate == NULL)
		libvarpd_panic("missing callback scb_vl2_invalidate");
	if (svp->svp_cb.scb_vl3_inject == NULL)
		libvarpd_panic("missing callback scb_vl3_inject");

	check.svp_vid = svp->svp_vid;
	if (avl_find(&srp->sr_tree, &check, &where) != NULL)
		libvarpd_panic("found duplicate entry with vid %ld",
		    svp->svp_vid);
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
		libvarpd_panic("trying to detach remote when none exists");

	mutex_lock(&srp->sr_lock);
	lookup = avl_find(&srp->sr_tree, svp, NULL);
	if (lookup == NULL || lookup != svp)
		libvarpd_panic("inconsitent remote avl tree...");
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
		libvarpd_panic("unexpected sa_family for the vl3 lookup");

	svp->svp_cb.scb_vl3_lookup(svp, SVP_S_NOTFOUND, NULL, NULL, NULL, arg);
}

void
svp_remote_dns_timer(void *unused)
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
	svp_conn_t *scp, *next;
	int ngen;

	mutex_lock(&srp->sr_lock);
	srp->sr_gen++;
	ngen = srp->sr_gen;
	mutex_unlock(&srp->sr_lock);

	for (a = newaddrs; a != NULL; a = a->ai_next) {
		struct in6_addr in6;
		struct in6_addr *addrp;

		if (a->ai_family != AF_INET && a->ai_family != AF_INET6)
			continue;

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
		for (scp = list_head(&srp->sr_conns); scp != NULL;
		    scp = list_next(&srp->sr_conns, scp)) {
			mutex_lock(&scp->sc_lock);
			if (bcmp(addrp, &scp->sc_addr,
			    sizeof (struct in6_addr)) == 0) {
				scp->sc_gen = ngen;
				mutex_unlock(&scp->sc_lock);
				break;
			}
			mutex_unlock(&scp->sc_lock);
		}

		/*
		 * We need to be careful in the assumptions that we make here,
		 * as there's a good chance that svp_remote_conn_create will
		 * drop the svp_remote_t`sr_lock to kick off its effective event
		 * loop.
		 */
		if (scp == NULL)
			svp_remote_conn_create(srp, addrp);
		mutex_unlock(&srp->sr_lock);
	}

	/*
	 * Now it's time to clean things up. We do not actively clean up the
	 * current connections that we have, instead allowing them to stay
	 * around assuming that they're still useful. Instead, we go through and
	 * purge the degraded list for anything that's from an older generation.
	 */
	mutex_lock(&srp->sr_lock);
	scp = list_head(&srp->sr_dconns);
	while (scp != NULL) {
		next = list_next(&srp->sr_dconns, scp);
		mutex_lock(&scp->sc_lock);
		if (scp->sc_gen != ngen) {
			mutex_unlock(&scp->sc_lock);
			list_remove(&srp->sr_dconns, scp);
			svp_remote_conn_destroy(srp, scp);
			scp = next;
			continue;
		}
		mutex_unlock(&scp->sc_lock);
		scp = next;
	}
	mutex_unlock(&srp->sr_lock);
}

void
svp_remote_degrade(svp_remote_t *srp, svp_degrade_state_t flag)
{
	int sf, nf;
	char buf[256];

	assert(MUTEX_HELD(&srp->sr_lock));

	if (flag == SVP_RD_ALL || flag == 0)
		libvarpd_panic("invalid flag passed to degrade");

	if ((flag & srp->sr_degrade) != 0) {
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
}

void
svp_remote_restore(svp_remote_t *srp, svp_degrade_state_t flag)
{
	int sf, nf;

	assert(MUTEX_HELD(&srp->sr_lock));
	sf = ffs(srp->sr_degrade);
	if ((srp->sr_degrade & flag) != flag)
		return;
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
}

int
svp_remote_init(void)
{
	avl_create(&svp_remote_tree, svp_remote_comparator,
	    sizeof (svp_remote_t), offsetof(svp_remote_t, sr_gnode));
	svp_dns_timer.st_func = svp_remote_dns_timer;
	svp_dns_timer.st_arg = NULL;
	svp_dns_timer.st_oneshot = B_FALSE;
	svp_dns_timer.st_value = svp_dns_timer_rate;
	svp_timer_add(&svp_dns_timer);
	return (0);
}

void
svp_remote_fini(void)
{
	svp_timer_remove(&svp_dns_timer);
	avl_destroy(&svp_remote_tree);
}
