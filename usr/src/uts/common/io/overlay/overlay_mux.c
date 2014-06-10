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
 * Copyright (c) 2014 Joyent, Inc.  All rights reserved.
 */

/*
 * Overlay device multiplexer. Handles dealing with devices
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ksynch.h>
#include <sys/ksocket.h>
#include <sys/avl.h>
#include <sys/list.h>
#include <sys/sysmacros.h>

#include <sys/overlay_impl.h>

static list_t overlay_mux_list;
static kmutex_t overlay_mux_lock;

void
overlay_mux_init(void)
{
	list_create(&overlay_mux_list, sizeof (overlay_mux_t),
	    offsetof(overlay_mux_t, omux_lnode));
	mutex_init(&overlay_mux_lock, NULL, MUTEX_DRIVER, NULL);
}

void
overlay_mux_fini(void)
{
	mutex_destroy(&overlay_mux_lock);
	list_destroy(&overlay_mux_list);
}

static int
overlay_mux_comparator(const void *a, const void *b)
{
	const overlay_dev_t *odl, *odr;
	odl = a;
	odr = b;
	if (odl->odd_vid > odr->odd_vid)
		return (1);
	else if (odl->odd_vid < odr->odd_vid)
		return (-1);
	else
		return (0);
}

/*
 * Register a given device with a socket backend. If no such device socket
 * exists, create a new one.
 */
overlay_mux_t *
overlay_mux_open(overlay_plugin_t *opp, int domain, int family, int protocol,
    struct sockaddr *addr, socklen_t len, int *errp)
{
	int err;
	overlay_mux_t *mux;
	ksocket_t ksock;

	if (errp == NULL)
		errp = &err;

	mutex_enter(&overlay_mux_lock);
	for (mux = list_head(&overlay_mux_list); mux != NULL;
	    mux = list_next(&overlay_mux_list, mux)) {
		if (domain == mux->omux_domain &&
		    family == mux->omux_family &&
		    protocol == mux->omux_protocol &&
		    len == mux->omux_alen &&
		    bcmp(addr, mux->omux_addr, len) == 0) {

			if (opp != mux->omux_plugin) {
				*errp = EEXIST;
				return (NULL);
			}

			mutex_enter(&mux->omux_lock);
			mux->omux_count++;
			mutex_exit(&mux->omux_lock);
			mutex_exit(&overlay_mux_lock);
			*errp = 0;
			return (mux);
		}
	}

	/*
	 * XXX This is entirely the wrong cred to use. Needs to be specific to
	 * the zone, etc.
	 */
	*errp = ksocket_socket(&ksock, domain, family, protocol, KSOCKET_SLEEP,
	    kcred);
	if (*errp != 0) {
		mutex_exit(&overlay_mux_lock);
		return (NULL);
	}

	/* XXX Again, wrong credp */
	*errp = ksocket_bind(ksock, addr, len, kcred);
	if (*errp != 0) {
		mutex_exit(&overlay_mux_lock);
		/* XXX This is the wrong cred */
		ksocket_close(ksock, kcred);
		return (NULL);
	}

	mux = kmem_alloc(sizeof (overlay_mux_t), KM_SLEEP);
	list_link_init(&mux->omux_lnode);
	mux->omux_ksock = ksock;
	mux->omux_plugin = opp;
	mux->omux_domain = domain;
	mux->omux_family = family;
	mux->omux_protocol = protocol;
	mux->omux_addr = kmem_alloc(len, KM_SLEEP);
	bcopy(addr, mux->omux_addr, len);
	mux->omux_alen = len;
	mux->omux_count = 1;
	avl_create(&mux->omux_devices, overlay_mux_comparator,
	    sizeof (overlay_dev_t), offsetof(overlay_dev_t, odd_muxnode));
	mutex_init(&mux->omux_lock, NULL, MUTEX_DRIVER, NULL);

	list_insert_tail(&overlay_mux_list, mux);
	mutex_exit(&overlay_mux_lock);

	*errp = 0;
	return (mux);
}

void
overlay_mux_close(overlay_mux_t *mux)
{
	mutex_enter(&overlay_mux_lock);
	mutex_enter(&mux->omux_lock);
	mux->omux_count--;
	if (mux->omux_count != 0) {
		mutex_exit(&mux->omux_lock);
		mutex_exit(&overlay_mux_lock);
		return;
	}
	list_remove(&overlay_mux_list, mux);
	mutex_exit(&mux->omux_lock);
	mutex_exit(&overlay_mux_lock);

	/* XXX This is the wrong cred */
	ksocket_close(mux->omux_ksock, kcred);
	avl_destroy(&mux->omux_devices);
	kmem_free(mux->omux_addr, mux->omux_alen);
	kmem_free(mux, sizeof (overlay_mux_t));
}

void
overlay_mux_add_dev(overlay_mux_t *mux, overlay_dev_t *odd)
{
	mutex_enter(&mux->omux_lock);
	avl_add(&mux->omux_devices, odd);
	mutex_exit(&mux->omux_lock);
}

void
overlay_mux_remove_dev(overlay_mux_t *mux, overlay_dev_t *odd)
{
	/* XXX We should verify it's in the tree */
	mutex_enter(&mux->omux_lock);
	avl_remove(&mux->omux_devices, odd);
	mutex_exit(&mux->omux_lock);
}

int
overlay_mux_tx(overlay_mux_t *mux, struct msghdr *hdr, mblk_t *mp)
{
	int ret;
	/*
	 * XXX We probably want MSG_MBLK_QUICKRELE, but that doesn't work by
	 * default with UDP
	 */
	ret = ksocket_sendmblk(mux->omux_ksock, hdr, 0, &mp, kcred);
	if (ret != 0)
		freemsg(mp);

	return (ret);
}
