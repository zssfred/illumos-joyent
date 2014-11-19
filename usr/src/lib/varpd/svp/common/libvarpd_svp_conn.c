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
 * Logic to manage an individual connection to a remote host
 */

#include <assert.h>
#include <umem.h>
#include <errno.h>
#include <strings.h>

#include <libvarpd_svp.h>

int
svp_remote_conn_create(svp_remote_t *srp, const struct in6_addr *addr)
{
	svp_conn_t *scp;

	assert(MUTEX_HELD(&srp->sr_lock));
	scp = umem_zalloc(sizeof (svp_conn_t), UMEM_DEFAULT);
	if (scp == NULL)
		return (ENOMEM);

	scp->sc_event.se_func = svp_remote_conn_handler;
	scp->sc_event.se_arg = scp;
	scp->sc_socket = socket(AF_INET6, SOCK_STREAM | SOCK_NONBLOCK, 0);
	if (scp->sc_socket != 0) {
		int ret = errno;
		umem_free(scp, sizeof (svp_conn_t));
		return (ret);
	}
	scp->sc_gen = srp->sr_gen;
	bcopy(addr, &scp->sc_addr, sizeof (struct in6_addr));
	scp->sc_cstate = SVP_CS_UNBOUND;
	scp->sc_next = srp->sr_conns;
	srp->sr_conns = scp;

	/*
	 * XXX Try to connect and let's get going.
	 */

	return (0);
}

void
svp_remote_conn_destroy(svp_remote_t *srp, svp_conn_t *scp)
{
	assert(MUTEX_HELD(&srp->sr_lock));

	abort();
}

void
svp_remote_conn_handler(port_event_t *pe, void *arg)
{
	abort();
}
