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
#include <unistd.h>

#include <libvarpd_svp.h>

int
svp_remote_conn_create(svp_remote_t *srp, const struct in6_addr *addr)
{
	svp_conn_t *scp;

	assert(MUTEX_HELD(&srp->sr_lock));
	scp = umem_zalloc(sizeof (svp_conn_t), UMEM_DEFAULT);
	if (scp == NULL)
		return (ENOMEM);

	scp->sc_remote = srp;
	scp->sc_event.se_func = svp_remote_conn_handler;
	scp->sc_event.se_arg = scp;
	scp->sc_socket = socket(AF_INET6, SOCK_STREAM | SOCK_NONBLOCK, 0);
	if (scp->sc_socket < 0) {
		int ret = errno;
		umem_free(scp, sizeof (svp_conn_t));
		return (ret);
	}
	scp->sc_gen = srp->sr_gen;
	bcopy(addr, &scp->sc_addr, sizeof (struct in6_addr));
	scp->sc_cstate = SVP_CS_UNBOUND;
	list_insert_tail(&srp->sr_conns, scp);
	srp->sr_tconns++;

	mutex_unlock(&srp->sr_lock);
	svp_remote_conn_handler(NULL, scp);
	mutex_lock(&srp->sr_lock);

	return (0);
}

/*
 * At the time of calling, the entry has been removed from all lists. In
 * addition, the entries state should be SVP_CS_ERROR, therefore, we know that
 * the fd should not be associated with the event loop. We'll double check that
 * just in case.
 */
void
svp_remote_conn_destroy(svp_remote_t *srp, svp_conn_t *scp)
{
	int ret;

	mutex_lock(&scp->sc_lock);
	if (scp->sc_cstate != SVP_CS_ERROR)
		libvarpd_panic("asked to tear down an active connection");

	if ((ret = svp_event_dissociate(&scp->sc_event, scp->sc_socket)) !=
	    ENOENT) {
		libvarpd_panic("dissociate failed or was actually "
		    "associated: %d", ret);
	}

	mutex_unlock(&scp->sc_lock);
	if (close(scp->sc_socket) != 0)
		libvarpd_panic("failed to close svp_conn_t`scp_socket fd "
		    "%d: %d", scp->sc_socket, errno);

	umem_free(scp, sizeof (svp_conn_t));
}

static void
svp_remote_conn_degrade(svp_conn_t *scp)
{
	svp_remote_t *srp = scp->sc_remote;

	mutex_lock(&srp->sr_lock);
	mutex_lock(&scp->sc_lock);
	list_remove(&srp->sr_conns, scp);
	list_insert_tail(&srp->sr_dconns, scp);
	srp->sr_ndconns++;
	mutex_unlock(&scp->sc_lock);

	if (srp->sr_ndconns == srp->sr_tconns)
		svp_remote_degrade(srp, SVP_RD_REMOTE_FAIL);
	mutex_unlock(&srp->sr_lock);
}

static boolean_t 
svp_remote_conn_connect(svp_conn_t *scp)
{
	int ret;
	struct sockaddr_in6 in6;

	assert(MUTEX_HELD(&scp->sc_lock));
	bzero(&in6, sizeof (struct sockaddr_in6));
	in6.sin6_family = AF_INET6;
	in6.sin6_port = htons(scp->sc_remote->sr_rport);
	bcopy(&scp->sc_addr, &in6.sin6_addr,  sizeof (struct in6_addr));
	ret = connect(scp->sc_socket, (struct sockaddr *)&in6,
	    sizeof (struct sockaddr_in6));
	if (ret != 0) {
		boolean_t async = B_FALSE;

		switch (errno) {
		case EACCES:
		case EADDRINUSE:
		case EAFNOSUPPORT:
		case EALREADY:
		case EBADF:
		case EISCONN:
		case ELOOP:
		case ENOENT:
		case ENOSR:
		case EWOULDBLOCK:
			libvarpd_panic("unanticipated connect errno %d", errno);
		case EINPROGRESS:
		case EINTR:
			async = B_TRUE;
		default:
			break;
		}

		/*
		 * So, we will be connecting to this in the future, advance our
		 * state and make sure that we poll for the next round.
		 */
		if (async == B_TRUE) {
			scp->sc_cstate = SVP_CS_CONNECTING;
			ret = svp_event_associate(&scp->sc_event,
			    scp->sc_socket);
			if (ret == 0)
				return (B_TRUE);
			scp->sc_error = SVP_CE_ASSOCIATE;
			scp->sc_errno = ret;
		} else {
			/*
			 * This call failed, which means that we obtained one of
			 * the following:
			 *
			 * EADDRNOTAVAIL
			 * ECONNREFUSED
			 * EIO
			 * ENETUNREACH
			 * EHOSTUNREACH
			 * ENXIO
			 * ETIMEDOUT
			 *
			 * These basically mean that this entry is bad. We
			 * should mark it as such and give up for this iteration
			 * and hope that another one of our connnections was
			 * able to connect.
			 */
			scp->sc_error = SVP_CE_CONNECT;
			scp->sc_errno = errno;
		}
		scp->sc_cstate = SVP_CS_ERROR;

	} else {
		/*
		 * We've connected. Successfully move ourselves to the bound
		 * state and start polling.
		 */
		scp->sc_cstate = SVP_CS_BOUND;
		ret = svp_event_associate(&scp->sc_event, scp->sc_socket);
		if (ret == 0)
			return (B_TRUE);
		scp->sc_error = SVP_CE_ASSOCIATE;
	}

	/*
	 * We didn't make it out in one piece, we need to notify our parent that
	 * we're toxic and unfit for service.
	 */
	scp->sc_cstate = SVP_CS_ERROR;
	return (B_FALSE);
}

/*
 * This should be the first call we get after a connect. If we have successfully
 * connected, we should see a writeable event. We may also see an error or a
 * hang up. In either of these cases, we transition to error mode. If there is
 * also a readable event, we ignore it at the moment and just let a
 * reassociation pick it up so we can simplify the set of state transitions that
 * we have.
 */
static boolean_t
svp_remote_conn_poll_connect(port_event_t *pe, svp_conn_t *scp)
{
	int ret, err;
	socklen_t sl = sizeof (err);
	if ((pe->portev_events & (POLLERR | POLLHUP)) ||
	    !(pe->portev_events & POLLOUT)) {
		if (pe->portev_events & POLLERR)
			scp->sc_error = SVP_CE_POLLERR;
		else if (pe->portev_events & POLLHUP)
			scp->sc_error = SVP_CE_POLLHUP;
		else
			scp->sc_error = SVP_CE_NOPOLLOUT;
		scp->sc_errno = 0;
		scp->sc_cstate = SVP_CS_ERROR;
		return (B_FALSE);
	}

	ret = getsockopt(scp->sc_socket, SOL_SOCKET, SO_ERROR, &err, &sl);
	/* XXX Really none of these? */
	if (ret != 0)
		libvarpd_panic("unanticipated getsockopt error");
	if (err != 0) {
		scp->sc_errno = err;
		scp->sc_cstate = SVP_CS_ERROR;
		return (B_FALSE);
	}

	scp->sc_cstate = SVP_CS_BOUND;
	ret = svp_event_associate(&scp->sc_event, scp->sc_socket);
	if (ret == 0)
		return (B_TRUE);
	scp->sc_error = SVP_CE_ASSOCIATE;
	scp->sc_errno = ret;
	scp->sc_cstate = SVP_CS_ERROR;
	return (B_FALSE);
}

/*
 * This is our general state transition function. We're called here when we want
 * to advance part of our state machine as well as to re-arm ourselves.
 */
void
svp_remote_conn_handler(port_event_t *pe, void *arg)
{
	svp_conn_t *scp = arg;
	boolean_t alive = B_TRUE;

	mutex_lock(&scp->sc_lock);
	switch (scp->sc_cstate) {
	case SVP_CS_ERROR:
		libvarpd_panic("svp_remote_conn_handler encountered "
		    "SVP_CS_ERROR");
		break;
	case SVP_CS_UNBOUND:
		assert(pe == NULL);
		alive = svp_remote_conn_connect(scp);
		break;
	case SVP_CS_CONNECTING:
		assert(pe != NULL);
		alive = svp_remote_conn_poll_connect(pe, scp);
		break;
	case SVP_CS_BOUND:
		/* XXX Do something at some point */
		break;
	}
	mutex_unlock(&scp->sc_lock);

	if (alive == B_FALSE)
		svp_remote_conn_degrade(scp);
}
