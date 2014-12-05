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
 * Logic to manage an individual connection to a remote host.
 */

#include <assert.h>
#include <umem.h>
#include <errno.h>
#include <strings.h>
#include <unistd.h>
#include <stddef.h>
#include <sys/uio.h>

#include <libvarpd_svp.h>

static int svp_conn_backoff_tbl[] = { 1, 2, 4, 8, 16, 32 };
static int svp_conn_nbackoff = sizeof (svp_conn_backoff_tbl) / sizeof (int);

typedef enum svp_conn_act {
	SVP_RA_NONE	= 0x00,
	SVP_RA_DEGRADE	= 0x01,
	SVP_RA_RESTORE	= 0x02,
	SVP_RA_ERROR	= 0x03
} svp_conn_act_t;

static void
svp_conn_degrade(svp_conn_t *scp)
{
	svp_remote_t *srp = scp->sc_remote;

	assert(MUTEX_HELD(&srp->sr_lock));
	assert(MUTEX_HELD(&scp->sc_lock));

	if (scp->sc_flags & SVP_CF_DEGRADED)
		return;

	scp->sc_flags |= SVP_CF_DEGRADED;
	srp->sr_ndconns++;
	if (srp->sr_ndconns == srp->sr_tconns)
		svp_remote_degrade(srp, SVP_RD_REMOTE_FAIL);
}

static void
svp_conn_restore(svp_conn_t *scp)
{
	svp_remote_t *srp = scp->sc_remote;

	assert(MUTEX_HELD(&srp->sr_lock));
	assert(MUTEX_HELD(&scp->sc_lock));

	if (!(scp->sc_flags & SVP_CF_DEGRADED))
		return;

	scp->sc_flags &= ~SVP_CF_DEGRADED;
	if (srp->sr_ndconns == srp->sr_tconns)
		svp_remote_restore(srp, SVP_RD_REMOTE_FAIL);
	srp->sr_ndconns--;
}

static svp_query_t *
svp_conn_query_find(svp_conn_t *scp, uint32_t id)
{
	svp_query_t *sqp;

	assert(MUTEX_HELD(&scp->sc_lock));

	for (sqp = list_head(&scp->sc_queries); sqp != NULL;
	    sqp = list_next(&scp->sc_queries, sqp)) {
		if (sqp->sq_header.svp_id == id)
			break;
	}

	return (sqp);
}

static svp_conn_act_t
svp_conn_backoff(svp_conn_t *scp)
{
	assert(MUTEX_HELD(&scp->sc_lock));

	scp->sc_cstate = SVP_CS_BACKOFF;
	scp->sc_nbackoff++;
	if (scp->sc_nbackoff >= svp_conn_nbackoff) {
		scp->sc_timer.st_value =
		    svp_conn_backoff_tbl[svp_conn_nbackoff - 1];
	} else {
		scp->sc_timer.st_value =
		    svp_conn_backoff_tbl[scp->sc_nbackoff - 1];
	}
	svp_timer_add(&scp->sc_timer);

	if (close(scp->sc_socket) != 0)
		libvarpd_panic("failed to close socket %d: %d\n",
		    scp->sc_socket, errno);

	if (scp->sc_nbackoff > svp_conn_nbackoff)
		return (SVP_RA_DEGRADE);
	return (SVP_RA_NONE);
}

static svp_conn_act_t
svp_conn_connect(svp_conn_t *scp)
{
	int ret;
	struct sockaddr_in6 in6;

	assert(MUTEX_HELD(&scp->sc_lock));
	assert(scp->sc_cstate == SVP_CS_BACKOFF ||
	    scp->sc_cstate == SVP_CS_INITIAL);
	assert(scp->sc_socket == -1);
	if (scp->sc_cstate == SVP_CS_INITIAL)
		scp->sc_nbackoff = 0;

	scp->sc_socket = socket(AF_INET6, SOCK_STREAM | SOCK_NONBLOCK, 0);
	if (scp->sc_socket == -1) {
		scp->sc_error = SVP_CE_SOCKET;
		scp->sc_errno = errno;
		scp->sc_cstate = SVP_CS_ERROR;
		return (SVP_RA_DEGRADE);
	}

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
			scp->sc_event.se_events = POLLOUT | POLLHUP;
			ret = svp_event_associate(&scp->sc_event,
			    scp->sc_socket);
			if (ret == 0)
				return (SVP_RA_NONE);
			scp->sc_error = SVP_CE_ASSOCIATE;
			scp->sc_errno = ret;
			scp->sc_cstate = SVP_CS_ERROR;
			return (SVP_RA_DEGRADE);
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
			 * Therefore we need to set ourselves into backoff and
			 * wait for that to clear up.
			 */
			return (svp_conn_backoff(scp));
		}
	}

	/*
	 * We've connected. Successfully move ourselves to the bound
	 * state and start polling.
	 */
	scp->sc_cstate = SVP_CS_ACTIVE;
	scp->sc_event.se_events = POLLIN | POLLRDNORM | POLLHUP;
	ret = svp_event_associate(&scp->sc_event, scp->sc_socket);
	if (ret == 0)
		return (SVP_RA_RESTORE);
	scp->sc_error = SVP_CE_ASSOCIATE;
	scp->sc_cstate = SVP_CS_ERROR;

	return (SVP_RA_DEGRADE);
}

/*
 * This should be the first call we get after a connect. If we have successfully
 * connected, we should see a writeable event. We may also see an error or a
 * hang up. In either of these cases, we transition to error mode. If there is
 * also a readable event, we ignore it at the moment and just let a
 * reassociation pick it up so we can simplify the set of state transitions that
 * we have.
 */
static svp_conn_act_t
svp_conn_poll_connect(port_event_t *pe, svp_conn_t *scp)
{
	int ret, err;
	socklen_t sl = sizeof (err);
	if (!(pe->portev_events & POLLOUT)) {
		scp->sc_errno = 0;
		scp->sc_error = SVP_CE_NOPOLLOUT;
		scp->sc_cstate = SVP_CS_ERROR;
		return (SVP_RA_DEGRADE);
	}

	ret = getsockopt(scp->sc_socket, SOL_SOCKET, SO_ERROR, &err, &sl);
	/* XXX Really none of these? */
	if (ret != 0)
		libvarpd_panic("unanticipated getsockopt error");
	if (err != 0) {
		return (svp_conn_backoff(scp));
	}

	scp->sc_cstate = SVP_CS_ACTIVE;
	scp->sc_event.se_events = POLLIN | POLLRDNORM | POLLHUP;
	ret = svp_event_associate(&scp->sc_event, scp->sc_socket);
	if (ret == 0)
		return (SVP_RA_RESTORE);
	scp->sc_error = SVP_CE_ASSOCIATE;
	scp->sc_errno = ret;
	scp->sc_cstate = SVP_CS_ERROR;
	return (SVP_RA_DEGRADE);
}

static svp_conn_act_t
svp_conn_pollout(svp_conn_t *scp)
{
	svp_query_t *sqp;
	svp_req_t *req;
	size_t off;
	struct iovec iov[2];
	int nvecs = 0;
	ssize_t ret;

	assert(MUTEX_HELD(&scp->sc_lock));

	/*
	 * We need to find a query and start writing it out.
	 */
	if (scp->sc_output.sco_query == NULL) {
		for (sqp = list_head(&scp->sc_queries); sqp != NULL;
		    sqp = list_next(&scp->sc_queries, sqp)) {
			if (sqp->sq_state != SVP_QUERY_INIT)
				continue;
			break;
		}

		if (sqp == NULL) {
			scp->sc_event.se_events &= ~POLLOUT;
			return (SVP_RA_NONE);
		}

		scp->sc_output.sco_query = sqp;
		scp->sc_output.sco_offset = 0;
		sqp->sq_state = SVP_QUERY_WRITING;
	}

	sqp = scp->sc_output.sco_query;
	req = &sqp->sq_header;
	off = scp->sc_output.sco_offset;
	if (off < sizeof (svp_req_t)) {
		iov[nvecs].iov_base = (void *)((uintptr_t)req + off);
		iov[nvecs].iov_len = sizeof (svp_req_t) - off;
		nvecs++;
		off = 0;
	} else {
		off -= sizeof (svp_req_t);
	}

	iov[nvecs].iov_base = (void *)((uintptr_t)sqp->sq_rdata + off);
	iov[nvecs].iov_len = sqp->sq_rsize - off;
	nvecs++;

	do {
		ret = writev(scp->sc_socket, iov, nvecs);
	} while (ret == -1 && errno == EAGAIN);
	if (ret == -1) {
		switch (errno) {
		case EAGAIN:
			scp->sc_event.se_events |= POLLOUT;
			return (SVP_RA_NONE);
		case EIO:
		case ENXIO:
		case ECONNRESET:
			return (SVP_RA_ERROR);
		default:
			libvarpd_panic("unexpected errno: %d", errno);
		}
	}

	scp->sc_output.sco_offset += ret;
	if (ret >= sizeof (svp_req_t) + sqp->sq_rsize) {
		sqp->sq_state = SVP_QUERY_READING;
		scp->sc_output.sco_query = NULL;
		scp->sc_output.sco_offset = 0;
		scp->sc_event.se_events |= POLLOUT;
	}
	return (SVP_RA_NONE);
}

static svp_conn_act_t
svp_conn_pollin(svp_conn_t *scp)
{
	size_t off, total;
	ssize_t ret;
	svp_query_t *sqp;

	assert(MUTEX_HELD(&scp->sc_lock));

	/*
	 * No query implies that we're reading in the header and that the offset
	 * is associted with it.
	 */
	off = scp->sc_input.sci_offset;
	sqp = scp->sc_input.sci_query;
	if (sqp == NULL) {
		svp_req_t *resp = &scp->sc_input.sci_req;
		uint32_t nop, nsize;

		assert(off < sizeof (svp_req_t));

		do {
			ret = read(scp->sc_socket,
			    (void *)((uintptr_t)resp + off),
			    sizeof (svp_req_t) - off);
		} while (ret == -1 && errno == EINTR);
		if (ret == -1) {
			switch (errno) {
			case EAGAIN:
				scp->sc_event.se_events |= POLLIN | POLLRDNORM;
				return (SVP_RA_NONE);
			case EIO:
			case ECONNRESET:
				return (SVP_RA_ERROR);
				break;
			default:
				libvarpd_panic("unexpeted read errno: %d", errno);
			}
		} else if (ret == 0) {
			/* Try to reconnect to the remote host */
			return (SVP_RA_ERROR);
		}

		/* Didn't get all the data we need */
		if (off + ret < sizeof (svp_req_t)) {
			scp->sc_input.sci_offset += ret;
			scp->sc_event.se_events |= POLLIN | POLLRDNORM;
			return (SVP_RA_NONE);
		}

		nop = ntohs(resp->svp_op);
		nsize = ntohl(resp->svp_size);
		sqp = svp_conn_query_find(scp, resp->svp_id);
		if (sqp == NULL) {
			/*
			 * XXX Don't panic, probably kill connection and try
			 * again
			 */
			libvarpd_panic("got bad connection");
		}

		/* XXX Validate header, don't assume it has valid data */
		/*
		 * XXX probably shouldn't assert our internal state, as a bad
		 * server could take us out here, we should instead close
		 * connection and resend elsewhere...
		 */
		assert(sqp->sq_state == SVP_QUERY_READING);
		scp->sc_input.sci_query = sqp;
		if (nop != SVP_R_VL2_ACK && nop != SVP_R_VL3_ACK)
			libvarpd_panic("unimplemented op: %d", nop);
		sqp->sq_wdata = &sqp->sq_wdun;
		sqp->sq_wsize = sizeof (svp_query_data_t);
		assert(sqp->sq_wsize >= nsize);
	}

	total = ntohl(scp->sc_input.sci_req.svp_size);
	do {
		ret = read(scp->sc_socket, sqp->sq_wdata + off, total - off);
	} while (ret == -1 && errno == EINTR);

	if (ret == -1) {
		switch (errno) {
		case EAGAIN:
			scp->sc_event.se_events |= POLLIN | POLLRDNORM;
			return (SVP_RA_NONE);
		case EIO:
		case ECONNRESET:
			return (SVP_RA_ERROR);
			break;
		default:
			libvarpd_panic("unexpeted read errno: %d", errno);
		}
	} else if (ret == 0) {
		/* Try to reconnect to the remote host */
		return (SVP_RA_ERROR);
	}

	if (ret + off < total) {
		scp->sc_input.sci_offset += ret;
		return (SVP_RA_NONE);
	}

	/* XXX Validate crc32 */
	scp->sc_input.sci_query = NULL;
	scp->sc_input.sci_offset = 0;

	if (scp->sc_input.sci_req.svp_op == SVP_R_VL2_ACK) {
		svp_vl2_ack_t *sl2a = sqp->sq_wdata;
		sqp->sq_status = ntohl(sl2a->sl2a_status);
	} else if (scp->sc_input.sci_req.svp_op == SVP_R_VL3_ACK) {
		svp_vl3_ack_t *sl3a = sqp->sq_wdata;
		sqp->sq_status = ntohl(sl3a->sl3a_status);
	} else {
		sqp->sq_status = SVP_S_OK;
	}

	/*
	 * XXX What assumptions can now be violated?
	 */
	list_remove(&scp->sc_queries, sqp);
	mutex_unlock(&scp->sc_lock);

	/*
	 * We have to release all of our resources associated with this entry
	 * before we call the callback. After we call it, the memory will be
	 * lost to time.
	 */
	svp_query_release(sqp);
	sqp->sq_func(sqp, sqp->sq_arg);
	mutex_lock(&scp->sc_lock);
	scp->sc_event.se_events |= POLLIN | POLLRDNORM;

	return (SVP_RA_NONE);
}

static svp_conn_act_t
svp_conn_reset(svp_conn_t *scp)
{
	assert(MUTEX_HELD(&scp->sc_lock));

	assert(svp_event_dissociate(&scp->sc_event, scp->sc_socket) ==
	    ENOENT);
	if (close(scp->sc_socket) != 0)
		libvarpd_panic("failed to close socket %d: %d", scp->sc_socket,
		    errno);
	scp->sc_socket = -1;
#if 0
	scp->sc_socket = socket(AF_INET6, SOCK_STREAM | SOCK_NONBLOCK, 0);
	if (scp->sc_socket == -1) {
		scp->sc_error = SVP_CE_SOCKET;
		scp->sc_errno = errno;
		scp->sc_cstate = SVP_CS_ERROR;
		return (SVP_RA_DEGRADE);
	}
#endif

	scp->sc_cstate = SVP_CS_INITIAL;
	return (svp_conn_connect(scp));
}

/*
 * This is our general state transition function. We're called here when we want
 * to advance part of our state machine as well as to re-arm ourselves.
 */
static void
svp_conn_handler(port_event_t *pe, void *arg)
{
	svp_conn_t *scp = arg;
	svp_remote_t *srp = scp->sc_remote;
	svp_conn_act_t ret = SVP_RA_NONE;

	mutex_lock(&scp->sc_lock);

	/* Check if this is being torn down */
	if (scp->sc_flags & SVP_CF_REAP) {
		mutex_unlock(&scp->sc_lock);
		mutex_lock(&srp->sr_lock);
		svp_conn_destroy(scp);
		mutex_unlock(&srp->sr_lock);
		return;
	}

	switch (scp->sc_cstate) {
	case SVP_CS_INITIAL:
	case SVP_CS_BACKOFF:
		assert(pe == NULL);
		ret = svp_conn_connect(scp);
		break;
	case SVP_CS_CONNECTING:
		assert(pe != NULL);
		ret = svp_conn_poll_connect(pe, scp);
		break;
	case SVP_CS_ACTIVE:
		assert(pe != NULL);
		if (pe->portev_events & POLLOUT)
			ret = svp_conn_pollout(scp);
		if (ret == SVP_RA_NONE && (pe->portev_events & POLLIN))
			ret = svp_conn_pollin(scp);
		/* XXX Need to handle queued requests... */
		if (ret == SVP_RA_NONE) {
			int err;
			if ((err = svp_event_associate(&scp->sc_event,
			    scp->sc_socket)) != 0) {
				scp->sc_error = SVP_CE_ASSOCIATE;
				scp->sc_errno = ret;
				scp->sc_cstate = SVP_CS_ERROR;
			}
			ret = SVP_RA_DEGRADE;
		} else if (ret == SVP_RA_ERROR) {
			ret = svp_conn_reset(scp);
		}
		break;
	default:
		libvarpd_panic("svp_conn_handler encountered "
		    "SVP_CS_ERROR");
	}
	mutex_unlock(&scp->sc_lock);

	if (ret == SVP_RA_NONE)
		return;

	mutex_lock(&srp->sr_lock);
	mutex_lock(&scp->sc_lock);
	if (ret == SVP_RA_DEGRADE)
		svp_conn_degrade(scp);
	else if (ret == SVP_RA_RESTORE)
		svp_conn_restore(scp);
	mutex_unlock(&scp->sc_lock);
	mutex_unlock(&srp->sr_lock);
}

static void
svp_conn_backtimer(void *arg)
{
	svp_conn_t *scp = arg;

	svp_conn_handler(NULL, scp);
}

/*
 * This connection has fallen out of DNS, figure out what we need to do with it.
 */
void
svp_conn_fallout(svp_conn_t *scp)
{
	boolean_t unlock = B_TRUE;
	svp_remote_t *srp = scp->sc_remote;

	assert(MUTEX_HELD(&srp->sr_lock));

	mutex_lock(&scp->sc_lock);
	switch (scp->sc_cstate) {
	case SVP_CS_ERROR:
		/*
		 * Connection is already inactive, so it's safe to tear down.
		 */
		mutex_unlock(&scp->sc_lock);
		svp_conn_destroy(scp);
		unlock = B_FALSE;
		break;
	case SVP_CS_INITIAL:
	case SVP_CS_BACKOFF:
	case SVP_CS_CONNECTING:
		/*
		 * Here, we have something actively going on, so we'll let it be
		 * clean up the next time we hit the event loop by the event
		 * loop itself. As it has no connections, there isn't much to
		 * really do.
		 */
		scp->sc_flags |= SVP_CF_REAP;
		break;
	case SVP_CS_ACTIVE:
		scp->sc_cstate = SVP_CS_WINDDOWN;
		/*
		 * XXX We need to look at what's currently outstanding. If
		 * nothing is going on at the moment, we should try to
		 * port disassociate, and if succsesful, eg. not ENOENT, clean
		 * up right here and now.
		 */
		break;
	case SVP_CS_WINDDOWN:
		/*
		 * Nothing specific to do here, we'e finishing up with this,
		 * just haven't finished yet.
		 */
		break;
	default:
		libvarpd_panic("svp_conn_fallout encountered"
		    "unkonwn state");
	}
	if (unlock == B_TRUE)
		mutex_unlock(&scp->sc_lock);
	mutex_unlock(&srp->sr_lock);
}

int
svp_conn_create(svp_remote_t *srp, const struct in6_addr *addr)
{
	svp_conn_t *scp;

	assert(MUTEX_HELD(&srp->sr_lock));
	scp = umem_zalloc(sizeof (svp_conn_t), UMEM_DEFAULT);
	if (scp == NULL)
		return (ENOMEM);

	scp->sc_remote = srp;
	scp->sc_event.se_func = svp_conn_handler;
	scp->sc_event.se_arg = scp;
	scp->sc_timer.st_func = svp_conn_backtimer;
	scp->sc_timer.st_arg = scp;
	scp->sc_timer.st_oneshot = B_TRUE;
	scp->sc_timer.st_value = 0;
	scp->sc_socket = -1;
#if 0
	scp->sc_socket = socket(AF_INET6, SOCK_STREAM | SOCK_NONBLOCK, 0);
	if (scp->sc_socket < 0) {
		int ret = errno;
		umem_free(scp, sizeof (svp_conn_t));
		return (ret);
	}
#endif
	list_create(&scp->sc_queries, sizeof (svp_query_t),
	    offsetof(svp_query_t, sq_lnode));
	scp->sc_gen = srp->sr_gen;
	bcopy(addr, &scp->sc_addr, sizeof (struct in6_addr));
	scp->sc_cstate = SVP_CS_INITIAL;
	list_insert_tail(&srp->sr_conns, scp);
	srp->sr_tconns++;

	mutex_unlock(&srp->sr_lock);
	svp_conn_handler(NULL, scp);
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
svp_conn_destroy(svp_conn_t *scp)
{
	int ret;
	svp_remote_t *srp = scp->sc_remote;

	assert(MUTEX_HELD(&srp->sr_lock));
	mutex_lock(&scp->sc_lock);
	if (scp->sc_cstate != SVP_CS_ERROR)
		libvarpd_panic("asked to tear down an active connection");

	if ((ret = svp_event_dissociate(&scp->sc_event, scp->sc_socket)) !=
	    ENOENT) {
		libvarpd_panic("dissociate failed or was actually "
		    "associated: %d", ret);
	}
	mutex_unlock(&scp->sc_lock);

	if (scp->sc_flags & SVP_CF_DEGRADED) {
		srp->sr_ndconns--;
	}
	srp->sr_tconns--;

	if (srp->sr_tconns == srp->sr_ndconns)
		svp_remote_degrade(srp, SVP_RD_REMOTE_FAIL);

	if (scp->sc_socket != -1 && close(scp->sc_socket) != 0)
		libvarpd_panic("failed to close svp_conn_t`scp_socket fd "
		    "%d: %d", scp->sc_socket, errno);

	list_destroy(&scp->sc_queries);
	umem_free(scp, sizeof (svp_conn_t));
}

void
svp_conn_queue(svp_conn_t *scp, svp_query_t *sqp)
{
	assert(MUTEX_HELD(&scp->sc_lock));
	assert(scp->sc_cstate == SVP_CS_ACTIVE);

	list_insert_tail(&scp->sc_queries, sqp);
	if (!(scp->sc_event.se_events & POLLOUT)) {
		scp->sc_event.se_events |= POLLOUT;
		/*
		 * XXX If this fails, we should give up this set of conns or
		 * something... For now, abort.
		 */
		if (svp_event_associate(&scp->sc_event, scp->sc_socket) != 0)
			libvarpd_panic("svp_event_associate failed somehow");
	}
}
