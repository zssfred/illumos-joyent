/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2011 NetApp, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY NETAPP, INC ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL NETAPP, INC OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

/*
 * Copyright 2018 Joyent, Inc.
 */

/*
 * Micro event library for FreeBSD, designed for a single i/o thread 
 * using kqueue, and having events be persistent by default.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <assert.h>
#ifndef WITHOUT_CAPSICUM
#include <capsicum_helpers.h>
#endif
#include <err.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include <sys/types.h>
#ifndef WITHOUT_CAPSICUM
#include <sys/capsicum.h>
#endif
#ifdef __FreeBSD__
#include <sys/event.h>
#else
#include <port.h>
#include <sys/poll.h>
#include <sys/siginfo.h>
#include <sys/queue.h>
#endif
#include <sys/time.h>

#include <pthread.h>
#include <pthread_np.h>

#include "mevent.h"

#define	MEVENT_MAX	64

#define	MEV_ADD		1
#define	MEV_ENABLE	2
#define	MEV_DISABLE	3
#define	MEV_DEL_PENDING	4

extern char *vmname;

static pthread_t mevent_tid;
static int mevent_timid = 43;
static int mevent_pipefd[2];
static pthread_mutex_t mevent_lmutex = PTHREAD_MUTEX_INITIALIZER;

struct mevent {
	void	(*me_func)(int, enum ev_type, void *);
#define me_msecs me_fd
	int	me_fd;
#ifdef __FreeBSD__
	int	me_timid;
#else
	timer_t me_timid;
#endif
	enum ev_type me_type;
	void    *me_param;
	int	me_cq;
	int	me_state;
	int	me_closefd;
#ifndef __FreeBSD__
	port_notify_t	me_notify;
	struct sigevent	me_sigev;
	boolean_t	me_auto_requeue;
#endif
	LIST_ENTRY(mevent) me_list;
};

static LIST_HEAD(listhead, mevent) global_head, change_head;

static void
mevent_qlock(void)
{
	pthread_mutex_lock(&mevent_lmutex);
}

static void
mevent_qunlock(void)
{
	pthread_mutex_unlock(&mevent_lmutex);
}

static void
mevent_pipe_read(int fd, enum ev_type type, void *param)
{
	char buf[MEVENT_MAX];
	int status;

	/*
	 * Drain the pipe read side. The fd is non-blocking so this is
	 * safe to do.
	 */
	do {
		status = read(fd, buf, sizeof(buf));
	} while (status == MEVENT_MAX);
}

static void
mevent_notify(void)
{
	char c;
	
	/*
	 * If calling from outside the i/o thread, write a byte on the
	 * pipe to force the i/o thread to exit the blocking kevent call.
	 */
	if (mevent_pipefd[1] != 0 && pthread_self() != mevent_tid) {
		write(mevent_pipefd[1], &c, 1);
	}
}
#ifdef __FreeBSD__
static int
mevent_kq_filter(struct mevent *mevp)
{
	int retval;

	retval = 0;

	if (mevp->me_type == EVF_READ)
		retval = EVFILT_READ;

	if (mevp->me_type == EVF_WRITE)
		retval = EVFILT_WRITE;

	if (mevp->me_type == EVF_TIMER)
		retval = EVFILT_TIMER;

	if (mevp->me_type == EVF_SIGNAL)
		retval = EVFILT_SIGNAL;

	return (retval);
}

static int
mevent_kq_flags(struct mevent *mevp)
{
	int ret;

	switch (mevp->me_state) {
	case MEV_ADD:
		ret = EV_ADD;		/* implicitly enabled */
		break;
	case MEV_ENABLE:
		ret = EV_ENABLE;
		break;
	case MEV_DISABLE:
		ret = EV_DISABLE;
		break;
	case MEV_DEL_PENDING:
		ret = EV_DELETE;
		break;
	default:
		assert(0);
		break;
	}

	return (ret);
}

static int
mevent_kq_fflags(struct mevent *mevp)
{
	/* XXX nothing yet, perhaps EV_EOF for reads ? */
	return (0);
}

static int
mevent_build(int mfd, struct kevent *kev)
{
	struct mevent *mevp, *tmpp;
	int i;

	i = 0;

	mevent_qlock();

	LIST_FOREACH_SAFE(mevp, &change_head, me_list, tmpp) {
		if (mevp->me_closefd) {
			/*
			 * A close of the file descriptor will remove the
			 * event
			 */
			close(mevp->me_fd);
		} else {
			if (mevp->me_type == EVF_TIMER) {
				kev[i].ident = mevp->me_timid;
				kev[i].data = mevp->me_msecs;
			} else {
				kev[i].ident = mevp->me_fd;
				kev[i].data = 0;
			}
			kev[i].filter = mevent_kq_filter(mevp);
			kev[i].flags = mevent_kq_flags(mevp);
			kev[i].fflags = mevent_kq_fflags(mevp);
			kev[i].udata = mevp;
			i++;
		}

		mevp->me_cq = 0;
		LIST_REMOVE(mevp, me_list);

		if (mevp->me_state == MEV_DEL_PENDING) {
			free(mevp);
		} else {
			LIST_INSERT_HEAD(&global_head, mevp, me_list);
		}

		assert(i < MEVENT_MAX);
	}

	mevent_qunlock();

	return (i);
}

static void
mevent_handle(struct kevent *kev, int numev)
{
	struct mevent *mevp;
	int i;

	for (i = 0; i < numev; i++) {
		mevp = kev[i].udata;

		/* XXX check for EV_ERROR ? */

		(*mevp->me_func)(mevp->me_fd, mevp->me_type, mevp->me_param);
	}
}

#else /* __FreeBSD__ */

static void
mevent_update_one(struct mevent *mevp)
{
	int portfd = mevp->me_notify.portnfy_port;

	switch (mevp->me_type) {
	case EVF_READ:
	case EVF_WRITE:
		mevp->me_auto_requeue = B_FALSE;

		switch (mevp->me_state) {
		case MEV_ADD:
		case MEV_ENABLE:
		{
			int events;

			events = (mevp->me_type == EVF_READ) ? POLLIN : POLLOUT;

			if (port_associate(portfd, PORT_SOURCE_FD, mevp->me_fd,
			    events, mevp) != 0) {
				(void) fprintf(stderr,
				    "port_associate fd %d %p failed: %s\n",
				    mevp->me_fd, mevp, strerror(errno));
			}
			return;
		}
		case MEV_DISABLE:
		case MEV_DEL_PENDING:
			/*
			 * A disable that comes in while an event is being
			 * handled will result in an ENOENT.
			 */
			if (port_dissociate(portfd, PORT_SOURCE_FD,
			    mevp->me_fd) != 0 && errno != ENOENT) {
				(void) fprintf(stderr, "port_dissociate "
				    "portfd %d fd %d mevp %p failed: %s\n",
				    portfd, mevp->me_fd, mevp, strerror(errno));
			}
			return;
		default:
			goto abort;
		}

	case EVF_TIMER:
		mevp->me_auto_requeue = B_TRUE;

		switch (mevp->me_state) {
		case MEV_ADD:
		case MEV_ENABLE:
		{
			struct itimerspec it = { 0 };

			mevp->me_sigev.sigev_notify = SIGEV_PORT;
			mevp->me_sigev.sigev_value.sival_ptr = &mevp->me_notify;

			if (timer_create(CLOCK_REALTIME, &mevp->me_sigev,
			    &mevp->me_timid) != 0) {
				(void) fprintf(stderr,
				    "timer_create failed: %s", strerror(errno));
				return;
			}

			/* The first timeout */
			it.it_value.tv_sec = mevp->me_msecs / MILLISEC;
			it.it_value.tv_nsec =
				MSEC2NSEC(mevp->me_msecs % MILLISEC);
			/* Repeat at the same interval */
			it.it_interval = it.it_value;

			if (timer_settime(mevp->me_timid, 0, &it, NULL) != 0) {
				(void) fprintf(stderr, "timer_settime failed: "
				    "%s", strerror(errno));
			}
			return;
		}
		case MEV_DISABLE:
		case MEV_DEL_PENDING:
			if (timer_delete(mevp->me_timid) != 0) {
				(void) fprintf(stderr, "timer_delete failed: "
				    "%s", strerror(errno));
			}
			return;
		default:
			goto abort;
		}
	default:
		/* EVF_SIGNAL not yet implemented. */
		goto abort;
	}

abort:
	(void) fprintf(stderr, "%s: unhandled type %d state %d\n", __func__,
	    mevp->me_type, mevp->me_state);
	abort();
}

static void
mevent_update_pending(int portfd)
{
	struct mevent *mevp, *tmpp;

	mevent_qlock();

	LIST_FOREACH_SAFE(mevp, &change_head, me_list, tmpp) {
		mevp->me_notify.portnfy_port = portfd;
		mevp->me_notify.portnfy_user = mevp;
		if (mevp->me_closefd) {
			/*
			 * A close of the file descriptor will remove the
			 * event
			 */
			(void) close(mevp->me_fd);
			mevp->me_fd = -1;
		} else {
			mevent_update_one(mevp);
		}

		mevp->me_cq = 0;
		LIST_REMOVE(mevp, me_list);

		if (mevp->me_state == MEV_DEL_PENDING) {
			free(mevp);
		} else {
			LIST_INSERT_HEAD(&global_head, mevp, me_list);
		}
	}

	mevent_qunlock();
}

static void
mevent_handle_pe(port_event_t *pe)
{
	struct mevent *mevp = pe->portev_user;

	mevent_qunlock();

	(*mevp->me_func)(mevp->me_fd, mevp->me_type, mevp->me_param);

	mevent_qlock();
	if (!mevp->me_cq && !mevp->me_auto_requeue) {
		mevent_update_one(mevp);
	}
	mevent_qunlock();
}
#endif

struct mevent *
mevent_add(int tfd, enum ev_type type,
	   void (*func)(int, enum ev_type, void *), void *param)
{
	struct mevent *lp, *mevp;

	if (tfd < 0 || func == NULL) {
		return (NULL);
	}

	mevp = NULL;

	mevent_qlock();

	/*
	 * Verify that the fd/type tuple is not present in any list
	 */
	LIST_FOREACH(lp, &global_head, me_list) {
		if (type != EVF_TIMER && lp->me_fd == tfd &&
		    lp->me_type == type) {
			goto exit;
		}
	}

	LIST_FOREACH(lp, &change_head, me_list) {
		if (type != EVF_TIMER && lp->me_fd == tfd &&
		    lp->me_type == type) {
			goto exit;
		}
	}

	/*
	 * Allocate an entry, populate it, and add it to the change list.
	 */
	mevp = calloc(1, sizeof(struct mevent));
	if (mevp == NULL) {
		goto exit;
	}

	if (type == EVF_TIMER) {
		mevp->me_msecs = tfd;
		mevp->me_timid = mevent_timid++;
	} else
		mevp->me_fd = tfd;
	mevp->me_type = type;
	mevp->me_func = func;
	mevp->me_param = param;

	LIST_INSERT_HEAD(&change_head, mevp, me_list);
	mevp->me_cq = 1;
	mevp->me_state = MEV_ADD;
	mevent_notify();

exit:
	mevent_qunlock();

	return (mevp);
}

static int
mevent_update(struct mevent *evp, int newstate)
{
	/*
	 * It's not possible to enable/disable a deleted event
	 */
	if (evp->me_state == MEV_DEL_PENDING)
		return (EINVAL);

	/*
	 * No update needed if state isn't changing
	 */
	if (evp->me_state == newstate)
		return (0);
	
	mevent_qlock();

	evp->me_state = newstate;

	/*
	 * Place the entry onto the changed list if not already there.
	 */
	if (evp->me_cq == 0) {
		evp->me_cq = 1;
		LIST_REMOVE(evp, me_list);
		LIST_INSERT_HEAD(&change_head, evp, me_list);
		mevent_notify();
	}

	mevent_qunlock();

	return (0);
}

int
mevent_enable(struct mevent *evp)
{

	return (mevent_update(evp, MEV_ENABLE));
}

int
mevent_disable(struct mevent *evp)
{

	return (mevent_update(evp, MEV_DISABLE));
}

static int
mevent_delete_event(struct mevent *evp, int closefd)
{
	mevent_qlock();

	/*
         * Place the entry onto the changed list if not already there, and
	 * mark as to be deleted.
         */
        if (evp->me_cq == 0) {
		evp->me_cq = 1;
		LIST_REMOVE(evp, me_list);
		LIST_INSERT_HEAD(&change_head, evp, me_list);
		mevent_notify();
        }
	evp->me_state = MEV_DEL_PENDING;

	if (closefd)
		evp->me_closefd = 1;

	mevent_qunlock();

	return (0);
}

int
mevent_delete(struct mevent *evp)
{

	return (mevent_delete_event(evp, 0));
}

int
mevent_delete_close(struct mevent *evp)
{

	return (mevent_delete_event(evp, 1));
}

static void
mevent_set_name(void)
{

	pthread_set_name_np(mevent_tid, "mevent");
}

void
mevent_dispatch(void)
{
#ifdef __FreeBSD__
	struct kevent changelist[MEVENT_MAX];
	struct kevent eventlist[MEVENT_MAX];
	struct mevent *pipev;
	int mfd;
	int numev;
#else
	struct mevent *pipev;
	int portfd;
#endif
	int ret;
#ifndef WITHOUT_CAPSICUM
	cap_rights_t rights;
#endif

	mevent_tid = pthread_self();
	mevent_set_name();

#ifdef __FreeBSD__
	mfd = kqueue();
	assert(mfd > 0);
#else
	portfd = port_create();
	assert(portfd >= 0);
#endif

#ifndef WITHOUT_CAPSICUM
	cap_rights_init(&rights, CAP_KQUEUE);
	if (caph_rights_limit(mfd, &rights) == -1)
		errx(EX_OSERR, "Unable to apply rights for sandbox");
#endif

	/*
	 * Open the pipe that will be used for other threads to force
	 * the blocking kqueue call to exit by writing to it. Set the
	 * descriptor to non-blocking.
	 */
	ret = pipe(mevent_pipefd);
	if (ret < 0) {
		perror("pipe");
		exit(0);
	}

#ifndef WITHOUT_CAPSICUM
	cap_rights_init(&rights, CAP_EVENT, CAP_READ, CAP_WRITE);
	if (caph_rights_limit(mevent_pipefd[0], &rights) == -1)
		errx(EX_OSERR, "Unable to apply rights for sandbox");
	if (caph_rights_limit(mevent_pipefd[1], &rights) == -1)
		errx(EX_OSERR, "Unable to apply rights for sandbox");
#endif

	/*
	 * Add internal event handler for the pipe write fd
	 */
	pipev = mevent_add(mevent_pipefd[0], EVF_READ, mevent_pipe_read, NULL);
	assert(pipev != NULL);

	for (;;) {
#ifdef __FreeBSD__
		/*
		 * Build changelist if required.
		 * XXX the changelist can be put into the blocking call
		 * to eliminate the extra syscall. Currently better for
		 * debug.
		 */
		numev = mevent_build(mfd, changelist);
		if (numev) {
			ret = kevent(mfd, changelist, numev, NULL, 0, NULL);
			if (ret == -1) {
				perror("Error return from kevent change");
			}
		}

		/*
		 * Block awaiting events
		 */
		ret = kevent(mfd, NULL, 0, eventlist, MEVENT_MAX, NULL);
		if (ret == -1 && errno != EINTR) {
			perror("Error return from kevent monitor");
		}
		
		/*
		 * Handle reported events
		 */
		mevent_handle(eventlist, ret);

#else /* __FreeBSD__ */
		port_event_t pev;

		/* Handle any pending updates */
		mevent_update_pending(portfd);

		/* Block awaiting events */
		ret = port_get(portfd, &pev, NULL);
		if (ret != 0 && errno != EINTR) {
			perror("Error return from port_get");
			continue;
		}

		/* Handle reported event */
		mevent_handle_pe(&pev);
#endif /* __FreeBSD__ */
	}			
}
