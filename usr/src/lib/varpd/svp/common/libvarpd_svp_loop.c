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
 * Event loop mechanism for our backend.
 */

#include <unistd.h>
#include <thread.h>
#include <port.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <umem.h>

#include <libvarpd_svp.h>

typedef struct svp_event_loop {
	int		sel_port;	/* RO */
	int		sel_nthread;	/* RO */
	thread_t	*sel_threads;	/* RO */
	boolean_t	sel_continue;	/* svp_elock */
	timer_t		sel_hosttimer;
} svp_event_loop_t;

int svp_hosttime = 60 * 5;	/* 5 minutes in seconds */
static svp_event_t svp_hosttimer;
static struct sigevent svp_hostevp;
static port_notify_t svp_hostnotify;
static svp_event_loop_t svp_event;
static mutex_t svp_elock = DEFAULTMUTEX;


static void *
svp_event_thr(void *arg)
{
	for (;;) {
		int ret;
		port_event_t pe;
		svp_event_t *sep;

		mutex_lock(&svp_elock);
		if (svp_event.sel_continue == B_FALSE) {
			mutex_unlock(&svp_elock);
			break;
		}
		mutex_unlock(&svp_elock);

		ret = port_get(svp_event.sel_port, &pe, NULL);
		if (ret != 0) {
			switch (errno) {
			case EFAULT:
			case EBADF:
			case EINVAL:
				abort();
			default:
				break;
			}
		}

		/* TODO Process the event */
		if (pe.portev_user == NULL)
			abort();
		sep = (svp_event_t *)pe.portev_user;
		sep->se_func(&pe, sep->se_arg);
	}

	return (NULL);
}

int
svp_event_init(void)
{
	long i, ncpus;
	struct itimerspec ts;

	svp_event.sel_port = port_create();
	if (svp_event.sel_port == -1)
		return (errno);

	ncpus = sysconf(_SC_NPROCESSORS_ONLN) * 2 + 1;
	if (ncpus <= 0)
		abort();

	svp_hosttimer.se_func = svp_remote_dns_timer;
	svp_hosttimer.se_arg = NULL;
	svp_hostnotify.portnfy_port = svp_event.sel_port;
	svp_hostnotify.portnfy_user = &svp_hosttimer;
	svp_hostevp.sigev_notify = SIGEV_PORT;
	svp_hostevp.sigev_value.sival_ptr = &svp_hostnotify;
	if (timer_create(CLOCK_MONOTONIC, &svp_hostevp,
	    &svp_event.sel_hosttimer) != 0) {
		int ret = errno;
		(void) close(svp_event.sel_port);
		svp_event.sel_port = -1;
		return (ret);
	}

	ts.it_value.tv_sec = svp_hosttime;
	ts.it_value.tv_nsec = 0;
	ts.it_interval.tv_sec = svp_hosttime;
	ts.it_interval.tv_nsec = 0;
	if (timer_settime(svp_event.sel_hosttimer, TIMER_RELTIME, &ts,
	    NULL) != 0) {
		int ret = errno;
		(void) timer_delete(svp_event.sel_hosttimer);
		(void) close(svp_event.sel_port);
		svp_event.sel_port = -1;
		return (ret);
	}

	svp_event.sel_threads = umem_alloc(sizeof (thread_t) * ncpus,
	    UMEM_DEFAULT);
	if (svp_event.sel_threads == NULL) {
		int ret = errno;
		(void) timer_delete(svp_event.sel_hosttimer);
		(void) close(svp_event.sel_port);
		svp_event.sel_port = -1;
		return (ret);
	}

	for (i = 0; i < ncpus; i++) {
		int ret;
		thread_t *thr = &svp_event.sel_threads[i];

		ret = thr_create(NULL, 0, svp_event_thr, NULL,
		    THR_DETACHED | THR_DAEMON, thr);
		if (ret != 0) {
			ret = errno;
			(void) timer_delete(svp_event.sel_hosttimer);
			(void) close(svp_event.sel_port);
			svp_event.sel_port = -1;
			return (errno);
		}
	}

	return (0);
}

void
svp_event_fini(void)
{
	mutex_lock(&svp_elock);
	svp_event.sel_continue = B_FALSE;
	mutex_unlock(&svp_elock);

	(void) timer_delete(svp_event.sel_hosttimer);
	(void) close(svp_event.sel_port);
}
