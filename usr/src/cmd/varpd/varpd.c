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
 * virtual arp daemon -- varpd
 *
 * The virtual arp daemon is the user land counterpart to overlay(9XXX). It's
 * purpose is to provide a means for looking up mappings between layer two hosts
 * and a corresponding encapsulation plugin.
 */

#include <libvarpd.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <libgen.h>
#include <stdarg.h>
#include <stdlib.h>

#define	VARPD_EXIT_FATAL	1
#define	VARPD_EXIT_USAGE	2

#define	VARPD_RUNDIR	"/var/run/varpd"

static varpd_handle_t varpd_handle;
static const char *varpd_pname;

/*
 * Debug builds are automatically wired up for umem debugging.
 */
#ifdef	DEBUG
const char *
_umem_debug_init()
{
	return ("default,verbose");
}

const char *
_umem_logging_init(void)
{
	return ("fail,contents");
}
#endif	/* DEBUG */

static void
varpd_vwarn(const char *fmt, va_list ap)
{
	int error = errno;

	(void) fprintf(stderr, "%s: ", varpd_pname);
	(void) vfprintf(stderr, fmt, ap);

	if (fmt[strlen(fmt) - 1] != '\n')
		(void) fprintf(stderr, ": %s\n", strerror(error));
}

static void
varpd_warn(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	varpd_vwarn(fmt, ap);
	va_end(ap);
}

static void
varpd_fatal(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	varpd_vwarn(fmt, ap);
	va_end(ap);

	exit(VARPD_EXIT_FATAL);
}

static int
plugin_walk_cb(varpd_handle_t vph, const char *name, void *unused)
{
	printf("loaded %s!\n", name);
	return (0);
}

static void
varpd_dir_setup(void)
{
	int fd;

	if (mkdir(VARPD_RUNDIR, 0700) != 0) {
		if (errno != EEXIST)
			varpd_fatal("failed to create %s", VARPD_RUNDIR);
	}

	fd = open(VARPD_RUNDIR, O_RDONLY);
	if (fd < 0)
		varpd_fatal("failed to open %s", VARPD_RUNDIR);
}

/*
 * XXX There are a bunch of things that we need to do here:
 *
 *   o Ensure that /var/run/varpd exists or create it
 *   o make stdin /dev/null (stdout?)
 *   o Ensure any other fds that we somehow inherited are closed, eg.
 *     closefrom()
 *   o Properly daemonize
 *   o Mask all signals except sigabrt before creating our first door -- all
 *     other doors will inherit from that.
 *   o Have the main thread sigsuspend looking for most things that are
 *     actionable...
 */
int
main(int argc, char *argv[])
{
	int err, c;
	const char *doorpath = NULL;
	sigset_t set;

	varpd_pname = basename(argv[0]);

	if ((err = libvarpd_create(&varpd_handle)) != 0) {
		/* XXX Proper logging */
		fprintf(stderr, "failed to create a handle: %d\n", err);
		return (1);
	}

	while ((c = getopt(argc, argv, ":i:d:")) != -1) {
		switch (c) {
		case 'i':
			err = libvarpd_plugin_load(varpd_handle, optarg);
			if (err != 0) {
				(void) fprintf(stderr,
				    "failed to load from %s: %s\n",
				    optarg, strerror(err));
				return (1);
			}
			break;
		case 'd':
			doorpath = optarg;
			break;
		default:
			(void) fprintf(stderr, "unknown option: %c\n", c);
			return (1);
		}
	}

	if (doorpath == NULL) {
		(void) fprintf(stderr, "missing required doorpath\n");
		return (1);
	}

	varpd_dir_setup();

	/* XXX Simple comments */
	libvarpd_plugin_walk(varpd_handle, plugin_walk_cb, NULL);

	if ((err = libvarpd_persist_enable(varpd_handle, VARPD_RUNDIR)) != 0)
		varpd_fatal("failed to enable varpd persistence: %s",
		    strerror(errno));

	if ((err = libvarpd_persist_restore(varpd_handle)) != 0)
		varpd_fatal("failed to enable varpd persistence: %s",
		    strerror(errno));

	/* XXX open a door server/bind */
	if ((err = libvarpd_door_server_create(varpd_handle, doorpath)) != 0) {
		(void) fprintf(stderr, "failed to create door server at %s\n");
		return (1);
	}

	(void) sigemptyset(&set);
	for (;;) {
		(void) sigsuspend(&set);
	}
	/* XXX Daemonize / sigsuspend */
	return (0);
}
