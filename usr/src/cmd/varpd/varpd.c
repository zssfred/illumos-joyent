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

static varpd_handle_t varpd_handle;

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

static int
plugin_walk_cb(varpd_handle_t vph, const char *name, void *unused)
{
	printf("loaded %s!\n", name);
	return (0);
}

int
main(int argc, char *argv[])
{
	int err, c;
	const char *doorpath = NULL;
	sigset_t set;

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

	/* XXX Simple comments */
	libvarpd_plugin_walk(varpd_handle, plugin_walk_cb, NULL);
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
