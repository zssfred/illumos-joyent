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

#ifndef _LIBVARPD_SVP_H
#define	_LIBVARPD_SVP_H

/*
 * Implementation details of the SVP plugin and the SVP protocol.
 */

#include <netinet/in.h>
#include <sys/ethernet.h>
#include <thread.h>
#include <synch.h>
#include <libvarpd_provider.h>
#include <sys/avl.h>
#include <port.h>
#include <sys/list.h>

#include <libvarpd_svp_prot.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct svp svp_t;
typedef struct svp_remote svp_remote_t;
typedef struct svp_conn svp_conn_t;

typedef void (*svp_event_f)(port_event_t *, void *);

typedef struct svp_event {
	svp_event_f	se_func;
	void		*se_arg;
} svp_event_t;

typedef void (*svp_timer_f)(void *);

typedef struct svp_timer {
	svp_timer_f	st_func;
	void		*st_arg;
	boolean_t	st_oneshot;
	uint32_t	st_value;
	/* Fields below here are private to the svp_timer implementaiton */
	uint64_t	st_expire;
	boolean_t	st_delivering;
	avl_node_t	st_link;
} svp_timer_t;

typedef enum svp_conn_state {
	SVP_CS_ERROR		= 0x00,
	SVP_CS_UNBOUND		= 0x01,
	SVP_CS_CONNECTING	= 0x02,
	SVP_CS_BOUND		= 0x03
} svp_conn_state_t;

typedef enum svp_conn_error {
	SVP_CE_NONE		= 0x00,
	SVP_CE_ASSOCIATE	= 0x01,
	SVP_CE_CONNECT		= 0x02,
	SVP_CE_POLLHUP		= 0x03,
	SVP_CE_POLLERR		= 0x04,
	SVP_CE_NOPOLLOUT	= 0x05
} svp_conn_error_t;

typedef struct svp_conn_out {
	void	*sco_buffer;
	size_t	sco_buflen;
	size_t	sco_offset;
} svp_conn_out_t;

typedef enum svp_conn_in_state {
	SVP_CIS_NEED_HEADER	= 0x00,
	SVP_CIS_NEED_BODY	= 0x01
} svp_conn_in_state_t;

typedef struct svp_conn_in {
	svp_conn_in_state_t	sci_state;
	size_t			sci_nbytes;
	size_t			sci_offset;
	svp_req_t		sci_req;
	void			*sci_body;
} svp_conn_in_t;

struct svp_conn {
	svp_remote_t		*sc_remote;	/* RO */
	struct in6_addr		sc_addr;	/* RO */
	list_node_t		sc_rlist;	/* svp_remote_t`sr_lock */
	mutex_t			sc_lock;
	svp_event_t		sc_event;
	int			sc_socket;
	uint_t			sc_gen;
	svp_conn_state_t	sc_cstate;
	svp_conn_error_t	sc_error;
	int			sc_errno;
	hrtime_t		sc_lastact;
	svp_conn_out_t		sc_output;
	svp_conn_in_t		sc_input;
};

typedef enum svp_remote_state {
	SVP_RS_LOOKUP_SCHEDULED		= 0x01,	/* On the DNS Queue */
	SVP_RS_LOOKUP_INPROGRESS 	= 0x02,	/* Doing a DNS lookup */
	SVP_RS_LOOKUP_VALID		= 0x04	/* addrinfo valid */
} svp_remote_state_t;

/*
 * These series of bit-based flags should be ordered such that the most severe
 * is first. We only can set one message that user land can see, so if more than
 * one is set we want to make sure that one is there.
 */
typedef enum svp_degrade_state {
	SVP_RD_DNS_FAIL		= 0x01,	/* DNS Resolution Failure */
	SVP_RD_REMOTE_FAIL	= 0x02,	/* cannot reach any remote peers */
	SVP_RD_ALL		= 0x03	/* Only suitable for restore */
} svp_degrade_state_t;

struct svp_remote {
	char			*sr_hostname;	/* RO */
	uint16_t		sr_rport;	/* RO */
	avl_node_t		sr_gnode;	/* svp_remote_lock */
	svp_remote_t		*sr_nexthost;	/* svp_host_lock */
	mutex_t			sr_lock;
	svp_remote_state_t	sr_state;
	svp_degrade_state_t	sr_degrade;
	struct addrinfo 	*sr_addrinfo;
	avl_tree_t		sr_tree;
	uint_t			sr_count;	/* active count */
	uint_t			sr_gen;
	uint_t			sr_tconns;	/* total conns + dconns */
	uint_t			sr_ndconns;	/* number of degraded conns */
	list_t			sr_conns;	/* active conns */
	list_t			sr_dconns;	/* degraded conns */
};

/*
 * We have a bunch of different things that we get back from the API at the
 * plug-in layer. These include:
 *
 *   o OOB Shootdowns
 *   o VL3->VL2 Lookups
 *   o VL2->UL3 Lookups
 *   o VL2 Log invalidations
 *   o VL3 Log injections
 */
typedef void (*svp_vl2_lookup_f)(svp_t *, svp_status_t, const struct in6_addr *,
    const uint16_t, void *);
typedef void (*svp_vl3_lookup_f)(svp_t *, svp_status_t, const uint8_t *,
    const struct in6_addr *, const uint16_t, void *);
typedef void (*svp_vl2_invalidation_f)(svp_t *, const uint8_t *);
typedef void (*svp_vl3_inject_f)(svp_t *, const uint16_t,
    const struct in6_addr *, const uint8_t *, const uint8_t *);
typedef void (*svp_shootdown_f)(svp_t *, const uint8_t *,
    const struct in6_addr *, const uint16_t uport);

typedef struct svp_cb {
	svp_vl2_lookup_f	scb_vl2_lookup;
	svp_vl3_lookup_f	scb_vl3_lookup;
	svp_vl2_invalidation_f	scb_vl2_invalidate;
	svp_vl3_inject_f	scb_vl3_inject;
	svp_shootdown_f		scb_shootdown;
} svp_cb_t;

/*
 * Core implementation structure.
 */
struct svp {
	overlay_plugin_dest_t	svp_dest;	/* RO */
	varpd_provider_handle_t	svp_hdl;	/* RO */
	svp_cb_t		svp_cb;		/* RO */
	uint64_t		svp_vid;	/* RO? */
	avl_node_t 		svp_rlink;	/* Owned by svp_remote */
	svp_remote_t		*svp_remote;	/* ROish XXX */
	mutex_t			svp_lock;
	char			*svp_host;
	uint16_t		svp_port;
	uint16_t		svp_uport;
	boolean_t		svp_huip;
	struct in6_addr		svp_uip;
};

extern int svp_comparator(const void *, const void *);

/*
 * XXX Strawman backend APIs
 */
extern int svp_remote_find(char *, uint16_t, svp_remote_t **);
extern int svp_remote_attach(svp_remote_t *, svp_t *);
extern void svp_remote_detach(svp_t *);
extern void svp_remote_release(svp_remote_t *);
extern void svp_remote_vl3_lookup(svp_t *, const struct sockaddr *, void *);
extern void svp_remote_vl2_lookup(svp_t *, const uint8_t *, void *);

/*
 * Init functions
 */
extern int svp_remote_init(void);
extern void svp_remote_fini(void);
extern int svp_event_init(void);
extern int svp_event_timer_init(svp_event_t *);
extern void svp_event_fini(void);
extern int svp_host_init(void);
extern int svp_timer_init(void);

/*
 * Timers
 */
extern int svp_tickrate;
extern void svp_timer_add(svp_timer_t *);
extern void svp_timer_remove(svp_timer_t *);

/*
 * Event loop management
 */
extern int svp_event_associate(svp_event_t *, int);
extern int svp_event_dissociate(svp_event_t *, int);

/*
 * Connection manager
 */
extern void svp_remote_conn_handler(port_event_t *, void *);
extern int svp_remote_conn_create(svp_remote_t *, const struct in6_addr *);
extern void svp_remote_conn_destroy(svp_remote_t *, svp_conn_t *);

/*
 * FMA related
 */
extern void svp_remote_degrade(svp_remote_t *, svp_degrade_state_t);
extern void svp_remote_restore(svp_remote_t *, svp_degrade_state_t);

/*
 * Misc.
 */
extern void svp_remote_resolved(svp_remote_t *, struct addrinfo *);
extern void svp_host_queue(svp_remote_t *);

#ifdef __cplusplus
}
#endif

#endif /* _LIBVARPD_SVP_H */
