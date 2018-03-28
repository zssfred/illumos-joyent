/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2015 Joyent, Inc.
 */

/*
 * Copyright (c) 1982, 1986 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

/*
 * Udp protocol header.
 * Per RFC 768, September, 1981.
 */

#ifndef	_NETINET_UDP_H
#define	_NETINET_UDP_H

#ifdef	__cplusplus
extern "C" {
#endif

struct udphdr {
	in_port_t	uh_sport;		/* source port */
	in_port_t	uh_dport;		/* destination port */
	int16_t		uh_ulen;		/* udp length */
	uint16_t	uh_sum;			/* udp checksum */
};

/* Option definitions. */
#define	UDP_ANONPRIVBIND	0x0100		/* for internal use only */
#define	UDP_EXCLBIND		0x0101		/* for internal use only */
#define	UDP_RCVHDR		0x0102		/* for internal use only */
#define	UDP_NAT_T_ENDPOINT	0x0103		/* for internal use only */
#define	UDP_TUNNEL		0x0104		/* for internal use only */
#define	UDP_SND_TO_CONNECTED	0x0105		/* for internal use only */

#ifdef _KERNEL

/*
 * Internal structure defintions for UDP_TUNNEL.
 */
#define	UDP_TUNNEL_VXLAN	1
#define	UDP_TUNNEL_OPT_SRCPORT_HASH	0x01
#define	UDP_TUNNEL_OPT_HWCAP		0x02
#define	UDP_TUNNEL_OPT_RELAX_CKSUM	0x04

typedef struct udp_tunnel_opt {
	uint32_t	uto_type;
	uint32_t	uto_opts;
	uint32_t	uto_cksum_flags;
	uint32_t	uto_lso_flags;
	uint32_t	uto_lso_tcp_max;
} udp_tunnel_opt_t;

#endif	/* _KERNEL */

/*
 * Following option in UDP_ namespace required to be exposed through
 * <xti.h> (It also requires exposing options not implemented). The options
 * with potential for conflicts use #ifndef guards.
 *
 */
#ifndef UDP_CHECKSUM
#define	UDP_CHECKSUM	0x0600
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _NETINET_UDP_H */
