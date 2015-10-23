#ifndef	_NET_PF_COMPAT_H
#define	_NET_PF_COMPAT_H

#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/cmn_err.h>

typedef uint8_t u_int8_t;
typedef uint16_t u_int16_t;
typedef uint32_t u_int32_t;
typedef uint64_t u_int64_t;

struct m_tag;

#define	NMBCLUSTERS	6144		/* map size, max cluster allocation */


#define	unhandled_af(af)	panic("unhandled af %d", af)

/*
 * XXX We should go and replace usages of "time_uptime" with gethrtime().
 */
#define	time_uptime		ddi_get_time()

typedef struct pool {
	kmem_cache_t *p_cache;
} pool_t;

/*
 * XXX define wrappers in terms of kmem_cache*, or just replace these wholesale.
 */
struct pool_allocator;

void pool_put(pool_t *pp, void *v);
void *pool_get(pool_t *pp, int flags);
void pool_init(pool_t *pp, size_t size, u_int align, u_int ioff, int flags,
    const char *wchan, struct pool_allocator *palloc);

#define PR_WAITOK       0x0001 /* M_WAITOK */
#define PR_NOWAIT       0x0002 /* M_NOWAIT */
#define PR_LIMITFAIL    0x0004 /* M_CANFAIL */
#define PR_ZERO         0x0008 /* M_ZERO */

#define	KASSERT(a)	VERIFY(a)

/*
 * XXX from sys/mbuf.h on openbsd..
 */
/* pf stuff */
struct pf_state_key;
struct inpcb;

struct pkthdr_pf {
	struct pf_state_key *statekey;	/* pf stackside statekey */
	struct inpcb	*inp;		/* connected pcb for outgoing packet */
	u_int32_t	 qid;		/* queue id */
	u_int16_t	 tag;		/* tag id */
	u_int8_t	 flags;
	u_int8_t	 routed;
	u_int8_t	 prio;
	u_int8_t	 pad[3];
};

/* pkthdr_pf.flags */
#define	PF_TAG_GENERATED		0x01
#define	PF_TAG_TRANSLATE_LOCALHOST	0x04
#define	PF_TAG_DIVERTED			0x08
#define	PF_TAG_DIVERTED_PACKET		0x10
#define	PF_TAG_REROUTE			0x20
#define	PF_TAG_REFRAGMENTED		0x40	/* refragmented ipv6 packet */
#define	PF_TAG_PROCESSED		0x80	/* packet was checked by pf */

/*
 * XXX end from sys/mbuf.h on openbsd
 */

#endif	/* !_NET_PF_COMPAT_H */
