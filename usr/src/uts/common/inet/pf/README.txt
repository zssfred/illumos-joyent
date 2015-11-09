this copy of pf came from commit:
	be1ab1b22057216a2366879300de2fa1dfe090e0
of:
	git://source.eait.uq.edu.au/openbsd-src


---------------------
Main entrypoint...

	pf_test(): in OpenBSD, called from ...

7 ip_input.c    ipv4_input    318 if (pf_test(AF_INET, PF_IN, ifp, &m) != PF_PASS)
8 ip_output.c   ip_output     448 pf_test(AF_INET, PF_OUT, encif, &m) != PF_PASS) {
9 ip_output.c   ip_output     526 if (pf_test(AF_INET, PF_OUT, ifp, &m) != PF_PASS)
                                  {
a ip6_forward.c ip6_forward   329 pf_test(AF_INET6, PF_FWD, encif, &m) != PF_PASS)
                                  {
b ip6_forward.c ip6_forward   410 if (pf_test(AF_INET6, PF_FWD, rt->rt_ifp, &m) !=
                                  PF_PASS) {
c ip6_input.c   ip6_input     328 if (pf_test(AF_INET6, PF_IN, ifp, &m) != PF_PASS)
d ip6_output.c  ip6_output    494 pf_test(AF_INET6, PF_OUT, encif, &m) != PF_PASS)
                                  {
e ip6_output.c  ip6_output    717 if (pf_test(AF_INET6, PF_OUT, ifp, &m) !=
                                  PF_PASS) {

	returns...

		PF_PASS
		PF_DROP

	This is presumably something we'll wire up through pfhooks.


---------------------
Architectural thoughts:

 123 /*
 124  * Global variables
 125  */
 126 struct pf_state_tree     pf_statetbl;
 127 struct pf_queuehead      pf_queues[2];
 128 struct pf_queuehead     *pf_queues_active;
 129 struct pf_queuehead     *pf_queues_inactive;
 130
 131 struct pf_status         pf_status;

These will presumably have to become per-netstack state variables.


---------------------
Logging:

It seems there is a lot of usage of "log()" and "addlog()", to start
a new syslog message or append to the existing message?

This is obviously not going to cut it.  Is this only for debugging?  Can
we replace these with SDT probes?


---------------------
Data structures:

a TAILQ_ and a LIST_ (from "sys/queue.h") are both apparently doubly-linked
lists, and can likely be replaced with a "list_t" directly

SLIST_ is single-link, but hell, start with a "list_t" to begin with.

RB_TREE --> avl_tree_t

	** Define the type:

	RB_HEAD(HEADNAME, ELEM_TYPE)
		HEADNAME as in "struct HEADNAME"
		ELEM_TYPE is the element type

	--> Instead, we just use the "avl_tree_t" type.

	** Forward declaration of implementation functions:
	RB_PROTOTYPE(HEADNAME, ELEM_TYPE, FIELD, COMPARATOR)
	** Function definition:
	RB_GENERATE(HEADNAME, ELEM_TYPE, FIELD, COMPARATOR)

	--> Instead, we provide details in "avl_create()"

	** Define linkage structure (node):

	RB_ENTRY(ELEM_TYPE)

	--> embed "avl_node_t", size/offset provided to "avl_create()"


---------------------
"struct mbuf" -> "mblk_t"

	- allocb(), dupb(), freeb(), freemsg(), etc

Used in "pf.c":

	m_adj(struct mbuf *mp, int req_len):
             Trims req_len bytes of data from the mbuf chain pointed to by mp.
             If req_len is positive, the data will be trimmed from the head of
             the mbuf chain and if it is negative, it will be trimmed from the
             tail of the mbuf chain.

		--> int adjmsg(mblk_t *mp, ssize_t len)

	m_pulldown(struct mbuf *m, int off, int len, int *offp):
             Ensure that the data in the mbuf chain starting at off and ending
             at off+len will be put in a continuous memory region.  len must
             be smaller or equal than MCLBYTES.  The pointer returned points
             to an mbuf in the chain and the new offset for data in this mbuf
             is *offp.  If this function fails, m is freed.

		*** THIS IS ONLY USED IN ONE PLACE, and we could probably
			just "pullupmsg()" or "msgpullup()" here...

	m_split(struct mbuf *m0, int len0, int wait):
             Split an mbuf chain in two pieces, returning a pointer to the
             tail (which is made of the previous mbuf chain except the first
             len0 bytes).

	m_cat(struct mbuf *m, struct mbuf *n):
             Concatenate the mbuf chain pointed to by n to the mbuf chain
             pointed to by m.  The mbuf chains must be of the same type.

		--> "linkb()" ?
			(sticks "n" into "b_cont" on last in chain "m")

	m_copyback(struct mbuf *m0, int off, int len, caddr_t cp):
             Copy data from a buffer pointed to by cp back into the mbuf chain
             pointed to by m0 starting at off bytes from the beginning, ex-
             tending the mbuf chain if necessary.  The mbuf chain must be ini-
             tialized properly, including setting m_len.

		--> "mb_copyback()" from "uts/common/inet/ipf/misc.c" ??

	m_gethdr(M_DONTWAIT, MT_HEADER):
             Return a pointer to an mbuf of the type specified after initial-
             izing it to contain a packet header.  See m_get() for a descrip-
             tion of how.
		m_get(int how, int type)
			Return a pointer to an mbuf of the type specified.
			If the how argument is M_WAITOK, the function may
			call tsleep(9) to await resources.
			If how is M_DONTWAIT and resources are not available,
			m_get() returns NULL.

		** THIS SEEMS TO JUST BE allocation of mbufs of various types.

	m_copym(m, 0, M_COPYALL, M_NOWAIT):
	m_copym(struct mbuf *m, int off, int len, int wait):
             Copy an mbuf chain starting at off bytes from the beginning and
             continuing for len bytes.  If off is zero and m has the M_PKTHDR
             flag set, the header is copied.  If len is M_COPYALL the whole
             mbuf is copied.  The wait parameter can be M_WAIT or M_DONTWAIT.
             It does not copy clusters, it just increases their reference
             count.
	m_copym2(struct mbuf *m, int off, int len, int wait):
             The same as m_copym() except that it copies cluster mbufs, where-
             as m_copym() just increases the reference count of the clusters.

		** WE DO NOT USE this in any form other than M_COPYALL, so
		   this probably devolves to something like "dupmsg()"

	m_freem(struct mbuf *m):
             Free the mbuf chain pointed to by m.

		--> freeb() or freemsg()?

	m_tag_find(): ?

	m_tag_prepend(): ?


---------------------

tsleep() appears to be used to have "pf_purge_thread()" wake up every second to
do work.  This could just be "ddi_periodic_add()" or whatever.


---------------------

struct rwlock / RWLOCK_INITIALIZER()
	- pf_ioctl.c -- pf_consistency_lock


---------------------

FROM GLOBALS TO PER-ZONE STATE:

	One "pf_netstack_t" object will exist for each zone's netstack.

---------------------

POOLS (pool_put, pool_get) BECOME kmem_cache_alloc/free()...

	"pf_state_pl" --> "struct pf_state"


---------------------

	"struct pf_state"
		- pf_create_state()

MODULE INIT:

	pfattach() in "pf_ioctl.c"


