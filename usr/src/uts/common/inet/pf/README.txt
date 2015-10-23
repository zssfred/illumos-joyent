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


---------------------
"struct mbuf" -> "mblk_t"

Used in "pf.c":

	m_adj():

	m_pulldown():

	m_split():

	m_cat():

	m_copyback():

	m_gethdr(M_DONTWAIT, MT_HEADER):

	m_copym(m, 0, M_COPYALL, M_NOWAIT):

	m_copym2():

	m_freem():

	m_tag_find(): ?

	m_tag_prepend(): ?


