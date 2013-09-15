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
 * Copyright (c) 2013 Joyent, Inc.  All rights reserved.
 */

#ifndef _SYS_MUTEX_IMPL_H
#define	_SYS_MUTEX_IMPL_H

/*
 * ARM mutex implementaiton
 */

#ifndef	_ASM
#include <sys/types.h>
#include <sys/machlock.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define	MUTEX_THREAD		(-0x8)
#ifndef _ASM

/*
 * Per the rules of the mutex big theory statement, mutex_enter() assumes that
 * the lock is of an adaptive type and will try only once to do an atomic
 * compare and swap on the first work of the mutex. A failure can happen for two
 * different reasons due to the _m_owner field being non zero and due to ARM
 * specific locking behavior:
 *
 *   o The lock is a spin lock and thus we always fail by design.
 *
 *   o The adaptive lock is already held.
 *
 *   o The strex fails
 *
 * Both of these will cause us to venture into mutex_vector_enter. Note that we
 * do not go into mutex_vector_enter on strdex failure. More explaination can be
 * found in uts/arm/ml/lock_prim.s.
 */
typedef union mutex_impl {

	/*
	 * Adaptive mutex
	 */
	struct adaptive_mutex {
		uintptr_t _m_owner;	/* 0-3 owner and waiters */
		uintptr_t _m_filler;	/* unused */
	} m_adaptive;

	/*
	 * Spin Mutex
	 */
	struct spin_mutex {
		lock_t	m_dummylock;	/* 0	dummy lock (always set) */
		lock_t	m_spinlock;	/* 1	real lock */
		ushort_t m_filler;	/* 2-3	unused */
		ushort_t m_oldspl;	/* 4-5	old pil value */
		ushort_t m_minspl;	/* 6-7	min pil val if lock held */
	} m_spin;

} mutex_impl_t;

/*
 * Name space polluting garbage required by uts/common/os/mutex.c.
 */
#define	m_owner	m_adaptive._m_owner

/*
 * Definitions used for platform specific behavior.
 */

#define	MUTEX_ALIGN	_LONG_ALIGNMENT
#define	MUTEX_ALIGN_WARNINGS	10

#define	MUTEX_WAITERS		0x1
#define	MUTEX_DEAD		0x6

#define	MUTEX_OWNER(lp)		((kthread_id_t)((lp)->m_owner & MUTEX_THREAD))
#define	MUTEX_NO_OWNER		((kthread_id_t)NULL)

#define	MUTEX_SET_WAITERS(lp)						\
{									\
	uintptr_t old;							\
	while ((old = (lp)->m_adaptive._m_owner) != 0 &&		\
	    casip(&(lp)->m_adaptive._m_owner, old,			\
	    old | MUTEX_WAITERS) != old)				\
		continue;						\
}

#define	MUTEX_HAS_WAITERS(lp)			((lp)->m_owner & MUTEX_WAITERS)
#define	MUTEX_CLEAR_LOCK_AND_WAITERS(lp)	(lp)->m_owner = 0

#define	MUTEX_SET_TYPE(lp, type)
#define	MUTEX_TYPE_ADAPTIVE(lp)	(((lp)->m_owner & MUTEX_DEAD) == 0)
#define	MUTEX_TYPE_SPIN(lp)	((lp)->m_spin.m_dummylock == LOCK_HELD_VALUE)

#define	MUTEX_DESTROY(lp)	\
	(lp)->m_owner = ((uintptr_t)curthread | MUTEX_DEAD)

/* mutex backoff delay macro and constants, taken from x86  */
#define	MUTEX_BACKOFF_BASE	1
#define	MUTEX_BACKOFF_SHIFT	2
#define	MUTEX_CAP_FACTOR	64
#define	MUTEX_DELAY()	{ \
				mutex_delay(); \
			}

/* low-overhead clock read */
/* XXX When we have a better sense of the bsm modules and time, revisit this. */
extern hrtime_t mutex_gettick();
#define	MUTEX_GETTICK()	mutex_gettick()
#define	MUTEX_SYNC()	panic("mutex_sync");

extern int mutex_adaptive_tryenter(mutex_impl_t *);
extern void *mutex_owner_running(mutex_impl_t *);

#endif	/* _ASM */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_MUTEX_IMPL_H */
