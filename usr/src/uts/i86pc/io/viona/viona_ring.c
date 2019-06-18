/*
 * Copyright (c) 2013  Chris Torek <torek @ torek net>
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 *
 * Copyright 2015 Pluribus Networks Inc.
 * Copyright 2019 Joyent, Inc.
 */


#include <sys/disp.h>

#include "viona_impl.h"

#define	VRING_ALIGN_LEGACY	4096
#define	VRING_MAX_LEN		32768

#define	VRING_SZ_DESCR(qsz)	((qsz) * sizeof (struct virtio_desc))
#define	VRING_SZ_AVAIL(qsz)	((qsz) * sizeof (uint16_t) + 6)
#define	VRING_SZ_USED(qsz)	(((qsz) * sizeof (struct virtio_used)) + 6)
#define	VRING_ALIGN_DESCR	(sizeof (struct virtio_desc))
#define	VRING_ALIGN_AVAIL	(sizeof (uint16_t))
#define	VRING_ALIGN_USED	(sizeof (struct virtio_used))

#define	VRING_PAGES(addr,sz)	\
	(P2ROUNDUP(P2PHASE((addr), PAGESIZE) + (sz), PAGESIZE)/PAGESIZE)

static boolean_t viona_ring_map_legacy(viona_vring_t *);
static void viona_ring_unmap_legacy(viona_vring_t *);
static kthread_t *viona_create_worker(viona_vring_t *);

static boolean_t
viona_ring_lease_expire_cb(void *arg)
{
	viona_vring_t *ring = arg;

	cv_broadcast(&ring->vr_cv);

	/* The lease will be broken asynchronously. */
	return (B_FALSE);
}

static void
viona_ring_lease_drop(viona_vring_t *ring)
{
	ASSERT(MUTEX_HELD(&ring->vr_lock));

	if (ring->vr_lease != NULL) {
		vmm_hold_t *hold = ring->vr_link->l_vm_hold;

		ASSERT(hold != NULL);

		/*
		 * Without an active lease, the ring mappings cannot be
		 * considered valid.
		 */
		viona_ring_unmap_legacy(ring);

		vmm_drv_lease_break(hold, ring->vr_lease);
		ring->vr_lease = NULL;
	}
}

boolean_t
viona_ring_lease_renew(viona_vring_t *ring)
{
	vmm_hold_t *hold = ring->vr_link->l_vm_hold;

	ASSERT(hold != NULL);
	ASSERT(MUTEX_HELD(&ring->vr_lock));

	viona_ring_lease_drop(ring);

	/*
	 * Lease renewal will fail if the VM has requested that all holds be
	 * cleaned up.
	 */
	ring->vr_lease = vmm_drv_lease_sign(hold, viona_ring_lease_expire_cb,
	    ring);
	if (ring->vr_lease != NULL) {
		/* A ring undergoing renewal will need valid guest mappings */
		if (ring->vr_gpa != 0 && ring->vr_size != 0) {
			/*
			 * If new mappings cannot be established, consider the
			 * lease renewal a failure.
			 */
			if (!viona_ring_map_legacy(ring)) {
				viona_ring_lease_drop(ring);
				return (B_FALSE);
			}
		}
	}
	return (ring->vr_lease != NULL);
}

void
viona_ring_alloc(viona_link_t *link, viona_vring_t *ring)
{
	ring->vr_link = link;
	mutex_init(&ring->vr_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&ring->vr_cv, NULL, CV_DRIVER, NULL);
	mutex_init(&ring->vr_a_mutex, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&ring->vr_u_mutex, NULL, MUTEX_DRIVER, NULL);
}

static void
viona_ring_misc_free(viona_vring_t *ring)
{
	const uint_t qsz = ring->vr_size;

	viona_tx_ring_free(ring, qsz);
}

void
viona_ring_free(viona_vring_t *ring)
{
	mutex_destroy(&ring->vr_lock);
	cv_destroy(&ring->vr_cv);
	mutex_destroy(&ring->vr_a_mutex);
	mutex_destroy(&ring->vr_u_mutex);
	ring->vr_link = NULL;
}

int
viona_ring_init(viona_link_t *link, uint16_t idx, uint16_t qsz, uint64_t pa)
{
	viona_vring_t *ring;
	kthread_t *t;
	int err = 0;

	if (idx >= VIONA_VQ_MAX) {
		return (EINVAL);
	}
	if (qsz == 0 || qsz > VRING_MAX_LEN || (1 << (ffs(qsz) - 1)) != qsz) {
		return (EINVAL);
	}

	ring = &link->l_vrings[idx];
	mutex_enter(&ring->vr_lock);
	if (ring->vr_state != VRS_RESET) {
		mutex_exit(&ring->vr_lock);
		return (EBUSY);
	}
	VERIFY(ring->vr_state_flags == 0);

	ring->vr_lease = NULL;
	if (!viona_ring_lease_renew(ring)) {
		err = EBUSY;
		goto fail;
	}

	ring->vr_size = qsz;
	ring->vr_mask = (ring->vr_size - 1);
	ring->vr_gpa = pa;
	if (!viona_ring_map_legacy(ring)) {
		err = EINVAL;
		goto fail;
	}

	/* Initialize queue indexes */
	ring->vr_cur_aidx = 0;

	if (idx == VIONA_VQ_TX) {
		viona_tx_ring_alloc(ring, qsz);
	}

	/* Zero out MSI-X configuration */
	ring->vr_msi_addr = 0;
	ring->vr_msi_msg = 0;

	/* Clear the stats */
	bzero(&ring->vr_stats, sizeof (ring->vr_stats));

	t = viona_create_worker(ring);
	if (t == NULL) {
		err = ENOMEM;
		goto fail;
	}
	ring->vr_worker_thread = t;
	ring->vr_state = VRS_SETUP;
	cv_broadcast(&ring->vr_cv);
	mutex_exit(&ring->vr_lock);
	return (0);

fail:
	viona_ring_lease_drop(ring);
	viona_ring_misc_free(ring);
	ring->vr_size = 0;
	ring->vr_mask = 0;
	mutex_exit(&ring->vr_lock);
	return (err);
}

int
viona_ring_reset(viona_vring_t *ring, boolean_t heed_signals)
{
	mutex_enter(&ring->vr_lock);
	if (ring->vr_state == VRS_RESET) {
		mutex_exit(&ring->vr_lock);
		return (0);
	}

	if ((ring->vr_state_flags & VRSF_REQ_STOP) == 0) {
		ring->vr_state_flags |= VRSF_REQ_STOP;
		cv_broadcast(&ring->vr_cv);
	}
	while (ring->vr_state != VRS_RESET) {
		if (!heed_signals) {
			cv_wait(&ring->vr_cv, &ring->vr_lock);
		} else {
			int rs;

			rs = cv_wait_sig(&ring->vr_cv, &ring->vr_lock);
			if (rs <= 0 && ring->vr_state != VRS_RESET) {
				mutex_exit(&ring->vr_lock);
				return (EINTR);
			}
		}
	}
	viona_ring_lease_drop(ring);
	mutex_exit(&ring->vr_lock);
	return (0);
}

static vmm_page_hold_t *
vring_map_pages(vmm_lease_t *lease, uint64_t gpa, uint_t pages, int prot)
{
	vmm_page_hold_t *holds;
	uint64_t pos;

	holds = kmem_zalloc(sizeof (vmm_page_hold_t) * pages, KM_SLEEP);

	pos = P2ALIGN(gpa, PAGESIZE);
	for (uint_t i = 0; i < pages; i++, pos += PAGESIZE) {
		if (!vmm_drv_gpa_hold(lease, &holds[i], pos, prot)) {
			if (i != 0) {
				do {
					vmm_drv_gpa_rele(lease, &holds[i]);
				} while (i != 0);
			}
			kmem_free(holds, sizeof (vmm_page_hold_t) * pages);
			return (NULL);
		}
	}
	return (holds);
}

static inline caddr_t
vring_addr_at(const vmm_page_hold_t *holds, uint64_t base, uint_t pages,
    uint64_t addr, uint_t size)
{
	const uint64_t offset = addr - base;
	const uint_t skip = offset / PAGESIZE;
	const uint_t poffset = P2PHASE(offset, PAGESIZE);

	ASSERT3U(skip, <, pages);
	ASSERT3U(poffset + size, <=, PAGESIZE);

	return ((caddr_t)holds[skip].vph_kva + poffset);
}

static boolean_t
viona_ring_map_descr(viona_vring_t *ring)
{
	const uint64_t gpa = ring->vr_descr_gpa;
	const uint_t pages = VRING_PAGES(gpa, VRING_SZ_DESCR(ring->vr_size));
	vmm_page_hold_t *holds;

	ASSERT(MUTEX_HELD(&ring->vr_lock));
	ASSERT0(gpa & VRING_ALIGN_DESCR);

	holds = vring_map_pages(ring->vr_lease, gpa, pages, PROT_READ);
	if (holds == NULL) {
		return (B_FALSE);
	}

	ring->vr_descr_pages = pages;
	ring->vr_descr_holds = holds;

	return (B_TRUE);
}

static boolean_t
viona_ring_map_avail(viona_vring_t *ring)
{
	const uint64_t gpa = ring->vr_avail_gpa;
	const uint_t pages = VRING_PAGES(gpa, VRING_SZ_AVAIL(ring->vr_size));
	const uint64_t base = P2ALIGN(gpa, PAGESIZE);
	vmm_page_hold_t *holds;

	ASSERT(MUTEX_HELD(&ring->vr_lock));
	ASSERT0(gpa & VRING_ALIGN_AVAIL);

	holds = vring_map_pages(ring->vr_lease, gpa, pages, PROT_READ);
	if (holds == NULL) {
		return (B_FALSE);
	}

	ring->vr_avail_gpa = gpa;
	ring->vr_avail_holds = holds;
	ring->vr_avail_pages = pages;

	ring->vr_avail_flags = (volatile uint16_t *)vring_addr_at(holds, base,
	    pages, gpa, 2);
	ring->vr_avail_idx = (volatile uint16_t *)vring_addr_at(holds, base,
	    pages, gpa + 2, 2);
	ring->vr_avail_used_event = (volatile uint16_t *)vring_addr_at(holds,
	    base, pages, gpa + 4 + (ring->vr_size * 2),
	    sizeof (uint16_t));

	return (B_TRUE);
}

static boolean_t
viona_ring_map_used(viona_vring_t *ring)
{
	const uint64_t gpa = ring->vr_used_gpa;
	const uint_t pages = VRING_PAGES(gpa, VRING_SZ_USED(ring->vr_size));
	const uint64_t base = P2ALIGN(gpa, PAGESIZE);
	vmm_page_hold_t *holds;

	ASSERT(MUTEX_HELD(&ring->vr_lock));
	ASSERT0(gpa & VRING_ALIGN_USED);

	holds = vring_map_pages(ring->vr_lease, gpa, pages, PROT_WRITE);
	if (holds == NULL) {
		return (B_FALSE);
	}

	ring->vr_used_gpa = gpa;
	ring->vr_used_holds = holds;
	ring->vr_used_pages = pages;

	ring->vr_used_flags = (volatile uint16_t *)vring_addr_at(holds, base,
	    pages, gpa, 2);
	ring->vr_used_idx = (volatile uint16_t *)vring_addr_at(holds, base,
	    pages, gpa + 2, 2);
	ring->vr_used_avail_event = (volatile uint16_t *)vring_addr_at(holds,
	    base, pages, gpa + 4 + (ring->vr_size * 8), 2);

	return (B_TRUE);
}

static void
viona_ring_unmap_descr(viona_vring_t *ring)
{
	const uint_t pages = ring->vr_descr_pages;
	vmm_page_hold_t *holds = ring->vr_descr_holds;

	ASSERT(MUTEX_HELD(&ring->vr_lock));

	for (uint_t i = 0; i < pages; i++) {
		vmm_drv_gpa_rele(ring->vr_lease, &holds[i]);
	}

	ring->vr_descr_pages = 0;
	ring->vr_descr_holds = NULL;
	kmem_free(holds, sizeof (vmm_page_hold_t) * pages);
}

static void
viona_ring_unmap_avail(viona_vring_t *ring)
{
	const uint_t pages = ring->vr_avail_pages;
	vmm_page_hold_t *holds = ring->vr_avail_holds;

	ASSERT(MUTEX_HELD(&ring->vr_lock));

	for (uint_t i = 0; i < pages; i++) {
		vmm_drv_gpa_rele(ring->vr_lease, &holds[i]);
	}

	ring->vr_avail_flags = NULL;
	ring->vr_avail_idx = NULL;
	ring->vr_avail_used_event = NULL;

	ring->vr_avail_pages = 0;
	ring->vr_avail_holds = NULL;
	kmem_free(holds, sizeof (vmm_page_hold_t) * pages);
}

static void
viona_ring_unmap_used(viona_vring_t *ring)
{
	const uint_t pages = ring->vr_used_pages;
	vmm_page_hold_t *holds = ring->vr_used_holds;

	ASSERT(MUTEX_HELD(&ring->vr_lock));
	ASSERT(ring->vr_used_gpa != 0);

	for (uint_t i = 0; i < pages; i++) {
		vmm_drv_gpa_rele(ring->vr_lease, &holds[i]);
	}

	ring->vr_used_flags = NULL;
	ring->vr_used_idx = NULL;
	ring->vr_used_avail_event = NULL;

	ring->vr_used_pages = 0;
	ring->vr_used_holds = NULL;
	kmem_free(holds, sizeof (vmm_page_hold_t) * pages);
}

static boolean_t
viona_ring_map_legacy(viona_vring_t *ring)
{
	const uint16_t qsz = ring->vr_size;

	ASSERT3U(qsz, !=, 0);
	ASSERT3U(pos, !=, 0);
	ASSERT(MUTEX_HELD(&ring->vr_lock));

	/* Expecting page alignment for a legacy ring */
	if ((ring->vr_gpa & PAGEOFFSET) != 0) {
		return (B_FALSE);
	}

	ring->vr_descr_gpa = ring->vr_gpa;
	ring->vr_avail_gpa = ring->vr_descr_gpa + VRING_SZ_DESCR(qsz);
	ring->vr_used_gpa = P2ALIGN(ring->vr_avail_gpa + VRING_SZ_AVAIL(qsz),
	    PAGESIZE);

	if (!viona_ring_map_descr(ring)) {
		goto fail;
	}
	if (!viona_ring_map_avail(ring)) {
		viona_ring_unmap_descr(ring);
		goto fail;
	}
	if (!viona_ring_map_used(ring)) {
		viona_ring_unmap_descr(ring);
		viona_ring_unmap_avail(ring);
		goto fail;
	}
	return (B_TRUE);

fail:
	ring->vr_descr_gpa = 0;
	ring->vr_avail_gpa = 0;
	ring->vr_used_gpa = 0;
	return (B_FALSE);
}

static void
viona_ring_unmap_legacy(viona_vring_t *ring)
{
	ASSERT(MUTEX_HELD(&ring->vr_lock));

	if (ring->vr_descr_gpa != 0) {
		ASSERT(ring->vr_avail_gpa);
		ASSERT(ring->vr_used_gpa);

		viona_ring_unmap_descr(ring);
		viona_ring_unmap_avail(ring);
		viona_ring_unmap_used(ring);
		ring->vr_descr_gpa = 0;
		ring->vr_avail_gpa = 0;
		ring->vr_used_gpa = 0;
	}
}

static inline struct virtio_desc
vring_read_descr(viona_vring_t *ring, uint_t idx)
{
	ASSERT(MUTEX_HELD(&ring->vr_a_mutex));
	ASSERT(ring->vr_descr_gpa != 0);

	volatile struct virtio_desc *valp = (struct virtio_desc *)
	    vring_addr_at(ring->vr_descr_holds,
	    P2ALIGN(ring->vr_descr_gpa, PAGESIZE),
	    ring->vr_descr_pages,
	    ring->vr_descr_gpa + (idx * sizeof (struct virtio_desc)),
	    sizeof (struct virtio_desc));

	return (*valp);
}

static inline uint16_t
vring_read_avail(viona_vring_t *ring, uint_t idx)
{
	ASSERT(MUTEX_HELD(&ring->vr_a_mutex));
	ASSERT(ring->vr_avail_gpa != 0);

	const uint_t midx = idx & ring->vr_mask;
	volatile uint16_t *valp = (uint16_t *)
	    vring_addr_at(ring->vr_avail_holds,
	    P2ALIGN(ring->vr_avail_gpa, PAGESIZE),
	    ring->vr_avail_pages,
	    ring->vr_avail_gpa + 4 + (midx * 2),
	    2);

	return (*valp);
}

static inline void
vring_write_used(viona_vring_t *ring, uint_t idx, uint16_t id, uint32_t len)
{
	ASSERT(MUTEX_HELD(&ring->vr_u_mutex));
	ASSERT(ring->vr_used_gpa != 0);

	const uint_t midx = idx & ring->vr_mask;
	volatile struct virtio_used *vu = (struct virtio_used *)
	    vring_addr_at(ring->vr_used_holds,
	    P2ALIGN(ring->vr_used_gpa, PAGESIZE),
	    ring->vr_used_pages,
	    ring->vr_used_gpa + 4 + (midx * 8),
	    2);

	vu->vu_idx = id;
	vu->vu_tlen = len;
}

void
viona_intr_ring(viona_vring_t *ring)
{
	uint64_t addr;

	mutex_enter(&ring->vr_lock);
	/* Deliver the interrupt directly, if so configured. */
	if ((addr = ring->vr_msi_addr) != 0) {
		uint64_t msg = ring->vr_msi_msg;

		mutex_exit(&ring->vr_lock);
		(void) vmm_drv_msi(ring->vr_lease, addr, msg);
		return;
	}
	mutex_exit(&ring->vr_lock);

	if (atomic_cas_uint(&ring->vr_intr_enabled, 0, 1) == 0) {
		pollwakeup(&ring->vr_link->l_pollhead, POLLRDBAND);
	}
}

static void
viona_worker(void *arg)
{
	viona_vring_t *ring = (viona_vring_t *)arg;
	viona_link_t *link = ring->vr_link;
	proc_t *p = ttoproc(curthread);

	mutex_enter(&ring->vr_lock);
	VERIFY3U(ring->vr_state, ==, VRS_SETUP);

	/* Bail immediately if ring shutdown or process exit was requested */
	if (VRING_NEED_BAIL(ring, p)) {
		goto cleanup;
	}

	/* Report worker thread as alive and notify creator */
	ring->vr_state = VRS_INIT;
	cv_broadcast(&ring->vr_cv);

	while (ring->vr_state_flags == 0) {
		/*
		 * Keeping lease renewals timely while waiting for the ring to
		 * be started is important for avoiding deadlocks.
		 */
		if (vmm_drv_lease_expired(ring->vr_lease)) {
			if (!viona_ring_lease_renew(ring)) {
				goto cleanup;
			}
		}

		(void) cv_wait_sig(&ring->vr_cv, &ring->vr_lock);

		if (VRING_NEED_BAIL(ring, p)) {
			goto cleanup;
		}
	}

	ASSERT((ring->vr_state_flags & VRSF_REQ_START) != 0);
	ring->vr_state = VRS_RUN;
	ring->vr_state_flags &= ~VRSF_REQ_START;

	/* Ensure ring lease is valid first */
	if (vmm_drv_lease_expired(ring->vr_lease)) {
		if (!viona_ring_lease_renew(ring)) {
			goto cleanup;
		}
	}

	/* Process actual work */
	if (ring == &link->l_vrings[VIONA_VQ_RX]) {
		viona_worker_rx(ring, link);
	} else if (ring == &link->l_vrings[VIONA_VQ_TX]) {
		viona_worker_tx(ring, link);
	} else {
		panic("unexpected ring: %p", (void *)ring);
	}

cleanup:
	if (ring->vr_txdesb != NULL) {
		/*
		 * Transmit activity must be entirely concluded before the
		 * associated descriptors can be cleaned up.
		 */
		VERIFY(ring->vr_xfer_outstanding == 0);
	}
	viona_ring_misc_free(ring);

	viona_ring_lease_drop(ring);
	ring->vr_cur_aidx = 0;
	ring->vr_state = VRS_RESET;
	ring->vr_state_flags = 0;
	ring->vr_worker_thread = NULL;
	cv_broadcast(&ring->vr_cv);
	mutex_exit(&ring->vr_lock);

	mutex_enter(&ttoproc(curthread)->p_lock);
	lwp_exit();
}

static kthread_t *
viona_create_worker(viona_vring_t *ring)
{
	k_sigset_t hold_set;
	proc_t *p = curproc;
	kthread_t *t;
	klwp_t *lwp;

	ASSERT(MUTEX_HELD(&ring->vr_lock));
	ASSERT(ring->vr_state == VRS_RESET);

	sigfillset(&hold_set);
	lwp = lwp_create(viona_worker, (void *)ring, 0, p, TS_STOPPED,
	    minclsyspri - 1, &hold_set, curthread->t_cid, 0);
	if (lwp == NULL) {
		return (NULL);
	}

	t = lwptot(lwp);
	mutex_enter(&p->p_lock);
	t->t_proc_flag = (t->t_proc_flag & ~TP_HOLDLWP) | TP_KTHREAD;
	lwp_create_done(t);
	mutex_exit(&p->p_lock);

	return (t);
}

static uint_t
vq_popchain_direct(viona_vring_t *ring, const struct virtio_desc *vd,
    vring_iovec_t *iov, uint_t niov, uint_t i)
{
	if (vdir.vd_len == 0) {
		VIONA_PROBE2(desc_bad_len,
		    viona_vring_t *, ring,
		    uint32_t, vdir.vd_len);
		VIONA_RING_STAT_INCR(ring, desc_bad_len);
		goto bail;
	}
	uint_t pages = VRING_PAGES(vd->vd_addr, vd->vd_len);

	ASSERT(i < niov);

	if (pages == 1) {
		uint_t off = P2PHASE(vd->vd_addr, PAGESIZE);
		uint64_t base = P2ALIGN(vd->vd_addr, PAGESIZE);

		if (!vmm_drv_gpa_hold(ring->vr_lease, &iov[i].riov_hold, base,
		    PROT_READ|PROT_WRITE)) {
			/* XXX bail-out handline */
		}
		iov[i].riov_offset = off;
		iov[i].riov_len = vd.vd_len;
		return (i + 1);
	} else {
		/*
		 * The guest has provided a descriptor referring to a
		 * guest-physical contiguous mapping.  With no guarantee (or
		 * frankly, likelihood) of it being host-physical contiguous,
		 * treat it like multiple descriptors.
		 */

		if ((i + pages) >= niov) {
			/* bail if there is not adequate room */
			return (i);
		}
		while (vd.vd_len > 0) {
			uint_t off = P2PHASE(vd->vd_addr, PAGESIZE);
			uint64_t base = P2ALIGN(vd->vd_addr, PAGESIZE);
			if (!vmm_drv_gpa_hold(ring->vr_lease, &iov[i].riov_hold,
			    base, PROT_READ|PROT_WRITE)) {
				/* XXX bail-out handline */
			}
			iov[i].riov_offset = off;
			iov[i].riov_len = PAGESIZE - off;
			i++;
		}
	}

	buf = viona_gpa2kva(ring, vdir.vd_addr, vdir.vd_len);
	if (buf == NULL) {
		VIONA_PROBE_BAD_RING_ADDR(ring, vdir.vd_addr);
		VIONA_RING_STAT_INCR(ring, bad_ring_addr);
		goto bail;
	}
	iov[i].iov_base = buf;
	iov[i].iov_len = vdir.vd_len;
	i++;
}

static uint_t
vq_popchain_indirect(viona_vring_t *ring, const struct virtio_desc *vd,
    vring_iovec_t *iov, uint_t niov, uint_t i)
{
	const uint_t nindir = vd->vd_len / sizeof (struct virtio_desc);

	if (P2PHASE(vd->vd_len, sizeof (struct virtio_desc)) != 0 ||
	    nindir == 0) {
		VIONA_PROBE2(indir_bad_len, viona_vring_t *, ring,
		    uint32_t, vd->vd_len);
		VIONA_RING_STAT_INCR(ring, indir_bad_len);
		goto bail;
	}


	const uint_t pages = VRING_PAGES(vd->vd_addr, vd->vd_len);

	vindir = viona_gpa2kva(ring, vdir.vd_addr, vdir.vd_len);
	if (vindir == NULL) {
		VIONA_PROBE_BAD_RING_ADDR(ring, vdir.vd_addr);
		VIONA_RING_STAT_INCR(ring, bad_ring_addr);
		goto bail;
	}
	next = 0;
	for (;;) {
		struct virtio_desc vp;

		/*
		 * A copy of the indirect descriptor is made
		 * here, rather than simply using a reference
		 * pointer.  This prevents malicious or
		 * erroneous guest writes to the descriptor
		 * from fooling the flags/bounds verification
		 * through a race.
		 */
		vp = vindir[next];
		if (vp.vd_flags & VRING_DESC_F_INDIRECT) {
			VIONA_PROBE1(indir_bad_nest,
			    viona_vring_t *, ring);
			VIONA_RING_STAT_INCR(ring,
			    indir_bad_nest);
			goto bail;
		} else if (vp.vd_len == 0) {
			VIONA_PROBE2(desc_bad_len,
			    viona_vring_t *, ring,
			    uint32_t, vp.vd_len);
			VIONA_RING_STAT_INCR(ring,
			    desc_bad_len);
			goto bail;
		}
		buf = viona_gpa2kva(ring, vp.vd_addr,
		    vp.vd_len);
		if (buf == NULL) {
			VIONA_PROBE_BAD_RING_ADDR(ring,
			    vp.vd_addr);
			VIONA_RING_STAT_INCR(ring,
			    bad_ring_addr);
			goto bail;
		}
		iov[i].iov_base = buf;
		iov[i].iov_len = vp.vd_len;
		i++;

		if ((vp.vd_flags & VRING_DESC_F_NEXT) == 0)
			break;
		if (i >= niov) {
			goto loopy;
		}

		next = vp.vd_next;
		if (next >= nindir) {
			VIONA_PROBE3(indir_bad_next,
			    viona_vring_t *, ring,
			    uint16_t, next,
			    uint_t, nindir);
			VIONA_RING_STAT_INCR(ring,
			    indir_bad_next);
			goto bail;
		}
	}
}

int
vq_popchain(viona_vring_t *ring, ring_iovec_t *iov, uint_t niov,
    uint16_t *cookie)
{
	uint_t i, ndesc, idx, head, next;
	struct virtio_desc vdir;
	void *buf;

	ASSERT(iov != NULL);
	ASSERT(niov > 0 && niov < INT_MAX);

	mutex_enter(&ring->vr_a_mutex);
	idx = ring->vr_cur_aidx;
	ndesc = (uint16_t)((unsigned)*ring->vr_avail_idx - (unsigned)idx);

	if (ndesc == 0) {
		mutex_exit(&ring->vr_a_mutex);
		return (0);
	}
	if (ndesc > ring->vr_size) {
		/*
		 * Despite the fact that the guest has provided an 'avail_idx'
		 * which indicates that an impossible number of descriptors are
		 * available, continue on and attempt to process the next one.
		 *
		 * The transgression will not escape the probe or stats though.
		 */
		VIONA_PROBE2(ndesc_too_high, viona_vring_t *, ring,
		    uint16_t, ndesc);
		VIONA_RING_STAT_INCR(ring, ndesc_too_high);
	}

	head = vring_read_avail(ring, idx);
	next = head;

	for (i = 0; i < niov; next = vdir.vd_next) {
		if (next >= ring->vr_size) {
			VIONA_PROBE2(bad_idx, viona_vring_t *, ring,
			    uint16_t, next);
			VIONA_RING_STAT_INCR(ring, bad_idx);
			goto bail;
		}

		vdir = vring_read_descr(ring, next);
		if ((vdir.vd_flags & VRING_DESC_F_INDIRECT) == 0) {
			if (vdir.vd_len == 0) {
				VIONA_PROBE2(desc_bad_len,
				    viona_vring_t *, ring,
				    uint32_t, vdir.vd_len);
				VIONA_RING_STAT_INCR(ring, desc_bad_len);
				goto bail;
			}
			vq_popchain_direct(ring, &vdir)

			iov[i].iov_base = buf;
			iov[i].iov_len = vdir.vd_len;
			i++;
		} else {
			vq_popchain_indirect(ring, &vdir);


			const uint_t nindir = vdir.vd_len / 16;
			volatile struct virtio_desc *vindir;

			if ((vdir.vd_len & 0xf) || nindir == 0) {
				VIONA_PROBE2(indir_bad_len,
				    viona_vring_t *, ring,
				    uint32_t, vdir.vd_len);
				VIONA_RING_STAT_INCR(ring, indir_bad_len);
				goto bail;
			}
			vindir = viona_gpa2kva(ring, vdir.vd_addr, vdir.vd_len);
			if (vindir == NULL) {
				VIONA_PROBE_BAD_RING_ADDR(ring, vdir.vd_addr);
				VIONA_RING_STAT_INCR(ring, bad_ring_addr);
				goto bail;
			}
			next = 0;
			for (;;) {
				struct virtio_desc vp;

				/*
				 * A copy of the indirect descriptor is made
				 * here, rather than simply using a reference
				 * pointer.  This prevents malicious or
				 * erroneous guest writes to the descriptor
				 * from fooling the flags/bounds verification
				 * through a race.
				 */
				vp = vindir[next];
				if (vp.vd_flags & VRING_DESC_F_INDIRECT) {
					VIONA_PROBE1(indir_bad_nest,
					    viona_vring_t *, ring);
					VIONA_RING_STAT_INCR(ring,
					    indir_bad_nest);
					goto bail;
				} else if (vp.vd_len == 0) {
					VIONA_PROBE2(desc_bad_len,
					    viona_vring_t *, ring,
					    uint32_t, vp.vd_len);
					VIONA_RING_STAT_INCR(ring,
					    desc_bad_len);
					goto bail;
				}
				buf = viona_gpa2kva(ring, vp.vd_addr,
				    vp.vd_len);
				if (buf == NULL) {
					VIONA_PROBE_BAD_RING_ADDR(ring,
					    vp.vd_addr);
					VIONA_RING_STAT_INCR(ring,
					    bad_ring_addr);
					goto bail;
				}
				iov[i].iov_base = buf;
				iov[i].iov_len = vp.vd_len;
				i++;

				if ((vp.vd_flags & VRING_DESC_F_NEXT) == 0)
					break;
				if (i >= niov) {
					goto loopy;
				}

				next = vp.vd_next;
				if (next >= nindir) {
					VIONA_PROBE3(indir_bad_next,
					    viona_vring_t *, ring,
					    uint16_t, next,
					    uint_t, nindir);
					VIONA_RING_STAT_INCR(ring,
					    indir_bad_next);
					goto bail;
				}
			}
		}
		if ((vdir.vd_flags & VRING_DESC_F_NEXT) == 0) {
			*cookie = head;
			ring->vr_cur_aidx++;
			mutex_exit(&ring->vr_a_mutex);
			return (i);
		}
	}

loopy:
	VIONA_PROBE1(too_many_desc, viona_vring_t *, ring);
	VIONA_RING_STAT_INCR(ring, too_many_desc);
bail:
	mutex_exit(&ring->vr_a_mutex);
	return (-1);
}

void
vq_pushchain(viona_vring_t *ring, uint32_t len, uint16_t cookie)
{
	uint_t uidx;

	mutex_enter(&ring->vr_u_mutex);

	uidx = ring->vr_cur_uidx;
	vring_write_used(ring, uidx, cookie, len);
	uidx++;
	membar_producer();
	*ring->vr_used_idx = uidx;
	ring->vr_cur_uidx = uidx;

	mutex_exit(&ring->vr_u_mutex);
}

void
vq_pushchain_many(viona_vring_t *ring, uint_t num_bufs, used_elem_t *elem)
{
	uint_t uidx;

	ASSERT(num_bufs <= ring->vr_size);

	mutex_enter(&ring->vr_u_mutex);

	uidx = ring->vr_cur_uidx;
	for (uint_t i = 0; i < num_bufs; i++) {
		vring_write_used(ring, uidx, elem[i].id, elem[i].len);
		uidx++;
	}
	membar_producer();
	*ring->vr_used_idx = uidx;
	ring->vr_cur_uidx = uidx;

	mutex_exit(&ring->vr_u_mutex);
}
