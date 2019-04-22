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
 * Copyright 2019 Joyent, Inc.
 */

#include "vioscsi.h"

void
vioscsi_dma_free(vioscsi_dma_t *vsdma)
{
	if (vsdma->vsdma_level & VIOSCSI_DMALEVEL_HANDLE_BOUND) {
		VERIFY3U(ddi_dma_unbind_handle(vsdma->vsdma_dma_handle), ==,
		    DDI_SUCCESS);

		vsdma->vsdma_level &= ~VIOSCSI_DMALEVEL_HANDLE_BOUND;
	}

	if (vsdma->vsdma_level & VIOSCSI_DMALEVEL_MEMORY_ALLOC) {
		ddi_dma_mem_free(&vsdma->vsdma_acc_handle);

		vsdma->vsdma_level &= ~VIOSCSI_DMALEVEL_MEMORY_ALLOC;
	}

	if (vsdma->vsdma_level & VIOSCSI_DMALEVEL_HANDLE_ALLOC) {
		ddi_dma_free_handle(&vsdma->vsdma_dma_handle);

		vsdma->vsdma_level &= ~VIOSCSI_DMALEVEL_HANDLE_ALLOC;
	}
}

int
vioscsi_dma_alloc(vioscsi_t *vis, vioscsi_dma_t *vsdma, size_t sz,
    int kmflags, void **vap, uint32_t *pap)
{
	caddr_t va;
	int r;
	dev_info_t *dip = vis->vis_dip;
	int (*dma_wait)(caddr_t) = (kmflags == KM_SLEEP) ? DDI_DMA_SLEEP :
	    DDI_DMA_DONTWAIT;

	VERIFY(kmflags == KM_SLEEP || kmflags == KM_NOSLEEP);

	VERIFY0(vsdma->vsdma_level);

	if ((r = ddi_dma_alloc_handle(dip, &vioscsi_dma_attr,
	    dma_wait, NULL, &vsdma->vsdma_dma_handle)) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "DMA handle allocation failed (%x)", r);
		goto fail;
	}
	vsdma->vsdma_level |= VIOSCSI_DMALEVEL_HANDLE_ALLOC;

	if ((r = ddi_dma_mem_alloc(vsdma->vsdma_dma_handle, sz,
	    &virtio_attr /* XXX */, DDI_DMA_CONSISTENT, dma_wait, NULL,
	    &va, &vsdma->vsdma_real_size, &vsdma->vsdma_acc_handle)) !=
	    DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "DMA memory allocation failed (%x)", r);
		goto fail;
	}
	vsdma->vsdma_level |= VIOSCSI_DMALEVEL_MEMORY_ALLOC;

	/*
	 * Prepare a binding that can be used for both read and write.  We'll
	 * split the binding up into virtqueue descriptor entries each with the
	 * appropriate read or write direction for the command.
	 */
	if ((r = ddi_dma_addr_bind_handle(vsdma->vsdma_dma_handle,
	    NULL, va, vsdma->vsdma_real_size,
	    DDI_DMA_CONSISTENT | DDI_DMA_RDWR, dma_wait, NULL,
	    vsdma->vsdma_cookies, &vsdma->vsdma_ncookies)) !=
	    DDI_DMA_MAPPED) {
		dev_err(dip, CE_WARN, "DMA handle bind failed (%x)", r);
		goto fail;
	}
	vsdma->vsdma_level |= VIOSCSI_DMALEVEL_HANDLE_BOUND;

	VERIFY3U(vsdma->vsdma_ncookies, ==, 1);
	*pap = vsdma->vsdma_cookies[0].dmac_address;
	*vap = (void *)va;
	return (DDI_SUCCESS);

fail:
	*vap = NULL;
	*pap = 0;
	vioscsi_dma_free(vsdma);
	return (DDI_FAILURE);
}

vioscsi_cmd_t *
vioscsi_cmd_alloc(vioscsi_t *vis, vioscsi_q_t *visq, size_t sz)
{
	int kmflags = KM_SLEEP;

	vioscsi_cmd_t *vsc;
	if ((vsc = kmem_zalloc(sizeof (*vsc), kmflags)) == NULL) {
		return (NULL);
	}
	vsc->vsc_vioscsi = vis;
	vsc->vsc_q = visq;

	if (vioscsi_dma_alloc(vis, &vsc->vsc_dma, sz, kmflags,
	    &vsc->vsc_va, &vsc->vsc_pa) != DDI_SUCCESS) {
		kmem_free(vsc, sizeof (*vsc));
		return (NULL);
	}
	vsc->vsc_sz = sz;

	bzero(vsc->vsc_va, vsc->vsc_dma.vsdma_real_size); /* XXX? */

	return (vsc);
}

#if 0
/*
 * Change the reserved descriptor count for this command.
 */
static int
vioscsi_cmd_reserve(vioscsi_cmd_t *vsc, uint_t count)
{
	if (count > 64) {
		return (EINVAL);
	}

	/*
	 * Count how many descriptors are currently reserved.
	 */
	uint_t actual = 0;
	for (uint_t i = 0; i < 64; i++) {
		if (vsc->vsc_reserved[i] != NULL) {
			actual++;
		}
	}

	if (actual > count) {
	} else if (actual < count) {
	}
}
#endif

void
vioscsi_cmd_free(vioscsi_cmd_t *vsc)
{
	if (vsc->vsc_qe != NULL) {
		virtio_free_chain(vsc->vsc_qe);
	}
	vioscsi_dma_free(&vsc->vsc_dma);
	kmem_free(vsc, sizeof (*vsc));
}

void
vioscsi_cmd_clear(vioscsi_cmd_t *vsc)
{
	if (vsc->vsc_qe != NULL) {
		virtio_free_chain(vsc->vsc_qe);
		vsc->vsc_qe = NULL;
	}
}

/*
 * Append a descriptor.
 */
struct vq_entry *
vioscsi_cmd_append(vioscsi_cmd_t *vsc)
{
	struct vq_entry *qe;

	if ((qe = vq_alloc_entry(vsc->vsc_q->visq_vq)) == NULL) {
		return (NULL);
	}

	if (vsc->vsc_qe == NULL) {
		/*
		 * This is the first descriptor in the chain.
		 */
		vsc->vsc_qe = qe;
	} else {
		/*
		 * There are descriptors already.  Find the last one and append
		 * the new entry.
		 */
		struct vq_entry *last = vsc->vsc_qe;

		while (last->qe_next != NULL) {
			last = last->qe_next;
		}

		virtio_ventry_stick(last, qe);
	}

	return (qe);
}

void
vioscsi_q_fini(vioscsi_q_t *visq)
{
	if (!visq->visq_init) {
		return;
	}

	VERIFY(avl_is_empty(&visq->visq_inflight));
	avl_destroy(&visq->visq_inflight);

	virtio_free_vq(visq->visq_vq);
	visq->visq_vq = NULL;

	visq->visq_init = B_FALSE;
}

void
vioscsi_q_push(vioscsi_cmd_t *vsc)
{
	vioscsi_t *vis = vsc->vsc_vioscsi;
	vioscsi_q_t *visq = vsc->vsc_q;

	VERIFY(MUTEX_HELD(&vis->vis_mutex));

	VERIFY3P(vsc->vsc_qe, !=, NULL);

	VERIFY0(vsc->vsc_vqidx); /* XXX 0 is valid surely */
	vsc->vsc_vqidx = vsc->vsc_qe->qe_index;

	if (ddi_dma_sync(vsc->vsc_dma.vsdma_dma_handle, 0, 0,
	    DDI_DMA_SYNC_FORDEV) != DDI_SUCCESS) {
		/*
		 * XXX PANIC?
		 */
		dev_err(vis->vis_dip, CE_WARN, "DMA sync failure");
	}

	VERIFY(!(vsc->vsc_status & VIOSCSI_CMD_STATUS_INFLIGHT));
	avl_add(&visq->visq_inflight, vsc);
	vsc->vsc_status |= VIOSCSI_CMD_STATUS_INFLIGHT;

	dev_err(vis->vis_dip, CE_WARN, "q %d push idx %x", visq->visq_name,
	    (uint_t)vsc->vsc_qe->qe_index);

	vsc->vsc_time_push = gethrtime();

	virtio_push_chain(vsc->vsc_qe, B_TRUE);
}

vioscsi_cmd_t *
vioscsi_q_pull(vioscsi_q_t *visq)
{
	vioscsi_t *vis = visq->visq_vioscsi;
	struct vq_entry *qe;
	uint32_t len;

	VERIFY(MUTEX_HELD(&vis->vis_mutex));

top:
	if ((qe = virtio_pull_chain(visq->visq_vq, &len)) == NULL) {
		return (NULL);
	}

	dev_err(vis->vis_dip, CE_WARN, "q %d pull idx %x", visq->visq_name,
	    (uint_t)qe->qe_index);

	vioscsi_cmd_t search;
	search.vsc_q = visq;
	search.vsc_vqidx = qe->qe_index;

	vioscsi_cmd_t *vsc = avl_find(&visq->visq_inflight, &search, NULL);
	if (vsc == NULL) {
		/*
		 * XXX panic?
		 */
		dev_err(vis->vis_dip, CE_WARN, "no command!");
		virtio_free_chain(qe);
		goto top;
	}
	VERIFY3P(vsc->vsc_qe, ==, qe);
	VERIFY3U(vsc->vsc_vqidx, ==, vsc->vsc_qe->qe_index);

	VERIFY(vsc->vsc_status & VIOSCSI_CMD_STATUS_INFLIGHT);
	vsc->vsc_status &= ~VIOSCSI_CMD_STATUS_INFLIGHT;

	avl_remove(&visq->visq_inflight, vsc);
	vsc->vsc_vqidx = 0; /* XXX isn't 0 a valid idx? :( */

	if (ddi_dma_sync(vsc->vsc_dma.vsdma_dma_handle, 0, 0,
	    DDI_DMA_SYNC_FORCPU) != DDI_SUCCESS) {
		/*
		 * XXX panic?
		 */
		dev_err(vis->vis_dip, CE_WARN, "DMA sync failure");
	}

	return (vsc);
}

int
vioscsi_q_init(vioscsi_t *vis, vioscsi_q_t *visq, const char *strname,
    uint32_t index, vioscsi_queue_name_t name)
{
	VERIFY(!visq->visq_init);

	if ((visq->visq_vq = virtio_alloc_vq(&vis->vis_virtio,
	    index, 0, 0, strname)) == NULL) {
		return (DDI_FAILURE);
	}

	virtio_start_vq_intr(visq->visq_vq);

	avl_create(&visq->visq_inflight, vioscsi_cmd_comparator,
	    sizeof (vioscsi_cmd_t), offsetof(vioscsi_cmd_t, vsc_node));

	visq->visq_vioscsi = vis;
	visq->visq_init = B_TRUE;
	return (DDI_SUCCESS);
}

int
vioscsi_cmd_comparator(const void *lp, const void *rp)
{
	const vioscsi_cmd_t *l = lp;
	const vioscsi_cmd_t *r = rp;

	/*
	 * Make sure we're comparing descriptor indexes for the same virtqueue.
	 */
	VERIFY3P(l->vsc_q, ==, r->vsc_q);

	if (l->vsc_vqidx > r->vsc_vqidx) {
		return (1);
	} else if (l->vsc_vqidx < r->vsc_vqidx) {
		return (-1);
	} else {
		return (0);
	}
}
