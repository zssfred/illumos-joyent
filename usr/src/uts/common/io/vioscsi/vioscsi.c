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

#include <sys/conf.h>
#include <sys/devops.h>
#include <sys/modctl.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/containerof.h>
#include <sys/debug.h>
#include "virtiovar.h"
#include "virtioreg.h"

#include <sys/pci.h> /* XXX remove after splitting into common code? */

/*
 * VIRTIO SCSI FEATURE BITS
 */

#define	VIRTIO_SCSI_F_INOUT		(1ULL << 0)
/*
 * A single request can include both device-readable and device-writable data
 * buffers.
 */

#define	VIRTIO_SCSI_F_HOTPLUG		(1ULL << 1)
/*
 * The host SHOULD enable reporting of hot-plug and hot-unplug events for LUNs
 * and targets on the SCSI bus. The guest SHOULD handle hot-plug and hot-unplug
 * events.
 */

#define	VIRTIO_SCSI_F_CHANGE		(1ULL << 2)
/*
 * The host will report changes to LUN parameters via a
 * VIRTIO_SCSI_T_PARAM_CHANGE event; the guest SHOULD handle them. 
 */

#define	VIRTIO_SCSI_F_T10_PI		(1ULL << 3)
/*
 * The extended fields for T10 protection information (DIF/DIX) are included in
 * the SCSI request header.
 */

/*
 * VIRTIO SCSI CONFIGURATION REGISTERS
 */
#define	VIRTIO_SCSI_CFG_NUM_QUEUES	0x00	/* 32 */
#define	VIRTIO_SCSI_CFG_SEG_MAX		0x04	/* 32 */
#define	VIRTIO_SCSI_CFG_MAX_SECTORS	0x08	/* 32 */
#define	VIRTIO_SCSI_CFG_CMD_PER_LUN	0x0c	/* 32 */
#define	VIRTIO_SCSI_CFG_EVENT_INFO_SIZE	0x10	/* 32 */
#define	VIRTIO_SCSI_CFG_SENSE_SIZE	0x14	/* 32 */
#define	VIRTIO_SCSI_CFG_CDB_SIZE	0x18	/* 32 */
#define	VIRTIO_SCSI_CFG_MAX_CHANNEL	0x1c	/* 16 */
#define	VIRTIO_SCSI_CFG_MAX_TARGET	0x1e	/* 16 */
#define	VIRTIO_SCSI_CFG_MAX_LUN		0x20	/* 32 */

/*
 * VIRTIO SCSI VIRTQUEUES
 */
#define	VIRTIO_SCSI_VIRTQ_CONTROL	0
#define	VIRTIO_SCSI_VIRTQ_EVENT		1
#define	VIRTIO_SCSI_VIRTQ_REQUEST	2

#define	VIRTIO_SCSI_S_OK			0 
#define	VIRTIO_SCSI_S_OVERRUN			1
#define	VIRTIO_SCSI_S_ABORTED			2
#define	VIRTIO_SCSI_S_BAD_TARGET		3 
#define	VIRTIO_SCSI_S_RESET			4
#define	VIRTIO_SCSI_S_BUSY			5
#define	VIRTIO_SCSI_S_TRANSPORT_FAILURE		6
#define	VIRTIO_SCSI_S_TARGET_FAILURE		7
#define	VIRTIO_SCSI_S_NEXUS_FAILURE		8
#define	VIRTIO_SCSI_S_FAILURE			9
#define	VIRTIO_SCSI_S_FUNCTION_SUCCEEDED	10
#define	VIRTIO_SCSI_S_FUNCTION_REJECTED		11
#define	VIRTIO_SCSI_S_INCORRECT_LUN		12


static int vioscsi_attach(dev_info_t *, ddi_attach_cmd_t);
static int vioscsi_detach(dev_info_t *, ddi_detach_cmd_t);

void *vioscsi_state;

typedef struct vioscsi_cmd vioscsi_cmd_t;

typedef struct vioscsi {
	dev_info_t		*vis_dip;
	uint32_t		vis_instance;

	struct virtio_softc	vis_virtio;

	struct virtqueue	*vis_q_control;
	struct virtqueue	*vis_q_event;
	struct virtqueue	*vis_q_request;

	vioscsi_cmd_t		**vis_q_control_cmds;

	uint32_t		vis_cdb_size;
	uint32_t		vis_sense_size;
	uint32_t		vis_event_info_size;

} vioscsi_t;

/*
 * Device Operations Structure
 */
static struct dev_ops vioscsi_dev_ops = {
	.devo_rev =		DEVO_REV,
	.devo_refcnt =		0,

	.devo_attach =		vioscsi_attach,
	.devo_detach =		vioscsi_detach,

	.devo_getinfo =		nodev,
	.devo_identify =	nulldev,
	.devo_probe =		nulldev,
	.devo_reset =		nodev,
	.devo_cb_ops =		NULL,
	.devo_bus_ops =		NULL,
	.devo_power =		nodev,
	.devo_quiesce =		nodev
};

/*
 * Linkage structures
 */
static struct modldrv vioscsi_modldrv = {
	.drv_modops =		&mod_driverops,
	.drv_linkinfo =		"Virtio SCSI",
	.drv_dev_ops =		&vioscsi_dev_ops
};

static struct modlinkage vioscsi_modlinkage = {
	.ml_rev =		MODREV_1,
	.ml_linkage =		{ &vioscsi_modldrv, NULL }
};

/*
 * XXX
 */
static ddi_dma_attr_t vioscsi_dma_attr = {
	.dma_attr_version =		DMA_ATTR_V0,
	.dma_attr_addr_lo =		0x00000000,
	.dma_attr_addr_hi =		0xFFFFFFFF,
	.dma_attr_count_max =		0xFFFFFFFF,
	.dma_attr_align =		1,
	.dma_attr_burstsizes =		1,
	.dma_attr_minxfer =		1,
	.dma_attr_maxxfer =		0xFFFFFFFF,
	.dma_attr_seg =			0xFFFFFFFF,
	.dma_attr_sgllen =		1,
	.dma_attr_granular =		1, /* XXX? */
	.dma_attr_flags =		0
};

/*
 * XXX move to virtio common code
 */
static ddi_device_acc_attr_t virtio_attr = {
	.devacc_attr_version =		DDI_DEVICE_ATTR_V0,
	.devacc_attr_endian_flags =	DDI_NEVERSWAP_ACC,
	.devacc_attr_dataorder =	DDI_STORECACHING_OK_ACC,
	.devacc_attr_access =		DDI_DEFAULT_ACC
};

/*
 * XXX move to virtio common code
 */
void
virtio_legacy_fini(struct virtio_softc *sc)
{
	virtio_device_reset(sc);

	/*
	 * Unmap PCI BAR0.
	 */
	ddi_regs_map_free(&sc->sc_ioh);
}

/*
 * Early device initialisation for legacy (pre-1.0 specification) virtio
 * devices.
 * XXX move to virtio common code
 */
int
virtio_legacy_init(struct virtio_softc *sc, uint16_t expected_subsystem)
{
	int r;

	/*
	 * First, we want to confirm that this is a legacy device.
	 */
	ddi_acc_handle_t pci;
	if (pci_config_setup(sc->sc_dev, &pci) != DDI_SUCCESS) {
		dev_err(sc->sc_dev, CE_WARN, "pci_config_setup failed");
		return (DDI_FAILURE);
	}

	uint8_t revid;
	uint16_t subsysid;
	if ((revid = pci_config_get8(pci, PCI_CONF_REVID)) == PCI_EINVAL8 ||
	    (subsysid = pci_config_get16(pci, PCI_CONF_SUBSYSID)) ==
	    PCI_EINVAL16) {
		dev_err(sc->sc_dev, CE_WARN, "could not read config space");
		pci_config_teardown(&pci);
		return (DDI_FAILURE);
	}

	pci_config_teardown(&pci);

	/*
	 * The legacy specification requires that the device advertise as PCI
	 * Revision 0.
	 */
	if (revid != 0) {
		dev_err(sc->sc_dev, CE_WARN, "PCI Revision %u incorrect for "
		    "legacy virtio device", (uint_t)revid);
		return (DDI_FAILURE);
	}
	if (subsysid != expected_subsystem) {
		dev_err(sc->sc_dev, CE_WARN, "PCI Subsystem ID %u was "
		    "expected for this device, but found %u",
		    (uint_t)expected_subsystem,
		    (uint_t)subsysid);
		return (DDI_FAILURE);
	}

	/*
	 * Map PCI BAR0 for legacy device access.
	 */
	if ((r = ddi_regs_map_setup(sc->sc_dev, 1, (caddr_t *)&sc->sc_io_addr,
	    0, 0, &virtio_attr, &sc->sc_ioh)) != DDI_SUCCESS) {
		dev_err(sc->sc_dev, CE_WARN, "ddi_regs_map_setup failure (%d)",
		    r);
		return (DDI_FAILURE);
	}

	/*
	 * Legacy virtio devices require a few common steps before we can
	 * negotiate device features.
	 */
	virtio_device_reset(sc);
	virtio_set_status(sc, VIRTIO_CONFIG_DEVICE_STATUS_ACK);
	virtio_set_status(sc, VIRTIO_CONFIG_DEVICE_STATUS_DRIVER);

	/*
	 * XXX
	 */
	sc->sc_config_offset = VIRTIO_CONFIG_DEVICE_CONFIG_NOMSIX;

	return (DDI_SUCCESS);
}


int
_init()
{
	int r;

	VERIFY0(ddi_soft_state_init(&vioscsi_state, sizeof (vioscsi_t), 0));

	if ((r = mod_install(&vioscsi_modlinkage)) != 0) {
		goto fail;
	}

	return (r);

fail:
	ddi_soft_state_fini(&vioscsi_state);
	return (r);
}

int
_fini()
{
	int r;

	if ((r = mod_remove(&vioscsi_modlinkage)) == 0) {
		ddi_soft_state_fini(&vioscsi_state);
	}

	return (r);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&vioscsi_modlinkage, modinfop));
}

#define	VIRTIO_SCSI_T_TMF				0

#define	VIRTIO_SCSI_T_TMF_I_T_NEXUS_RESET		4
#define	VIRTIO_SCSI_T_TMF_LOGICAL_UNIT_RESET		5

#define	VIRTIO_SCSI_S_FUNCTION_COMPLETE			0
#define	VIRTIO_SCSI_S_FUNCTION_SUCCEEDED		10
#define	VIRTIO_SCSI_S_FUNCTION_REJECTED			11

#pragma pack(1)
struct virtio_scsi_ctrl_tmf_read {
	uint32_t vstmf_type;
	uint32_t vstmf_subtype;
	uint8_t vstmf_lun[8];
	uint64_t vstmf_id;
};
struct virtio_scsi_ctrl_tmf_write {
	uint8_t vstmf_response;
};
struct virtio_scsi_ctrl_tmf {
	struct virtio_scsi_ctrl_tmf_read vstmf_read;
	struct virtio_scsi_ctrl_tmf_write vstmf_write;
};
#pragma pack()

typedef enum vioscsi_dma_level {
	VIOSCSI_DMALEVEL_HANDLE_ALLOC =		(1ULL << 0),
	VIOSCSI_DMALEVEL_MEMORY_ALLOC =		(1ULL << 1),
	VIOSCSI_DMALEVEL_HANDLE_BOUND =		(1ULL << 2),
} vioscsi_dma_level_t;

typedef struct vioscsi_dma {
	vioscsi_dma_level_t vsdma_level;
	size_t vsdma_real_size;
	ddi_dma_handle_t vsdma_dma_handle;
	ddi_acc_handle_t vsdma_acc_handle;
	ddi_dma_cookie_t vsdma_cookies[1];
	uint_t vsdma_ncookies;
} vioscsi_dma_t;

struct vioscsi_cmd {
	vioscsi_t *vsc_vioscsi;

	vioscsi_dma_t vsc_dma;

	void *vsc_va;
	uint32_t vsc_pa;
};

static void
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

static int
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

/*
 * XXX Control queue request?
 */
static int
vioscsi_make_request(vioscsi_t *vis)
{
	vioscsi_cmd_t *vsc;
	int kmflags = KM_SLEEP;

	if ((vsc = kmem_zalloc(sizeof (*vsc), kmflags)) == NULL) {
		return (DDI_FAILURE);
	}
	vsc->vsc_vioscsi = vis;

	struct virtio_scsi_ctrl_tmf_read vstmf;
	bzero(&vstmf, sizeof (vstmf));
	vstmf.vstmf_type = VIRTIO_SCSI_T_TMF;
	vstmf.vstmf_subtype = VIRTIO_SCSI_T_TMF_LOGICAL_UNIT_RESET;

	size_t sz = sizeof (struct virtio_scsi_ctrl_tmf_read) +
	    sizeof (struct virtio_scsi_ctrl_tmf_write);
	if (vioscsi_dma_alloc(vis, &vsc->vsc_dma, sz, kmflags, &vsc->vsc_va,
	    &vsc->vsc_pa) != DDI_SUCCESS) {
		goto fail;
	}

	/*
	 * Write control request into allocated DMA memory.
	 */
	bzero(vsc->vsc_va, sz);
	bcopy(&vstmf, vsc->vsc_va, sizeof (vstmf));

	/*
	 * Allocate a descriptor for the driver-write portion of the command
	 * and for the device-write portion of the command:
	 */
	struct vq_entry *ve_driver, *ve_device;
	if ((ve_driver = vq_alloc_entry(vis->vis_q_control)) == NULL ||
	    (ve_device = vq_alloc_entry(vis->vis_q_control)) == NULL) {
		dev_err(vis->vis_dip, CE_WARN, "vq_alloc_entry failed");
		goto fail;
	}
	virtio_ventry_stick(ve_driver, ve_device);

	virtio_ve_set(ve_driver,
	    vsc->vsc_pa + 0,
	    sizeof (struct virtio_scsi_ctrl_tmf_read),
	    B_TRUE);
	virtio_ve_set(ve_device,
	    vsc->vsc_pa + sizeof (struct virtio_scsi_ctrl_tmf_read),
	    sizeof (struct virtio_scsi_ctrl_tmf_write),
	    B_FALSE);

	VERIFY3P(vis->vis_q_control_cmds[ve_driver->qe_index], ==, NULL);
	vis->vis_q_control_cmds[ve_driver->qe_index] = vsc;

	if (ddi_dma_sync(vsc->vsc_dma.vsdma_dma_handle, 0, 0,
	    DDI_DMA_SYNC_FORDEV) != DDI_SUCCESS) {
		/*
		 * XXX PANIC
		 */
		dev_err(vis->vis_dip, CE_WARN, "DMA sync failure");
		goto fail;
	}

	dev_err(vis->vis_dip, CE_WARN, "push chain idx %x",
	    (uint_t)ve_driver->qe_index);
	virtio_push_chain(ve_driver, B_TRUE);

	return (DDI_SUCCESS);

fail:
	vioscsi_dma_free(&vsc->vsc_dma);
	kmem_free(vsc, sizeof (*vsc));
	return (DDI_FAILURE);
}

static uint_t
vioscsi_handle_control(caddr_t arg0, caddr_t arg1)
{
	struct virtio_softc *sc = (void *)arg0;
	vioscsi_t *vis = __containerof(sc, vioscsi_t, vis_virtio);

	dev_err(vis->vis_dip, CE_WARN, "vioscsi_handle_control");

	struct vq_entry *qe;
	uint32_t len;
	while ((qe = virtio_pull_chain(vis->vis_q_control, &len)) != NULL) {
		dev_err(vis->vis_dip, CE_WARN, "pull idx %x",
		    (uint_t)qe->qe_index);

		vioscsi_cmd_t *cmd = vis->vis_q_control_cmds[qe->qe_index];
		if (cmd == NULL) {
			dev_err(vis->vis_dip, CE_WARN, "no command?!");
			virtio_free_chain(qe);
			continue;
		}

		struct virtio_scsi_ctrl_tmf *vstmf = cmd->vsc_va;
		dev_err(vis->vis_dip, CE_WARN, "response: %u",
		    (uint_t)vstmf->vstmf_write.vstmf_response);
		virtio_free_chain(qe);                                   

		if (ddi_dma_sync(cmd->vsc_dma.vsdma_dma_handle, 0, 0,
		    DDI_DMA_SYNC_FORCPU) != DDI_SUCCESS) {
			/*
			 * XXX
			 */
			dev_err(vis->vis_dip, CE_WARN, "DMA sync failure");
		}

		vioscsi_dma_free(&cmd->vsc_dma);
		kmem_free(cmd, sizeof (*cmd));
	}

	return (DDI_INTR_CLAIMED);
}

static uint_t
vioscsi_handle_event(caddr_t arg0, caddr_t arg1)
{
	struct virtio_softc *sc = (void *)arg0;
	vioscsi_t *vis = __containerof(sc, vioscsi_t, vis_virtio);

	dev_err(vis->vis_dip, CE_WARN, "vioscsi_handle_event");

	return (DDI_INTR_CLAIMED);
}

static uint_t
vioscsi_handle_request(caddr_t arg0, caddr_t arg1)
{
	struct virtio_softc *sc = (void *)arg0;
	vioscsi_t *vis = __containerof(sc, vioscsi_t, vis_virtio);

	dev_err(vis->vis_dip, CE_WARN, "vioscsi_handle_request");

	return (DDI_INTR_CLAIMED);
}

static int
vioscsi_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	uint32_t instance;
	vioscsi_t *vis;
	struct virtio_softc *vio;
	int r;
	int leg = 0;

	if (cmd != DDI_ATTACH) {
		return (DDI_FAILURE);
	}

	instance = ddi_get_instance(dip);
	if (ddi_soft_state_zalloc(vioscsi_state, instance) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "could not allocate soft state");
		return (DDI_FAILURE);
	}
	if ((vis = ddi_get_soft_state(vioscsi_state, instance)) == NULL) {
		dev_err(dip, CE_WARN, "could not get soft state");
		ddi_soft_state_free(vioscsi_state, instance);
		return (DDI_FAILURE);
	}

	vio = &vis->vis_virtio;
	vio->sc_dev = dip;

	vis->vis_dip = dip;
	vis->vis_instance = instance;
	ddi_set_driver_private(dip, vis);

	if (virtio_legacy_init(&vis->vis_virtio, 8) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "legacy init failure");
		goto fail;
	}
	leg = 1;

	uint32_t feat;
	feat = virtio_negotiate_features(&vis->vis_virtio, 0);

	/*
	 * The SCSI device has several virtqueues:
	 * 	0	control queue
	 * 	1	event queue
	 * 	2..n	request queue(s)
	 */
	struct virtio_int_handler vioscsi_handlers[] = {
		{ .vh_func = vioscsi_handle_control,	.vh_priv = vis },
		{ .vh_func = vioscsi_handle_event,	.vh_priv = vis },
		{ .vh_func = vioscsi_handle_request,	.vh_priv = vis },
		{ NULL },
	};

	if ((r = virtio_register_ints(&vis->vis_virtio, NULL,
	    vioscsi_handlers, B_TRUE)) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "interrupt setup failure");
		goto fail;
	}

	if ((vis->vis_q_control = virtio_alloc_vq(vio,
	    VIRTIO_SCSI_VIRTQ_CONTROL, 0, 0, "control")) == NULL ||
	    (vis->vis_q_event = virtio_alloc_vq(vio,
	    VIRTIO_SCSI_VIRTQ_EVENT, 0, 0, "event")) == NULL ||
	    (vis->vis_q_request = virtio_alloc_vq(vio,
	    VIRTIO_SCSI_VIRTQ_REQUEST, 0, 0, "request")) == NULL) {
		dev_err(dip, CE_WARN, "failed to allocate virtqueues");
		goto fail;
	}
	virtio_start_vq_intr(vis->vis_q_control);
	virtio_start_vq_intr(vis->vis_q_event);
	virtio_start_vq_intr(vis->vis_q_request);

	/*
	 * XXX This sucks.  Use an AVL!
	 */
	vis->vis_q_control_cmds = kmem_zalloc(sizeof (vioscsi_cmd_t *) *
	    vis->vis_q_control->vq_num, KM_SLEEP);

	if (virtio_enable_ints(vio) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "could not enable interrupts");
		goto fail;
	}

	/*
	 * Read some device configuration properties.
	 */
	uint32_t num_queues = virtio_read_device_config_4(&vis->vis_virtio,
	    VIRTIO_SCSI_CFG_NUM_QUEUES);
	dev_err(dip, CE_WARN, "config: num_queues = %u", num_queues);

	vis->vis_event_info_size = virtio_read_device_config_4(&vis->vis_virtio,
	    VIRTIO_SCSI_CFG_EVENT_INFO_SIZE);
	dev_err(dip, CE_WARN, "config: event_info_size = %u",
	    vis->vis_event_info_size);

	vis->vis_sense_size = virtio_read_device_config_4(&vis->vis_virtio,
	    VIRTIO_SCSI_CFG_SENSE_SIZE);
	dev_err(dip, CE_WARN, "config: sense_size = %u", vis->vis_sense_size);

	vis->vis_cdb_size = virtio_read_device_config_4(&vis->vis_virtio,
	    VIRTIO_SCSI_CFG_CDB_SIZE);
	dev_err(dip, CE_WARN, "config: cdb_size = %u", vis->vis_cdb_size);

	uint16_t max_channel = virtio_read_device_config_2(&vis->vis_virtio,
	    VIRTIO_SCSI_CFG_MAX_CHANNEL);
	dev_err(dip, CE_WARN, "config: max_channel = %u", (uint_t)max_channel);

	uint16_t max_target = virtio_read_device_config_2(&vis->vis_virtio,
	    VIRTIO_SCSI_CFG_MAX_TARGET);
	dev_err(dip, CE_WARN, "config: max_target = %u", (uint_t)max_target);

	uint32_t max_lun = virtio_read_device_config_4(&vis->vis_virtio,
	    VIRTIO_SCSI_CFG_MAX_LUN);
	dev_err(dip, CE_WARN, "config: max_lun = %u", max_lun);

	/*
	 * Start device operation.
	 */
	virtio_set_status(&vis->vis_virtio,
	    VIRTIO_CONFIG_DEVICE_STATUS_DRIVER_OK);

	dev_err(dip, CE_WARN, "attach ok");

	vioscsi_make_request(vis);

	return (DDI_SUCCESS);

fail:
	if (vis->vis_q_control != NULL) {
		virtio_free_vq(vis->vis_q_control);
	}
	if (vis->vis_q_event != NULL) {
		virtio_free_vq(vis->vis_q_event);
	}
	if (vis->vis_q_request != NULL) {
		virtio_free_vq(vis->vis_q_request);
	}
	if (leg) {
		virtio_legacy_fini(&vis->vis_virtio);
	}
	ddi_soft_state_free(vioscsi_state, instance);
	return (DDI_FAILURE);
}

static int
vioscsi_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	vioscsi_t *vis = ddi_get_driver_private(dip);

	if (cmd != DDI_DETACH) {
		return (DDI_FAILURE);
	}

	virtio_release_ints(&vis->vis_virtio);

	if (vis->vis_q_control != NULL) {
		virtio_free_vq(vis->vis_q_control);
	}
	if (vis->vis_q_event != NULL) {
		virtio_free_vq(vis->vis_q_event);
	}
	if (vis->vis_q_request != NULL) {
		virtio_free_vq(vis->vis_q_request);
	}

	virtio_legacy_fini(&vis->vis_virtio);

	ddi_soft_state_free(vioscsi_state, ddi_get_instance(vis->vis_dip));

	dev_err(dip, CE_WARN, "detach ok");
	return (DDI_SUCCESS);
}
