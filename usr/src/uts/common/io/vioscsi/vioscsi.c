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
#include <sys/sysmacros.h>
#include <sys/scsi/scsi.h>
#include <sys/scsi/impl/spc3_types.h>
#include <sys/avl.h>
#include "virtiovar.h"
#include "virtioreg.h"

#include <sys/pci.h> /* XXX remove after splitting into common code? */

#define	VIOSCSI_IPORT				"v0"

/*
 * The maintenance routine ... XXX.  The time is expressed in seconds.
 */
#define	VIOSCSI_PERIODIC_RATE			5

/*
 * VIRTIO SCSI FEATURE BITS
 */

#define	VIRTIO_SCSI_F_INOUT			(1ULL << 0)
/*
 * A single request can include both device-readable and device-writable data
 * buffers.
 */

#define	VIRTIO_SCSI_F_HOTPLUG			(1ULL << 1)
/*
 * The host SHOULD enable reporting of hot-plug and hot-unplug events for LUNs
 * and targets on the SCSI bus. The guest SHOULD handle hot-plug and hot-unplug
 * events.
 */

#define	VIRTIO_SCSI_F_CHANGE			(1ULL << 2)
/*
 * The host will report changes to LUN parameters via a
 * VIRTIO_SCSI_T_PARAM_CHANGE event; the guest SHOULD handle them.
 */

#define	VIRTIO_SCSI_F_T10_PI			(1ULL << 3)
/*
 * The extended fields for T10 protection information (DIF/DIX) are included in
 * the SCSI request header.
 */

/*
 * VIRTIO SCSI CONFIGURATION REGISTERS
 */
#define	VIRTIO_SCSI_CFG_NUM_QUEUES		0x00	/* 32 */
#define	VIRTIO_SCSI_CFG_SEG_MAX			0x04	/* 32 */
#define	VIRTIO_SCSI_CFG_MAX_SECTORS		0x08	/* 32 */
#define	VIRTIO_SCSI_CFG_CMD_PER_LUN		0x0c	/* 32 */
#define	VIRTIO_SCSI_CFG_EVENT_INFO_SIZE		0x10	/* 32 */
#define	VIRTIO_SCSI_CFG_SENSE_SIZE		0x14	/* 32 */
#define	VIRTIO_SCSI_CFG_CDB_SIZE		0x18	/* 32 */
#define	VIRTIO_SCSI_CFG_MAX_CHANNEL		0x1c	/* 16 */
#define	VIRTIO_SCSI_CFG_MAX_TARGET		0x1e	/* 16 */
#define	VIRTIO_SCSI_CFG_MAX_LUN			0x20	/* 32 */

/*
 * VIRTIO SCSI VIRTQUEUES
 */
#define	VIRTIO_SCSI_VIRTQ_CONTROL		0
#define	VIRTIO_SCSI_VIRTQ_EVENT			1
#define	VIRTIO_SCSI_VIRTQ_REQUEST		2

/*
 * VIRTIO SCSI ... XXX
 */
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

/*
 * VIRTIO SCSI CONTROL COMMAND TYPES? XXX
 */
#define	VIRTIO_SCSI_T_TMF			0

#define	VIRTIO_SCSI_T_TMF_I_T_NEXUS_RESET	4
#define	VIRTIO_SCSI_T_TMF_LOGICAL_UNIT_RESET	5


void *vioscsi_state;

typedef enum vioscsi_init_level {
	VIOSCSI_INITLEVEL_BASIC =		(0x1 << 0),
	VIOSCSI_INITLEVEL_VIRTIO =		(0x1 << 1),
	VIOSCSI_INITLEVEL_MUTEX =		(0x1 << 2),
	VIOSCSI_INITLEVEL_TASKQ =		(0x1 << 3),
	VIOSCSI_INITLEVEL_PERIODIC =		(0x1 << 4),
	VIOSCSI_INITLEVEL_INTERRUPTS =		(0x1 << 5),
	VIOSCSI_INITLEVEL_SCSA =		(0x1 << 6),
} vioscsi_init_level_t;

#define	INITLEVEL_SET(_vis, name)					\
	do {								\
		VERIFY(!((_vis)->vis_init_level & (name)));		\
		(_vis)->vis_init_level |= (name);			\
	} while (0)
#define	INITLEVEL_CLEAR(_vis, name)					\
	do { 								\
		VERIFY((_vis)->vis_init_level & (name));		\
		(_vis)->vis_init_level &= ~(name);			\
	} while (0)
#define	INITLEVEL_ACTIVE(_vis, name)					\
	(((_vis)->vis_init_level & (name)) != 0)

typedef struct vioscsi_target vioscsi_target_t;
typedef struct vioscsi_cmd vioscsi_cmd_t;
typedef struct vioscsi_cmd_scsa vioscsi_cmd_scsa_t;
typedef struct vioscsi vioscsi_t;

static int vioscsi_attach(dev_info_t *, ddi_attach_cmd_t);
static int vioscsi_detach(dev_info_t *, ddi_detach_cmd_t);
static int vioscsi_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);
static int vioscsi_cmd_comparator(const void *, const void *);
static void vioscsi_cleanup(vioscsi_t *);

typedef enum {
	VIOSCSI_CMDQ_CONTROL = 1000,
	VIOSCSI_CMDQ_EVENT,
	VIOSCSI_CMDQ_REQUEST
} vioscsi_queue_name_t;

typedef struct vioscsi_q {
	vioscsi_queue_name_t	visq_name;
	unsigned int		visq_index;
	struct virtqueue	*visq_vq;
	avl_tree_t		visq_inflight;
	boolean_t		visq_init;
	vioscsi_t		*visq_vioscsi;
} vioscsi_q_t;

typedef enum vioscsi_status {
	VIOSCSI_STATUS_DETACHING =		(0x1 << 0),

	VIOSCSI_STATUS_DISCOVERY_RUNNING =	(0x1 << 1),
	VIOSCSI_STATUS_DISCOVERY_REQUESTED =	(0x1 << 2),
	VIOSCSI_STATUS_DISCOVERY_PERIODIC =	(0x1 << 3),
} vioscsi_status_t;

#define	VIOSCSI_STATUS_DISCOVERY_MASK					\
	(VIOSCSI_STATUS_DISCOVERY_RUNNING |				\
	VIOSCSI_STATUS_DISCOVERY_REQUESTED |				\
	VIOSCSI_STATUS_DISCOVERY_PERIODIC)

struct vioscsi {
	dev_info_t		*vis_dip;
	uint32_t		vis_instance;

	kmutex_t		vis_mutex;
	kcondvar_t		vis_cv_finish;
	vioscsi_status_t	vis_status;
	vioscsi_init_level_t	vis_init_level;

	dev_info_t		*vis_iport;
	scsi_hba_tgtmap_t	*vis_tgtmap;

	uint64_t		vis_next_tag;

	struct virtio_softc	vis_virtio;

	vioscsi_q_t		vis_q_control;
	vioscsi_q_t		vis_q_event;
	vioscsi_q_t		vis_q_request;

	uint32_t		vis_seg_max;
	uint32_t		vis_cdb_size;
	uint32_t		vis_sense_size;
	uint32_t		vis_event_info_size;
	uint32_t		vis_max_channel;
	uint32_t		vis_max_target_raw;
	uint32_t		vis_max_target;
	uint32_t		vis_max_lun_raw;
};

/*
 * SCSA target tracking structure.
 */
struct vioscsi_target {
	vioscsi_t		*vist_vioscsi;
	struct scsi_device	*vist_scsi_dev;
	uint8_t			vist_lun[8];
};

static struct cb_ops vioscsi_cb_ops = {
	.cb_rev =		CB_REV,
	.cb_flag =		D_NEW | D_MP,

	.cb_open =		scsi_hba_open,
	.cb_close =		scsi_hba_close,

	.cb_ioctl =		vioscsi_ioctl,

	.cb_strategy =		nodev,
	.cb_print =		nodev,
	.cb_dump =		nodev,
	.cb_read =		nodev,
	.cb_write =		nodev,
	.cb_devmap =		nodev,
	.cb_mmap =		nodev,
	.cb_segmap =		nodev,
	.cb_chpoll =		nochpoll,
	.cb_prop_op =		ddi_prop_op,
	.cb_str =		NULL,
	.cb_aread =		nodev,
	.cb_awrite =		nodev
};

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

	if ((r = scsi_hba_init(&vioscsi_modlinkage)) != 0) {
		goto fail;
	}

	if ((r = mod_install(&vioscsi_modlinkage)) != 0) {
		scsi_hba_fini(&vioscsi_modlinkage);
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
		scsi_hba_fini(&vioscsi_modlinkage);
		ddi_soft_state_fini(&vioscsi_state);
	}

	return (r);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&vioscsi_modlinkage, modinfop));
}

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

struct virtio_scsi_event {
	/*
	 * Entirely device-writeable.
	 */
	uint32_t vsev_event;
	uint8_t vsev_lun[8];
	uint32_t vsev_reason;
};

struct virtio_scsi_req_cmd_read {
	uint8_t vsrq_lun[8];
	uint64_t vsrq_id;
	uint8_t vsrq_task_attr;
	uint8_t vsrq_prio;
	uint8_t vsrq_crn;
	char vsrq_cdb[];
};
/*
 *	char vsrq_dataout[];
 */
struct virtio_scsi_req_cmd_write {
	uint32_t vsrq_sense_len;
	uint32_t vsrq_residual;
	uint16_t vsrq_status_qualifier;
	uint8_t vsrq_status;
	uint8_t vsrq_response;
	uint8_t vsrq_sense[];
};
/*
 * 	char vsrq_datain[];
 */
#pragma pack()

/*
 * Ensure that the compiler is not adding any padding, or treating the flexible
 * array member as anything but empty.  If this is not true, the
 * device-writeable half of the request structure may be at the wrong offset.
 */
CTASSERT(offsetof(struct virtio_scsi_req_cmd_write, vsrq_sense) ==
    sizeof (struct virtio_scsi_req_cmd_write));
CTASSERT(offsetof(struct virtio_scsi_req_cmd_read, vsrq_cdb) ==
    sizeof (struct virtio_scsi_req_cmd_read));

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

struct vioscsi_cmd_scsa {
	struct scsi_pkt *vscs_pkt;
	vioscsi_cmd_t *vscs_cmd;
};

typedef enum vioscsi_cmd_status {
	VIOSCSI_CMD_STATUS_INFLIGHT =		(0x1 << 0),
	VIOSCSI_CMD_STATUS_COMPLETE =		(0x1 << 1),
	VIOSCSI_CMD_STATUS_POLLED =		(0x1 << 2),
	VIOSCSI_CMD_STATUS_POLL_COMPLETE =	(0x1 << 3),
	VIOSCSI_CMD_STATUS_TRAN_START =		(0x1 << 4),
	VIOSCSI_CMD_STATUS_ERROR =		(0x1 << 5),
} vioscsi_cmd_status_t;

struct vioscsi_cmd {
	vioscsi_t *vsc_vioscsi;
	vioscsi_q_t *vsc_q;

	vioscsi_cmd_status_t vsc_status;
	hrtime_t vsc_time_push;

	vioscsi_dma_t vsc_dma;

	void *vsc_va;
	uint32_t vsc_pa;
	size_t vsc_sz;

	/*
	 * So that we can locate this command object in the virtqueue interrupt
	 * handler, we note the index of the head descriptor in the chain.
	 * Each virtqueue has an AVL to track currently issued commands, using
	 * this index as the key.
	 */
	uint16_t vsc_vqidx;
	avl_node_t vsc_node;

	struct vq_entry *vsc_qe;

	offset_t vsc_response_offset;
	vioscsi_cmd_scsa_t *vsc_scsa;

	char vsc_info[256];
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

static vioscsi_cmd_t *
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

static void
vioscsi_cmd_free(vioscsi_cmd_t *vsc)
{
	if (vsc->vsc_qe != NULL) {
		virtio_free_chain(vsc->vsc_qe);
	}
	vioscsi_dma_free(&vsc->vsc_dma);
	kmem_free(vsc, sizeof (*vsc));
}

static void
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
static struct vq_entry *
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

static int
vioscsi_fill_events(vioscsi_t *vis)
{
	int kmflags = KM_SLEEP;
	size_t sz = MAX(sizeof (struct virtio_scsi_event),
	    vis->vis_event_info_size);

	/*
	 * Put 64 buffers in the event queue, just in case.
	 */
	for (uint_t n = 0; n < 64; n++) {
		vioscsi_cmd_t *vsc;
		struct vq_entry *ve;

		if ((vsc = vioscsi_cmd_alloc(vis, &vis->vis_q_event, sz)) ==
		    NULL) {
			break;
		}

		if ((ve = vioscsi_cmd_append(vsc)) == NULL) {
			vioscsi_cmd_free(vsc);
			break;
		}

		virtio_ve_set(ve, vsc->vsc_pa, sz, B_FALSE);

		vioscsi_q_push(vsc);
	}

	return (DDI_SUCCESS);
}

static int
vioscsi_scsi_request(vioscsi_t *vis, uint8_t target)
{
	vioscsi_cmd_t *vsc;
	int kmflags = KM_SLEEP;

	if ((vsc = kmem_zalloc(sizeof (*vsc), kmflags)) == NULL) {
		return (DDI_FAILURE);
	}
	vsc->vsc_vioscsi = vis;

	/*
	 * Allocate an object into which we will write the command header and
	 * the CDB.
	 */
	struct virtio_scsi_req_cmd_read *vsrq;
	size_t vsrq_sz = sizeof (*vsrq) + vis->vis_cdb_size;
	if ((vsrq = kmem_zalloc(vsrq_sz, kmflags)) == NULL) {
		kmem_free(vsc, sizeof (*vsc));
	}

	size_t dataout_sz = 0;
	size_t datain_sz = 2048;

	/*
	 * The specification suggests a REPORT LUNS command can be sent to the
	 * well-known logical unit with address [C1, 01, 00...].  This does not
	 * appear to be supported in GCE.
	 *
	 * Instead, we must construct a LUN address based on the (target,LUN)
	 * tuple, which I suspect is fixed at (target,0) when max_lun is 1.
	 */
	vsrq->vsrq_lun[0] = 0x01; /* fixed at 0x01 */
	vsrq->vsrq_lun[1] = target; /* target */
	vsrq->vsrq_lun[2] = 0x00; /* LUN... */
	vsrq->vsrq_lun[3] = 0x00; /* LUN... */

	vsrq->vsrq_id = 1; /* command tag */

#if 0
	/*
	 * XXX Maybe use "spc3_report_luns_cdb_t" here?
	 */
	vsrq->vsrq_cdb[0] = SCMD_REPORT_LUNS;
	vsrq->vsrq_cdb[2] = SPC3_RL_SR_ADDRESSING;
	/* XXX? vsrq->vsrq_cdb[2] = SPC3_RL_SR_ALL; */
	vsrq->vsrq_cdb[6] = (datain_sz >> (3 * 8)) & 0xFF; /* MSB */
	vsrq->vsrq_cdb[7] = (datain_sz >> (2 * 8)) & 0xFF;
	vsrq->vsrq_cdb[8] = (datain_sz >> (1 * 8)) & 0xFF;
	vsrq->vsrq_cdb[9] = (datain_sz >> (0 * 8)) & 0xFF; /* LSB */
	vsrq->vsrq_cdb[11] = 0; /* XXX CONTROL byte? */
#else
	vsrq->vsrq_cdb[0] = SCMD_INQUIRY;
	vsrq->vsrq_cdb[2] = 0; /* PAGE CODE (see also EVPD bit in [1]) */
	vsrq->vsrq_cdb[3] = (datain_sz >> (1 * 8)) & 0xFF; /* MSB */
	vsrq->vsrq_cdb[4] = (datain_sz >> (0 * 8)) & 0xFF; /* LSB */
	vsrq->vsrq_cdb[5] = 0; /* XXX CONTROL byte? */
#endif

	size_t sz = vsrq_sz + dataout_sz +
	    sizeof (struct virtio_scsi_req_cmd_write) +
	    vis->vis_sense_size + datain_sz;
	if (vioscsi_dma_alloc(vis, &vsc->vsc_dma, sz, kmflags, &vsc->vsc_va,
	    &vsc->vsc_pa) != DDI_SUCCESS) {
		goto fail;
	}

	snprintf(vsc->vsc_info, sizeof (vsc->vsc_info), "INQUIRY (%u,0)",
	    target);

	bcopy(vsrq, vsc->vsc_va, vsrq_sz);

	/*
	 * Allocate a descriptor for the driver-write portion of the command
	 * and for the device-write portion of the command:
	 */
	struct vq_entry *ve_driver, *ve_device;
	if ((ve_driver = vq_alloc_entry(vis->vis_q_request)) == NULL ||
	    (ve_device = vq_alloc_entry(vis->vis_q_request)) == NULL) {
		dev_err(vis->vis_dip, CE_WARN, "vq_alloc_entry failed");
		goto fail;
	}
	virtio_ventry_stick(ve_driver, ve_device);

	/*
	 * Store the offset at which the response begins within the DMA memory.
	 */
	vsc->vsc_response_offset = vsrq_sz + dataout_sz;

	virtio_ve_set(ve_driver,
	    vsc->vsc_pa + 0,
	    vsrq_sz + dataout_sz,
	    B_TRUE);
	virtio_ve_set(ve_device,
	    vsc->vsc_pa + vsc->vsc_response_offset,
	    sizeof (struct virtio_scsi_req_cmd_write) + vis->vis_sense_size +
	        datain_sz,
	    B_FALSE);

	VERIFY3P(vis->vis_q_request_cmds[ve_driver->qe_index], ==, NULL);
	vis->vis_q_request_cmds[ve_driver->qe_index] = vsc;

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

	vioscsi_cmd_t *vsc;
	while ((vsc = vioscsi_q_pull(&vis->vis_q_control)) != NULL) {
		volatile struct virtio_scsi_ctrl_tmf *vstmf = vsc->vsc_va;
		dev_err(vis->vis_dip, CE_WARN, "response: %u",
		    (uint_t)vstmf->vstmf_write.vstmf_response);

		vioscsi_cmd_free(vsc);
	}

	return (DDI_INTR_CLAIMED);
}

static uint_t
vioscsi_handle_event(caddr_t arg0, caddr_t arg1)
{
	struct virtio_softc *sc = (void *)arg0;
	vioscsi_t *vis = __containerof(sc, vioscsi_t, vis_virtio);

	dev_err(vis->vis_dip, CE_WARN, "vioscsi_handle_event");

	vioscsi_cmd_t *vsc;
	while ((vsc = vioscsi_q_pull(&vis.vis_q_event)) != NULL) {
		volatile struct virtio_scsi_event *vsev = vsc->vsc_va;
		dev_err(vis->vis_dip, CE_WARN,
		    "lun %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x, "
		    "event: %x, reason: %x",
		    (uint_t)vsev->vsev_lun[0],
		    (uint_t)vsev->vsev_lun[1],
		    (uint_t)vsev->vsev_lun[2],
		    (uint_t)vsev->vsev_lun[3],
		    (uint_t)vsev->vsev_lun[4],
		    (uint_t)vsev->vsev_lun[5],
		    (uint_t)vsev->vsev_lun[6],
		    (uint_t)vsev->vsev_lun[7],
		    vsev->vsev_event, vsev->vsev_reason);

		/*
		 * We want to keep a standing pool of event buffers, so put
		 * this one back in the ring.
		 */
		bzero(vsc->vsc_va, vsc->vsc_sz);
		vioscsi_q_push(vsc);
	}

	return (DDI_INTR_CLAIMED);
}

static uint_t
vioscsi_handle_request(caddr_t arg0, caddr_t arg1)
{
	struct virtio_softc *sc = (void *)arg0;
	vioscsi_t *vis = __containerof(sc, vioscsi_t, vis_virtio);

	dev_err(vis->vis_dip, CE_WARN, "vioscsi_handle_request");

	struct vq_entry *qe;
	uint32_t len;
	while ((qe = virtio_pull_chain(vis->vis_q_request, &len)) != NULL) {
		dev_err(vis->vis_dip, CE_WARN, "request pull idx %x",
		    (uint_t)qe->qe_index);

		vioscsi_cmd_t *cmd = vis->vis_q_request_cmds[qe->qe_index];
		if (cmd == NULL) {
			dev_err(vis->vis_dip, CE_WARN, "no command?!");
			virtio_free_chain(qe);
			continue;
		}
		vis->vis_q_request_cmds[qe->qe_index] = NULL;

		if (ddi_dma_sync(cmd->vsc_dma.vsdma_dma_handle, 0, 0,
		    DDI_DMA_SYNC_FORCPU) != DDI_SUCCESS) {
			/*
			 * XXX
			 */
			dev_err(vis->vis_dip, CE_WARN, "DMA sync failure");
		}

		dev_err(vis->vis_dip, CE_WARN, "reponse offset %x",
		    (uint_t)cmd->vsc_response_offset);
		volatile struct virtio_scsi_req_cmd_write *vsrq = cmd->vsc_va +
		    cmd->vsc_response_offset;
		dev_err(vis->vis_dip, CE_WARN, "info \"%s\" sense_len %u "
		    "residual %u "
		    "status_qualifier 0x%x status 0x%x response 0x%x",
		    cmd->vsc_info,
		    vsrq->vsrq_sense_len,
		    vsrq->vsrq_residual,
		    (uint_t)vsrq->vsrq_status_qualifier,
		    (uint_t)vsrq->vsrq_status,
		    (uint_t)vsrq->vsrq_response);

		if (vsrq->vsrq_status == 0 && vsrq->vsrq_response == 0 &&
		    (2048 - vsrq->vsrq_residual) > 36) {
			/*
			 * Attempt to decode inquiry?
			 */
			char s[32];

			void *dp = cmd->vsc_va +
			    cmd->vsc_response_offset +
			    sizeof (struct virtio_scsi_req_cmd_write) +
			    vis->vis_sense_size;

			bzero(s, sizeof (s));
			bcopy(dp + 8, s, 8);
			dev_err(vis->vis_dip, CE_WARN, "VENDOR \"%s\"", s);

			bzero(s, sizeof (s));
			bcopy(dp + 16, s, 8);
			dev_err(vis->vis_dip, CE_WARN, "PRODUCT \"%s\"", s);

			bzero(s, sizeof (s));
			bcopy(dp + 32, s, 4);
			dev_err(vis->vis_dip, CE_WARN, "REVISION \"%s\"", s);
		}

		virtio_free_chain(qe);

		vioscsi_dma_free(&cmd->vsc_dma);
		kmem_free(cmd, sizeof (*cmd));
	}

	return (DDI_INTR_CLAIMED);
}

static void
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

static void
vioscsi_q_push(vioscsi_cmd_t *vsc)
{
	VERIFY3P(vsc->vsc_qe, !=, NULL);
	VERIFY3P(vsc->vsc_qe->qe_queue, ==, visq->visq_vq);

	VERIFY0(vsc->vsc_vqidx); /* XXX 0 is valid surely */
	vsc->vsc_vqidx = vsc->vsc_qe->qe_index;

	if (ddi_dma_sync(vsc->vsc_dma.vsdma_dma_handle, 0, 0,
	    DDI_DMA_SYNC_FORDEV) != DDI_SUCCESS) {
		/*
		 * XXX PANIC?
		 */
		dev_err(vis->vis_dip, CE_WARN, "DMA sync failure");
	}

	VERIFY(!(vsc->vsc_status & VIOSCSI_STATUS_INFLIGHT));
	avl_add(&visq->visq_inflight, vsc);
	vsc->vsc_status |= VIOSCSI_STATUS_INFLIGHT;

	dev_err(vis->vis_dip, CE_WARN, "q %d push idx %x", visq->visq_name,
	    (uint_t)vsc->vsc_qe->qe_index);

	vsc->vsc_time_push = gethrtime();

	virtio_push_chain(vsc->vsc_qe, B_TRUE);
}

static vioscsi_cmd_t *
vioscsi_q_pull(vioscsi_q_t *visq)
{
	vioscsi_t *vis = visq->visq_vioscsi;
	struct vq_entry *qe;
	uint32_t len;

top:
	if ((qe = virtio_pull_chain(visq->visq_vq, &len)) == NULL) {
		return (NULL);
	}

	dev_err(vis->vis_dip, CE_WARN, "q %d pull idx %x", visq->visq_name,
	    (uint_t)qe->qe_index);

	vioscsi_cmd_t search;
	search.vsc_q = visq->visq_vq;
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

static int
vioscsi_q_init(vioscsi_t *vis, vioscsi_q_t *visq, const char *strname,
    uint32_t index, vioscsi_queue_name_t name)
{
	VERIFY(!visq->visq_init);

	if ((visq->visq_vq = virtio_alloc_vq(vis->vis_virtio,
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

static void
vioscsi_discover(void *arg)
{
	vioscsi_t *vis = arg;
	uint64_t gen;
	uint32_t max_target, max_lun;
	int r;

	mutex_enter(&vis->vis_mutex);
	vis->vis_status |= VIOSCSI_STATUS_DISCOVERY_RUNNING;
	vis->vis_status &= ~VIOSCSI_STATUS_DISCOVERY_REQUESTED;

	max_target = vis->vis_max_target;
	mutex_exit(&vis->vis_mutex);

	/*
	 * Begin updating the target map.
	 */
	if (scsi_hba_tgtmap_set_begin(vis->vis_tgtmap) != DDI_SUCCESS) {
		dev_err(vis->vis_dip, CE_WARN, "failed to begin target map "
		    "observation on %s", VIOSCSI_IPORT);
		r = EIO;
		goto done;
	}

	/*
	 * XXX Primitive discovery loop.  We'll walk the full range of target
	 * addresses that we believe is possible, submitting REPORT LUNS to LUN
	 * zero at each target.  If that succeeds, we'll mark the target as
	 * active.
	 */
	for (uint32_t target = 0; target <= max_target; target++) {
		vioscsi_cmd_t *vsc;
		int res;

		if ((vsc = vioscsi_report_luns_alloc(vis, target)) == NULL) {
			r = ENOMEM;
			goto done;
		}

		vioscsi_q_push(vsc);

		if ((res = vioscsi_poll_for(vsc)) != 0) {
			dev_err(vis->vis_dip, CE_WARN,
			    "disco REPORT LUNS poll failure (%u) = %u",
			    target, res);
			r = EIO;
			goto done;
		}

		if (!(vsc->vsc_status & VIOSCSI_CMD_STATUS_ERROR)) {
			/*
			 * Successful REPORT LUNS!  Mark this target and LUN as
			 * available.
			 * XXX Technically we should look _inside_ the REPORT
			 * LUNS response, rather than assume it's a disk on
			 * LUN 0?
			 */

			/*
			 * We use the same format for our address as is
			 * expected by devfsadm; see disk_callback_chan().
			 */
			char addr[128];
			(void) snprintf(addr, sizeof (addr), "%x,%x",
			    target, 0);

			if (scsi_hba_tgtmap_set_add(vis->vis_tgtmap,
			    SCSI_TGT_SCSI_DEVICE, addr, NULL) != DDI_SUCCESS) {
				r = EIO;
				goto done;
			}
		}

		vioscsi_cmd_free(vsc);
	}

	r = 0;

done:
	if (r == 0) {
		if (scsi_hba_tgtmap_set_end(vis->vis_tgtmap) != DDI_SUCCESS) {
			dev_err(vis->vis_dip, CE_WARN, "target map update "
			    "failed");
			r = EIO;
		}
	} else {
		/*
		 * We were unable to complete a full scan, so abandon this
		 * target map update.
		 */
		if (scsi_hba_tgtmap_set_flush(vis->vis_tgtmap) != DDI_SUCCESS) {
			dev_err(vis->vis_dip, CE_WARN, "target map update "
			    "cancel failed");
		}
	}

	mutex_enter(&vis->vis_mutex);
	vis->vis_status &= ~VIOSCSI_STATUS_DISCOVERY_RUNNING;
	if (r == 0) {
		/*
		 * Update the time of the last successful discovery:
		 */
		vis->vis_time_last_discovery = gethrtime();
	}

	/*
	 * If this discovery scan failed or if discovery was requested while we
	 * were already running, request a new discovery scan at the next
	 * periodic maintenance interval.
	 */
	if (r != 0 || (vis->vis_status & VIOSCSI_STATUS_DISCOVERY_REQUESTED)) {
		vis->vis_status |= VIOSCSI_STATUS_DISCOVERY_PERIODIC;
	}
	mutex_exit(&vis->vis_mutex);

	return (r);
}

static void
vioscsi_discover_request(vioscsi_t *vis)
{
	boolean_t run;
	VERIFY(MUTEX_HELD(&vis->vis_mutex));

	if (ddi_in_panic()) {
		return;
	}

	/*
	 * We only need to activate the discovery task queue if discovery is
	 * not in progress, and has not been scheduled for the periodic
	 * routine.
	 */
	run = (vis->vis_status & VIOSCSI_STATUS_DISCOVERY_MASK) == 0;
	vis->vis_status |= VIOSCSI_STATUS_DISCOVERY_REQUESTED;
	if (!run) {
		return;
	}

	if (ddi_taskq_dispatch(vis->vis_discover_taskq, vioscsi_discover,
	    vis, DDI_NOSLEEP) != DDI_SUCCESS) {
		/*
		 * We couldn't kick off the discovery task queue, so fall
		 * back to requesting discovery from the periodic routine.
		 */
		vis->vis_status |= VIOSCSI_STATUS_DISCOVERY_PERIODIC;
	}
}

void
vioscsi_periodic(void *arg)
{
	vioscsi_t *vis = arg;

	mutex_enter(&vis->vis_mutex);

	/*
	 * XXX Maintain!
	 */

	mutex_exit(&vis->vis_mutex);
}

static int
vioscsi_tran_setup_pkt(struct scsi_pkt *pkt, int (*callback)(caddr_t),
    caddr_t arg)
{
	struct scsi_device *sd;
	vioscsi_target_t *vist;
	vioscsi_t *vis;
	vioscsi_cmd_scsa_t *vscs;
	vioscsi_cmd_t *vsc;

	VERIFY((sd = scsi_address_device(&pkt->pkt_addres)) != NULL);
	VERIFY((vist = scsi_device_hba_private_get(sd)) != NULL);
	VERIFY((vis = vist->vist_vioscsi) != NULL);
	VERIFY((vscs = (vioscsi_cmd_scsa_t *)pkt->pkt_ha_private) != NULL);

	if (pkt->pkt_cdblen > vis->vis_cdb_size) {
		dev_err(vis->vis_dip, CE_WARN, "oversize CDB: had %u, "
		    "needed %u", vis->vis_cdb_size, pkt->pkt_cdblen);
		return (-1);
	}

	/*
	 * The storage we allocate in the command itself will cover the
	 * outgoing command block, not including "datain", and the incoming
	 * response, not including "dataout".  The data space will come from
	 * cookies provided by SCSA.
	 */
	size_t sz = sizeof (struct virtio_scsi_req_cmd_read) +
	    vis->vis_cdb_size +
	    sizeof (struct virtio_scsi_req_cmd_write) +
	    vis->vis_sense_size;
	if ((vsc = vioscsi_cmd_alloc(vis, &vis->vis_q_request, sz)) == NULL) {
		return (-1);
	}
	vsc->vsc_scsa = vscs;
	vsc->vsc_response_offset = sizeof (struct virtio_scsi_req_cmd_read) +
	    vis->vis_cdb_size;
	vscs->vscs_cmd = vsc;
	vscs->vscs_pkt = pkt;

	struct virtio_scsi_req_cmd_read *vsrq = vsc->vsc_va;
	pkt->pkt_cdbp = &vsrq->vsrq_cdb[0];

	return (0);
}

static void
vioscsi_tran_teardown_pkt(struct scsi_pkt *pkt)
{
	vioscsi_cmd_scsa_t *vscs = (vioscsi_cmd_scsa_t)pkt->pkt_ha_private;
	vioscsi_cmd_t *vsc = vscs->vscs_cmd;

	vioscsi_cmd_free(vsc);

	pkt->pkt_cdbp = NULL;
}

static int
vioscsi_tran_reset(struct scsi_address *ap, int level)
{
	/*
	 * XXX Pretend we did a reset.
	 */
	return (1);
}

static int
vioscsi_tran_abort(struct scsi_address *sa, struct scsi_pkt *pkt)
{
	/*
	 * XXX Fail to abort anything right now.
	 */
	return (0);
}

static int
vioscsi_tran_start(struct scsi_address *sa, struct scsi_pkt *pkt)
{
	struct scsi_device *sd;
	vioscsi_target_t *vist;
	vioscsi_t *vis;
	vioscsi_cmd_t *vsc;
	vioscsi_cmd_scsa_t *vscs;

	VERIFY((sd = scsi_address_device(&pkt->pkt_address)) != NULL);
	VERIFY((vist = scsi_device_hba_private_get(sd)) != NULL);
	VERIFY((vis = vist->vist_vioscsi) != NULL);
	VERIFY((vscs = (vioscsi_cmd_scsa_t *)pkt->pkt_ha_private) != NULL);
	VERIFY((vsc = vscs->vscs_cmd) != NULL);

	if (vsc->vsc_status & VIOSCSI_CMD_STATUS_TRAN_START) {
		/*
		 * We have already used this command structure once.  We'll
		 * need to clear it out so that we can set up the descriptors
		 * again from scratch.
		 */
		vioscsi_cmd_clear(vsc);
	}
	vsc->vsc_status |= VIOSCSI_CMD_STATUS_TRAN_START;

	dev_err(vis->vis_dip, CE_WARN, "device %s tran_start opcode 0x%x",
	    scsi_device_unit_address(sd), (uint_t)pkt->pkt_cdbp[0]);

	if (pkt->pkt_flags & FLAG_NOINTR) {
		/*
		 * We must sleep and wait for the completion of this command.
		 */
		vsc->vsc_status |= VIOSCSI_CMD_STATUS_POLLED;
	}

	volatile struct virtio_scsi_req_cmd_read *vsrq = vsc->vsc_va;
	bcopy(vist->vist_lun, vsrq->vsrq_lun, 8);
	vsrq->vsrq_id = vis->vis_next_tag++;

	/*
	 * Add the device-readable request header in the first descriptor.
	 */
	struct vq_entry *qe;
	if ((qe = vioscsi_cmd_append(vsc)) == NULL) {
		return (TRAN_BADPKT);
	}

	virtio_ve_set(qe, vsc->vsc_pa, vsc->vsc_response_offset, B_TRUE);

	/*
	 * Append any outbound cookies between the request and response
	 * descriptors.
	 */
	if (pkt->pkt_numcookies > 0 && (pkt->pkt_dma_flags & DDI_DMA_WRITE)) {
		for (uint_t n = 0; n < pkt->pkt_numcookies; n++) {
			if ((qe = vioscsi_cmd_append(vsc)) == NULL) {
				return (TRAN_BADPKT);
			}

			virtio_ve_set(qe, pkt->pkt_cookies[n].dmac_laddress,
			    pkt->pkt_cookies[n].dmac_size, B_TRUE);
		}
	}

	/*
	 * Add the device-writeable response header.
	 */
	if ((qe = vioscsi_cmd_append(vsc)) == NULL) {
		return (TRAN_BADPKT);
	}

	virtio_ve_set(qe, vsc->vsc_pa + vsc->vsc_response_offset,
	    vsc->vsc_sz - vsc->vsc_response_offset, B_FALSE);

	/*
	 * Append any inbound cookies after the response header.
	 */
	if (pkt->pkt_numcookies > 0 && (pkt->pkt_dma_flags & DDI_DMA_READ)) {
		for (uint_t n = 0; n < pkt->pkt_numcookies; n++) {
			if ((qe = vioscsi_cmd_append(vsc)) == NULL) {
				return (TRAN_BADPKT);
			}

			virtio_ve_set(qe, pkt->pkt_cookies[n].dmac_laddress,
			    pkt->pkt_cookies[n].dmac_size, B_FALSE);
		}
	}

	/*
	 * Initialise the SCSI packet as described in tran_start(9E).  We will
	 * progressively update these fields as the command moves through the
	 * submission and completion states.
	 */
	pkt->pkt_resid = 0;
	pkt->pkt_reason = CMD_CMPLT;
	pkt->pkt_statistics = 0;
	pkt->pkt_state = 0;

	/*
	 * XXX pkt->pkt_time
	 */

	vioscsi_q_push(vsc);

	/*
	 * Update the SCSI packet to reflect submission of the command.
	 */
	pkt->pkt_state |= STATE_GOT_BUS | STATE_GOT_TARGET | STATE_SENT_CMD;

	if (pkt->pkt_flags & FLAG_NOINTR) {
		/*
		 * XXX poll
		 */
		vioscsi_poll_for(vsc);
	}

	mutex_exit(&vis->vis_mutex);
	return (TRAN_ACCEPT);
}


static int
vioscsi_setcap(struct scsi_address *sa, char *cap, int value, int whom)
{
	int index;

	if ((index = scsi_hba_lookup_capstr(cap)) == DDI_FAILURE) {
		return (-1);
	}

	if (whom == 0) {
		return (-1);
	}

	switch (index) {
	case SCSI_CAP_CDB_LEN:
	case SCSI_CAP_DMA_MAX:
	case SCSI_CAP_SECTOR_SIZE:
	case SCSI_CAP_INITIATOR_ID:
	case SCSI_CAP_DISCONNECT:
	case SCSI_CAP_SYNCHRONOUS:
	case SCSI_CAP_WIDE_XFER:
	case SCSI_CAP_ARQ:
	case SCSI_CAP_UNTAGGED_QING:
	case SCSI_CAP_TAGGED_QING:
	case SCSI_CAP_RESET_NOTIFICATION:
	case SCSI_CAP_INTERCONNECT_TYPE:
		/*
		 * We do not support changing any capabilities at this time.
		 */
		return (0);

	default:
		/*
		 * The capability in question is not known to this driver.
		 */
		return (-1);
	}
}

static int
vioscsi_getcap(struct scsi_address *sa, char *cap, int whom)
{
	struct scsi_device *sd;
	vioscsi_target_t *vist;
	vioscsi_t *vis;
	int index;

	VERIFY((sd = scsi_address_device(sa)) != NULL);
	VERIFY((vist = scsi_device_hba_private_get(sd)) != NULL);
	VERIFY((vis = vist->vist_vioscsi) != NULL);

	if ((index = scsi_hba_lookup_capstr(cap)) == DDI_FAILURE) {
		return (-1);
	}

	switch (index) {
	case SCSI_CAP_CDB_LEN:
		return (vis->vis_cdb_size);

	case SCSI_CAP_DMA_MAX:
		return ((int)vioscsi_dma_attr.dma_attr_maxxfer);

	case SCSI_CAP_SECTOR_SIZE:
		if (vioscsi_dma_attr.dma_attr_granular > INT_MAX) {
			return (-1);
		}
		return ((int)vioscsi_dma_attr.dma_attr_granular);

	case SCSI_CAP_INTERCONNECT_TYPE:
		/*
		 * Virtio SCSI devices are identified by a simple (target, lun)
		 * pair.  So that devfsadm does not expect a full SAS WWN,
		 * identify as a simple SCSI bus for this device.
		 */
		return (INTERCONNECT_PARALLEL);

	case SCSI_CAP_DISCONNECT:
	case SCSI_CAP_SYNCHRONOUS:
	case SCSI_CAP_WIDE_XFER:
	case SCSI_CAP_ARQ:
	case SCSI_CAP_UNTAGGED_QING:
	case SCSI_CAP_TAGGED_QING:
		/*
		 * These capabilities are supported by the driver and the
		 * controller.  See scsi_ifgetcap(9F) for more information.
		 */
		return (1);

	case SCSI_CAP_INITIATOR_ID:
	case SCSI_CAP_RESET_NOTIFICATION:
		/*
		 * These capabilities are not supported.
		 */
		return (0);

	default:
		return (-1);
	}
}

static int
vioscsi_no_tran_tgt_init(dev_info_t *hba_dip, dev_info_t *tgt_dip,
    scsi_hba_tran_t *hba_tran, struct scsi_device *sd)
{
	return (DDI_FAILURE);
}

static int
vioscsi_no_tran_start(struct scsi_address *sa, struct scsi_pkt *pkt)
{
	return (TRAN_BADPKT);
}

static int
vioscsi_hba_setup(vioscsi_t *vis)
{
	scsi_hba_tran_t *tran;

	if ((tran = scsi_hba_tran_alloc(dip, SCSI_HBA_CANSLEEP)) == NULL) {
		dev_err(vis->vis_dip, CE_WARN, "could not allocate SCSA "
		    "resources");
		return (DDI_FAILURE);
	}

	vis->vis_hba_tran = tran;
	tran->tran_hba_private = vis;

	tran->tran_tgt_init = vioscsi_no_tran_tgt_init;
	tran->tran_tgt_probe = scsi_hba_probe;

	tran->tran_start = vioscsi_no_tran_start;

	tran->tran_getcap = vioscsi_getcap;
	tran->tran_setcap = vioscsi_setcap;

	tran->tran_setup_pkt = vioscsi_tran_setup_pkt;
	tran->tran_teardown_pkt = vioscsi_tran_teardown_pkt;
	tran->tran_hba_len = sizeof (vioscsi_cmd_scsa_t);
	tran->tran_interconnect_type = INTERCONNECT_SAS;

	if (scsi_hba_attach_setup(vis->vis_dip, &vioscsi_dma_attr,
	    tran, SCSI_HBA_HBA | SCSI_HBA_TRAN_SCB | SCSI_HBA_ADDR_COMPLEX) !=
	    DDI_SUCCESS) {
		dev_err(vis->vis_dip, CE_WARN,
		    "could not attach to SCSA framework");
		scsi_hba_tran_free(tran);
		return (DDI_FAILURE);
	}

	INITLEVEL_SET(vis, VIOSCSI_INITLEVEL_SCSA);
	return (DDI_SUCCESS);
}

static void
vioscsi_hba_teardown(vioscsi_t *vis)
{
	if (!INITLEVEL_ACTIVE(vis, VIOSCSI_INITLEVEL_SCSA)) {
		return;
	}

	VERIFY(scsi_hba_detach(vis->vis_dip) != DDI_FAILURE);
	scsi_hba_tran_free(vis->vis_hba_tran);
	INITLEVEL_CLEAR(vis, VIOSCSI_INITLEVEL_SCSA);
}

static boolean_t
vioscsi_addr_parse(const char *ua, uint_t *targetp, uint_t *lunp)
{
	long target, lun;
	const char *comma;
	char *eptr;

	if ((comma = strchr(ua, ',')) == NULL) {
		return (B_FALSE);
	}

	if (ddi_strtol(ua, &eptr, 16, &target) != 0 || eptr != comma ||
	    target < 0 || target > UINT8_MAX) {
		return (B_FALSE);
	}

	if (ddi_strtol(comma + 1, &eptr, 16, &lun) != 0 || *eptr != '\0' ||
	    lun < 0 || lun > UINT16_MAX) {
		return (B_FALSE);
	}

	if (targetp != NULL) {
		*targetp = (uint_t)target;
	}
	if (lunp != NULL) {
		*lunp = (uint_t)lun;
	}
	return (B_TRUE);
}

static void
vioscsi_tgtmap_activate(void *arg, char *addr, scsi_tgtmap_tgt_type_t type,
    void **privpp)
{
	vioscsi_t *vis = arg;

	VERIFY3S(type, ==, SCSI_TGT_SCSI_DEVICE);
	VERIFY(vioscsi_addr_parse(addr, NULL, NULL));

	/*
	 * XXX more validation?
	 */
}

boolean_t
vioscsi_tgtmap_deactivate(void *arg, char *addr,
    scsi_tgtmap_tgt_type_t type, void *priv, scsi_tgtmap_deact_rsn_t reason)
{
	VERIFY3S(type, ==, SCSI_TGT_SCSI_DEVICE);
	VERIFY(vioscsi_addr_parse(addr, NULL, NULL));

	/*
	 * XXX more validation?
	 */

	return (B_FALSE);
}

static int
vioscsi_tran_tgt_init(dev_info_t *hba_dip, dev_info_t *tgt_dip,
    scsi_hba_tran_t *hba_tran, struct scsi_device *sd)
{
	vioscsi_t *vis = (vioscsi_t *)hba_tran->tran_hba_private;
	const char *ua;
	uint_t target, lun;

	/*
	 * Convert the unit address string back into a target and LUN number.
	 */
	if ((ua = scsi_device_unit_address(sd)) == NULL ||
	    !vioscsi_addr_parse(ua, &target, &lun)) {
		return (DDI_FAILURE);
	}

	vioscsi_target_t *vist;
	if ((vist = kmem_zalloc(sizeof (*vist), KM_NOSLEEP)) == NULL) {
		dev_err(dip, CE_WARN, "could not allocate target object "
		    "due to memory exhaustion");
		return (DDI_FAILURE);
	}

	mutex_enter(&vis->vis_mutex);
	if (vis->vis_status & VIOSCSI_STATUS_DETACHING) {
		/*
		 * We are detaching.  Do not accept any more requests to
		 * attach targets from the framework.
		 */
		mutex_exit(&vis->vis_mutex);
		kmem_free(vist, sizeof (*vist));
		return (DDI_FAILURE);
	}

	vist->vist_vioscsi = vis;
	vist->vist_scsi_dev = sd;
	VERIFY3P(sd->sd_dev, ==, tgt_dip);

	/*
	 * As per the specification, the first LUN address byte is 1, followed
	 * by the target, then a 2-byte logical unit.
	 * XXX It's really not clear if they mean the LUN to be LE16...
	 */
	vist->vist_lun[0] = 0x01;
	vist->vist_lun[1] = target & 0xFF;
	vist->vist_lun[2] = lun & 0xFF;
	vist->vist_lun[3] = (lun >> 8) && 0xFF;

	/*
	 * XXX Link this target object to the controller.
	 */

	scsi_device_hba_private_set(sd, vist);

	mutex_exit(&vis->vis_mutex);
	return (DDI_SUCCESS);
}

static void
vioscsi_tran_tgt_free(dev_info_t *hba_dip, dev_info_t *tgt_dip,
    scsi_hba_tran_t *hba_tran, struct scsi_device *sd)
{
	vioscsi_t *vis = (vioscsi_t *)hba_tran->tran_hba_private;
	vioscsi_target_t *vist = scsi_device_hba_private_get(sd);

	VERIFY3P(vist->vist_scsi_dev, ==, sd);

	mutex_enter(&smrt->smrt_mutex);
	/*
	 * XXX remove from controller target list.
	 */
	mutex_exit(&smrt->smrt_mutex);

	scsi_device_hba_private_set(sd, NULL);

	kmem_free(vist, sizeof (*vist));
}

static int
vioscsi_iport_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	const char *addr;
	vioscsi_t *vis;

	if (cmd != DDI_ATTACH) {
		return (DDI_FAILURE);
	}

	VERIFY((addr = scsi_hba_iport_unit_address(dip)) != NULL);

	/*
	 * We cannot get to our parent via the tran_hba_private member.  This
	 * member is reset to NULL when the scsi_hba_tran_t structure is
	 * duplicated.
	 */
	VERIFY((vis = ddi_get_soft_state(vioscsi_state,
	    ddi_get_instance(ddi_get_parent(dip)))) != NULL);

	if (strcmp(addr, VIOSCSI_IPORT) != 0) {
		/*
		 * We only support the one hard-coded iport for now.
		 */
		return (DDI_FAILURE);
	}

	scsi_hba_tran_t *tran;
	if ((tran = ddi_get_driver_private(dip)) == NULL) {
		return (DDI_FAILURE);
	}

	tran->tran_tgt_init = vioscsi_tran_tgt_init;
	tran->tran_tgt_free = vioscsi_tran_tgt_free;

	tran->tran_start = vioscsi_tran_start;
	tran->tran_reset = vioscsi_tran_reset;
	tran->tran_abort = vioscsi_tran_abort;

	tran->tran_hba_private = vioscsi;

	mutex_enter(&vis->vis_mutex);

	if (scsi_hba_tgtmap_create(dip, SCSI_TM_FULLSET, MICROSEC, 2 * MICROSEC,
	    vis, vioscsi_tgtmap_activate, vioscsi_tgtmap_deactivate,
	    &vis->vis_tgtmap) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	/*
	 * XXX SCHEDULE A DISCOVERY REQUEST NOW...
	 */
	vioscsi_discover_request(vis);

	vis->vis_iport = dip;

	mutex_exit(&vis->vis_mutex);
	return (DDI_SUCCESS);
}

static int
vioscsi_iport_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	char *addr;
	scsi_hba_tran_t *tran;
	vioscsi_t *vis;

	if (cmd != DDI_DETACH) {
		return (DDI_FAILURE);
	}

	VERIFY((tran = ddi_get_driver_private(dip)) != NULL);
	VERIFY((vis = tran->tran_hba_private) != NULL);

	VERIFY((addr = scsi_hba_iport_unit_address(dip)) != NULL);

	if (strcmp(addr, VIOSCSI_IPORT) != 0) {
		/*
		 * We only support one hard-coded iport for now.
		 */
		return (DDI_FAILURE);
	}

	/*
	 * XXX TAKE LOCK
	 */

	if (vis->vis_tgtmap != NULL) {
		scsi_hba_tgtmap_t *t = vis->vis_tgtmap;
		vis->vis_tgtmap = NULL;

		/*
		 * XXX DROP LOCK.
		 */
		scsi_hba_tgtmap_destroy(t);
		/*
		 * XXX TAKE LOCK
		 */
	}

	vis->vis_iport = NULL;

	/*
	 * XXX DROP LOCK
	 */

	return (DDI_SUCCESS);
}

static int
vioscsi_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	uint32_t instance;
	vioscsi_t *vis;
	struct virtio_softc *vio;
	int r;

	if (scsi_hba_iport_unit_address(dip) != NULL) {
		return (vioscsi_iport_attach(dip, cmd));
	}

	if (cmd != DDI_ATTACH) {
		return (DDI_FAILURE);
	}

	/*
	 * Allocate the per-controller soft state object and get a pointer to
	 * it.
	 */
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

	/*
	 * Initialise per-controller state object.
	 */
	vio = &vis->vis_virtio;
	vio->sc_dev = dip;

	vis->vis_dip = dip;
	vis->vis_instance = instance;

	INITLEVEL_SET(vis, VIOSCSI_INITLEVEL_BASIC);

	/*
	 * Perform common virtio initialisation and feature negotiation.
	 */
	if (virtio_legacy_init(&vis->vis_virtio, 8) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "legacy init failure");
		goto fail;
	}
	INITLEVEL_SET(vis, VIOSCSI_INITLEVEL_VIRTIO);

	uint32_t feat;
	feat = virtio_negotiate_features(&vis->vis_virtio,
	    VIRTIO_SCSI_F_HOTPLUG);

	/*
	 * The SCSI device has several virtqueues:
	 * 	0	control queue
	 * 	1	event queue
	 * 	2..n	request queue(s)
	 *
	 * We need to register an interrupt handler for each.
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

	if (vioscsi_q_init(vis, &vis->vis_q_control, "control",
	    VIRTIO_SCSI_VIRTQ_CONTROL, VIOSCSI_CMDQ_CONTROL) != DDI_SUCCESS ||
	    vioscsi_q_init(vis, &vis->vis_q_event, "event",
	    VIRTIO_SCSI_VIRTQ_EVENT, VIOSCSI_CMDQ_EVENT) != DDI_SUCCESS ||
	    vioscsi_q_init(vis, &vis->vis_q_request, "request",
	    VIRTIO_SCSI_VIRTQ_REQUEST, VIOSCSI_CMDQ_REQUEST) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "failed to allocate virtqueues");
		goto fail;
	}

	/*
	 * Now that we have the correct interrupt priority, we can initialise
	 * the mutex.  This must be done before the interrupt handler is
	 * enabled.
	 */
	mutex_init(&vis->vis_mutex, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(vio->sc_intr_prio));
	cv_init(&vis->vis_cv_finish, NULL, CV_DRIVER, NULL);
	INITLEVEL_SET(vis, VIOSCSI_INITLEVEL_MUTEX);

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

	/*
	 * XXX I believe this should be used to constrain the number of chained
	 * descriptors to use for a command.
	 */
	vis->vis_seg_max = virtio_read_device_config_4(&vis->vis_virtio,
	    VIRTIO_SCSI_CFG_SEG_MAX);
	dev_err(dip, CE_WARN, "config: seg_max = %u", vis->vis_seg_max);

	/*
	 * The specification suggests the maximum channel value SHOULD be zero.
	 * At least one implementation in the wild returns a value of one.
	 * It's not clear from the specification how one would actually include
	 * a channel number in the described LUN address format, so for now
	 * just report if the value is outside the range we've seen.
	 */
	vis->vis_max_channel = virtio_read_device_config_2(&vis->vis_virtio,
	    VIRTIO_SCSI_CFG_MAX_CHANNEL);
	if (vis->vis_max_channel > 1) {
		/*
		 * We don't need to clamp because we don't actually use this
		 * value for anything.
		 */
		dev_err(dip, CE_WARN, "max_channel value of %u is higher "
		    "than expected", vis->vis_max_channel);
	}

	/*
	 * The specification suggests that the maximum target number should be
	 * capped at 255.  We'll clamp at that value in order to avoid an even
	 * more expensive scan than usual.
	 */
	vis->vis_max_target_raw = virtio_read_device_config_2(&vis->vis_virtio,
	    VIRTIO_SCSI_CFG_MAX_TARGET);
	if (vis->vis_max_target_raw > 255) {
		vis->vis_max_target = 255;
		dev_err(dip, CE_WARN, "max_target value was %u, clamping at "
		    "%u", vis->vis_max_target_raw, vis->vis_max_target);
	} else {
		vis->vis_max_target = vis->vis_max_target_raw;
	}

	/*
	 * The maximum LUN number should be capped at 16383 according to the
	 * specification.  In practice, it seems that most implementations will
	 * just use LUN 0 on each target.
	 */
	vis->vis_max_lun_raw = virtio_read_device_config_4(&vis->vis_virtio,
	    VIRTIO_SCSI_CFG_MAX_LUN);
	if (vis->vis_max_lun_raw > 1) {
		vis->vis_max_lun = 1;
		dev_err(dip, CE_WARN, "max_lun value was %u, clamping at "
		    "%u", vis->vis_max_lun_raw, vis->vis_max_lun);
	} else {
		vis->vis_max_lun = vis->vis_max_lun_raw;
	}

	/*
	 * Register the maintenance routine for periodic execution:
	 */
	vis->vis_periodic = ddi_periodic_add(vioscsi_periodic, vis,
	    VIOSCSI_PERIODIC_RATE * NANOSEC, DDI_IPL_0);
	INITLEVEL_SET(vis, VIOSCSI_INITLEVEL_PERIODIC);

	/*
	 * Create a task queue to manage the discovery of targets and LUNs.
	 */
	char taskq_name[64];
	(void) snprintf(taskq_name, sizeof (taskq_name), "vioscsi_discover_%u",
	    instance);
	if ((vis->vis_discover_taskq = ddi_taskq_create(dip, taskq_name, 1,
	    TASKQ_DEFAULTPRI, 0)) == NULL) {
		dev_err(dip, CE_WARN, "failed to create discovery task queue");
		goto fail;
	}
	INITLEVEL_SET(vis, VIOSCSI_INITLEVEL_TASKQ);

	/*
	 * Populate the event virtqueue with some buffers so that the host can
	 * notify us of topology changes.  This is done prior to the first
	 * probe for targets so that we don't miss any topology changes.
	 */
	(void) vioscsi_fill_events(vis); /* XXX */

	if (vioscsi_hba_setup(vis) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "SCSI framework setup failed");
		goto fail;
	}

	if (scsi_hba_iport_register(dip, VIOSCSI_IPORT) != DDI_SUCCESS) {
		goto fail;
	}

	/*
	 * Start device operation.
	 */
	virtio_set_status(&vis->vis_virtio,
	    VIRTIO_CONFIG_DEVICE_STATUS_DRIVER_OK);

	/*
	 * Announce the attachment of this controller.
	 */
	ddi_report_dev(dip);
	dev_err(dip, CE_WARN, "attach ok");

	return (DDI_SUCCESS);

fail:
	vioscsi_cleanup(vis);
	return (DDI_FAILURE);
}

static void
vioscsi_cleanup(vioscsi_t *vis)
{
	vioscsi_q_fini(&vis->vis_q_control);
	vioscsi_q_fini(&vis->vis_q_event);
	vioscsi_q_fini(&vis->vis_q_release);

	if (INITLEVEL_ACTIVE(vis, VIOSCSI_INITLEVEL_TASKQ)) {
		ddi_taskq_destroy(vis->vis_taskq);
		vis->vis_taskq = NULL;

		INITLEVEL_CLEAR(vis, VIOSCSI_INITLEVEL_TASKQ);
	}

	if (INITLEVEL_ACTIVE(vis, VIOSCSI_INITLEVEL_PERIODIC)) {
		ddi_periodic_delete(vis->vis_periodic);

		INITLEVEL_CLEAR(vis, VIOSCSI_INITLEVEL_PERIODIC);
	}

	if (INITLEVEL_ACTIVE(vis, VIOSCSI_INITLEVEL_INTERRUPTS)) {
		virtio_release_ints(&vis->vis_virtio);

		INITLEVEL_CLEAR(vis, VIOSCSI_INITLEVEL_INTERRUPTS);
	}

	if (INITLEVEL_ACTIVE(vis, VIOSCSI_INITLEVEL_VIRTIO)) {
		virtio_legacy_fini(&vis->vis_virtio);

		INITLEVEL_CLEAR(vis, VIOSCSI_INITLEVEL_VIRTIO);
	}

	if (INITLEVEL_ACTIVE(vis, VIOSCSI_INITLEVEL_BASIC)) {

		INITLEVEL_CLEAR(vis, VIOSCSI_INITLEVEL_BASIC);
	}

	if (INITLEVEL_ACTIVE(vis, VIOSCSI_INITLEVEL_MUTEX)) {
		mutex_destroy(&vis->vis_mutex);
		cv_destroy(&vis->vis_cv_finish);

		INITLEVEL_CLEAR(vis, VIOSCSI_INITLEVEL_MUTEX);
	}

	VERIFY0(vis->vis_init_level);

	ddi_soft_state_free(vioscsi_state, ddi_get_instance(vis->vis_dip));
}

static int
vioscsi_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	scsi_hba_tran_t *tran = ddi_get_driver_private(dip);
	vioscsi_t *vis = (vioscsi_t *)tran->tran_hba_private;

	if (scsi_hba_iport_unit_address(dip) != NULL) {
		return (vioscsi_iport_detach(dip, cmd));
	}

	if (cmd != DDI_DETACH) {
		return (DDI_FAILURE);
	}

	mutex_enter(&vis->vis_mutex);
	if (vis->vis_iport != NULL) {
		mutex_exit(&vis->vis_mutex);
		dev_err(vis->vis_dip, CE_WARN, "cannot detach: iports still "
		    "attached");
		return (DDI_FAILURE);
	}

	vis->vis_status |= VIOSCSI_STATUS_DETACHING;
	mutex_exit(&vis->vis_mutex);

	vioscsi_cleanup(vis);

	dev_err(dip, CE_WARN, "detach ok");
	return (DDI_SUCCESS);
}

static int
vioscsi_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rval)
{
	int inst = MINOR2INST(getminor(dev));
	int status;

	if (secpolicy_sys_config(credp, B_FALSE) != 0) {
		return (EPERM);
	}

	if (ddi_get_soft_state(vioscsi_state, inst) == NULL) {
		return (ENXIO);
	}

	switch (cmd) {
	default:
		status = scsi_hba_ioctl(dev, cmd, arg, mode, credp, rval);
		break;
	}

	return (status);
}

static int
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
	} else if (l->vsc_vqidx < r-<vsc_vqidx) {
		return (-1);
	} else {
		return (0);
	}
}
