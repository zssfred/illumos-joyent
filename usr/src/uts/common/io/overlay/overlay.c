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
 * Copyright (c) 2014 Joyent, Inc.  All rights reserved.
 */

/*
 * XXX
 */

#include <sys/conf.h>
#include <sys/errno.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/policy.h>
#include <sys/stream.h>
#include <sys/strsubr.h>
#include <sys/strsun.h>
#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/param.h>
#include <sys/sysmacros.h>

#include <sys/dls.h>
#include <sys/dld_ioc.h>
#include <sys/mac_provider.h>
#include <sys/mac_ether.h>
#include <sys/vlan.h>
#include <sys/overlay_impl.h>

static kmutex_t overlay_dev_lock;
static list_t overlay_dev_list;
static dev_info_t *overlay_dip;
static uint8_t overlay_xxx_macaddr[ETHERADDRL] =
	{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

typedef enum overlay_dev_flag {
	OVERLAY_F_INACTIVE = 0x01	/* Indicates create in progress */
} overlay_dev_flag_t;

typedef struct overlay_dev {
	list_node_t	odd_link;
	mac_handle_t	odd_mh;
	datalink_id_t	odd_linkid;
	overlay_plugin_t *odd_plugin;
} overlay_dev_t;

static int
overlay_m_stat(void *arg, uint_t stat, uint64_t *val)
{
	return (ENOTSUP);
}

static int
overlay_m_start(void *arg)
{
	/*
	 * XXX We should use this as a means of lazily opening the lower level
	 * port that we end up using.
	 */
	return (0);
}

static void
overlay_m_stop(void *arg)
{
	/* XXX Undo anything we do in start, eg. close ports, etc. */
}

static int
overlay_m_promisc(void *arg, boolean_t on)
{
	/* XXX Is there anything for us to do for promisc, I don't think so */
	return (0);
}

static int
overlay_m_multicast(void *arg, boolean_t add, const uint8_t *addrp)
{
	/*
	 * XXX Semantically we support an unlimited number of multicast mac
	 * addresses. I think the real long term question is should this hit
	 * varpd for notification and/or approval? Likely only the former.
	 */
	return (0);
}

static int
overlay_m_unicast(void *arg, const uint8_t *macaddr)
{
	/*
	 * XXX Semantically we support an unlimited number of multicast mac
	 * addresses. I think the real long term question is should this hit
	 * varpd for notification and/or approval? Likely only the former.
	 */
	return (0);
}

static mblk_t *
overlay_m_tx(void *arg, mblk_t *mp_chain)
{
	/*
	 * XXX this should go through and actually send this over our underlying
	 * encapsulation protocol...
	 */
	freemsgchain(mp_chain);
	return (NULL);
}

static void
overlay_m_ioctl(void *arg, queue_t *q, mblk_t *mp)
{
	miocnak(q, mp, 0, ENOTSUP);
}

static boolean_t
overlay_m_getcapab(void *arg, mac_capab_t cap, void *cap_data)
{
	return (B_FALSE);
}

static int
overlay_m_setprop(void *arg, const char *pr_name, mac_prop_id_t pr_num,
    uint_t pr_valsize, const void *pr_val)
{
	return (ENOTSUP);
}

static int
overlay_m_getprop(void *arg, const char *pr_name, mac_prop_id_t pr_num,
    uint_t pr_valsize, void *pr_val)
{
	return (ENOTSUP);
}

static void
overlay_m_propinfo(void *arg, const char *pr_name, mac_prop_id_t pr_num,
    mac_prop_info_handle_t prh)
{
}

static mac_callbacks_t overlay_m_callbacks = {
	.mc_callbacks = (MC_IOCTL | MC_GETCAPAB | MC_SETPROP | MC_GETPROP |
	    MC_PROPINFO),
	.mc_getstat = overlay_m_stat,
	.mc_start = overlay_m_start,
	.mc_stop = overlay_m_stop,
	.mc_setpromisc = overlay_m_promisc,
	.mc_multicst = overlay_m_multicast,
	.mc_unicst = overlay_m_unicast,
	.mc_tx = overlay_m_tx,
	.mc_ioctl = overlay_m_ioctl,
	.mc_getcapab = overlay_m_getcapab,
	.mc_getprop = overlay_m_getprop,
	.mc_setprop = overlay_m_setprop,
	.mc_propinfo = overlay_m_propinfo
};

static boolean_t
overlay_valid_name(const char *name, size_t buflen)
{
	size_t actlen;
	int err, i;

	for (i = 0; i < buflen; i++) {
		if (name[i] == '\0')
			break;
	}

	if (i == 0 || i == buflen)
		return (B_FALSE);
	actlen = i;
	if (strchr(name, '/') != NULL)
		return (B_FALSE);
	if (u8_validate((char *)name, actlen, NULL,
	    U8_VALIDATE_ENTIRE, &err) < 0)
		return (B_FALSE);
	return (B_TRUE);
}

static int
overlay_ioc_create(void *karg, intptr_t arg, int mode, cred_t *cred, int *rvalp)
{
	int err;
	overlay_dev_t *odd;
	mac_register_t *mac;
	char name[MAXLINKNAMELEN];
	overlay_ioc_create_t *oicp = karg;

	if (overlay_valid_name(oicp->oic_encap, MAXLINKNAMELEN) == B_FALSE)
		return (EINVAL);


	mutex_enter(&overlay_dev_lock);
	for (odd = list_head(&overlay_dev_list); odd != NULL;
	    odd = list_next(&overlay_dev_list, odd)) {
		if (odd->odd_linkid == oicp->oic_overlay_id) {
			mutex_exit(&overlay_dev_lock);
			return (EEXIST);
		}
	}


	odd = kmem_zalloc(sizeof (overlay_dev_t), KM_SLEEP);
	odd->odd_linkid = oicp->oic_overlay_id;
	odd->odd_plugin = overlay_plugin_lookup(oicp->oic_encap);
	if (odd->odd_plugin == NULL) {
		mutex_exit(&overlay_dev_lock);
		kmem_free(odd, sizeof (overlay_dev_t));
		return (ENOENT);
	}

	mac = mac_alloc(MAC_VERSION);
	if (mac == NULL) {
		mutex_exit(&overlay_dev_lock);
		overlay_plugin_rele(odd->odd_plugin);
		kmem_free(odd, sizeof (overlay_dev_t));
		return (EINVAL);
	}

	/* TODO These are always good props */
	mac->m_type_ident = MAC_PLUGIN_IDENT_ETHER;
	mac->m_driver = odd;
	mac->m_dip = overlay_dip;
	mac->m_dst_addr = NULL;
	mac->m_callbacks = &overlay_m_callbacks;
	mac->m_pdata = NULL;
	mac->m_pdata_size = 0;

	/* XXX This will almost certainly change */
	mac->m_priv_props = NULL;

	/* XXX I think we should let mac handle this itself */
	mac->m_instance = (uint_t)-1;

	/*
	 * XXX This is definitely wrong. There is no real source address that
	 * should be used here, but saying that we're not ethernet is going to
	 * cause its own problems.
	 */
	mac->m_src_addr = overlay_xxx_macaddr;

	/*
	 * XXX These should come from the underlying device that we've been
	 * created over and be influenced based on the encap method.
	 */
	mac->m_min_sdu = 1300;
	mac->m_max_sdu = 1400;

	/*
	 * XXX This needs to come from the encapsulation protocol, well, really,
	 * we'll ask if it it supports vlans then go from there. In this case
	 * the underlying device doesn't matter, since it will be encapsulated.
	 */
	mac->m_margin = VLAN_TAGSZ;

	/*
	 * XXX While it seems like we should say that we have no virt
	 * assistence, we should figure out what that implies elsewhere and
	 * whether we can leverage existing software.
	 */
	mac->m_v12n = MAC_VIRT_NONE;

	/*
	 * XXX I'm not sure that we should bother emulating a separate multicast
	 * sdu. While we will have to take it into account in our min and max
	 * sdu that we give because some of our traffic may be arbitrarily sent
	 * over multicast, I'm pretty sure vnics above us don't need it.
	 */
	mac->m_multicast_sdu = 0;

	err = mac_register(mac, &odd->odd_mh);
	mac_free(mac);
	if (err != 0) {
		mutex_exit(&overlay_dev_lock);
		overlay_plugin_rele(odd->odd_plugin);
		kmem_free(odd, sizeof (overlay_dev_t));
		return (err);
	}

	err = dls_devnet_create(odd->odd_mh, odd->odd_linkid,
	    crgetzoneid(cred));
	if (err != 0) {
		mutex_exit(&overlay_dev_lock);
		(void) mac_unregister(odd->odd_mh);
		overlay_plugin_rele(odd->odd_plugin);
		kmem_free(odd, sizeof (overlay_dev_t));
		return (err);
	}

	list_insert_tail(&overlay_dev_list, odd);
	mutex_exit(&overlay_dev_lock);

	return (0);
}

static int
overlay_ioc_delete(void *karg, intptr_t arg, int mode, cred_t *cred, int *rvalp)
{
	overlay_ioc_delete_t *oidp = karg;
	overlay_dev_t *odd;
	datalink_id_t tid;
	int ret;

	mutex_enter(&overlay_dev_lock);

	for (odd = list_head(&overlay_dev_list); odd != NULL;
	    odd = list_next(&overlay_dev_list, odd)) {
		if (odd->odd_linkid == oidp->oid_overlay_id)
			break;
	}
	if (odd == NULL) {
		mutex_exit(&overlay_dev_lock);
		return (ENOENT);
	}

	/*
	 * To remove this, we need to first remove it from dls and then remove
	 * it from mac. The act of removing it from mac will check if there are
	 * devices on top of this, eg. vnics. If there are, then that will fail
	 * and we'll have to go through and recreate the dls entry. Only after
	 * mac_unregister has succeeded, then we'll go through and actually free
	 * everything and drop the dev lock.
	 */
	ret = dls_devnet_destroy(odd->odd_mh, &tid, B_TRUE);
	if (ret != 0) {
		mutex_exit(&overlay_dev_lock);
		return (ret);
	}

	ASSERT(oidp->oid_linkid == tid);
	ret = mac_disable(odd->odd_mh);
	if (ret != 0) {
		(void) dls_devnet_create(odd->odd_mh, odd->odd_linkid,
		    crgetzoneid(cred));
		mutex_exit(&overlay_dev_lock);
		return (ret);
	}

	list_remove(&overlay_dev_list, odd);
	mutex_exit(&overlay_dev_lock);

	overlay_plugin_rele(odd->odd_plugin);
	kmem_free(odd, sizeof (overlay_dev_t));

	return (0);
}

static dld_ioc_info_t overlay_ioc_list[] = {
	{ OVERLAY_IOC_CREATE, DLDCOPYIN, sizeof (overlay_ioc_create_t),
		overlay_ioc_create, secpolicy_dl_config },
	{ OVERLAY_IOC_DELETE, DLDCOPYIN, sizeof (overlay_ioc_delete_t),
		overlay_ioc_delete, secpolicy_dl_config },
};

static int
overlay_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	if (overlay_dip != NULL || ddi_get_instance(dip) != 0)
		return (DDI_FAILURE);

	if (dld_ioc_register(OVERLAY_IOC, overlay_ioc_list,
	    DLDIOCCNT(overlay_ioc_list)) != 0)
		return (DDI_FAILURE);

	overlay_dip = dip;
	return (DDI_SUCCESS);
}

static int
overlay_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **resp)
{
	int error;

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*resp = (void *)overlay_dip;
		error = DDI_SUCCESS;
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*resp = (void *)0;
		error = DDI_SUCCESS;
		break;
	default:
		error = DDI_FAILURE;
		break;
	}

	return (error);
}

static int
overlay_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	dld_ioc_unregister(VNIC_IOC);
	overlay_dip = NULL;
	return (DDI_SUCCESS);
}

static struct cb_ops overlay_cbops = {
	nulldev,		/* cb_open */
	nulldev,		/* cb_close */
	nodev,			/* cb_strategy */
	nodev,			/* cb_print */
	nodev,			/* cb_dump */
	nodev,			/* cb_read */
	nodev,			/* cb_write */
	nodev,			/* cb_ioctl */
	nodev,			/* cb_devmap */
	nodev,			/* cb_mmap */
	nodev,			/* cb_segmap */
	nochpoll,		/* cb_chpoll */
	ddi_prop_op,		/* cb_prop_op */
	NULL,			/* cb_stream */
	D_MP,			/* cb_flag */
	CB_REV,			/* cb_rev */
	nodev,			/* cb_aread */
	nodev,			/* cb_awrite */
};

static struct dev_ops overlay_dev_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* devo_refcnt */
	overlay_getinfo,	/* devo_getinfo */
	nulldev,		/* devo_identify */
	nulldev,		/* devo_probe */
	overlay_attach,		/* devo_attach */
	overlay_detach,		/* devo_detach */
	nulldev,		/* devo_reset */
	&overlay_cbops,		/* devo_cb_ops */
	NULL,			/* devo_bus_ops */
	NULL,			/* devo_power */
	ddi_quiesce_not_supported	/* devo_quiesce */
};

static struct modldrv overlay_modldrv = {
	&mod_driverops,
	"Overlay Network Driver",
	&overlay_dev_ops
};

static struct modlinkage overlay_linkage = {
	MODREV_1,
	&overlay_modldrv
};

static int
overlay_init(void)
{
	mutex_init(&overlay_dev_lock, NULL, MUTEX_DRIVER, NULL);
	list_create(&overlay_dev_list, sizeof (overlay_dev_t),
	    offsetof(overlay_dev_t, odd_link));
	overlay_plugin_init();

	return (DDI_SUCCESS);
}

static void
overlay_fini(void)
{
	overlay_plugin_fini();
	mutex_destroy(&overlay_dev_lock);
	list_destroy(&overlay_dev_list);
}

int
_init(void)
{
	int err;

	if ((err = overlay_init()) != DDI_SUCCESS)
		return (err);

	mac_init_ops(&overlay_dev_ops, "overlay");
	err = mod_install(&overlay_linkage);
	if (err != DDI_SUCCESS) {
		mac_fini_ops(&overlay_dev_ops);
		overlay_fini();
		return (err);
	}

	return (0);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&overlay_linkage, modinfop));
}

int
_fini(void)
{
	int err;

	mutex_enter(&overlay_dev_lock);
	if (!list_is_empty(&overlay_dev_list)) {
		mutex_exit(&overlay_dev_lock);
		return (EBUSY);
	}
	mutex_exit(&overlay_dev_lock);

	err = mod_remove(&overlay_linkage);
	if (err != 0)
		return (err);

	mac_fini_ops(&overlay_dev_ops);
	overlay_fini();
	return (0);
}
