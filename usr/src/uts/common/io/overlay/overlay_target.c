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
 * Copyright (c) 2014 Joyent, Inc.
 */

/*
 * Overlay devices can operate in one of many modes. They may be a point to
 * point tunnel, they may be on a single multicast group, or they may have
 * dynamic destinations. All of these are programmed via varpd.
 *
 * XXX This all probably won't remain true.
 */

#include <sys/types.h>
#include <sys/ethernet.h>
#include <sys/kmem.h>
#include <sys/policy.h>

#include <sys/overlay_impl.h>

typedef int (*overlay_target_ioctl_f)(void *);

typedef struct overaly_target_ioctl {
	int		oti_cmd;	/* ioctl id */
	boolean_t	oti_write;	/* ioctl requires FWRITE */
	boolean_t	oti_copyout;	/* copyout data? */
	overlay_target_ioctl_f oti_func; /* function to call */
	size_t		oti_size;	/* size of user level structure */
} overlay_target_ioctl_t;

static kmem_cache_t *overlay_target_cache;

static int
overlay_target_cache_constructor(void *buf, void *arg, int kmflgs)
{
	overlay_target_t *ott = buf;

	mutex_init(&ott->ott_lock, NULL, MUTEX_DRIVER, NULL);
	return (0);
}

static void
overlay_target_cache_destructor(void *buf, void *arg)
{
	overlay_target_t *ott = buf;
	mutex_destroy(&ott->ott_lock);
}

void
overlay_target_init(void)
{
	overlay_target_cache = kmem_cache_create("overlay_target",
	    sizeof (overlay_target_t), 0, overlay_target_cache_constructor,
	    overlay_target_cache_destructor, NULL, NULL, NULL, 0);
}

void
overlay_target_fini(void)
{
	kmem_cache_destroy(overlay_target_cache);
}

void
overlay_target_free(overlay_dev_t *odd)
{
	if (odd->odd_target == NULL)
		return;

	kmem_cache_free(overlay_target_cache, odd->odd_target);
}

/* XXX This is assuming a non-gre style bits */
int
overlay_target_lookup(overlay_dev_t *odd, mblk_t *mp, struct sockaddr *sock,
    socklen_t *slenp)
{
	struct sockaddr_in6 *v6;
	overlay_target_t *ott;

	ASSERT(odd->odd_target != NULL);

	ott = odd->odd_target;
	if (ott->ott_dest != (OVERLAY_PLUGIN_D_IP | OVERLAY_PLUGIN_D_PORT))
		panic("implement me rm...");

	v6 = (struct sockaddr_in6 *)sock;
	bzero(v6, sizeof (struct sockaddr_in6));
	v6->sin6_family = AF_INET6;

	/* XXX Can we go lockless here, aka RO when in a mux? */
	mutex_enter(&ott->ott_lock);
	bcopy(&ott->ott_u.ott_point.otp_ip, &v6->sin6_addr,
	    sizeof (struct in6_addr));
	v6->sin6_port = htons(ott->ott_u.ott_point.otp_port);
	mutex_exit(&ott->ott_lock);
	*slenp = sizeof (struct sockaddr_in6);

	return (0);
}

static int
overlay_target_info(void *arg)
{
	overlay_dev_t *odd;
	overlay_targ_info_t *oti = arg;

	odd = overlay_hold_by_dlid(oti->oti_linkid);
	if (odd == NULL)
		return (ENOENT);

	oti->oti_needs = odd->odd_plugin->ovp_dest;
	return (0);
}

static int
overlay_target_associate(void *arg)
{
	overlay_dev_t *odd;
	overlay_target_t *ott;
	overlay_targ_associate_t *ota = arg;

	odd = overlay_hold_by_dlid(ota->ota_linkid);
	if (odd == NULL)
		return (ENOENT);

	if (ota->ota_id == 0) {
		overlay_hold_rele(odd);
		return (EINVAL);
	}

	if (ota->ota_mode != OVERLAY_TARGET_POINT) {
		overlay_hold_rele(odd);
		return (EINVAL);
	}

	if (ota->ota_provides != odd->odd_plugin->ovp_dest) {
		overlay_hold_rele(odd);
		return (EINVAL);
	}

	/* XXX What checks make sense for Ethernet? */

	if (ota->ota_provides & OVERLAY_PLUGIN_D_IP) {
		if (IN6_IS_ADDR_UNSPECIFIED(&ota->ota_point.otp_ip) ||
		    IN6_IS_ADDR_V4COMPAT(&ota->ota_point.otp_ip) ||
		    IN6_IS_ADDR_V4MAPPED_ANY(&ota->ota_point.otp_ip)) {
			overlay_hold_rele(odd);
			return (EINVAL);
		}
	}

	if (ota->ota_provides & OVERLAY_PLUGIN_D_PORT) {
		if (ota->ota_point.otp_port == 0) {
			overlay_hold_rele(odd);
			return (EINVAL);
		}
	}

	ott = kmem_cache_alloc(overlay_target_cache, KM_SLEEP);
	ott->ott_mode = ota->ota_mode;
	ott->ott_dest = ota->ota_provides;
	ott->ott_id = ota->ota_id;
	bcopy(&ota->ota_point, &ott->ott_u.ott_point,
	    sizeof (overlay_target_point_t));
	mutex_enter(&odd->odd_lock);
	if (odd->odd_flags & OVERLAY_F_VARPD) {
		mutex_exit(&odd->odd_lock);
		kmem_cache_free(overlay_target_cache, ott);
		overlay_hold_rele(odd);
		return (EEXIST);
	}

	odd->odd_flags |= OVERLAY_F_VARPD;
	odd->odd_target = ott;
	mutex_exit(&odd->odd_lock);
	overlay_hold_rele(odd);

	return (0);
}

static overlay_target_ioctl_t overlay_target_ioctab[] = {
	{ OVERLAY_TARG_INFO, B_TRUE, B_TRUE,
		overlay_target_info,
		sizeof (overlay_targ_info_t)		},
	{ OVERLAY_TARG_ASSOCIATE, B_TRUE, B_FALSE,
		overlay_target_associate,
		sizeof (overlay_targ_associate_t)	},
	{ 0 }
};

int
overlay_target_open(dev_t *devp, int flags, int otype, cred_t *credp)
{
	if (secpolicy_dl_config(credp) != 0)
		return (EPERM);

	if (getminor(*devp) != 0)
		return (ENXIO);

	if (otype & OTYP_BLK)
		return (EINVAL);

	/* XXX nonblock, excl? */
	if (flags & ~(FREAD | FWRITE))
		return (EINVAL);

	/* XXX Really, you need FREAD and FWRITE? */
	if (!(flags & FREAD) || !(flags & FWRITE))
		return (EINVAL);

	return (0);
}

int
overlay_target_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rvalp)
{
	overlay_target_ioctl_t *ioc;

	if (secpolicy_dl_config(credp) != 0)
		return (EPERM);

	if (getminor(dev) != 0)
		return (ENXIO);

	for (ioc = &overlay_target_ioctab[0]; ioc->oti_cmd != 0; ioc++) {
		int ret;
		caddr_t buf;

		if (ioc->oti_cmd != cmd)
			continue;

		/* XXX Really the write errno? */
		if (ioc->oti_write == B_TRUE && !(mode & FWRITE))
			return (EBADF);

		buf = kmem_alloc(ioc->oti_size, KM_SLEEP);
		if (ddi_copyin((void *)(uintptr_t)arg, buf, ioc->oti_size,
		    mode & FKIOCTL) != 0) {
			kmem_free(buf, ioc->oti_size);
			return (EFAULT);
		}

		ret = ioc->oti_func(buf);
		if (ret == 0 && ioc->oti_size != 0 &&
		    ioc->oti_copyout == B_TRUE) {
			if (ddi_copyout(buf, (void *)(uintptr_t)arg,
			    ioc->oti_size, mode & FKIOCTL) != 0)
				ret = EFAULT;
		}

		kmem_free(buf, ioc->oti_size);
		return (ret);
	}

	return (ENOTTY);
}

int
overlay_target_close(dev_t dev, int flags, int otype, cred_t *credp)
{
	if (getminor(dev) != 0)
		return (ENXIO);

	return (0);
}
