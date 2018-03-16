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
 * Copyright 2018, Joyent, Inc.
 */

/*
 * Files based plug-in for varpd
 *
 * This is a dynamic varpd plug-in that has a static backing store. It's really
 * nothing more than a glorified version of /etc/ethers, though it facilitiates
 * a bit more. The files module allows for the full set of mappings to be fixed
 * at creation time. In addition, it also provides support for proxying ARP,
 * NDP, and DHCP.
 *
 * At this time, the plugin requires that the destination type involve both an
 * IP address and a port; however, there's no reason that this cannot be made
 * more flexible as we have additional encapsulation algorithms that support it.
 * The plug-in only has a single property, which is the location of the JSON
 * file. The JSON file itself looks something like:
 *
 *	{
 *		"aa:bb:cc:dd:ee:ff": {
 *			"arp": "10.23.69.1",
 *			"ndp": "2600:3c00::f03c:91ff:fe96:a264",
 *			"ip": "192.168.1.1",
 *			"port": 8080
 *		},
 *		...
 *
 *		"local-subnet1": {
 *			"prefix": "192.168.1.0/24",
 *			"vlan": 123
 *		},
 *		...
 *
 *		"remote-subnet1": {
 *			"dcid": 11223344,
 *			"prefix": "10.21.10.0/24",
 *			"vnet": 5340123,
 *			"vlan": 789,
 *			"routermac": "12:34:56:78:aa:bb",
 *			"macs": {
 *				"aa:bb:cc:dd:ee:ff": {
 *					"arp": "192.168.50.22",
 *					...
 *				}
 *			}
 *		},
 *		...
 *		"attach-group1": [
 *			"remote-subnet1",
 *			"remote-subnet2",
 *			"local-subnet1",
 *			...
 *		],
 *		...
 *
 * Entries for performing VL3 routing (local-, remote-, and attach-) must
 * all start with their respective prefixes (local-, remote-, or attach-) to
 * identify the type of entry.  Names of entries are limited to
 * FABRIC_NAME_MAX-1  characters.
 *
 * NOTE: This isn't very sophisticated, so attachment entries need to appear
 * after the entries referenced in it.
 */

#include <libvarpd_provider.h>
#include <umem.h>
#include <errno.h>
#include <thread.h>
#include <synch.h>
#include <strings.h>
#include <assert.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <libnvpair.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/ethernet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <libvarpd_files_json.h>

#define	FABRIC_NAME_MAX	64
typedef struct varpd_files_fabric {
	char		vafs_name[FABRIC_NAME_MAX];
	nvlist_t	*vafs_nvl;
	struct in6_addr	vafs_addr;
	uint64_t	vafs_vnet;
	uint32_t	vafs_dcid;
	uint16_t	vafs_vlan;
	uint8_t		vafs_prefixlen;
	uint8_t		vafs_routermac[ETHERADDRL];
} varpd_files_fabric_t;

typedef struct varpd_files_attach {
	varpd_files_fabric_t **vff_fabrics;
} varpd_files_attach_t;

typedef struct varpd_files {
	overlay_plugin_dest_t	vaf_dest;	/* RO */
	varpd_provider_handle_t	*vaf_hdl;	/* RO */
	char			*vaf_path;	/* WO */
	nvlist_t		*vaf_nvl;	/* WO */
	uint64_t		vaf_nmisses;	/* Atomic */
	uint64_t		vaf_narp;	/* Atomic */
	varpd_files_fabric_t	*vaf_fabrics;	/* RO */
	varpd_files_attach_t	*vaf_attach;	/* RO */
	uint64_t		vaf_vnet;	/* RO */
	uint32_t		vaf_dcid;	/* RO */
} varpd_files_t;

static const char *varpd_files_props[] = {
	"files/config"
};

/*
 * Try to convert a string to an IP address or IP address + prefix.  We first
 * try to convert as an IPv6 address, and if that fails, we try to convert as
 * an IPv4 adress and then wrap it in an IPv6 address.
 *
 * To parse an address+prefix length (e.g. 192.168.0.1/24), prefixlen must be
 * non-NULL.  If prefixlen is not NULL and a lone address is supplied,
 * *prefixlen will be set to 128.  If prefixlen is NULL, only a lone address
 * can be successfully parsed.
 *
 * Note: if this is a wrapped IPv4 address with a prefix, *prefixlen is adjusted
 * to reflect the value as an IPv6 address, e.g. 192.168.1.0/24 will have a
 * prefixlen of 120 (96 + 24).
 *
 */
static int
str_to_ip(const char *s, struct in6_addr *v6, uint8_t *prefixlen)
{
	const char *slash;	/* he is real */
	char addrstr[INET6_ADDRSTRLEN] = { 0 };
	size_t addrlen;
	boolean_t is_v4 = B_FALSE;

	slash = strchr(s, '/');

	if (prefixlen != NULL) {
		addrlen = (slash != NULL) ? (size_t)(slash - s) : strlen(s);
	} else {
		if (slash != NULL)
			return (EINVAL);
		addrlen = strlen(s);
	}

	if (addrlen > sizeof (addrstr))
		return (EINVAL);

	bcopy(s, addrstr, addrlen);

	if (inet_pton(AF_INET6, addrstr, v6) != 1) {
		uint32_t v4;

		if (inet_pton(AF_INET, addrstr, &v4) != 1)
			return (EINVAL);

		IN6_IPADDR_TO_V4MAPPED(v4, v6);
		is_v4 = B_TRUE;
	}

	if (prefixlen != NULL) {
		if (slash == NULL) {
			*prefixlen = is_v4 ? 32 : 128;
		} else {
			unsigned long mask = 0;

			errno = 0;
			mask = strtoul(slash + 1, NULL, 10);
			if (errno != 0)
				return (EINVAL);

			if (is_v4) {
				if (mask > 32)
					return (EINVAL);
				mask += 96;
			}

			if (mask > 128)
				return (EINVAL);

			*prefixlen = (uint8_t)mask;
		}
	}

	return (0);
}

static boolean_t
varpd_files_valid_dest(overlay_plugin_dest_t dest)
{
	if (dest & ~(OVERLAY_PLUGIN_D_IP | OVERLAY_PLUGIN_D_PORT))
		return (B_FALSE);

	if (!(dest & (OVERLAY_PLUGIN_D_IP | OVERLAY_PLUGIN_D_PORT)))
		return (B_FALSE);

	return (B_TRUE);
}

static int
varpd_files_create(varpd_provider_handle_t *hdl, void **outp,
    overlay_plugin_dest_t dest)
{
	varpd_files_t *vaf;

	if (varpd_files_valid_dest(dest) == B_FALSE)
		return (ENOTSUP);

	vaf = umem_alloc(sizeof (varpd_files_t), UMEM_DEFAULT);
	if (vaf == NULL)
		return (ENOMEM);

	bzero(vaf, sizeof (varpd_files_t));
	vaf->vaf_dest = dest;
	vaf->vaf_path = NULL;
	vaf->vaf_nvl = NULL;
	vaf->vaf_hdl = hdl;
	vaf->vaf_dcid = libvarpd_plugin_dcid(hdl);
	*outp = vaf;
	return (0);
}

static int varpd_files_normalize_remote(nvlist_t *, nvlist_t *);

static int
varpd_files_normalize_ethers(nvlist_t *nvl, nvlist_t *out, boolean_t is_sub)
{
	int ret;
	nvpair_t *pair;

	for (pair = nvlist_next_nvpair(nvl, NULL); pair != NULL;
	    pair = nvlist_next_nvpair(nvl, pair)) {
		char *name, fname[ETHERADDRSTRL];
		nvlist_t *data;
		struct ether_addr ether, *e;
		e = &ether;

		if (nvpair_type(pair) != DATA_TYPE_NVLIST) {
			nvlist_free(out);
			return (EINVAL);
		}

		name = nvpair_name(pair);
		if ((ret = nvpair_value_nvlist(pair, &data)) != 0) {
			nvlist_free(out);
			return (EINVAL);
		}

		/* Remote subnet */
		if (!is_sub && strncmp(name, "remote-", 7) == 0) {
			nvlist_t *rem;

			ret = nvlist_alloc(&rem, NV_UNIQUE_NAME, 0);
			if (ret != 0) {
				nvlist_free(out);
				return (EINVAL);
			}

			ret = varpd_files_normalize_remote(data, rem);
			if (ret != 0) {
				nvlist_free(out);
				return (EINVAL);
			}

			ret = nvlist_add_nvlist(out, name, rem);
			nvlist_free(rem);
			if (ret != 0) {
				nvlist_free(out);
				return (EINVAL);
			}
			continue;
		}

		/* attached and local fabrics */
		if (!is_sub && (strncmp(name, "attach-", 7) == 0 ||
		    strncmp(name, "local-", 6) == 0)) {
			if ((ret = nvlist_add_nvlist(out, name, data)) != 0) {
				nvlist_free(out);
				return (EINVAL);
			}
			continue;
		}

		if (ether_aton_r(name, e) == NULL) {
			nvlist_free(out);
			return (EINVAL);
		}

		if (ether_ntoa_r(e, fname) == NULL) {
			nvlist_free(out);
			return (ENOMEM);
		}

		if ((ret = nvlist_add_nvlist(out, fname, data)) != 0) {
			nvlist_free(out);
			return (EINVAL);
		}
	}

	return (0);
}

static int
varpd_files_normalize_remote(nvlist_t *nvl, nvlist_t *out)
{
	nvlist_t *macs, *mout;
	nvpair_t *pair;
	int ret;

	for (pair = nvlist_next_nvpair(nvl, NULL); pair != NULL;
	    pair = nvlist_next_nvpair(nvl, pair)) {
		char *name;

		name = nvpair_name(pair);

		if (strcmp(name, "macs") == 0) {
			if ((ret = nvpair_value_nvlist(pair, &macs)) != 0) {
				nvlist_free(out);
				return (EINVAL);
			}

			/* This entry is handled at the end */
			continue;
		}

		if ((ret = nvlist_add_nvpair(out, pair)) != 0) {
			nvlist_free(out);
			return (EINVAL);
		}
	}

	if (macs == NULL) {
		nvlist_free(out);
		return (EINVAL);
	}

	if ((ret = nvlist_alloc(&mout, NV_UNIQUE_NAME, 0)) != 0) {
		nvlist_free(out);
		return (EINVAL);
	}

	if ((ret = varpd_files_normalize_ethers(macs, mout, B_TRUE)) != 0) {
		/* mout is freed on error by varpd_files_normalize_ethers() */
		nvlist_free(out);
		return (EINVAL);
	}

	ret = nvlist_add_nvlist(out, "macs", mout);
	nvlist_free(mout);
	if (ret != 0) {
		nvlist_free(out);
		return (EINVAL);
	}

	return (0);
}

static int
varpd_files_normalize_nvlist(varpd_files_t *vaf, nvlist_t *nvl)
{
	int ret;
	nvlist_t *out;
	nvpair_t *pair;

	if ((ret = nvlist_alloc(&out, NV_UNIQUE_NAME, 0)) != 0)
		return (ret);

	if ((ret = varpd_files_normalize_ethers(nvl, out, B_FALSE)) != 0) {
		/* varpd_files_normalize_ethers() frees out on error */
		return (EINVAL);
	}

	vaf->vaf_nvl = out;
	return (0);
}

static int
varpd_files_add_local_subnet(varpd_files_t *vaf, varpd_files_fabric_t *net,
    const char *name, nvlist_t *nvl)
{
	char *s;
	int32_t vlan;
	int ret;

	net->vafs_dcid = vaf->vaf_dcid;
	net->vafs_vnet = vaf->vaf_vnet;
	net->vafs_nvl = vaf->vaf_nvl;

	(void) strlcpy(net->vafs_name, name, sizeof (net->vafs_name));

	if ((ret = nvlist_lookup_string(nvl, "prefix", &s)) != 0)
		return (EINVAL);
	if (str_to_ip(s, &net->vafs_addr, &net->vafs_prefixlen) != 0)
		return (EINVAL);

	if ((ret = nvlist_lookup_int32(nvl, "prefix", &vlan)) != 0)
		return (EINVAL);
	if (vlan < 0 || vlan > 4096)
		return (EINVAL);
	net->vafs_vlan = (uint16_t)vlan;

	/* XXX: routermac */
	return (0);
}

static int
varpd_files_add_remote_subnet(varpd_files_fabric_t *net, const char *netname,
    nvlist_t *nvl)
{
	nvpair_t *pair;
	int ret;

	(void) strlcpy(net->vafs_name, netname, sizeof (net->vafs_name));

	for (pair = nvlist_next_nvpair(nvl, NULL); pair != NULL;
	    pair = nvlist_next_nvpair(nvl, pair)) {
		char *name = nvpair_name(pair);
		int32_t i32;

		if (strcmp(name, "dcid") == 0) {
			if ((ret = nvpair_value_int32(pair, &i32)) != 0)
				return (ret);

			net->vafs_dcid = (uint32_t)i32;
		} else if (strcmp(name, "prefix") == 0) {
			char *s;

			if ((ret = nvpair_value_string(pair, &s)) != 0)
				return (ret);

			if (str_to_ip(s, &net->vafs_addr,
			    &net->vafs_prefixlen) != 0)
				return (EINVAL);
		} else if (strcmp(name, "vnet") == 0) {
			if ((ret = nvpair_value_int32(pair, &i32)) != 0)
				return (ret);
			net->vafs_vnet = i32;
		} else if (strcmp(name, "vlan") == 0) {
			if ((ret = nvpair_value_int32(pair, &i32)) != 0)
				return (ret);
			if (i32 > 4096 || i32 < 0)
				return (EINVAL);
			net->vafs_vlan = i32;
		} else if (strcmp(name, "macs") == 0) {
			nvlist_t *macs;

			if ((ret = nvpair_value_nvlist(pair, &macs)) != 0)
				return (ret);

			if ((ret = nvlist_dup(macs, &net->vafs_nvl, 0)) != 0)
				return (ret);
		} else if (strcmp(name, "routermac") == 0) {
			char *s;
			struct ether_addr *e;
			e = (struct ether_addr *)&net->vafs_routermac;

			if ((ret = nvpair_value_string(pair, &s)) != 0)
				return (ret);

			if (ether_aton_r(s, e) == NULL)
				return (EINVAL);

		}
	}

	return (0);
}

static void varpd_files_stop_fabrics(varpd_files_t *);

static int
varpd_files_start_fabrics(varpd_files_t *vaf)
{
	nvpair_t *pair;
	size_t nfabric = 0;
	int ret;

	for (pair = nvlist_next_nvpair(vaf->vaf_nvl, NULL); pair != NULL;
	    pair = nvlist_next_nvpair(vaf->vaf_nvl, pair)) {
		char *name = nvpair_name(pair);

		if (strncmp(name, "remote-", 7) != 0 &&
		    strncmp(name, "attach-", 7) != 0)
			continue;

		nfabric++;
	}

	if (nfabric == 0)
		return (0);

	vaf->vaf_fabrics = calloc(nfabric + 1, sizeof (varpd_files_fabric_t));
	if (vaf->vaf_fabrics == NULL)
		return (ENOMEM);

	nfabric = 0;
	for (pair = nvlist_next_nvpair(vaf->vaf_nvl, NULL); pair != NULL;
	    pair = nvlist_next_nvpair(vaf->vaf_nvl, pair)) {
		char *name = nvpair_name(pair);
		boolean_t is_remote = B_FALSE;
		boolean_t is_local = B_FALSE;

		if (strncmp(name, "remote-", 7) == 0)
			is_remote = B_TRUE;
		if (strncmp(name, "local-", 7) == 0)
			is_local = B_TRUE;

		if (!is_remote && !is_local)
			continue;

		varpd_files_fabric_t *net = &vaf->vaf_fabrics[nfabric++];
		nvlist_t *netnvl;

		if ((ret = nvpair_value_nvlist(pair, &netnvl)) != 0) {
			varpd_files_stop_fabrics(vaf);
			return (ret);
		}

		ret = is_remote ?
		    varpd_files_add_remote_subnet(net, name, netnvl) :
		    varpd_files_add_local_subnet(vaf, net, name, netnvl);

		if (ret != 0) {
			varpd_files_stop_fabrics(vaf);
			return (ret);
		}
	}

	return (0);
}

static varpd_files_fabric_t *
varpd_files_fabric_getbyname(varpd_files_t *vaf, const char *name)
{
	varpd_files_fabric_t *fab = &vaf->vaf_fabrics[0];

	for (fab = &vaf->vaf_fabrics[0]; fab->vafs_name[0] != '\0'; fab++) {
		if (strcmp(fab->vafs_name, name) != 0)
			continue;
		return (fab);
	}

	return (NULL);
}

static void
varpd_files_stop_attached(varpd_files_t *vaf)
{
	size_t i;

	if (vaf->vaf_attach == NULL)
		return;

	for (i = 0; vaf->vaf_attach[i].vff_fabrics != NULL; i++)
		free(vaf->vaf_attach[i].vff_fabrics);

	free(vaf->vaf_attach);
	vaf->vaf_attach = NULL;
}

static int
varpd_files_start_attached(varpd_files_t *vaf)
{
	nvpair_t *pair;
	size_t nattach = 0;
	int ret;

	for (pair = nvlist_next_nvpair(vaf->vaf_nvl, NULL); pair != NULL;
	    pair = nvlist_next_nvpair(vaf->vaf_nvl, pair)) {
		char *name;

		name = nvpair_name(pair);
		if (strncmp(name, "attach-", 7) != 0)
			continue;

		if (nvpair_type(pair) != DATA_TYPE_STRING_ARRAY)
			return (EINVAL);

		nattach++;
	}

	if (nattach == 0)
		return (0);

	if ((vaf->vaf_attach = calloc(nattach + 1,
	    sizeof (varpd_files_attach_t))) == NULL)
		return (ENOMEM);

	nattach = 0;
	for (pair = nvlist_next_nvpair(vaf->vaf_nvl, NULL); pair != NULL;
	    pair = nvlist_next_nvpair(vaf->vaf_nvl, pair)) {
		varpd_files_attach_t *fa = &vaf->vaf_attach[nattach++];
		char **fabrics = NULL;
		uint_t i, nelem = 0;

		if ((ret = nvpair_value_string_array(pair, &fabrics,
		    &nelem)) != NULL) {
			varpd_files_stop_attached(vaf);
			return (ret);
		}

		if ((fa = calloc(nelem + 1, sizeof (varpd_files_fabric_t *))) ==
		    NULL) {
			varpd_files_stop_attached(vaf);
			return (ENOMEM);
		}

		for (i = 0; i < nelem; i++) {
			fa->vff_fabrics[i] =
			    varpd_files_fabric_getbyname(vaf, fabrics[i]);
			if (fa->vff_fabrics[i] == NULL) {
				varpd_files_stop_attached(vaf);
				return (ENOENT);
			}
		}
	}

	return (0);
}

static int
varpd_files_start(void *arg)
{
	int fd, ret;
	void *maddr;
	struct stat st;
	nvlist_t *nvl;
	varpd_files_t *vaf = arg;

	if (vaf->vaf_path == NULL)
		return (EAGAIN);

	if ((fd = open(vaf->vaf_path, O_RDONLY)) < 0)
		return (errno);

	if (fstat(fd, &st) != 0) {
		ret = errno;
		if (close(fd) != 0)
			abort();
		return (ret);
	}

	maddr = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE,
	    fd, 0);
	if (maddr == NULL) {
		ret = errno;
		if (close(fd) != 0)
			abort();
		return (ret);
	}

	ret = nvlist_parse_json(maddr, st.st_size, &nvl,
	    NVJSON_FORCE_INTEGER, NULL);
	if (ret == 0) {
		ret = varpd_files_normalize_nvlist(vaf, nvl);
		nvlist_free(nvl);
		nvl = NULL;
	}
	if (munmap(maddr, st.st_size) != 0)
		abort();
	if (close(fd) != 0)
		abort();
	if (ret != 0) {
		nvlist_free(nvl);
		return (ret);
	}

	if ((ret = varpd_files_start_fabrics(vaf)) != 0) {
		nvlist_free(nvl);
		return (ret);
	}

	if ((ret = varpd_files_start_attached(vaf)) != 0) {
		varpd_files_stop_fabrics(vaf);
		nvlist_free(nvl);
		return (ret);
	}

	return (ret);
}

static void
varpd_files_stop_fabrics(varpd_files_t *vaf)
{
	varpd_files_fabric_t *net = NULL;

	if (vaf == NULL || vaf->vaf_fabrics == NULL)
		return;

	for (net = vaf->vaf_fabrics; net->vafs_name[0] != '\0'; net++) {
		if (net->vafs_nvl != vaf->vaf_nvl)
			nvlist_free(net->vafs_nvl);
	}
	free(vaf->vaf_fabrics);
	vaf->vaf_fabrics = NULL;
}


static void
varpd_files_stop(void *arg)
{
	varpd_files_t *vaf = arg;

	varpd_files_stop_fabrics(vaf);
	nvlist_free(vaf->vaf_nvl);
	vaf->vaf_nvl = NULL;
}

static void
varpd_files_destroy(void *arg)
{
	varpd_files_t *vaf = arg;

	assert(vaf->vaf_nvl == NULL);
	if (vaf->vaf_path != NULL) {
		umem_free(vaf->vaf_path, strlen(vaf->vaf_path) + 1);
		vaf->vaf_path = NULL;
	}
	umem_free(vaf, sizeof (varpd_files_t));
}

static nvlist_t *
varpd_files_lookup_l3subnet(varpd_files_t *vaf, varpd_files_attach_t *attach,
    const struct in6_addr *dst, overlay_target_point_t *otp,
    overlay_target_route_t *otr)
{
	varpd_files_fabric_t *net = NULL;
	nvlist_t *macs = NULL;
	size_t i;
	boolean_t found = B_FALSE;

	for (i = 0; attach->vff_fabrics[i] != NULL; i++) {
		net = attach->vff_fabrics[i];

		if (IN6_ARE_PREFIXEDADDR_EQUAL(dst, &net->vafs_addr,
		    net->vafs_prefixlen)) {
			found = B_TRUE;
			break;
		}
	}

	if (nvlist_lookup_nvlist(net->vafs_nvl, "macs", &macs) != 0)
		return (NULL);

	otr->otr_vnet = net->vafs_vnet;
	otr->otr_vlan = net->vafs_vlan;
	otr->otr_dcid = net->vafs_dcid;
	otr->otr_dst_prefixlen = net->vafs_prefixlen;
	bcopy(net->vafs_routermac, otr->otr_srcmac, ETHERADDRL);
	return (macs);
}

static varpd_files_attach_t *
varpd_files_find_attach(varpd_files_t *vaf, const struct in6_addr *src,
    uint16_t vlan, overlay_target_route_t *otr)
{
	varpd_files_attach_t *attach;
	varpd_files_fabric_t *fab;
	size_t i;

	if (vaf->vaf_attach == NULL)
		return (NULL);

	for (attach = vaf->vaf_attach; attach->vff_fabrics != NULL; attach++) {
		for (i = 0; attach->vff_fabrics[i] != NULL; i++) {
			fab = attach->vff_fabrics[i];

			if (fab->vafs_dcid == vaf->vaf_dcid &&
			    fab->vafs_vlan == vlan &&
			    IN6_ARE_PREFIXEDADDR_EQUAL(src, &fab->vafs_addr,
			    fab->vafs_prefixlen)) {
				otr->otr_src_prefixlen = fab->vafs_prefixlen;
				return (attach);
			}
			fab++;
		}
	}

	return (NULL);
}

static void
varpd_files_lookup_l3(varpd_files_t *vaf, varpd_query_handle_t *qh,
    const overlay_targ_lookup_t *otl, overlay_target_point_t *otp,
    overlay_target_route_t *otr)
{
	const struct in6_addr *dest_ip;
	const struct in6_addr *src_ip;
	struct in6_addr ul3 = { 0 };
	varpd_files_attach_t *attach = NULL;
	char *s;
	nvlist_t *macs = NULL, *entry = NULL;
	nvpair_t *pair = NULL;
	int32_t prefixlen;

	dest_ip = &otl->otl_addru.otlu_l3.otl3_dstip;
	src_ip = &otl->otl_addru.otlu_l3.otl3_srcip;

	if ((attach = varpd_files_find_attach(vaf, src_ip, otl->otl_vlan,
	    otr)) == NULL) {
		libvarpd_plugin_query_reply(qh, VARPD_LOOKUP_DROP);
		return;
	}

	if ((macs = varpd_files_lookup_l3subnet(vaf, attach, dest_ip,
	    otp, otr)) == NULL) {
		libvarpd_plugin_query_reply(qh, VARPD_LOOKUP_DROP);
		return;
	}

	for (pair = nvlist_next_nvpair(macs, NULL); pair != NULL;
	    pair = nvlist_next_nvpair(macs, pair)) {
		char *s;
		struct in6_addr v6;

		if (nvpair_value_nvlist(pair, &entry) != 0)
			continue;

		if (nvlist_lookup_string(entry, "arp", &s) != 0)
			continue;

		if (str_to_ip(s, &v6, NULL) != 0)
			continue;

		if (IN6_ARE_ADDR_EQUAL(dest_ip, &v6))
			break;
	}

	if (pair == NULL) {
		libvarpd_plugin_query_reply(qh, VARPD_LOOKUP_DROP);
		return;
	}

	if (nvlist_lookup_string(entry, "ip", &s) != 0) {
		libvarpd_plugin_query_reply(qh, VARPD_LOOKUP_DROP);
		return;
	}

	if (str_to_ip(s, &ul3, NULL) != 0) {
		libvarpd_plugin_query_reply(qh, VARPD_LOOKUP_DROP);
		return;
	}
	bcopy(&ul3, &otp->otp_ip, sizeof (ul3));

	if (vaf->vaf_dest & OVERLAY_PLUGIN_D_PORT) {
		int32_t port;

		if (nvlist_lookup_int32(entry, "port", &port) != 0) {
			libvarpd_plugin_query_reply(qh, VARPD_LOOKUP_DROP);
			return;
		}

		otp->otp_port = port;
	} else {
		otp->otp_port = 0;
	}

	s = nvpair_name(pair);

	if (ether_aton_r(s, (struct ether_addr *)otp->otp_mac) == NULL) {
		libvarpd_plugin_query_reply(qh, VARPD_LOOKUP_DROP);
		return;
	}

	libvarpd_plugin_query_reply(qh, VARPD_LOOKUP_OK);
}

static void
varpd_files_lookup(void *arg, varpd_query_handle_t *qh,
    const overlay_targ_lookup_t *otl, overlay_target_point_t *otp,
    overlay_target_route_t *otr)
{
	char macstr[ETHERADDRSTRL], *ipstr;
	nvlist_t *nvl;
	varpd_files_t *vaf = arg;
	int32_t port;
	static const uint8_t bcast[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

	/* We don't support a default */
	if (otl == NULL) {
		libvarpd_plugin_query_reply(qh, VARPD_LOOKUP_DROP);
		return;
	}

	/*
	 * Shuffle off L3 lookups to their own codepath.
	 */
	if (otl->otl_l3req) {
		varpd_files_lookup_l3(vaf, qh, otl, otp, otr);
		return;
	}

	/*
	 * At this point, the traditional overlay_target_point_t is all that
	 * needs filling in.  Zero-out the otr for safety.
	 */
	bzero(otr, sizeof (*otr));

	if (otl->otl_addru.otlu_l2.otl2_sap == ETHERTYPE_ARP) {
		libvarpd_plugin_proxy_arp(vaf->vaf_hdl, qh, otl);
		return;
	}

	if (otl->otl_addru.otlu_l2.otl2_sap == ETHERTYPE_IPV6 &&
	    otl->otl_addru.otlu_l2.otl2_dstaddr[0] == 0x33 &&
	    otl->otl_addru.otlu_l2.otl2_dstaddr[1] == 0x33) {
		libvarpd_plugin_proxy_ndp(vaf->vaf_hdl, qh, otl);
		return;
	}

	if (otl->otl_addru.otlu_l2.otl2_sap == ETHERTYPE_IP &&
	    bcmp(otl->otl_addru.otlu_l2.otl2_dstaddr, bcast, ETHERADDRL) == 0) {
		char *mac;
		struct ether_addr a, *addr;

		addr = &a;
		if (ether_ntoa_r(
		    (struct ether_addr *)otl->otl_addru.otlu_l2.otl2_srcaddr,
		    macstr) == NULL) {
			libvarpd_plugin_query_reply(qh, VARPD_LOOKUP_DROP);
			return;
		}

		if (nvlist_lookup_nvlist(vaf->vaf_nvl, macstr, &nvl) != 0) {
			libvarpd_plugin_query_reply(qh, VARPD_LOOKUP_DROP);
			return;
		}

		if (nvlist_lookup_string(nvl, "dhcp-proxy", &mac) != 0) {
			libvarpd_plugin_query_reply(qh, VARPD_LOOKUP_DROP);
			return;
		}

		if (ether_aton_r(mac, addr) == NULL) {
			libvarpd_plugin_query_reply(qh, VARPD_LOOKUP_DROP);
			return;
		}

		libvarpd_plugin_proxy_dhcp(vaf->vaf_hdl, qh, otl);
		return;
	}

	if (ether_ntoa_r(
	    (struct ether_addr *)otl->otl_addru.otlu_l2.otl2_dstaddr,
	    macstr) == NULL) {
		libvarpd_plugin_query_reply(qh, VARPD_LOOKUP_DROP);
		return;
	}

	if (nvlist_lookup_nvlist(vaf->vaf_nvl, macstr, &nvl) != 0) {
		libvarpd_plugin_query_reply(qh, VARPD_LOOKUP_DROP);
		return;
	}

	if (nvlist_lookup_int32(nvl, "port", &port) != 0) {
		libvarpd_plugin_query_reply(qh, VARPD_LOOKUP_DROP);
		return;
	}

	if (port <= 0 || port > UINT16_MAX) {
		libvarpd_plugin_query_reply(qh, VARPD_LOOKUP_DROP);
		return;
	}
	otp->otp_port = port;

	if (nvlist_lookup_string(nvl, "ip", &ipstr) != 0) {
		libvarpd_plugin_query_reply(qh, VARPD_LOOKUP_DROP);
		return;
	}

	if (str_to_ip(ipstr, &otp->otp_ip, NULL) != 0) {
		libvarpd_plugin_query_reply(qh, VARPD_LOOKUP_DROP);
		return;
	}

	libvarpd_plugin_query_reply(qh, VARPD_LOOKUP_OK);
}

/* ARGSUSED */
static int
varpd_files_nprops(void *arg, uint_t *nprops)
{
	*nprops = 1;
	return (0);
}

/* ARGSUSED */
static int
varpd_files_propinfo(void *arg, uint_t propid, varpd_prop_handle_t *vph)
{
	if (propid != 0)
		return (EINVAL);

	libvarpd_prop_set_name(vph, varpd_files_props[0]);
	libvarpd_prop_set_prot(vph, OVERLAY_PROP_PERM_RRW);
	libvarpd_prop_set_type(vph, OVERLAY_PROP_T_STRING);
	libvarpd_prop_set_nodefault(vph);

	return (0);
}

static int
varpd_files_getprop(void *arg, const char *pname, void *buf, uint32_t *sizep)
{
	varpd_files_t *vaf = arg;

	if (strcmp(pname, varpd_files_props[0]) != 0)
		return (EINVAL);

	if (vaf->vaf_path != NULL) {
		size_t len = strlen(vaf->vaf_path) + 1;
		if (*sizep < len)
			return (EOVERFLOW);
		*sizep = len;
		(void) strlcpy(buf, vaf->vaf_path, *sizep);
	} else {
		*sizep = 0;
	}

	return (0);
}

static int
varpd_files_setprop(void *arg, const char *pname, const void *buf,
    const uint32_t size)
{
	varpd_files_t *vaf = arg;

	if (strcmp(pname, varpd_files_props[0]) != 0)
		return (EINVAL);

	if (vaf->vaf_path != NULL)
		umem_free(vaf->vaf_path, strlen(vaf->vaf_path) + 1);

	vaf->vaf_path = umem_alloc(size, UMEM_DEFAULT);
	if (vaf->vaf_path == NULL)
		return (ENOMEM);
	(void) strlcpy(vaf->vaf_path, buf, size);
	return (0);
}

static int
varpd_files_save(void *arg, nvlist_t *nvp)
{
	int ret;
	varpd_files_t *vaf = arg;

	if (vaf->vaf_path == NULL)
		return (0);

	if ((ret = nvlist_add_string(nvp, varpd_files_props[0],
	    vaf->vaf_path)) != 0)
		return (ret);

	if ((ret = nvlist_add_uint64(nvp, "files/vaf_nmisses",
	    vaf->vaf_nmisses)) != 0)
		return (ret);

	if ((ret = nvlist_add_uint64(nvp, "files/vaf_narp",
	    vaf->vaf_narp)) != 0)
		return (ret);
	return (0);
}

static int
varpd_files_restore(nvlist_t *nvp, varpd_provider_handle_t *hdl,
    overlay_plugin_dest_t dest, void **outp)
{
	varpd_files_t *vaf;
	char *str;
	int ret;
	uint64_t nmisses, narp;

	if (varpd_files_valid_dest(dest) == B_FALSE)
		return (EINVAL);

	ret = nvlist_lookup_string(nvp, varpd_files_props[0], &str);
	if (ret != 0 && ret != ENOENT)
		return (ret);
	else if (ret == ENOENT)
		str = NULL;

	if (nvlist_lookup_uint64(nvp, "files/vaf_nmisses", &nmisses) != 0)
		return (EINVAL);
	if (nvlist_lookup_uint64(nvp, "files/vaf_narp", &narp) != 0)
		return (EINVAL);

	vaf = umem_alloc(sizeof (varpd_files_t), UMEM_DEFAULT);
	if (vaf == NULL)
		return (ENOMEM);

	bzero(vaf, sizeof (varpd_files_t));
	vaf->vaf_dest = dest;
	if (str != NULL) {
		size_t len = strlen(str) + 1;
		vaf->vaf_path = umem_alloc(len, UMEM_DEFAULT);
		if (vaf->vaf_path == NULL) {
			umem_free(vaf, sizeof (varpd_files_t));
			return (ENOMEM);
		}
		(void) strlcpy(vaf->vaf_path, str, len);
	}

	vaf->vaf_hdl = hdl;
	*outp = vaf;
	return (0);
}

static void
varpd_files_proxy_arp(void *arg, varpd_arp_handle_t *vah, int kind,
    const struct sockaddr *sock, uint8_t *out)
{
	varpd_files_t *vaf = arg;
	const struct sockaddr_in *ip;
	const struct sockaddr_in6 *ip6;
	nvpair_t *pair;

	if (kind != VARPD_QTYPE_ETHERNET) {
		libvarpd_plugin_arp_reply(vah, VARPD_LOOKUP_DROP);
		return;
	}

	if (sock->sa_family != AF_INET && sock->sa_family != AF_INET6) {
		libvarpd_plugin_arp_reply(vah, VARPD_LOOKUP_DROP);
		return;
	}

	ip = (const struct sockaddr_in *)sock;
	ip6 = (const struct sockaddr_in6 *)sock;
	for (pair = nvlist_next_nvpair(vaf->vaf_nvl, NULL); pair != NULL;
	    pair = nvlist_next_nvpair(vaf->vaf_nvl, pair)) {
		char *mac, *ipstr;
		nvlist_t *data;
		struct in_addr ia;
		struct in6_addr ia6;
		struct ether_addr ether, *e;
		e = &ether;

		if (nvpair_type(pair) != DATA_TYPE_NVLIST)
			continue;

		mac = nvpair_name(pair);
		if (nvpair_value_nvlist(pair, &data) != 0)
			continue;


		if (sock->sa_family == AF_INET) {
			if (nvlist_lookup_string(data, "arp", &ipstr) != 0)
				continue;

			if (inet_pton(AF_INET, ipstr, &ia) != 1)
				continue;

			if (bcmp(&ia, &ip->sin_addr,
			    sizeof (struct in_addr)) != 0)
				continue;
		} else {
			if (nvlist_lookup_string(data, "ndp", &ipstr) != 0)
				continue;

			if (inet_pton(AF_INET6, ipstr, &ia6) != 1)
				continue;

			if (bcmp(&ia6, &ip6->sin6_addr,
			    sizeof (struct in6_addr)) != 0)
				continue;
		}

		if (ether_aton_r(mac, e) == NULL) {
			libvarpd_plugin_arp_reply(vah, VARPD_LOOKUP_DROP);
			return;
		}

		bcopy(e, out, ETHERADDRL);
		libvarpd_plugin_arp_reply(vah, VARPD_LOOKUP_OK);
		return;
	}

	libvarpd_plugin_arp_reply(vah, VARPD_LOOKUP_DROP);
}

static void
varpd_files_proxy_dhcp(void *arg, varpd_dhcp_handle_t *vdh, int type,
    const overlay_targ_lookup_t *otl, uint8_t *out)
{
	varpd_files_t *vaf = arg;
	nvlist_t *nvl;
	char macstr[ETHERADDRSTRL], *mac;
	struct ether_addr a, *addr;

	addr = &a;
	if (type != VARPD_QTYPE_ETHERNET) {
		libvarpd_plugin_dhcp_reply(vdh, VARPD_LOOKUP_DROP);
		return;
	}

	if (ether_ntoa_r(
	    (struct ether_addr *)otl->otl_addru.otlu_l2.otl2_srcaddr,
	    macstr) == NULL) {
		libvarpd_plugin_dhcp_reply(vdh, VARPD_LOOKUP_DROP);
		return;
	}

	if (nvlist_lookup_nvlist(vaf->vaf_nvl, macstr, &nvl) != 0) {
		libvarpd_plugin_dhcp_reply(vdh, VARPD_LOOKUP_DROP);
		return;
	}

	if (nvlist_lookup_string(nvl, "dhcp-proxy", &mac) != 0) {
		libvarpd_plugin_dhcp_reply(vdh, VARPD_LOOKUP_DROP);
		return;
	}

	if (ether_aton_r(mac, addr) == NULL) {
		libvarpd_plugin_dhcp_reply(vdh, VARPD_LOOKUP_DROP);
		return;
	}

	bcopy(addr, out, ETHERADDRL);
	libvarpd_plugin_dhcp_reply(vdh, VARPD_LOOKUP_OK);
}

static const varpd_plugin_ops_t varpd_files_ops = {
	0,
	varpd_files_create,
	varpd_files_start,
	varpd_files_stop,
	varpd_files_destroy,
	NULL,
	varpd_files_lookup,
	varpd_files_nprops,
	varpd_files_propinfo,
	varpd_files_getprop,
	varpd_files_setprop,
	varpd_files_save,
	varpd_files_restore,
	varpd_files_proxy_arp,
	varpd_files_proxy_dhcp
};

#pragma init(varpd_files_init)
static void
varpd_files_init(void)
{
	int err;
	varpd_plugin_register_t *vpr;

	vpr = libvarpd_plugin_alloc(VARPD_CURRENT_VERSION, &err);
	if (vpr == NULL)
		return;

	vpr->vpr_mode = OVERLAY_TARGET_DYNAMIC;
	vpr->vpr_name = "files";
	vpr->vpr_ops = &varpd_files_ops;
	(void) libvarpd_plugin_register(vpr);
	libvarpd_plugin_free(vpr);
}
