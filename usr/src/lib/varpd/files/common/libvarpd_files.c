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
#include <sys/avl.h>
#include <sys/debug.h>
#include <sys/list.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <libnvpair.h>
#include <stddef.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/ethernet.h>
#include <sys/socket.h>
#include <sys/vlan.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <libvarpd_files_json.h>

#define	FABRIC_NAME_MAX	64
struct varpd_files_attach;
typedef struct varpd_files_attach varpd_files_attach_t;

typedef struct varpd_files_fabric {
	avl_node_t	vafs_avlnode;
	list_node_t	vafs_attached_node;
	varpd_files_attach_t *vafs_attach;
	char		vafs_name[FABRIC_NAME_MAX];
	struct in6_addr	vafs_addr;
	uint64_t	vafs_vnet;
	uint32_t	vafs_dcid;
	uint16_t	vafs_vlan;
	uint8_t		vafs_prefixlen;
	uint8_t		vafs_routermac[ETHERADDRL];
} varpd_files_fabric_t;

struct varpd_files_attach {
	list_node_t	vfa_node;
	char		vfa_name[FABRIC_NAME_MAX];
	list_t		vfa_fabrics;
};

typedef struct varpd_files_if {
	avl_node_t	vfi_macnode;
	avl_node_t	vfi_ipnode;
	avl_node_t	vfi_ndpnode;
	struct in6_addr	vfi_ip;
	struct in6_addr vfi_llocalip;	/* IPv6 link local if specified */
	uint64_t	vfi_vnet;
	uint32_t	vfi_dcid;
	uint16_t	vfi_vlan;
	uint8_t		vfi_mac[ETHERADDRL];
	uint8_t		vfi_dhcp[ETHERADDRL]; /* dhcp-proxy MAC address */
	boolean_t	vfi_has_dhcp;
	boolean_t	vfi_has_lladdr;
	overlay_target_point_t vfi_dest;
} varpd_files_if_t;

typedef struct varpd_files {
	overlay_plugin_dest_t	vaf_dest;	/* RO */
	varpd_provider_handle_t	*vaf_hdl;	/* RO */
	char			*vaf_path;	/* WO */
	uint64_t		vaf_nmisses;	/* Atomic */
	uint64_t		vaf_narp;	/* Atomic */

				/* These hold varpd_files_fabric_t's */
	avl_tree_t		vaf_fabrics;	/* WO */
	list_t			vaf_attached;	/* WO */

				/* These hold varpd_files_if_t */
	avl_tree_t		vaf_macs;	/* WO */
	avl_tree_t		vaf_ips;	/* WO */
	avl_tree_t		vaf_ndp;	/* WO */

	uint64_t		vaf_vnet;	/* RO */
	uint32_t		vaf_dcid;	/* RO */
} varpd_files_t;

static const char *varpd_files_props[] = {
	"files/config"
};

static bunyan_logger_t *files_bunyan;

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

static int
varpd_files_if_mac_avl(const void *a, const void *b)
{
	const varpd_files_if_t *l = a;
	const varpd_files_if_t *r = b;
	int i;

	if (l->vfi_dcid < r->vfi_dcid)
		return (-1);
	if (l->vfi_dcid > r->vfi_dcid)
		return (1);

	for (i = 0; i < ETHERADDRL; i++) {
		if (l->vfi_mac[i] < r->vfi_mac[i])
			return (-1);
		if (l->vfi_mac[i] > r->vfi_mac[i])
			return (1);
	}

	return (0);
}

static int
varpd_files_if_ip_avl(const void *a, const void *b)
{
	const varpd_files_if_t *l = a;
	const varpd_files_if_t *r = b;
	int i;

	if (l->vfi_vnet < r->vfi_vnet)
		return (-1);
	if (l->vfi_vnet > r->vfi_vnet)
		return (1);
	if (l->vfi_vlan < r->vfi_vlan)
		return (-1);
	if (l->vfi_vlan > r->vfi_vlan)
		return (1);
	for (i = 0; i < sizeof (struct in6_addr); i++) {
		if (l->vfi_ip.s6_addr[i] < r->vfi_ip.s6_addr[i])
			return (-1);
		if (l->vfi_ip.s6_addr[i] > r->vfi_ip.s6_addr[i])
			return (1);
	}
	return (0);
}

static int
varpd_files_if_ndp_avl(const void *a, const void *b)
{
	const varpd_files_if_t *l = a;
	const varpd_files_if_t *r = b;
	int i;

	VERIFY(l->vfi_has_lladdr);
	VERIFY(r->vfi_has_lladdr);

	for (i = 0; i < sizeof (struct in6_addr); i++) {
		if (l->vfi_llocalip.s6_addr[i] < r->vfi_llocalip.s6_addr[i])
			return (-1);
		if (l->vfi_llocalip.s6_addr[i] > r->vfi_llocalip.s6_addr[i])
			return (1);
	}
	return (0);
}

static int
varpd_files_fabric_avl(const void *a, const void *b)
{
	const varpd_files_fabric_t *l = a;
	const varpd_files_fabric_t *r = b;
	int i;

	/*
	 * Sort by dcid, vnet, vlan, subnet.  With subnet last, we can use
	 * avl_nearest() to find the fabric for an IP (given the other pieces
	 * of information).
	 */
	if (l->vafs_dcid < r->vafs_dcid)
		return (-1);
	if (l->vafs_dcid > r->vafs_dcid)
		return (1);
	if (l->vafs_vnet < r->vafs_vnet)
		return (-1);
	if (l->vafs_vnet > r->vafs_vnet)
		return (1);
	if (l->vafs_vlan < r->vafs_vlan)
		return (-1);
	if (l->vafs_vlan > r->vafs_vlan)
		return (1);

	for (i = 0; i < sizeof (struct in6_addr); i++) {
		if (l->vafs_addr.s6_addr[i] < r->vafs_addr.s6_addr[i])
			return (-1);
		if (l->vafs_addr.s6_addr[i] > r->vafs_addr.s6_addr[i])
			return (1);
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

	vaf = umem_zalloc(sizeof (varpd_files_t), UMEM_DEFAULT);
	if (vaf == NULL)
		return (ENOMEM);

	vaf->vaf_dest = dest;
	vaf->vaf_hdl = hdl;
	vaf->vaf_dcid = libvarpd_plugin_dcid(hdl);
	vaf->vaf_vnet = libvarpd_plugin_vnetid(hdl);
	avl_create(&vaf->vaf_macs, varpd_files_if_mac_avl,
	    sizeof (varpd_files_if_t), offsetof(varpd_files_if_t, vfi_macnode));
	avl_create(&vaf->vaf_ips, varpd_files_if_ip_avl,
	    sizeof (varpd_files_if_t), offsetof(varpd_files_if_t, vfi_ipnode));
	avl_create(&vaf->vaf_ndp, varpd_files_if_ndp_avl,
	    sizeof (varpd_files_if_t), offsetof(varpd_files_if_t, vfi_ndpnode));
	avl_create(&vaf->vaf_fabrics, varpd_files_fabric_avl,
	    sizeof (varpd_files_fabric_t),
	    offsetof(varpd_files_fabric_t, vafs_avlnode));
	list_create(&vaf->vaf_attached, sizeof (varpd_files_attach_t),
	    offsetof(varpd_files_attach_t, vfa_node));
	*outp = vaf;
	return (0);
}

static varpd_files_fabric_t *
varpd_files_fabric_getbyname(varpd_files_t *vaf, const char *name)
{
	varpd_files_fabric_t *fab = NULL;

	for (fab = avl_first(&vaf->vaf_fabrics); fab != NULL;
	    fab = AVL_NEXT(&vaf->vaf_fabrics, fab)) {
		if (strcmp(fab->vafs_name, name) == 0)
			return (fab);
	}

	return (NULL);
}

static int
varpd_files_convert_attached(varpd_files_t *vaf, nvlist_t *att)
{
	nvlist_t *nvl = NULL;
	nvpair_t *nvp = NULL;
	int ret;

	while ((nvp = nvlist_next_nvpair(att, nvp)) != NULL) {
		varpd_files_attach_t *att;
		char **nets = NULL;
		uint32_t i, n;

		if (nvpair_type(nvp) != DATA_TYPE_NVLIST) {
			(void) bunyan_error(files_bunyan,
			    "attached fabric group value is not an nvlist",
			    BUNYAN_T_STRING, "group", nvpair_name(nvp),
			    BUNYAN_T_END);
			return (EINVAL);
		}

		if ((ret = nvpair_value_nvlist(nvp, &nvl)) != 0) {
			(void) bunyan_error(files_bunyan,
			    "unexpected error retrieving attached fabric group",
			    BUNYAN_T_STRING, "group", nvpair_name(nvp),
			    BUNYAN_T_STRING, "errmsg", strerror(ret),
			    BUNYAN_T_END);
			return (EINVAL);
		}

		if ((ret = nvlist_lookup_boolean(nvl, ".__json_array")) != 0) {
			(void) bunyan_error(files_bunyan,
			    "group value does not appear to be a JSON array",
			    BUNYAN_T_STRING, "group", nvpair_name(nvp),
			    BUNYAN_T_END);
			return (EINVAL);
		}

		if ((ret = nvlist_lookup_uint32(nvl, "length", &n)) != 0) {
			(void) bunyan_error(files_bunyan,
			    "unexpected error obtain group array length",
			    BUNYAN_T_STRING, "group", nvpair_name(nvp),
			    BUNYAN_T_STRING, "errmsg", strerror(ret),
			    BUNYAN_T_END);
			return (ret);
		}

		if ((nets = calloc(n, sizeof (char *))) == NULL) {
			(void) bunyan_error(files_bunyan,
			    "out of memory", BUNYAN_T_END);
			return (ENOMEM);
		}

		/*
		 * Note, we are just storing references to the names in
		 * nets, so we only need to call free(nets), and not on
		 * each entry (e.g. free(nets[0])).  We strlcpy() it out,
		 * so we don't need to worry about it going away before we
		 * done with it.
		 */
		for (i = 0; i < n; i++) {
			char buf[11];	/* largest uint32_t val + NUL */

			(void) snprintf(buf, sizeof (buf), "%u", i);
			ret = nvlist_lookup_string(nvl, buf, &nets[i]);
			if (ret != 0) {
				(void) bunyan_error(files_bunyan,
				    "unexpected error lookup up group array "
				    "value",
				    BUNYAN_T_STRING, "group", nvpair_name(nvp),
				    BUNYAN_T_UINT32, "index", i,
				    BUNYAN_T_STRING, "errmsg", strerror(ret),
				    BUNYAN_T_END);
				free(nets);
				return (ret);
			}
		}

		if ((att = umem_zalloc(sizeof (*att), UMEM_DEFAULT)) == NULL) {
			(void) bunyan_error(files_bunyan, "out of memory",
			    BUNYAN_T_END);
			free(nets);
			return (ENOMEM);
		}

		if (strlcpy(att->vfa_name, nvpair_name(nvp),
		    sizeof (att->vfa_name)) >= sizeof (att->vfa_name)) {
			(void) bunyan_error(files_bunyan,
			    "attached fabric group name is too long",
			    BUNYAN_T_STRING, "group", nvpair_name(nvp),
			    BUNYAN_T_UINT32, "len",
			    (uint32_t)strlen(nvpair_name(nvp)),
			    BUNYAN_T_UINT32, "maxlen",
			    (uint32_t)sizeof (att->vfa_name) - 1,
			    BUNYAN_T_END);
			umem_free(att, sizeof (*att));
			free(nets);
			return (EOVERFLOW);
		}

		list_create(&att->vfa_fabrics, sizeof (varpd_files_fabric_t),
		    offsetof(varpd_files_fabric_t, vafs_attached_node));

		list_insert_tail(&vaf->vaf_attached, att);

		for (i = 0; i < n; i++) {
			varpd_files_fabric_t *fab;

			fab = varpd_files_fabric_getbyname(vaf, nets[i]);
			if (fab == NULL) {
				(void) bunyan_error(files_bunyan,
				    "subnet name not found",
				    BUNYAN_T_STRING, "subnet", nets[i],
				    BUNYAN_T_STRING, "group", nvpair_name(nvp),
				    BUNYAN_T_END);
				free(nets);
				return (ENOENT);
			}

			if (fab->vafs_attach != NULL) {
				(void) bunyan_error(files_bunyan,
				    "subnet already attached to another group",
				    BUNYAN_T_STRING, "subnet", nets[i],
				    BUNYAN_T_STRING, "group", nvpair_name(nvp),
				    BUNYAN_T_STRING, "existing_group",
				    fab->vafs_attach->vfa_name,
				    BUNYAN_T_END);
				free(nets);
				return (EBUSY);
			}

			fab->vafs_attach = att;
			list_insert_tail(&att->vfa_fabrics, fab);
		}
		free(nets);
	}

	return (0);
}

static int
varpd_files_convert_fabrics(varpd_files_t *vaf, nvpair_t *fpair)
{
	nvlist_t *nvl = NULL;
	nvpair_t *nvp = NULL;
	int ret;

	ASSERT(strcmp(nvpair_name(fpair), "fabrics") == 0);

	if (nvpair_type(fpair) != DATA_TYPE_NVLIST) {
		(void) bunyan_error(files_bunyan,
		    "'fabrics' value is not an nvlist", BUNYAN_T_END);
		return (EINVAL);
	}

	if ((ret = nvpair_value_nvlist(fpair, &nvl)) != 0) {
		(void) bunyan_error(files_bunyan,
		    "unexpected error reading value of 'fabrics'",
		    BUNYAN_T_STRING, "errmsg", strerror(errno),
		    BUNYAN_T_END);
		return (ret);
	}

	while ((nvp = nvlist_next_nvpair(nvl, nvp)) != NULL) {
		struct in6_addr ip = { 0 };
		varpd_files_fabric_t *fab = NULL;
		varpd_files_if_t *vl2 = NULL;
		nvlist_t *vnvl = NULL;
		int32_t i32;
		char *s;

		if (strcmp(nvpair_name(nvp), "attached-fabrics") == 0) {
			if (nvpair_type(nvp) != DATA_TYPE_NVLIST) {
				(void) bunyan_error(files_bunyan,
				    "'attached-fabrics' value is not an nvlist",
				    BUNYAN_T_END);
				return (EINVAL);
			}

			if ((ret = nvpair_value_nvlist(nvp, &vnvl)) != 0) {
				(void) bunyan_error(files_bunyan,
				    "unexpected error in 'attached-fabrics' "
				    "value",
				    BUNYAN_T_STRING, "errmsg", strerror(ret),
				    BUNYAN_T_END);
				return (ret);
			}
			ret = varpd_files_convert_attached(vaf, vnvl);
			if (ret != 0) {
				return (ret);
			}
			continue;
		}

		if (nvpair_type(nvp) != DATA_TYPE_NVLIST) {
			(void) bunyan_error(files_bunyan,
			    "subnet value is not an nvlist",
			    BUNYAN_T_STRING, "subnet", nvpair_name(nvp),
			    BUNYAN_T_END);
			return (EINVAL);
		}

		if ((ret = nvpair_value_nvlist(nvp, &vnvl)) != 0) {
			(void) bunyan_error(files_bunyan,
			    "unexpected error reading subnet value",
			    BUNYAN_T_STRING, "subnet", nvpair_name(nvp),
			    BUNYAN_T_END);
			return (ret);
		}

		if ((fab = umem_zalloc(sizeof (*fab), UMEM_DEFAULT)) == NULL) {
			(void) bunyan_error(files_bunyan, "out of memory",
			    BUNYAN_T_END);
			return (ENOMEM);
		}
		/* Default to our vid if none is given */
		fab->vafs_vnet = vaf->vaf_vnet;

		if (strlcpy(fab->vafs_name, nvpair_name(nvp),
		    sizeof (fab->vafs_name)) >= sizeof (fab->vafs_name)) {
			(void) bunyan_error(files_bunyan,
			    "subnet name is too long",
			    BUNYAN_T_STRING, "subnet", nvpair_name(nvp),
			    BUNYAN_T_UINT32, "length",
			    (uint32_t)strlen(nvpair_name(nvp)),
			    BUNYAN_T_UINT32, "maxlen",
			    (uint32_t)sizeof (fab->vafs_name) - 1,
			    BUNYAN_T_END);
			umem_free(fab, sizeof (*fab));
			return (EOVERFLOW);
		}

		if ((ret = nvlist_lookup_string(vnvl, "prefix", &s)) != 0) {
			(void) bunyan_error(files_bunyan,
			    "'prefix' value is missing from subnet",
			    BUNYAN_T_STRING, "subnet", nvpair_name(nvp),
			    BUNYAN_T_END);
			umem_free(fab, sizeof (*fab));
			return (EINVAL);
		}
		if ((ret = str_to_ip(s, &fab->vafs_addr,
		    &fab->vafs_prefixlen)) != 0) {
			(void) bunyan_error(files_bunyan,
			    "prefix value is not valid",
			    BUNYAN_T_STRING, "prefix", s,
			    BUNYAN_T_STRING, "subnet", nvpair_name(nvp),
			    BUNYAN_T_END);
			umem_free(fab, sizeof (*fab));
			return (ret);
		}
		/* XXX: Make sure it's the subnet address */

		if ((ret = nvlist_lookup_int32(vnvl, "vlan", &i32)) != 0) {
			(void) bunyan_error(files_bunyan,
			    "'vlan' value is missing",
			    BUNYAN_T_STRING, "subnet", nvpair_name(nvp),
			    BUNYAN_T_END);
			umem_free(fab, sizeof (*fab));
			return (EINVAL);
		}
		if (i32 < 0 || i32 > VLAN_ID_MAX) {
			(void) bunyan_error(files_bunyan,
			    "vlan value is out of range (0-4094)",
			    BUNYAN_T_INT32, "vlan", i32,
			    BUNYAN_T_STRING, "subnet", nvpair_name(nvp),
			    BUNYAN_T_END);
			umem_free(fab, sizeof (*fab));
			return (ERANGE);
		}
		fab->vafs_vlan = (uint16_t)i32;

		if ((ret = nvlist_lookup_string(vnvl, "routerip", &s)) != 0) {
			(void) bunyan_error(files_bunyan,
			    "'routerip' value is missing",
			    BUNYAN_T_STRING, "subnet", nvpair_name(nvp),
			    BUNYAN_T_END);
			umem_free(fab, sizeof (*fab));
			return (EINVAL);
		}
		if ((ret = str_to_ip(s, &ip, NULL)) != 0) {
			(void) bunyan_error(files_bunyan,
			    "'routerip' value is not an IP",
			    BUNYAN_T_STRING, "routerip", s,
			    BUNYAN_T_STRING, "subnet", nvpair_name(nvp),
			    BUNYAN_T_END);
			umem_free(fab, sizeof (*fab));
			return (ret);
		}

		if ((ret = nvlist_lookup_string(vnvl, "routermac", &s)) != 0) {
			(void) bunyan_error(files_bunyan,
			    "'routermac' value is missing from subnet",
			    BUNYAN_T_STRING, "subnet", nvpair_name(nvp),
			    BUNYAN_T_END);
			umem_free(fab, sizeof (*fab));
			return (EINVAL);
		}
		if (ether_aton_r(s,
		    (struct ether_addr *)fab->vafs_routermac) == NULL) {
			(void) bunyan_error(files_bunyan,
			    "'routermac' is not a valid MAC address",
			    BUNYAN_T_STRING, "mac", s,
			    BUNYAN_T_STRING, "subnet", nvpair_name(nvp),
			    BUNYAN_T_END);
			umem_free(fab, sizeof (*fab));
			return (EINVAL);
		}

		/*
		 * XXX: Because of the quirks of javascript, representing
		 * integers > INT32_MAX in json becomes dicey.  Should we
		 * just use a string instead?
		 */
		switch (ret = nvlist_lookup_int32(vnvl, "dcid", &i32)) {
		case 0:
			fab->vafs_dcid = (uint32_t)i32;
			break;
		case ENOENT:
			fab->vafs_dcid = vaf->vaf_dcid;
			break;
		default:
			(void) bunyan_error(files_bunyan,
			    "unexpected error processing 'dcid' value",
			    BUNYAN_T_STRING, "errmsg", strerror(errno),
			    BUNYAN_T_STRING, "subnet", nvpair_name(nvp),
			    BUNYAN_T_END);
			umem_free(fab, sizeof (*fab));
			return (ret);
		}

		switch (ret = nvlist_lookup_string(vnvl, "vid", &s)) {
		case ENOENT:
			fab->vafs_vnet = vaf->vaf_vnet;
			break;
		case 0:
			errno = 0;
			if ((fab->vafs_vnet = strtoul(s, NULL, 10)) != 0 ||
			    errno == 0)
				break;
			ret = errno;
			(void) bunyan_error(files_bunyan,
			    "unable to parse 'vid' as a number",
			    BUNYAN_T_STRING, "vid", s,
			    BUNYAN_T_STRING, "subnet", nvpair_name(nvp),
			    BUNYAN_T_END);
			umem_free(fab, sizeof (*fab));
			return (ret);
		default:
			(void) bunyan_error(files_bunyan,
			    "unexpected error processing 'vid' value",
			    BUNYAN_T_STRING, "errmsg", strerror(errno),
			    BUNYAN_T_STRING, "subnet", nvpair_name(nvp),
			    BUNYAN_T_END);
			umem_free(fab, sizeof (*fab));
			return (ret);
		}

		/* Make sure router ip is in subnet */
		if (!IN6_ARE_PREFIXEDADDR_EQUAL(&ip, &fab->vafs_addr,
		    fab->vafs_prefixlen)) {
			void *ipp = &fab->vafs_addr;
			bunyan_type_t type =
			    IN6_IS_ADDR_V4MAPPED(&fab->vafs_addr) ?
			    BUNYAN_T_IP : BUNYAN_T_IP6;

			(void) bunyan_error(files_bunyan,
			    "'routerip' value is not within subnet",
			    type, "routerip", ipp,
			    BUNYAN_T_END);
			umem_free(fab, sizeof (*fab));
			return (EINVAL);
		}

		/*
		 * Add VL2 entry for overlay router on this fabric.
		 * Use umem_zalloc so vl2->vfi_dest (UL3 address) is all zeros.
		 */
		if ((vl2 = umem_zalloc(sizeof (*vl2), UMEM_DEFAULT)) == NULL) {
			(void) bunyan_error(files_bunyan,
			    "out of memory", BUNYAN_T_END);
			umem_free(fab, sizeof (*fab));
			return (ENOMEM);
		}

		bcopy(&ip, &vl2->vfi_ip, sizeof (struct in6_addr));
		bcopy(fab->vafs_routermac, vl2->vfi_mac, ETHERADDRL);
		vl2->vfi_dcid = fab->vafs_dcid;
		vl2->vfi_vnet = fab->vafs_vnet;
		vl2->vfi_vlan = fab->vafs_vlan;
		avl_add(&vaf->vaf_macs, vl2);
		avl_add(&vaf->vaf_ips, vl2);

		avl_add(&vaf->vaf_fabrics, fab);
	}

	return (0);
}

static int
varpd_files_convert_nvlist(varpd_files_t *vaf, nvlist_t *data, uint_t level)
{
	nvpair_t *nvp = NULL;
	nvlist_t *nvl = NULL;
	char *name;
	int ret;

	while ((nvp = nvlist_next_nvpair(data, nvp)) != NULL) {
		varpd_files_if_t *ifp = NULL;
		char *s;
		int32_t i32;

		name = nvpair_name(nvp);

		(void) bunyan_debug(files_bunyan, "processing key",
		    BUNYAN_T_STRING, "key", name,
		    BUNYAN_T_END);

		if (nvpair_type(nvp) != DATA_TYPE_NVLIST) {
			(void) bunyan_error(files_bunyan,
			    "value is not a hash (nvlist)",
			    BUNYAN_T_STRING, "key", name,
			    BUNYAN_T_END);
			return (EINVAL);
		}

		if ((ret = nvpair_value_nvlist(nvp, &nvl)) != 0) {
			(void) bunyan_error(files_bunyan,
			    "unexpected error reading values for mac entry",
			    BUNYAN_T_STRING, "mac", name,
			    BUNYAN_T_STRING, "errmsg", strerror(ret),
			    BUNYAN_T_END);
			return (ret);
		}

		if (strcmp(name, "fabrics") == 0) {
			if (level > 0) {
				(void) bunyan_error(files_bunyan,
				    "'fabrics' can only appear at the top-most "
				    "level", BUNYAN_T_END);
				return (EINVAL);
			}
			ret = varpd_files_convert_fabrics(vaf, nvp);
			if (ret != 0) {
				return (ret);
			}
			continue;
		}

		if ((ifp = umem_zalloc(sizeof (*ifp), UMEM_DEFAULT)) == NULL) {
			(void) bunyan_error(files_bunyan,
			    "out of memory", BUNYAN_T_END);
			return (ENOMEM);
		}
		ifp->vfi_dcid = vaf->vaf_dcid;

		struct ether_addr *ep = (struct ether_addr *)ifp->vfi_mac;
		if (ether_aton_r(name, ep) == NULL) {
			(void) bunyan_error(files_bunyan, "invalid MAC address",
			    BUNYAN_T_STRING, "mac", name,
			    BUNYAN_T_END);
			umem_free(ifp, sizeof (*ifp));
			return (EINVAL);
		}

		if ((ret = nvlist_lookup_int32(nvl, "vlan", &i32)) != 0) {
			(void) bunyan_error(files_bunyan,
			    "'vlan' entry is missing",
			    BUNYAN_T_STRING, "mac", name,
			    BUNYAN_T_END);
			umem_free(ifp, sizeof (*ifp));
			return (ret);
		}
		if (i32 < 0 || i32 > VLAN_ID_MAX) {
			(void) bunyan_error(files_bunyan,
			    "vlan value is out of range (0-4094)",
			    BUNYAN_T_STRING, "mac", name,
			    BUNYAN_T_INT32, "vlan", i32,
			    BUNYAN_T_END);
			umem_free(ifp, sizeof (*ifp));
			return (ERANGE);
		}
		ifp->vfi_vlan = (uint16_t)i32;

		if ((ret = nvlist_lookup_string(nvl, "arp", &s)) != 0) {
			(void) bunyan_error(files_bunyan,
			    "'arp' entry is missing",
			    BUNYAN_T_STRING, "mac", name,
			    BUNYAN_T_STRING, "errmsg", strerror(ret),
			    BUNYAN_T_END);
			umem_free(ifp, sizeof (*ifp));
			return (ret);
		}
		if ((ret = str_to_ip(s, &ifp->vfi_ip, NULL)) != 0) {
			(void) bunyan_error(files_bunyan,
			    "'arp' value is not an IP address",
			    BUNYAN_T_STRING, "arp", s,
			    BUNYAN_T_STRING, "mac", name,
			    BUNYAN_T_END);
			umem_free(ifp, sizeof (*ifp));
			return (ret);
		}

		if ((ret = nvlist_lookup_string(nvl, "ip", &s)) != 0) {
			(void) bunyan_error(files_bunyan,
			    "'ip' entry is missing",
			    BUNYAN_T_STRING, "ip", s,
			    BUNYAN_T_STRING, "mac", name,
			    BUNYAN_T_END);
			umem_free(ifp, sizeof (*ifp));
			return (ret);
		}
		if ((ret = str_to_ip(s, &ifp->vfi_dest.otp_ip, NULL)) != 0) {
			(void) bunyan_error(files_bunyan,
			    "'ip' value is not a IP address",
			    BUNYAN_T_STRING, "ip", s,
			    BUNYAN_T_STRING, "mac", name,
			    BUNYAN_T_END);
			umem_free(ifp, sizeof (*ifp));
			return (ret);
		}

		if (vaf->vaf_dest & OVERLAY_PLUGIN_D_PORT) {
			ret = nvlist_lookup_int32(nvl, "port", &i32);
			if (ret != 0) {
				(void) bunyan_error(files_bunyan,
				    "'port' value is required, but is missing",
				    BUNYAN_T_STRING, "mac", name,
				    BUNYAN_T_END);
				umem_free(ifp, sizeof (*ifp));
				return (ret);
			}

			if (i32 <= 0 || i32 > UINT16_MAX) {
				(void) bunyan_error(files_bunyan,
				    "'port' value is out of range (0-65535)",
				    BUNYAN_T_INT32, "port", i32,
				    BUNYAN_T_STRING, "mac", name,
				    BUNYAN_T_END);
				umem_free(ifp, sizeof (*ifp));
				return (ERANGE);
			}
			ifp->vfi_dest.otp_port = i32;
		}

		switch (ret = nvlist_lookup_string(nvl, "ndp", &s)) {
		case 0:
			ret = str_to_ip(s, &ifp->vfi_llocalip, NULL);
			if (ret != 0) {
				(void) bunyan_error(files_bunyan,
				    "'ndp' value is not an IP",
				    BUNYAN_T_STRING, "ndp", s,
				    BUNYAN_T_STRING, "mac", name,
				    BUNYAN_T_END);
				return (ret);
			}
			ifp->vfi_has_lladdr = B_TRUE;
			break;
		case ENOENT:
			/* Ok if missing */
			break;
		default:
			(void) bunyan_error(files_bunyan,
			    "unexpected error processing 'ndp' value",
			    BUNYAN_T_STRING, "errmsg", strerror(errno),
			    BUNYAN_T_STRING, "mac", name,
			    BUNYAN_T_END);
			umem_free(ifp, sizeof (*ifp));
			return (ret);
		}

		switch (ret = nvlist_lookup_string(nvl, "dhcp-proxy", &s)) {
		case 0:
			ep = (struct ether_addr *)&ifp->vfi_dhcp;
			if (ether_aton_r(s, ep) == NULL) {
				(void) bunyan_error(files_bunyan,
				    "value of 'dhcp-proxy' is not a "
				    "MAC address",
				    BUNYAN_T_STRING, "dhcp-proxy", s,
				    BUNYAN_T_STRING, "mac", name,
				    BUNYAN_T_END);
				umem_free(ifp, sizeof (*ifp));
				return (EINVAL);
			}
			ifp->vfi_has_dhcp = B_TRUE;
			break;
		case ENOENT:
			/* Ok if missing */
			break;
		default:
			(void) bunyan_error(files_bunyan,
			    "unexpected error reading 'dhcp-proxy' value",
			    BUNYAN_T_STRING, "errmsg", strerror(errno),
			    BUNYAN_T_STRING, "mac", name,
			    BUNYAN_T_END);
			umem_free(ifp, sizeof (*ifp));
			return (ret);
		}

		switch (ret = nvlist_lookup_string(nvl, "vid", &s)) {
		case ENOENT:
			ifp->vfi_vnet = vaf->vaf_vnet;
			break;
		case 0:
			errno = 0;
			if ((ifp->vfi_vnet = strtoul(s, NULL, 10)) != 0 ||
			    errno == 0)
				break;
			ret = errno;
			(void) bunyan_error(files_bunyan,
			    "unable to parse 'vid' as a number",
			    BUNYAN_T_STRING, "vid", s,
			    BUNYAN_T_STRING, "mac", name,
			    BUNYAN_T_END);
			umem_free(ifp, sizeof (*ifp));
			return (ret);
		default:
			(void) bunyan_error(files_bunyan,
			    "unexpected error processing 'vid' value",
			    BUNYAN_T_STRING, "errmsg", strerror(errno),
			    BUNYAN_T_STRING, "mac", name,
			    BUNYAN_T_END);
			umem_free(ifp, sizeof (*ifp));
			return (ret);
		}

		/* Make sure router ip is in subnet */
		avl_add(&vaf->vaf_macs, ifp);
		avl_add(&vaf->vaf_ips, ifp);
		if (ifp->vfi_has_lladdr && (ifp->vfi_dcid == vaf->vaf_dcid))
			avl_add(&vaf->vaf_ndp, ifp);
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
	nvlist_parse_json_error_t jerr = { 0 };

	if (vaf->vaf_path == NULL)
		return (EAGAIN);

	if ((fd = open(vaf->vaf_path, O_RDONLY)) < 0) {
		(void) bunyan_error(files_bunyan,
		    "Cannot read destination data",
		    BUNYAN_T_STRING, "path", vaf->vaf_path,
		    BUNYAN_T_STRING, "errmsg", strerror(errno),
		    BUNYAN_T_END);
		return (errno);
	}

	if (fstat(fd, &st) != 0) {
		ret = errno;
		if (close(fd) != 0)
			abort();
		(void) bunyan_error(files_bunyan,
		    "could not determine status of file (stat(2) failed)",
		    BUNYAN_T_STRING, "path", vaf->vaf_path,
		    BUNYAN_T_STRING, "errmsg", strerror(ret),
		    BUNYAN_T_END);
		return (ret);
	}

	maddr = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE,
	    fd, 0);
	if (maddr == NULL) {
		ret = errno;
		if (close(fd) != 0)
			abort();
		(void) bunyan_error(files_bunyan,
		    "could not load destination data (mmap(2) failed)",
		    BUNYAN_T_STRING, "path", vaf->vaf_path,
		    BUNYAN_T_STRING, "errmsg", strerror(errno),
		    BUNYAN_T_END);
		return (ret);
	}

	if ((ret = nvlist_parse_json(maddr, st.st_size, &nvl,
	    NVJSON_FORCE_INTEGER, &jerr)) != 0) {
		(void) bunyan_error(files_bunyan,
		    "could not parse destination JSON file",
		    BUNYAN_T_STRING, "path", vaf->vaf_path,
		    BUNYAN_T_STRING, "parse_msg", jerr.nje_message,
		    BUNYAN_T_UINT32, "pos", (uint32_t)jerr.nje_pos,
		    BUNYAN_T_INT32, "errno", (int32_t)jerr.nje_errno,
		    BUNYAN_T_STRING, "errmsg", strerror(jerr.nje_errno),
		    BUNYAN_T_END);
	} else {
		ret = varpd_files_convert_nvlist(vaf, nvl, 0);
		nvlist_free(nvl);
		nvl = NULL;
	}

	if (munmap(maddr, st.st_size) != 0)
		abort();
	if (close(fd) != 0)
		abort();

	return (ret);
}

static void
varpd_files_stop(void *arg)
{
	varpd_files_t *vaf = arg;
	varpd_files_if_t *vif;
	varpd_files_attach_t *att;
	varpd_files_fabric_t *fab;

	/*
	 * VL2 data should appear in both trees, so free only after removed
	 * from second tree.
	 */
	while ((vif = avl_first(&vaf->vaf_ips)) != NULL)
		avl_remove(&vaf->vaf_ips, vif);

	while ((vif = avl_first(&vaf->vaf_macs)) != NULL) {
		avl_remove(&vaf->vaf_macs, vif);
		umem_free(vif, sizeof (*vif));
	}

	/*
	 * A fabric could be unattached, and not appear in any attachment
	 * group.  Therefore, remove the fabrics from all the attached groups,
	 * then free them after removing from the global list of fabrics.
	 */
	while ((att = list_remove_head(&vaf->vaf_attached)) != NULL) {
		do {
			fab = list_remove_head(&att->vfa_fabrics);
		} while (fab != NULL);
		umem_free(att, sizeof (*att));
	}

	while ((fab = avl_first(&vaf->vaf_fabrics)) != NULL) {
		avl_remove(&vaf->vaf_fabrics, fab);
		umem_free(fab, sizeof (*fab));
	}
}

static void
varpd_files_destroy(void *arg)
{
	varpd_files_t *vaf = arg;

	if (vaf->vaf_path != NULL) {
		umem_free(vaf->vaf_path, strlen(vaf->vaf_path) + 1);
		vaf->vaf_path = NULL;
	}

	avl_destroy(&vaf->vaf_fabrics);
	avl_destroy(&vaf->vaf_macs);
	avl_destroy(&vaf->vaf_ips);
	list_destroy(&vaf->vaf_attached);

	umem_free(vaf, sizeof (varpd_files_t));
}

static varpd_files_fabric_t *
varpd_files_find_dstfab(varpd_files_t *vaf, varpd_files_attach_t *att,
    const struct in6_addr *dst)
{
	varpd_files_fabric_t *net = NULL;

	for (net = list_head(&att->vfa_fabrics); net != NULL;
	    net = list_next(&att->vfa_fabrics, net)) {
		if (IN6_ARE_PREFIXEDADDR_EQUAL(dst, &net->vafs_addr,
		    net->vafs_prefixlen)) {
			return (net);
		}
	}

	return (NULL);
}

static varpd_files_attach_t *
varpd_files_find_attach(varpd_files_t *vaf, const struct in6_addr *src,
    uint16_t vlan, overlay_target_route_t *otr)
{
	varpd_files_fabric_t *fab;
	varpd_files_fabric_t lookup = {
		.vafs_vnet = vaf->vaf_vnet,
		.vafs_dcid = vaf->vaf_dcid,
		.vafs_vlan = vlan,
		.vafs_addr = *src
	};
	avl_index_t where = 0;

	/*
	 * Since fabrics are sorted by subnet address last, any given IP
	 * potentially in a fabric subnet should lie between two adjacent
	 * fabric entries in the tree.  Find where such an IP would go in
	 * the tree, and the entry before the insertion point should be the
	 * fabric (if it is present).
	 */
	fab = avl_find(&vaf->vaf_fabrics, &lookup, &where);
	if (fab != NULL) {
		/*
		 * Someone requested the subnet address.  E.g. if the fabric
		 * is 192.168.10.0/24, someone asked for 192.168.10.0.  Treat
		 * as not found.
		 */
		return (NULL);
	}

	fab = avl_nearest(&vaf->vaf_fabrics, where, AVL_BEFORE);
	if (fab == NULL) {
		return (NULL);
	}

	/* Still must verify that the address lies in the range of the subnet */
	if (!IN6_ARE_PREFIXEDADDR_EQUAL(&fab->vafs_addr, src,
	   fab->vafs_prefixlen)) {
		return (NULL);
	}

	return (fab->vafs_attach);
}

static void
varpd_files_lookup_l3(varpd_files_t *vaf, varpd_query_handle_t *qh,
    const overlay_targ_lookup_t *otl, overlay_target_point_t *otp,
    overlay_target_route_t *otr, overlay_target_mac_t *otm)
{
	const struct in6_addr *dst_ip;
	const struct in6_addr *src_ip;
	varpd_files_attach_t *attach = NULL;
	varpd_files_fabric_t *fab = NULL;
	varpd_files_if_t *ifp = NULL;

	dst_ip = &otl->otl_addru.otlu_l3.otl3_dstip;
	src_ip = &otl->otl_addru.otlu_l3.otl3_srcip;

	if ((attach = varpd_files_find_attach(vaf, src_ip, otl->otl_vlan,
	    otr)) == NULL) {
		libvarpd_plugin_query_reply(qh, VARPD_LOOKUP_DROP);
		return;
	}

	if ((fab = varpd_files_find_dstfab(vaf, attach, dst_ip)) == NULL) {
		libvarpd_plugin_query_reply(qh, VARPD_LOOKUP_DROP);
		return;
	}

	varpd_files_if_t lookup = { 0 };

	lookup.vfi_vnet = fab->vafs_vnet;
	lookup.vfi_vlan = fab->vafs_vlan;
	bcopy(dst_ip, &lookup.vfi_ip, sizeof (struct in6_addr));

	if ((ifp = avl_find(&vaf->vaf_ips, &lookup, NULL)) == NULL) {
		libvarpd_plugin_query_reply(qh, VARPD_LOOKUP_DROP);
		return;
	}

	otr->otr_vnet = fab->vafs_vnet;
	otr->otr_vlan = fab->vafs_vlan;
	bcopy(fab->vafs_routermac, otr->otr_srcmac, ETHERADDRL);

	otm->otm_dcid = fab->vafs_dcid;
	bcopy(ifp->vfi_mac, otm->otm_mac, ETHERADDRL);

	bcopy(&ifp->vfi_dest, otp, sizeof (*otp));

	libvarpd_plugin_query_reply(qh, VARPD_LOOKUP_OK);
}

static void
varpd_files_lookup(void *arg, varpd_query_handle_t *qh,
    const overlay_targ_lookup_t *otl, overlay_target_point_t *otp,
    overlay_target_route_t *otr, overlay_target_mac_t *otm)
{
	varpd_files_t *vaf = arg;
	static const uint8_t bcast[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
	varpd_files_if_t *ifp = NULL;
	varpd_files_if_t lookup = { .vfi_dcid = vaf->vaf_dcid };


	/* We don't support a default */
	if (otl == NULL) {
		libvarpd_plugin_query_reply(qh, VARPD_LOOKUP_DROP);
		return;
	}

	/*
	 * Shuffle off L3 lookups to their own codepath.
	 */
	if (otl->otl_l3req) {
		varpd_files_lookup_l3(vaf, qh, otl, otp, otr, otm);
		return;
	}

	/*
	 * At this point, the traditional overlay_target_point_t is all that
	 * needs filling in.  Zero-out the otr and otm for safety.
	 */
	bzero(otr, sizeof (*otr));
	bzero(otm, sizeof (*otm));

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
		bcopy(otl->otl_addru.otlu_l2.otl2_srcaddr, lookup.vfi_mac,
		    ETHERADDRL);

		if ((ifp = avl_find(&vaf->vaf_macs, &lookup, NULL)) == NULL) {
			libvarpd_plugin_query_reply(qh, VARPD_LOOKUP_DROP);
			return;
		}

		if (!ifp->vfi_has_dhcp) {
			libvarpd_plugin_query_reply(qh, VARPD_LOOKUP_DROP);
			return;
		}

		libvarpd_plugin_proxy_dhcp(vaf->vaf_hdl, qh, otl);
		return;
	}

	bcopy(otl->otl_addru.otlu_l2.otl2_dstaddr, lookup.vfi_mac, ETHERADDRL);
	if ((ifp = avl_find(&vaf->vaf_macs, &lookup, NULL)) == NULL) {
		libvarpd_plugin_query_reply(qh, VARPD_LOOKUP_DROP);
		return;
	}

	bcopy(&ifp->vfi_dest, otp, sizeof (*otp));

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
    const struct sockaddr *sock, uint16_t vlan, uint8_t *out)
{
	varpd_files_t *vaf = arg;
	const struct sockaddr_in *ip;
	const struct sockaddr_in6 *ip6;
	varpd_files_if_t *ifp = NULL;
	varpd_files_if_t lookup = {
		.vfi_vnet = vaf->vaf_vnet,
		.vfi_dcid = vaf->vaf_dcid,
		.vfi_vlan = vlan
	};

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

	if (sock->sa_family == AF_INET) {
		IN6_IPADDR_TO_V4MAPPED(ip->sin_addr.s_addr, &lookup.vfi_ip);
		ifp = avl_find(&vaf->vaf_ips, &lookup, NULL);
	} else {
		bcopy(&ip6->sin6_addr, &lookup.vfi_llocalip,
		    sizeof (struct in6_addr));
		ifp = avl_find(&vaf->vaf_ndp, &lookup, NULL);
	}

	if (ifp == NULL) {
		libvarpd_plugin_arp_reply(vah, VARPD_LOOKUP_DROP);
		return;
	}

	bcopy(ifp->vfi_mac, out, ETHERADDRL);
	libvarpd_plugin_arp_reply(vah, VARPD_LOOKUP_OK);
}

static void
varpd_files_proxy_dhcp(void *arg, varpd_dhcp_handle_t *vdh, int type,
    const overlay_targ_lookup_t *otl, uint8_t *out)
{
	varpd_files_t *vaf = arg;
	varpd_files_if_t *ifp = NULL;
	varpd_files_if_t lookup = {
		.vfi_dcid = vaf->vaf_dcid,
		.vfi_mac = *otl->otl_addru.otlu_l2.otl2_srcaddr
	};

	if (type != VARPD_QTYPE_ETHERNET) {
		libvarpd_plugin_dhcp_reply(vdh, VARPD_LOOKUP_DROP);
		return;
	}

	if ((ifp = avl_find(&vaf->vaf_macs, &lookup, NULL)) == NULL) {
		libvarpd_plugin_dhcp_reply(vdh, VARPD_LOOKUP_DROP);
		return;
	}

	if (!ifp->vfi_has_dhcp) {
		libvarpd_plugin_dhcp_reply(vdh, VARPD_LOOKUP_DROP);
		return;
	}

	bcopy(ifp->vfi_dhcp, out, ETHERADDRL);
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

static int
files_bunyan_init(void)
{
	int ret;

	if ((ret = bunyan_init("files", &files_bunyan)) != 0)
		return (ret);
	ret = bunyan_stream_add(files_bunyan, "stderr", BUNYAN_L_INFO,
	    bunyan_stream_fd, (void *)STDERR_FILENO);
	if (ret != 0)
		bunyan_fini(files_bunyan);
	return (ret);
}

static void
files_bunyan_fini(void)
{
	if (files_bunyan != NULL)
		bunyan_fini(files_bunyan);
}

#pragma init(varpd_files_init)
static void
varpd_files_init(void)
{
	int err;
	varpd_plugin_register_t *vpr;

	if (files_bunyan_init() != 0)
		return;

	vpr = libvarpd_plugin_alloc(VARPD_CURRENT_VERSION, &err);
	if (vpr == NULL) {
		files_bunyan_fini();
		return;
	}

	vpr->vpr_mode = OVERLAY_TARGET_DYNAMIC;
	vpr->vpr_name = "files";
	vpr->vpr_ops = &varpd_files_ops;
	(void) libvarpd_plugin_register(vpr);
	libvarpd_plugin_free(vpr);
}
