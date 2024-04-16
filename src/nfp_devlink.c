// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright (C) 2017-2019 Netronome Systems, Inc. */

#include "nfp_net_compat.h"

#include <linux/firmware.h>
#include <linux/rtnetlink.h>
#include <net/devlink.h>

#include "nfpcore/nfp.h"
#include "nfpcore/nfp_nsp.h"
#include "nfp_app.h"
#include "nfp_main.h"
#include "nfp_port.h"

#define NFP_DEVLINK_ID_PF_START	NSP_ETH_MAX_COUNT

static int
nfp_devlink_fill_eth_port(struct nfp_port *port,
			  struct nfp_eth_table_port *copy)
{
	struct nfp_eth_table_port *eth_port;

	eth_port = __nfp_port_get_eth_port(port);
	if (!eth_port)
		return -EINVAL;

	memcpy(copy, eth_port, sizeof(*eth_port));

	return 0;
}

static int
#ifndef VERSION__DEVLINK_PORT_SPLIT
nfp_devlink_fill_eth_port_from_id(struct nfp_pf *pf, unsigned int port_index,
#else
nfp_devlink_fill_eth_port_from_id(struct nfp_pf *pf,
				  struct devlink_port *dl_port,
#endif /* VERSION__DEVLINK_PORT_SPLIT */
				  struct nfp_eth_table_port *copy)
{
	struct nfp_port *port;

#ifndef VERSION__DEVLINK_PORT_SPLIT
	port = nfp_port_from_id(pf, NFP_PORT_PHYS_PORT, port_index);
#else
	port = container_of(dl_port, struct nfp_port, dl_port);
#endif /* VERSION__DEVLINK_PORT_SPLIT */

	return nfp_devlink_fill_eth_port(port, copy);
}

static int
nfp_devlink_set_lanes(struct nfp_pf *pf, unsigned int idx, unsigned int lanes)
{
	struct nfp_nsp *nsp;
	int ret;

	nsp = nfp_eth_config_start(pf->cpp, idx);
	if (IS_ERR(nsp))
		return PTR_ERR(nsp);

	ret = __nfp_eth_set_split(nsp, lanes);
	if (ret) {
		nfp_eth_config_cleanup_end(nsp);
		return ret;
	}

	ret = nfp_eth_config_commit_end(nsp);
	if (ret < 0)
		return ret;
	if (ret) /* no change */
		return 0;

	return nfp_net_refresh_port_table_sync(pf);
}

static int
#if VER_NON_SLEL_LT(4, 18) || SLEL_LOCALVER_LT(4, 12, 14, 122, 37)
nfp_devlink_port_split(struct devlink *devlink, unsigned int port_index,
		       unsigned int count)
#else
#ifndef VERSION__DEVLINK_PORT_SPLIT
nfp_devlink_port_split(struct devlink *devlink, unsigned int port_index,
		       unsigned int count, struct netlink_ext_ack *extack)
#else
nfp_devlink_port_split(struct devlink *devlink, struct devlink_port *port,
		       unsigned int count, struct netlink_ext_ack *extack)
#endif /* VERSION__DEVLINK_PORT_SPLIT */
#endif
{
	struct nfp_pf *pf = devlink_priv(devlink);
	struct nfp_eth_table_port eth_port;
	unsigned int lanes;
	int ret;

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 18, 0)
	devl_lock(devlink);
#endif

	rtnl_lock();
#ifndef VERSION__DEVLINK_PORT_SPLIT
	ret = nfp_devlink_fill_eth_port_from_id(pf, port_index, &eth_port);
#else
	ret = nfp_devlink_fill_eth_port_from_id(pf, port, &eth_port);
#endif /* VERSION__DEVLINK_PORT_SPLIT */
	rtnl_unlock();
	if (ret)
		goto out;

	if (eth_port.port_lanes % count) {
#if VER_KERN_GE(4, 18)
		NL_SET_ERR_MSG_MOD(extack, "invalid count");
#endif
		ret = -EINVAL;
		goto out;
	}

	/* Special case the 100G CXP -> 2x40G split */
	lanes = eth_port.port_lanes / count;
	if (eth_port.lanes == 10 && count == 2)
		lanes = 8 / count;

	ret = nfp_devlink_set_lanes(pf, eth_port.index, lanes);
out:
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 18, 0)
	devl_unlock(devlink);
#endif

	return ret;
}

static int
#if VER_NON_SLEL_LT(4, 18) || SLEL_LOCALVER_LT(4, 12, 14, 122, 37)
nfp_devlink_port_unsplit(struct devlink *devlink, unsigned int port_index)
#else
#ifndef VERSION__DEVLINK_PORT_SPLIT
nfp_devlink_port_unsplit(struct devlink *devlink, unsigned int port_index,
			 struct netlink_ext_ack *extack)
#else
nfp_devlink_port_unsplit(struct devlink *devlink, struct devlink_port *port,
			 struct netlink_ext_ack *extack)
#endif /* VERSION__DEVLINK_PORT_SPLIT */
#endif
{
	struct nfp_pf *pf = devlink_priv(devlink);
	struct nfp_eth_table_port eth_port;
	unsigned int lanes;
	int ret;

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 18, 0)
	devl_lock(devlink);
#endif

	rtnl_lock();
#ifndef VERSION__DEVLINK_PORT_SPLIT
	ret = nfp_devlink_fill_eth_port_from_id(pf, port_index, &eth_port);
#else
	ret = nfp_devlink_fill_eth_port_from_id(pf, port, &eth_port);
#endif /* VERSION__DEVLINK_PORT_SPLIT */
	rtnl_unlock();
	if (ret)
		goto out;

	if (!eth_port.is_split) {
#if VER_KERN_GE(4, 18)
		NL_SET_ERR_MSG_MOD(extack, "port is not split");
#endif
		ret = -EINVAL;
		goto out;
	}

	/* Special case the 100G CXP -> 2x40G unsplit */
	lanes = eth_port.port_lanes;
	if (eth_port.port_lanes == 8)
		lanes = 10;

	ret = nfp_devlink_set_lanes(pf, eth_port.index, lanes);
out:
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 18, 0)
	devl_unlock(devlink);
#endif

	return ret;
}

#if COMPAT__HAS_DEVLINK_SB
static int
nfp_devlink_sb_pool_get(struct devlink *devlink, unsigned int sb_index,
			u16 pool_index, struct devlink_sb_pool_info *pool_info)
{
	struct nfp_pf *pf = devlink_priv(devlink);

	return nfp_shared_buf_pool_get(pf, sb_index, pool_index, pool_info);
}

static int
nfp_devlink_sb_pool_set(struct devlink *devlink, unsigned int sb_index,
			u16 pool_index,
#if VER_NON_RHEL_LT(5, 2) || VER_RHEL_LT(8, 2)
			u32 size, enum devlink_sb_threshold_type threshold_type)
#else
			u32 size, enum devlink_sb_threshold_type threshold_type,
			struct netlink_ext_ack *extack)
#endif
{
	struct nfp_pf *pf = devlink_priv(devlink);

	return nfp_shared_buf_pool_set(pf, sb_index, pool_index,
				       size, threshold_type);
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0)
static int nfp_devlink_eswitch_mode_get(struct devlink *devlink, u16 *mode)
{
	struct nfp_pf *pf = devlink_priv(devlink);

	return nfp_app_eswitch_mode_get(pf->app, mode);
}

#if (!COMPAT_SLELINUX && VER_NON_RHEL_OR_KYL_LT(4, 20)) || VER_RHEL_LT(8, 0) || \
    VER_KYL_LT(10, 3) || SLEL_LOCALVER_LT(4, 12, 14, 122, 37)
static int nfp_devlink_eswitch_mode_set(struct devlink *devlink, u16 mode)
#else
static int nfp_devlink_eswitch_mode_set(struct devlink *devlink, u16 mode,
					struct netlink_ext_ack *extack)
#endif
{
	struct nfp_pf *pf = devlink_priv(devlink);
	int ret;

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 18, 0)
	devl_lock(devlink);
#endif
	ret = nfp_app_eswitch_mode_set(pf->app, mode);
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 18, 0)
	devl_unlock(devlink);
#endif

	return ret;
}
#endif

#if VER_NON_RHEL_GE(5, 1) || VER_RHEL_GE(8, 2)
static const struct nfp_devlink_versions_simple {
	const char *key;
	const char *hwinfo;
} nfp_devlink_versions_hwinfo[] = {
	{ DEVLINK_INFO_VERSION_GENERIC_BOARD_ID,	"assembly.partno", },
	{ DEVLINK_INFO_VERSION_GENERIC_BOARD_REV,	"assembly.revision", },
	{ DEVLINK_INFO_VERSION_GENERIC_BOARD_MANUFACTURE, "assembly.vendor", },
	{ "board.model", /* code name */		"assembly.model", },
	{ "board.pn",					"pn", },
};

static int
nfp_devlink_versions_get_hwinfo(struct nfp_pf *pf, struct devlink_info_req *req)
{
	unsigned int i;
	int err;

	for (i = 0; i < ARRAY_SIZE(nfp_devlink_versions_hwinfo); i++) {
		const struct nfp_devlink_versions_simple *info;
		const char *val;

		info = &nfp_devlink_versions_hwinfo[i];

		val = nfp_hwinfo_lookup(pf->hwinfo, info->hwinfo);
		if (!val)
			continue;

		err = devlink_info_version_fixed_put(req, info->key, val);
		if (err)
			return err;
	}

	return 0;
}

static const struct nfp_devlink_versions {
	enum nfp_nsp_versions id;
	const char *key;
} nfp_devlink_versions_nsp[] = {
#if VER_RHEL_GE(8, 2)
	{ NFP_VERSIONS_BUNDLE,  "fw.bundle_id", },
#else
	{ NFP_VERSIONS_BUNDLE,	DEVLINK_INFO_VERSION_GENERIC_FW_BUNDLE_ID, },
#endif
	{ NFP_VERSIONS_BSP,	DEVLINK_INFO_VERSION_GENERIC_FW_MGMT, },
	{ NFP_VERSIONS_CPLD,	"fw.cpld", },
	{ NFP_VERSIONS_APP,	DEVLINK_INFO_VERSION_GENERIC_FW_APP, },
	{ NFP_VERSIONS_UNDI,	DEVLINK_INFO_VERSION_GENERIC_FW_UNDI, },
	{ NFP_VERSIONS_NCSI,	DEVLINK_INFO_VERSION_GENERIC_FW_NCSI, },
	{ NFP_VERSIONS_CFGR,	"chip.init", },
};

static int
nfp_devlink_versions_get_nsp(struct devlink_info_req *req, bool flash,
			     const u8 *buf, unsigned int size)
{
	unsigned int i;
	int err;

	for (i = 0; i < ARRAY_SIZE(nfp_devlink_versions_nsp); i++) {
		const struct nfp_devlink_versions *info;
		const char *version;

		info = &nfp_devlink_versions_nsp[i];

		version = nfp_nsp_versions_get(info->id, flash, buf, size);
		if (IS_ERR(version)) {
			if (PTR_ERR(version) == -ENOENT)
				continue;
			else
				return PTR_ERR(version);
		}

		if (flash)
			err = devlink_info_version_stored_put(req, info->key,
							      version);
		else
			err = devlink_info_version_running_put(req, info->key,
							       version);
		if (err)
			return err;
	}

	return 0;
}

static int
nfp_devlink_info_get(struct devlink *devlink, struct devlink_info_req *req,
		     struct netlink_ext_ack *extack)
{
	struct nfp_pf *pf = devlink_priv(devlink);
	const char *sn, *vendor, *part;
	struct nfp_nsp *nsp;
	char *buf = NULL;
	int err;

#if (VER_NON_RHEL_LT(6, 2)) || (RHEL_RELEASE_LT(9, 305, 0, 0))
	err = devlink_info_driver_name_put(req, "nfp");
	if (err)
		return err;
#endif

	vendor = nfp_hwinfo_lookup(pf->hwinfo, "assembly.vendor");
	part = nfp_hwinfo_lookup(pf->hwinfo, "assembly.partno");
	sn = nfp_hwinfo_lookup(pf->hwinfo, "assembly.serial");
	if (vendor && part && sn) {
		char *buf;

		buf = kmalloc(strlen(vendor) + strlen(part) + strlen(sn) + 1,
			      GFP_KERNEL);
		if (!buf)
			return -ENOMEM;

		buf[0] = '\0';
		strcat(buf, vendor);
		strcat(buf, part);
		strcat(buf, sn);

		err = devlink_info_serial_number_put(req, buf);
		kfree(buf);
		if (err)
			return err;
	}

	nsp = nfp_nsp_open(pf->cpp);
	if (IS_ERR(nsp)) {
		NL_SET_ERR_MSG_MOD(extack, "can't access NSP");
		return PTR_ERR(nsp);
	}

	if (nfp_nsp_has_versions(nsp)) {
		buf = kzalloc(NFP_NSP_VERSION_BUFSZ, GFP_KERNEL);
		if (!buf) {
			err = -ENOMEM;
			goto err_close_nsp;
		}

		err = nfp_nsp_versions(nsp, buf, NFP_NSP_VERSION_BUFSZ);
		if (err)
			goto err_free_buf;

		err = nfp_devlink_versions_get_nsp(req, false,
						   buf, NFP_NSP_VERSION_BUFSZ);
		if (err)
			goto err_free_buf;

		err = nfp_devlink_versions_get_nsp(req, true,
						   buf, NFP_NSP_VERSION_BUFSZ);
		if (err)
			goto err_free_buf;

		kfree(buf);
	}

	nfp_nsp_close(nsp);

	return nfp_devlink_versions_get_hwinfo(pf, req);

err_free_buf:
	kfree(buf);
err_close_nsp:
	nfp_nsp_close(nsp);
	return err;
}

#if VER_NON_RHEL_OR_SLEL_LT(5, 10) || VER_RHEL_LT(8, 5) || \
    SLEL_LOCALVER_LT(5, 3, 18, 57, 0)
static int
nfp_devlink_flash_update(struct devlink *devlink, const char *path,
			 const char *component, struct netlink_ext_ack *extack)
{
	if (component)
		return -EOPNOTSUPP;
	return nfp_flash_update_common(devlink_priv(devlink), path, extack);
}
#else
static int
nfp_devlink_flash_update(struct devlink *devlink,
			 struct devlink_flash_update_params *params,
			 struct netlink_ext_ack *extack)
{
	return nfp_flash_update_common(devlink_priv(devlink),
#if VER_NON_RHEL_GE(5, 11) || VER_RHEL_GE(8, 5)
				       params->fw,
#else
				       params->file_name,
#endif
				       extack);
}
#endif
#endif

const struct devlink_ops nfp_devlink_ops = {
#if VER_NON_RHEL_LT(6, 5) || RHEL_RELEASE_LT(9, 369, 0, 0)
	.port_split		= nfp_devlink_port_split,
	.port_unsplit		= nfp_devlink_port_unsplit,
#endif
#if COMPAT__HAS_DEVLINK_SB
	.sb_pool_get		= nfp_devlink_sb_pool_get,
	.sb_pool_set		= nfp_devlink_sb_pool_set,
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0)
	.eswitch_mode_get	= nfp_devlink_eswitch_mode_get,
	.eswitch_mode_set	= nfp_devlink_eswitch_mode_set,
#endif
#if VER_NON_RHEL_GE(5, 1) || VER_RHEL_GE(8, 2)
	.info_get		= nfp_devlink_info_get,
	.flash_update		= nfp_devlink_flash_update,
#endif
};

#if VER_NON_RHEL_GE(6, 5) || RHEL_RELEASE_GE(9, 369, 0, 0)
static const struct devlink_port_ops nfp_devlink_port_ops = {
	.port_split		= nfp_devlink_port_split,
	.port_unsplit		= nfp_devlink_port_unsplit,
};
#endif

bool nfp_devlink_is_port_registered(struct nfp_port *port)
{
	if (!port)
		return false;

#if VER_NON_RHEL_LT(6, 1) || VER_RHEL_LT(9, 2)
	return !!port->dl_port.devlink;
#else
	return port->dl_port.registered;
#endif
}

int nfp_devlink_port_register(struct nfp_app *app, struct nfp_port *port)
{
	struct compat__devlink_port_attrs attrs = {};
	struct nfp_eth_table_port eth_port;
	int __maybe_unused serial_len;
	struct devlink *devlink;
	int dl_port_index;
	const u8 *serial;
	int ret;

#if (VER_NON_RHEL_GE(6, 2)) || (RHEL_RELEASE_GE(9, 305, 0, 0))
	SET_NETDEV_DEVLINK_PORT(port->netdev, &port->dl_port);
#endif

	switch (port->type) {
	case NFP_PORT_PHYS_PORT:
		attrs.flavour = DEVLINK_PORT_FLAVOUR_PHYSICAL;
		rtnl_lock();
		ret = nfp_devlink_fill_eth_port(port, &eth_port);
		rtnl_unlock();
		if (ret)
			return ret;
		attrs.split = eth_port.is_split;
#if VER_NON_RHEL_GE(5, 9) || VER_RHEL_GE(8, 4)
		attrs.splittable = eth_port.port_lanes > 1 && !attrs.split;
		attrs.lanes = eth_port.port_lanes;
#endif
		attrs.phys.port_number = eth_port.label_port;
		attrs.phys.split_subport_number = eth_port.label_subport;
		dl_port_index = port->eth_id;
		break;
#if VER_NON_RHEL_GE(5, 3) || VER_RHEL_GE(8, 2)
	case NFP_PORT_PF_PORT:
		attrs.flavour = DEVLINK_PORT_FLAVOUR_PCI_PF;
		attrs.pci_pf.pf = port->pf_id;
		dl_port_index = NFP_DEVLINK_ID_PF_START + port->pf_id;
		break;
	case NFP_PORT_VF_PORT:
		attrs.flavour = DEVLINK_PORT_FLAVOUR_PCI_VF;
		attrs.pci_vf.pf = port->pf_id;
		attrs.pci_vf.vf = port->vf_id;
		dl_port_index = NFP_DEVLINK_ID_PF_START + 1 + port->vf_id;
		break;
#endif
	default:
		/* Unrecognised port types will not be registered with devlink,
		 * but this is not considered a failure. Subsequent devlink
		 * port access needs to be protected by
		 * nfp_devlink_is_port_registered.
		 */
		return 0;
	}
	serial_len = nfp_cpp_serial(port->app->cpp, &serial);
	memcpy(attrs.switch_id.id, serial, serial_len);
	attrs.switch_id.id_len = serial_len;
	compat__devlink_port_attrs_set(&port->dl_port, &attrs);

	devlink = priv_to_devlink(app->pf);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 5, 0)
	return devl_port_register_with_ops(devlink, &port->dl_port,
					   dl_port_index, &nfp_devlink_port_ops);
#else
	return devl_port_register(devlink, &port->dl_port, dl_port_index);
#endif
}

void nfp_devlink_port_unregister(struct nfp_port *port)
{
	devl_port_unregister(&port->dl_port);
}

#if (VER_NON_RHEL_LT(6, 2)) || (RHEL_RELEASE_LT(9, 305, 0, 0))
void nfp_devlink_port_type_eth_set(struct nfp_port *port)
{
	devlink_port_type_eth_set(&port->dl_port, port->netdev);
}

void nfp_devlink_port_type_clear(struct nfp_port *port)
{
	devlink_port_type_clear(&port->dl_port);
}
#endif

struct devlink *nfp_devlink_get_devlink(struct net_device *netdev)
{
	struct nfp_app *app;

	app = nfp_app_from_netdev(netdev);
	if (!app)
		return NULL;

	return priv_to_devlink(app->pf);
}

struct devlink_port *nfp_devlink_get_devlink_port(struct net_device *netdev)
{
	struct nfp_port *port;

	port = nfp_port_from_netdev(netdev);
	if (!port)
		return NULL;

	return &port->dl_port;
}
