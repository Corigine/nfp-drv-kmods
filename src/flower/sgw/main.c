/* Copyright (C) 2024 Corigine, Inc. */

#include "nfp_net_compat.h"

#include <linux/etherdevice.h>
#include <linux/vmalloc.h>

#include "../../nfpcore/nfp.h"
#include "../../nfpcore/nfp_nffw.h"
#include "../../nfp_app.h"
#include "../../nfp_main.h"
#include "../../nfp_port.h"
#include "../main.h"

#define NFP_SGW_ALLOWED_VER 0x0001000000010000UL

static const char *
nfp_sgw_extra_cap(struct nfp_app *app, struct nfp_net *nn)
{
	return "SGW";
}

static struct net_device *
nfp_sgw_dev_get(struct nfp_app *app, u32 port_id, bool *redir_egress)
{
	enum nfp_repr_type repr_type;
	struct nfp_reprs *reprs;
	u8 port = 0;

	/* Check if the port is internal. */
	if (FIELD_GET(NFP_FLOWER_CMSG_PORT_TYPE, port_id) ==
	    NFP_FLOWER_CMSG_PORT_TYPE_OTHER_PORT)
		return NULL;

	repr_type = nfp_flower_repr_get_type_and_port(app, port_id, &port);
	if (repr_type > NFP_REPR_TYPE_MAX)
		return NULL;

	reprs = rcu_dereference(app->reprs[repr_type]);
	if (!reprs)
		return NULL;

	port >>= NFP_PHY_REPR_INDEX_SHIFT;
	if (port >= reprs->num_reprs)
		return NULL;

	return rcu_dereference(reprs->reprs[port]);
}

static int
nfp_sgw_repr_netdev_open(struct nfp_app *app, struct nfp_repr *repr)
{
	int err;

	err = nfp_flower_cmsg_portmod(repr, true, repr->netdev->mtu, false);
	if (err)
		return err;

	netif_tx_wake_all_queues(repr->netdev);

	return 0;
}

static int
nfp_sgw_repr_netdev_stop(struct nfp_app *app, struct nfp_repr *repr)
{
	netif_tx_disable(repr->netdev);

	return nfp_flower_cmsg_portmod(repr, false, repr->netdev->mtu, false);
}

static void
nfp_sgw_repr_netdev_clean(struct nfp_app *app, struct net_device *netdev)
{
	struct nfp_repr *repr = netdev_priv(netdev);

	kfree(repr->app_priv);
}

static void
nfp_sgw_repr_netdev_preclean(struct nfp_app *app, struct net_device *netdev)
{
	struct nfp_repr *repr = netdev_priv(netdev);
	struct nfp_flower_priv *priv = app->priv;
	atomic_t *replies = &priv->reify_replies;
	int err;

	atomic_set(replies, 0);
	err = nfp_flower_cmsg_portreify(repr, false);
	if (err) {
		nfp_warn(app->cpp, "Failed to notify firmware about repr destruction\n");
		return;
	}

	nfp_flower_wait_repr_reify(app, replies, 1);
}

static int
nfp_sgw_vnic_alloc(struct nfp_app *app, struct nfp_net *nn,
		   unsigned int id)
{
	if (id > 0) {
		nfp_warn(app->cpp, "SgwNIC doesn't support more than one data vNIC\n");
		goto err_invalid_port;
	}

	eth_hw_addr_random(nn->dp.netdev);
	netif_keep_dst(nn->dp.netdev);
	nn->vnic_no_name = true;

	return 0;

err_invalid_port:
	nn->port = nfp_port_alloc(app, NFP_PORT_INVALID, nn->dp.netdev);
	return PTR_ERR_OR_ZERO(nn->port);
}

static int
nfp_sgw_sync_feature_bits(struct nfp_app *app)
{
	struct nfp_flower_priv *app_priv = app->priv;
	int err;

	/* Tell the firmware of the host supported features. */
	err = nfp_rtsym_write_le(app->pf->rtbl, "_abi_flower_host_mask",
				 app_priv->flower_ext_feats |
				 NFP_FL_FEATS_HOST_ACK);
	if (!err)
		nfp_flower_wait_host_bit(app);
	else if (err != -ENOENT)
		return err;

	return 0;
}

static int
nfp_sgw_init(struct nfp_app *app)
{
	struct nfp_flower_priv *app_priv;
	struct nfp_pf *pf = app->pf;
	u64 version, features;
	int err;

	if (!pf->eth_tbl) {
		nfp_warn(app->cpp, "SgwNIC requires eth table\n");
		return -EINVAL;
	}

	if (!pf->mac_stats_bar) {
		nfp_warn(app->cpp, "SgwNIC requires mac_stats BAR\n");
		return -EINVAL;
	}

	if (!pf->vf_cfg_bar) {
		nfp_warn(app->cpp, "SgwNIC requires vf_cfg BAR\n");
		return -EINVAL;
	}

	version = nfp_rtsym_read_le(app->pf->rtbl, "hw_flower_version", &err);
	if (err) {
		nfp_warn(app->cpp, "SgwNIC requires hw_flower_version memory symbol\n");
		return err;
	}

	/* We need to ensure hardware has enough sgw capabilities. */
	if (version != NFP_SGW_ALLOWED_VER) {
		nfp_warn(app->cpp, "SgwNIC: unsupported firmware version\n");
		return -EINVAL;
	}

	app_priv = vzalloc(sizeof(*app_priv));
	if (!app_priv)
		return -ENOMEM;

	app->priv = app_priv;
	app_priv->app = app;
	skb_queue_head_init(&app_priv->cmsg_skbs_high);
	skb_queue_head_init(&app_priv->cmsg_skbs_low);
	INIT_WORK(&app_priv->cmsg_work, nfp_flower_cmsg_process_rx);
	init_waitqueue_head(&app_priv->reify_wait_queue);

	init_waitqueue_head(&app_priv->mtu_conf.wait_q);
	spin_lock_init(&app_priv->mtu_conf.lock);

	/* Extract the extra features supported by the firmware. */
	features = nfp_rtsym_read_le(app->pf->rtbl,
				     "_abi_flower_extra_features", &err);
	if (err)
		app_priv->flower_ext_feats = 0;
	else
		app_priv->flower_ext_feats = features & NFP_FL_FEATS_HOST;

	err = nfp_sgw_sync_feature_bits(app);
	if (err)
		goto err_cleanup;

	return 0;

err_cleanup:
	vfree(app->priv);
	return err;
}

static void
nfp_sgw_clean(struct nfp_app *app)
{
	struct nfp_flower_priv *app_priv = app->priv;

	skb_queue_purge(&app_priv->cmsg_skbs_high);
	skb_queue_purge(&app_priv->cmsg_skbs_low);
	flush_work(&app_priv->cmsg_work);

	vfree(app->priv);
	app->priv = NULL;
}

static int
nfp_sgw_check_mtu(struct nfp_app *app, struct net_device *netdev,
		  int new_mtu)
{
	struct nfp_flower_priv *app_priv;
	struct nfp_net *nn;

	if (nfp_netdev_is_nfp_net(netdev)) {
		nn = netdev_priv(netdev);
	} else {
		app_priv = app->priv;
		nn = app_priv->nn;
	}

	if (new_mtu < 68 || new_mtu > nn->max_mtu)
		return -EINVAL;

	return 0;
}

const struct nfp_app_type app_sgw = {
	.id		= NFP_APP_SGW_NIC,
	.name		= "sgw",

	.ctrl_cap_mask	= ~0U,
	.ctrl_has_meta	= true,

	.extra_cap	= nfp_sgw_extra_cap,

	.init		= nfp_sgw_init,
	.clean		= nfp_sgw_clean,

	.check_mtu	= nfp_sgw_check_mtu,
	.repr_change_mtu = nfp_flower_repr_change_mtu,

	.vnic_alloc	= nfp_sgw_vnic_alloc,

	.repr_preclean	= nfp_sgw_repr_netdev_preclean,
	.repr_clean	= nfp_sgw_repr_netdev_clean,

	.repr_open	= nfp_sgw_repr_netdev_open,
	.repr_stop	= nfp_sgw_repr_netdev_stop,

	.ctrl_msg_rx	= nfp_flower_cmsg_rx,

	.dev_get	= nfp_sgw_dev_get,
};
