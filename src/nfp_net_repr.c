// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright (C) 2017-2018 Netronome Systems, Inc. */

#include "nfpcore/kcompat.h"

#include <linux/etherdevice.h>
#include <linux/io-64-nonatomic-hi-lo.h>
#include <linux/lockdep.h>
#include <net/dst_metadata.h>

#include "nfpcore/nfp_cpp.h"
#include "nfpcore/nfp_nsp.h"
#include "nfpcore/nfp_nffw.h"
#include "flower/main.h"
#include "nfp_app.h"
#include "nfp_main.h"
#include "nfp_net.h"
#include "nfp_net_ctrl.h"
#include "nfp_net_repr.h"
#include "nfp_net_sriov.h"
#include "nfp_port.h"
#include "nfp_net_dp.h"

static bool
nfp_vnic_ring_idx_check(struct nfp_net *nn,
			u8 ridx, bool is_rx_ring)
{
	if (is_rx_ring && ridx < nn->dp.num_rx_rings)
		return true;

	if (!is_rx_ring && ridx < nn->dp.num_tx_rings)
		return true;

	return false;
}

static u8
nfp_vnic_ring_idx_alloc(struct nfp_net *nn, bool is_rx_ring)
{
	struct nfp_vnic_ring_hdl *ring_hdl;
	struct nfp_net_dp *dp = &nn->dp;
	u8 idx;

	ring_hdl = &dp->ring_rsc_hdl;

	if (is_rx_ring) {
		for (idx = 0; idx < nn->dp.num_rx_rings; idx++) {
			if (ring_hdl->rx_ring_used[idx] == 0) {
				ring_hdl->rx_ring_used[idx] = 1;
				return idx;
			}
		}
		return NFP_NET_MAX_RX_RINGS;
	} else {
		for (idx = 0; idx < nn->dp.num_tx_rings; idx++) {
			if (ring_hdl->tx_ring_used[idx] == 0) {
				ring_hdl->tx_ring_used[idx] = 1;
				return idx;
			}
		}
		return NFP_NET_MAX_TX_RINGS;
	}
}

static void
nfp_vnic_ring_idx_free(struct nfp_net *nn,
		       bool is_rx_ring, u8 idx)
{
	struct nfp_vnic_ring_hdl *ring_hdl;
	struct nfp_net_dp *dp = &nn->dp;

	ring_hdl = &dp->ring_rsc_hdl;

	if (is_rx_ring)
		ring_hdl->rx_ring_used[idx] = 0;
	else
		ring_hdl->tx_ring_used[idx] = 0;
}

static int
nfp_repr_rx_ring_alloc(struct nfp_net *nn,
		       struct nfp_net_rx_ring **r, u8 *ridx,
		       struct net_device *netdev)
{
	struct nfp_net_rx_ring *rx_ring;
	int ret;
	u8 idx;

	idx = nfp_vnic_ring_idx_alloc(nn, true);
	if (!nfp_vnic_ring_idx_check(nn, idx, true)) {
		ret = -EINVAL;
		goto out;
	}

	rx_ring = &nn->dp.rx_rings[idx];
	rx_ring->netdev = netdev;
	nfp_net_rx_ring_init(rx_ring, &nn->r_vecs[idx], idx);

	ret = nfp_net_rx_ring_alloc(&nn->dp, rx_ring);
	if (ret)
		goto free_ring_idx;

	ret = nfp_net_rx_ring_bufs_alloc(&nn->dp, rx_ring);
	if (ret)
		goto free_ring_buf;

	*r = rx_ring;
	*ridx = idx;

	return 0;

free_ring_buf:
	nfp_net_rx_ring_bufs_free(&nn->dp, rx_ring);
	nfp_net_rx_ring_free(rx_ring);
free_ring_idx:
	nfp_vnic_ring_idx_free(nn, true, idx);
out:
	return ret;
}

static void
nfp_repr_rx_ring_free(struct nfp_net *nn, u8 ridx)
{
	struct nfp_net_rx_ring *rx_ring;

	if (!nfp_vnic_ring_idx_check(nn, ridx, true))
		return;

	rx_ring = &nn->dp.rx_rings[ridx];
	nfp_net_rx_ring_bufs_free(&nn->dp, rx_ring);
	nfp_net_rx_ring_free(rx_ring);

	nfp_vnic_ring_idx_free(nn, true, ridx);
}

static int
nfp_repr_tx_ring_alloc(struct nfp_net *nn,
		       struct nfp_net_tx_ring **r, u8 *ridx,
		       struct net_device *netdev)
{
	struct nfp_net_tx_ring *tx_ring;
	int bias = 0;
	int ret;
	u8 idx;

	idx = nfp_vnic_ring_idx_alloc(nn, false);
	if (!nfp_vnic_ring_idx_check(nn, idx, false)) {
		ret = -EINVAL;
		goto out;
	}

	if (idx >= nn->dp.num_stack_tx_rings)
		bias = nn->dp.num_stack_tx_rings;

	tx_ring = &nn->dp.tx_rings[idx];
	tx_ring->netdev = netdev;
	nfp_net_tx_ring_init(tx_ring, &nn->dp,
			     &nn->r_vecs[idx - bias], idx, bias);

	ret = nfp_net_tx_ring_alloc(&nn->dp, tx_ring);
	if (ret)
		goto free_ring_idx;

	ret = nfp_net_tx_ring_bufs_alloc(&nn->dp, tx_ring);
	if (ret)
		goto free_ring_buf;

	*r = tx_ring;
	*ridx = idx;

	return 0;

free_ring_buf:
	nfp_net_tx_ring_bufs_free(&nn->dp, tx_ring);
	nfp_net_tx_ring_free(&nn->dp, tx_ring);
free_ring_idx:
	nfp_vnic_ring_idx_free(nn, false, idx);
out:
	return ret;
}

static void
nfp_repr_tx_ring_free(struct nfp_net *nn, u8 ridx)
{
	struct nfp_net_tx_ring *tx_ring;

	if (!nfp_vnic_ring_idx_check(nn, ridx, false))
		return;

	tx_ring = &nn->dp.tx_rings[ridx];
	nfp_net_tx_ring_bufs_free(&nn->dp, tx_ring);
	nfp_net_tx_ring_free(&nn->dp, tx_ring);

	nfp_vnic_ring_idx_free(nn, false, ridx);
}

static int
nfp_repr_queue_to_port_set(struct nfp_repr *repr)
{
	const struct nfp_rtsym *queue_to_port_mem;
	struct nfp_flower_priv *app_priv;
	struct nfp_app *app = repr->app;
	struct nfp_net_tx_ring *tx_ring;
	u32 offset, i, j, phy_port;
	struct nfp_net *nn;

	const char *qp_island[3] = {
		"i32.QUEUE_TO_PORT_TABLE",
		"i33.QUEUE_TO_PORT_TABLE",
		"i34.QUEUE_TO_PORT_TABLE"
	};

	app_priv = (struct nfp_flower_priv *)repr->app->priv;
	nn = app_priv->nn;

	phy_port = nfp_flower_cmsg_phys_port(repr->port->eth_id);

	for (i = 0; i < ARRAY_SIZE(qp_island); i++) {
		queue_to_port_mem = nfp_rtsym_lookup(app->pf->rtbl,
						     qp_island[i]);
		if (!queue_to_port_mem) {
			nn_err(nn, "can't found %s\n", qp_island[i]);
			return -ENOENT;
		}
		for (j = 0; j < repr->nb_tx_rings; j++) {
			tx_ring = repr->tx_rings[j];
			offset = tx_ring->idx << 2;
			nfp_rtsym_write(app->pf->cpp, queue_to_port_mem,
					offset, &phy_port, sizeof(phy_port));
		}
	}

	return 0;
}

static int
nfp_repr_rss_itbl_hw_update(struct nfp_repr *repr,
			    u8 *rss_data, u32 size)
{
	const struct nfp_rtsym *rss_sym_mem;
	struct nfp_app *app = repr->app;
	struct nfp_rtsym sym_mem_temp;
	u32 i, j, port_idx;
	u32 *data, temp;

	const char *island[3] = {
		"i32.rss_indir_local",
		"i33.rss_indir_local",
		"i34.rss_indir_local"
	};

	if (size != NFP_NET_CFG_RSS_ITBL_SZ)
		return -EINVAL;

	port_idx = repr->port->eth_id;

	for (j = 0; j < ARRAY_SIZE(island); j++) {
		rss_sym_mem = nfp_rtsym_lookup(app->pf->rtbl, island[j]);
		if (!rss_sym_mem)
			return -ENOENT;

		data = (u32 *)rss_data;
		memcpy(&sym_mem_temp, rss_sym_mem, sizeof(struct nfp_rtsym));
		sym_mem_temp.addr += (port_idx * NFP_NET_CFG_RSS_ITBL_SZ);
		for (i = 0; i < (size >> 2); i++) {
			temp = cpu_to_be32(data[i]);
			nfp_rtsym_write(app->pf->cpp, &sym_mem_temp,
					(i << 2), &temp, sizeof(temp));
		}
	}

	return 0;
}

static int
nfp_repr_rss_idtl_update(struct nfp_repr *repr)
{
	u8 rss_reta[NFP_NET_CFG_RSS_ITBL_SZ];
	u32 base;
	u8 i, j;

	base = NFP_NET_TOTAL_QUEUE_NUM - NFP_NET_MAX_RX_RINGS;

	for (i = 0, j = 0; i < sizeof(rss_reta); i++) {
		rss_reta[i] = repr->vnic_rx_ring_map[j] + base;
		repr->reta[i] = j;
		j++;
		if (j == repr->nb_rx_rings)
			j = 0;
	}

	return nfp_repr_rss_itbl_hw_update(repr, rss_reta, sizeof(rss_reta));
}

static void
nfp_repr_rx_ring_enable(struct nfp_net *nn,
			struct nfp_repr *repr)
{
	struct nfp_net_rx_ring *rx_ring;
	u64 enable_rings = 0;
	u8 ridx;

	enable_rings = nn_readq(nn, NFP_NET_CFG_RXRS_ENABLE);
	for (ridx = 0; ridx < repr->nb_rx_rings; ridx++) {
		rx_ring = repr->rx_rings[ridx];
		enable_rings |= (1ULL << rx_ring->idx);
	}
	nn_writeq(nn, NFP_NET_CFG_RXRS_ENABLE, enable_rings);
}

static void
nfp_repr_rx_ring_disable(struct nfp_net *nn,
			 struct nfp_repr *repr)
{
	struct nfp_net_rx_ring *rx_ring;
	u64 enable_rings = 0;
	u8 ridx;

	enable_rings = nn_readq(nn, NFP_NET_CFG_RXRS_ENABLE);
	for (ridx = 0; ridx < repr->nb_rx_rings; ridx++) {
		rx_ring = repr->rx_rings[ridx];
		enable_rings &= (~(1ULL << rx_ring->idx));
	}
	nn_writeq(nn, NFP_NET_CFG_RXRS_ENABLE, enable_rings);
}

static void
nfp_repr_tx_ring_enable(struct nfp_net *nn,
			struct nfp_repr *repr)
{
	struct nfp_net_tx_ring *tx_ring;
	u64 enable_rings = 0;
	u8 ridx;

	enable_rings = nn_readq(nn, NFP_NET_CFG_TXRS_ENABLE);
	for (ridx = 0; ridx < repr->nb_tx_rings; ridx++) {
		tx_ring = repr->tx_rings[ridx];
		enable_rings |= (1ULL << tx_ring->idx);
	}
	nn_writeq(nn, NFP_NET_CFG_TXRS_ENABLE, enable_rings);
}

static void
nfp_repr_tx_ring_disable(struct nfp_net *nn,
			 struct nfp_repr *repr)
{
	struct nfp_net_tx_ring *tx_ring;
	u64 enable_rings = 0;
	u8 ridx;

	enable_rings = nn_readq(nn, NFP_NET_CFG_TXRS_ENABLE);
	for (ridx = 0; ridx < repr->nb_tx_rings; ridx++) {
		tx_ring = repr->tx_rings[ridx];
		enable_rings &= (~(1ULL << tx_ring->idx));
	}
	nn_writeq(nn, NFP_NET_CFG_TXRS_ENABLE, enable_rings);
}

static void
nfp_net_repr_set_config_and_enable(struct nfp_net *nn,
				   struct nfp_repr *repr)
{
	struct nfp_net_rx_ring *rx_ring;
	struct nfp_net_tx_ring *tx_ring;
	u8 ridx;

	for (ridx = 0; ridx < repr->nb_rx_rings; ridx++) {
		rx_ring = repr->rx_rings[ridx];
		nfp_net_rx_ring_hw_cfg_write(nn, rx_ring, rx_ring->idx);
	}
	nfp_repr_rss_idtl_update(repr);
	nfp_repr_rx_ring_enable(nn, repr);

	for (ridx = 0; ridx < repr->nb_tx_rings; ridx++) {
		tx_ring = repr->tx_rings[ridx];
		nfp_net_tx_ring_hw_cfg_write(nn, tx_ring, tx_ring->idx);
	}
	nfp_repr_queue_to_port_set(repr);
	nfp_repr_tx_ring_enable(nn, repr);
}

static void
nfp_net_repr_rx_rings_fill_freelist(struct nfp_net *nn,
				    struct nfp_repr *repr)
{
	struct nfp_net_rx_ring *rx_ring;
	u8 ridx;

	for (ridx = 0; ridx < repr->nb_rx_rings; ridx++) {
		rx_ring = repr->rx_rings[ridx];
		nfp_net_rx_ring_fill_freelist(&nn->dp, rx_ring);
	}
}

struct net_device *
nfp_repr_get_locked(struct nfp_app *app, struct nfp_reprs *set, unsigned int id)
{
	return rcu_dereference_protected(set->reprs[id],
					 nfp_app_is_locked(app));
}

static void
nfp_repr_inc_tx_stats(struct net_device *netdev, unsigned int len,
		      int tx_status)
{
	struct nfp_repr *repr = netdev_priv(netdev);
	struct nfp_repr_pcpu_stats *stats;

	if (unlikely(tx_status != NET_XMIT_SUCCESS &&
		     tx_status != NET_XMIT_CN)) {
		this_cpu_inc(repr->stats->tx_drops);
		return;
	}

	stats = this_cpu_ptr(repr->stats);
	u64_stats_update_begin(&stats->syncp);
	stats->tx_packets++;
	stats->tx_bytes += len;
	u64_stats_update_end(&stats->syncp);
}

void nfp_repr_inc_rx_stats(struct net_device *netdev, unsigned int len)
{
	struct nfp_repr *repr = netdev_priv(netdev);
	struct nfp_repr_pcpu_stats *stats;

	stats = this_cpu_ptr(repr->stats);
	u64_stats_update_begin(&stats->syncp);
	stats->rx_packets++;
	stats->rx_bytes += len;
	u64_stats_update_end(&stats->syncp);
}

static void
nfp_repr_phy_port_get_stats64(struct nfp_port *port,
			      struct rtnl_link_stats64 *stats)
{
	u8 __iomem *mem = port->eth_stats;

	stats->tx_packets = readq(mem + NFP_MAC_STATS_TX_FRAMES_TRANSMITTED_OK);
	stats->tx_bytes = readq(mem + NFP_MAC_STATS_TX_OUT_OCTETS);
	stats->tx_dropped = readq(mem + NFP_MAC_STATS_TX_OUT_ERRORS);

	stats->rx_packets = readq(mem + NFP_MAC_STATS_RX_FRAMES_RECEIVED_OK);
	stats->rx_bytes = readq(mem + NFP_MAC_STATS_RX_IN_OCTETS);
	stats->rx_dropped = readq(mem + NFP_MAC_STATS_RX_IN_ERRORS);
}

static void
nfp_repr_vnic_get_stats64(struct nfp_port *port,
			  struct rtnl_link_stats64 *stats)
{
	/* TX and RX stats are flipped as we are returning the stats as seen
	 * at the switch port corresponding to the VF.
	 */
	stats->tx_packets = readq(port->vnic + NFP_NET_CFG_STATS_RX_FRAMES);
	stats->tx_bytes = readq(port->vnic + NFP_NET_CFG_STATS_RX_OCTETS);
	stats->tx_dropped = readq(port->vnic + NFP_NET_CFG_STATS_RX_DISCARDS);

	stats->rx_packets = readq(port->vnic + NFP_NET_CFG_STATS_TX_FRAMES);
	stats->rx_bytes = readq(port->vnic + NFP_NET_CFG_STATS_TX_OCTETS);
	stats->rx_dropped = readq(port->vnic + NFP_NET_CFG_STATS_TX_DISCARDS);
}

static compat__stat64_ret_t
nfp_repr_get_stats64(struct net_device *netdev, struct rtnl_link_stats64 *stats)
{
	struct nfp_repr *repr = netdev_priv(netdev);

	if (WARN_ON(!repr->port))
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 11, 0)
		return stats;
#else
		return;
#endif

	switch (repr->port->type) {
	case NFP_PORT_PHYS_PORT:
		if (!__nfp_port_get_eth_port(repr->port))
			break;
		nfp_repr_phy_port_get_stats64(repr->port, stats);
		break;
	case NFP_PORT_PF_PORT:
	case NFP_PORT_VF_PORT:
		nfp_repr_vnic_get_stats64(repr->port, stats);
		break;
	default:
		break;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 11, 0)
	return stats;
#endif
}

static bool
nfp_repr_has_offload_stats(const struct net_device *dev, int attr_id)
{
	switch (attr_id) {
	case IFLA_OFFLOAD_XSTATS_CPU_HIT:
		return true;
	}

	return false;
}

static int
nfp_repr_get_host_stats64(const struct net_device *netdev,
			  struct rtnl_link_stats64 *stats)
{
	struct nfp_repr *repr = netdev_priv(netdev);
	int i;

	for_each_possible_cpu(i) {
		u64 tbytes, tpkts, tdrops, rbytes, rpkts;
		struct nfp_repr_pcpu_stats *repr_stats;
		unsigned int start;

		repr_stats = per_cpu_ptr(repr->stats, i);
		do {
			start = u64_stats_fetch_begin_irq(&repr_stats->syncp);
			tbytes = repr_stats->tx_bytes;
			tpkts = repr_stats->tx_packets;
			tdrops = repr_stats->tx_drops;
			rbytes = repr_stats->rx_bytes;
			rpkts = repr_stats->rx_packets;
		} while (u64_stats_fetch_retry_irq(&repr_stats->syncp, start));

		stats->tx_bytes += tbytes;
		stats->tx_packets += tpkts;
		stats->tx_dropped += tdrops;
		stats->rx_bytes += rbytes;
		stats->rx_packets += rpkts;
	}

	return 0;
}

static int
nfp_repr_get_offload_stats(int attr_id, const struct net_device *dev,
			   void *stats)
{
	switch (attr_id) {
	case IFLA_OFFLOAD_XSTATS_CPU_HIT:
		return nfp_repr_get_host_stats64(dev, stats);
	}

	return -EINVAL;
}

static int nfp_repr_change_mtu(struct net_device *netdev, int new_mtu)
{
	struct nfp_repr *repr = netdev_priv(netdev);
	int err;

	err = nfp_app_check_mtu(repr->app, netdev, new_mtu);
	if (err)
		return err;

	err = nfp_app_repr_change_mtu(repr->app, netdev, new_mtu);
	if (err)
		return err;

	netdev->mtu = new_mtu;

	return 0;
}

static netdev_tx_t nfp_repr_xmit(struct sk_buff *skb, struct net_device *netdev)
{
	struct nfp_repr *repr = netdev_priv(netdev);
	unsigned int len = skb->len;
	int ret;

	skb_dst_drop(skb);
	dst_hold((struct dst_entry *)repr->dst);
	skb_dst_set(skb, (struct dst_entry *)repr->dst);
	skb->dev = repr->dst->u.port_info.lower_dev;

	ret = dev_queue_xmit(skb);
	nfp_repr_inc_tx_stats(netdev, len, ret);

	return NETDEV_TX_OK;
}

netdev_tx_t
nfp_sgw_repr_xmit(struct sk_buff *skb, struct net_device *netdev)
{
	struct nfp_repr *repr = netdev_priv(netdev);
	struct nfp_flower_priv *app_priv;
	struct net_device *pf_netdev;
	unsigned int len = skb->len;
	u16 repr_ridx, vnic_ridx;
	struct nfp_net *nn;
	int ret;

	app_priv = (struct nfp_flower_priv *)repr->app->priv;
	nn = app_priv->nn;

	skb_dst_drop(skb);
	dst_hold((struct dst_entry *)repr->dst);
	skb_dst_set(skb, (struct dst_entry *)repr->dst);
	pf_netdev = repr->dst->u.port_info.lower_dev;

	repr_ridx = skb_get_queue_mapping(skb);
	vnic_ridx = repr->vnic_tx_ring_map[repr_ridx];
	skb_set_queue_mapping(skb, vnic_ridx);

	spin_lock(&repr->xmit_lock[repr_ridx]);
	ret = nn->dp.ops->xmit(skb, pf_netdev);
	spin_unlock(&repr->xmit_lock[repr_ridx]);

	nfp_repr_inc_tx_stats(netdev, len, ret);

	return NETDEV_TX_OK;
}

static void
nfp_repr_close_stack(struct nfp_repr *repr)
{
	struct nfp_net_rx_ring *rx_ring;
	struct nfp_net_tx_ring *tx_ring;
	struct nfp_net_r_vector *r_vec;
	u8 i;

	netif_carrier_off(repr->netdev);
	for (i = 0; i < repr->nb_rx_rings; i++) {
		rx_ring = repr->rx_rings[i];
		r_vec = rx_ring->r_vec;

		disable_irq(r_vec->irq_vector);
		napi_disable(&r_vec->napi);
#ifdef COMPAT_HAVE_DIM
		if (r_vec->rx_ring)
			cancel_work_sync(&r_vec->rx_dim.work);
#endif
	}
	for (i = 0; i < repr->nb_tx_rings; i++) {
		tx_ring = repr->tx_rings[i];
		r_vec = tx_ring->r_vec;

#ifdef COMPAT_HAVE_DIM
		if (r_vec->tx_ring)
			cancel_work_sync(&r_vec->tx_dim.work);
#endif
	}
	netif_tx_disable(repr->netdev);
}

/**
 * nfp_net_repr_reconfig() - Write control BAR and enable NFP
 * @nn:      NFP Net device to reconfigure
 */
static int
nfp_net_repr_reconfig(struct nfp_net *nn)
{
	u32 new_ctrl, update = 0;
	int err;

	new_ctrl = nn->dp.ctrl;

	/* Enable device */
	update |= NFP_NET_CFG_UPDATE_GEN;
	update |= NFP_NET_CFG_UPDATE_MSIX;
	update |= NFP_NET_CFG_UPDATE_RING;
	if (nn->cap & NFP_NET_CFG_CTRL_RINGCFG)
		new_ctrl |= NFP_NET_CFG_CTRL_RINGCFG;

	nn_writel(nn, NFP_NET_CFG_CTRL, new_ctrl);
	nn_writel(nn, NFP_NET_CFG_CTRL_WORD1, nn->dp.ctrl_w1);
	err = nfp_net_reconfig(nn, update);
	if (err) {
		nn_err(nn, "Failed to call nfp_net_reconfig, new_ctrl 0x%x update 0x%x (err=%d).\n",
		       new_ctrl, update, err);
		return err;
	}

	nn->dp.ctrl = new_ctrl;

	return 0;
}

static void
nfp_repr_ring_clear_config(struct nfp_net *nn,
			   struct nfp_repr *repr)
{
	struct nfp_net_rx_ring *rx_ring;
	struct nfp_net_tx_ring *tx_ring;
	u8 i;

	nfp_repr_tx_ring_disable(nn, repr);
	nfp_repr_rx_ring_disable(nn, repr);

	nfp_net_repr_reconfig(nn);

	for (i = 0; i < repr->nb_rx_rings; i++) {
		rx_ring = repr->rx_rings[i];
		nfp_net_rx_ring_reset(rx_ring);
		nfp_net_clear_rx_ring_hw_cfg(nn, rx_ring->idx);
	}
	for (i = 0; i < repr->nb_tx_rings; i++) {
		tx_ring = repr->tx_rings[i];
		nfp_net_tx_ring_reset(&nn->dp, tx_ring);
		nfp_net_clear_tx_ring_hw_cfg(nn, tx_ring->idx);
	}
}

static void
nfp_repr_close_free_all(struct nfp_net *nn,
			struct nfp_repr *repr)
{
	struct nfp_net_rx_ring *rx_ring;
	struct nfp_net_tx_ring *tx_ring;
	u8 i, ridx;

	for (i = 0; i < repr->nb_rx_rings; i++) {
		rx_ring = repr->rx_rings[i];
		ridx = rx_ring->idx;
		nfp_repr_rx_ring_free(nn, ridx);
		repr->rx_rings[i] = NULL;
		repr->vnic_rx_ring_map[i] = NFP_NET_MAX_RX_RINGS;
		nfp_net_cleanup_vector(nn, &nn->r_vecs[ridx]);
		nn->r_vecs[ridx].rx_ring = NULL;
	}
	for (i = 0; i < repr->nb_tx_rings; i++) {
		tx_ring = repr->tx_rings[i];
		ridx = tx_ring->idx;
		nfp_repr_tx_ring_free(nn, ridx);
		repr->tx_rings[i] = NULL;
		repr->vnic_tx_ring_map[i] = NFP_NET_MAX_TX_RINGS;
		nn->r_vecs[ridx].tx_ring = NULL;
	}
}

static int nfp_repr_stop(struct net_device *netdev)
{
	struct nfp_repr *repr = netdev_priv(netdev);
	int err;

	err = nfp_app_repr_stop(repr->app, repr);
	if (err)
		return err;

	nfp_port_configure(netdev, false);

	return 0;
}

int
nfp_sgw_repr_stop(struct net_device *netdev)
{
	struct nfp_repr *repr = netdev_priv(netdev);
	struct nfp_flower_priv *app_priv;
	struct nfp_net *nn;
	int err;

	app_priv = (struct nfp_flower_priv *)repr->app->priv;
	nn = app_priv->nn;

	if (repr->port->type != NFP_PORT_PHYS_PORT) {
		nn_dbg(nn, "vnic repr %s down", netdev->name);
		return 0;
	}

	/* Step 1: Disable RX and TX rings from the Linux kernel perspective
	 */
	nfp_repr_close_stack(repr);

	/* Step 2: Tell NFP
	 */
	nfp_repr_ring_clear_config(nn, repr);
	nfp_port_configure(netdev, false);
	err = nfp_app_repr_stop(repr->app, repr);
	if (err)
		return err;

	/* Step 3: Free resources
	 */
	nfp_repr_close_free_all(nn, repr);
	nn_dbg(nn, "phy repr %s down", netdev->name);

	return 0;
}

static void
nfp_repr_open_stack(struct nfp_repr *repr)
{
	struct nfp_net_rx_ring *rx_ring;
	struct nfp_net_tx_ring *tx_ring;
	struct nfp_net_r_vector *r_vec;
	u8 i;

	for (i = 0; i < repr->nb_rx_rings; i++) {
		rx_ring = repr->rx_rings[i];
		r_vec = rx_ring->r_vec;
#ifdef COMPAT_HAVE_DIM
		if (r_vec->rx_ring) {
			INIT_WORK(&r_vec->rx_dim.work, nfp_net_rx_dim_work);
			r_vec->rx_dim.mode = DIM_CQ_PERIOD_MODE_START_FROM_EQE;
		}
#endif
		napi_enable(&r_vec->napi);
		enable_irq(r_vec->irq_vector);
	}
	for (i = 0; i < repr->nb_tx_rings; i++) {
		tx_ring = repr->tx_rings[i];
		r_vec = tx_ring->r_vec;
#ifdef COMPAT_HAVE_DIM
		if (r_vec->tx_ring) {
			INIT_WORK(&r_vec->tx_dim.work, nfp_net_tx_dim_work);
			r_vec->tx_dim.mode = DIM_CQ_PERIOD_MODE_START_FROM_EQE;
		}
#endif
	}
	netif_tx_wake_all_queues(repr->netdev);
}

static void
nfp_repr_vector_assign_rx_ring(struct nfp_net_dp *dp,
			       struct nfp_net_r_vector *r_vec, int idx)
{
	r_vec->rx_ring = idx < dp->num_rx_rings ? &dp->rx_rings[idx] : NULL;
}

static void
nfp_repr_vector_assign_tx_ring(struct nfp_net_dp *dp,
			       struct nfp_net_r_vector *r_vec, int idx)
{
	r_vec->tx_ring =
		idx < dp->num_stack_tx_rings ? &dp->tx_rings[idx] : NULL;
}

static int nfp_repr_open(struct net_device *netdev)
{
	struct nfp_repr *repr = netdev_priv(netdev);
	int err;

	err = nfp_port_configure(netdev, true);
	if (err)
		return err;

	err = nfp_app_repr_open(repr->app, repr);
	if (err)
		goto err_port_disable;

	return 0;

err_port_disable:
	nfp_port_configure(netdev, false);
	return err;
}

int
nfp_sgw_repr_open(struct net_device *netdev)
{
	struct nfp_repr *repr = netdev_priv(netdev);
	u8 i, j, k, v, ridx = NFP_NET_MAX_RX_RINGS;
	struct nfp_flower_priv *app_priv;
	struct nfp_net_rx_ring *rx_ring;
	struct nfp_net_tx_ring *tx_ring;
	struct nfp_net *nn;
	int err;

	if (repr->port->type != NFP_PORT_PHYS_PORT)
		return 0;

	app_priv = (struct nfp_flower_priv *)repr->app->priv;
	nn = app_priv->nn;

	/* Step 1: Allocate resources for rings and the like
	 * - Request interrupts
	 * - Allocate RX and TX ring resources
	 * - Setup initial RSS table
	 */
	for (j = 0; j < repr->nb_tx_rings; j++) {
		err = nfp_repr_tx_ring_alloc(nn, &tx_ring, &ridx, netdev);
		if (err)
			goto err_tx_ring_alloc;

		tx_ring->repr_ridx = j;
		repr->tx_rings[j] = tx_ring;
		repr->vnic_tx_ring_map[j] = ridx;
	}

	for (i = 0; i < repr->nb_rx_rings; i++) {
		err = nfp_repr_rx_ring_alloc(nn, &rx_ring, &ridx, netdev);
		if (err)
			goto err_rx_ring_alloc;

		rx_ring->repr_ridx = i;
		repr->rx_rings[i] = rx_ring;
		repr->vnic_rx_ring_map[i] = ridx;
	}

	for (v = 0; v < repr->nb_rx_rings; v++) {
		ridx = repr->vnic_rx_ring_map[v];
		err = nfp_net_prepare_vector(nn, &nn->r_vecs[ridx], ridx);
		if (err)
			goto err_vector_prepare;
	}

	for (k = 0; k < repr->nb_rx_rings; k++) {
		ridx = repr->vnic_rx_ring_map[k];
		nfp_repr_vector_assign_rx_ring(&nn->dp,
					       &nn->r_vecs[ridx], ridx);
	}

	for (k = 0; k < repr->nb_tx_rings; k++) {
		ridx = repr->vnic_tx_ring_map[k];
		nfp_repr_vector_assign_tx_ring(&nn->dp,
					       &nn->r_vecs[ridx], ridx);
	}

	err = netif_set_real_num_tx_queues(netdev, repr->nb_tx_rings);
	if (err)
		goto err_vector_prepare;

	err = netif_set_real_num_rx_queues(netdev, repr->nb_rx_rings);
	if (err)
		goto err_vector_prepare;

	/* Step 2: Configure the NFP
	 * - Ifup the physical interface if it exists
	 * - Enable rings from 0 to tx_rings/rx_rings - 1.
	 * - Write MAC address (in case it changed)
	 * - Set the MTU
	 * - Set the Freelist buffer size
	 * - Enable the FW
	 */
	err = nfp_port_configure(netdev, true);
	if (err)
		return err;

	err = nfp_app_repr_open(repr->app, repr);
	if (err)
		goto err_port_disable;

	nfp_net_repr_set_config_and_enable(nn, repr);

	nfp_net_repr_reconfig(nn);

	nfp_net_repr_rx_rings_fill_freelist(nn, repr);

	/* Step 3: Enable for kernel
	 * - put some freelist descriptors on each RX ring
	 * - enable NAPI on each ring
	 * - enable all TX queues
	 * - set link state
	 */
	nfp_repr_open_stack(repr);
	nn_dbg(nn, "phy repr %s up", netdev->name);

	return 0;

err_port_disable:
	nfp_port_configure(netdev, false);
err_vector_prepare:
	for (k = 0; k < v; k++) {
		ridx = repr->vnic_rx_ring_map[k];
		nfp_net_cleanup_vector(nn, &nn->r_vecs[ridx]);
	}
err_rx_ring_alloc:
	for (k = 0; k < i; k++) {
		ridx = repr->vnic_rx_ring_map[k];
		nfp_repr_rx_ring_free(nn, ridx);
		repr->rx_rings[k] = NULL;
		repr->vnic_rx_ring_map[k] = NFP_NET_MAX_RX_RINGS;
	}
err_tx_ring_alloc:
	for (k = 0; k < j; k++) {
		ridx = repr->vnic_tx_ring_map[k];
		nfp_repr_tx_ring_free(nn, ridx);
		repr->tx_rings[k] = NULL;
		repr->vnic_tx_ring_map[k] = NFP_NET_MAX_TX_RINGS;
	}

	return err;
}

static netdev_features_t
nfp_repr_fix_features(struct net_device *netdev, netdev_features_t features)
{
	struct nfp_repr *repr = netdev_priv(netdev);
	netdev_features_t old_features = features;
	netdev_features_t lower_features;
	struct net_device *lower_dev;

	lower_dev = repr->dst->u.port_info.lower_dev;

	lower_features = lower_dev->features;
	if (lower_features & (NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM))
		lower_features |= NETIF_F_HW_CSUM;

	features = netdev_intersect_features(features, lower_features);
	features |= old_features & (NETIF_F_SOFT_FEATURES | NETIF_F_HW_TC);
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 12, 0)
	features |= NETIF_F_LLTX;
#endif

	return features;
}

const struct net_device_ops nfp_repr_netdev_ops = {
	.ndo_init		= nfp_app_ndo_init,
	.ndo_uninit		= nfp_app_ndo_uninit,
	.ndo_open		= nfp_repr_open,
	.ndo_stop		= nfp_repr_stop,
	.ndo_start_xmit		= nfp_repr_xmit,
	.ndo_change_mtu		= nfp_repr_change_mtu,
	.ndo_get_stats64	= nfp_repr_get_stats64,
	.ndo_has_offload_stats	= nfp_repr_has_offload_stats,
	.ndo_get_offload_stats	= nfp_repr_get_offload_stats,
	.ndo_get_phys_port_name	= nfp_port_get_phys_port_name,
	.ndo_setup_tc		= nfp_port_setup_tc,
	.ndo_set_vf_mac		= nfp_app_set_vf_mac,
	.ndo_set_vf_vlan	= nfp_app_set_vf_vlan,
	.ndo_set_vf_spoofchk	= nfp_app_set_vf_spoofchk,
	.ndo_set_vf_trust	= nfp_app_set_vf_trust,
	.ndo_get_vf_config	= nfp_app_get_vf_config,
	.ndo_set_vf_link_state	= nfp_app_set_vf_link_state,
	.ndo_fix_features	= nfp_repr_fix_features,
	.ndo_set_features	= nfp_port_set_features,
	.ndo_set_mac_address    = eth_mac_addr,
#if VER_NON_RHEL_GE(5, 1) || VER_RHEL_GE(8, 2)
	.ndo_get_port_parent_id	= nfp_port_get_port_parent_id,
#if VER_NON_RHEL_LT(5, 2) || VER_RHEL_LT(8, 2)
	.ndo_get_devlink	= nfp_devlink_get_devlink,
#elif VER_NON_RHEL_LT(6, 2)
	.ndo_get_devlink_port	= nfp_devlink_get_devlink_port,
#endif
#endif
};

const struct net_device_ops nfp_sgw_repr_netdev_ops = {
};

void
nfp_repr_transfer_features(struct net_device *netdev, struct net_device *lower)
{
	struct nfp_repr *repr = netdev_priv(netdev);

	if (repr->dst->u.port_info.lower_dev != lower)
		return;

	netif_inherit_tso_max(netdev, lower);

	netdev_update_features(netdev);
}

static void nfp_repr_clean(struct nfp_repr *repr)
{
	unregister_netdev(repr->netdev);
	if (nfp_devlink_is_port_registered(repr->port)) {
#if (VER_NON_RHEL_LT(6, 2)) || (RHEL_RELEASE_LT(9, 305, 0, 0))
		nfp_devlink_port_type_clear(repr->port);
#endif
		nfp_devlink_port_unregister(repr->port);
	}
	nfp_app_repr_clean(repr->app, repr->netdev);
	dst_release((struct dst_entry *)repr->dst);
	nfp_port_free(repr->port);
}

static struct lock_class_key nfp_repr_netdev_xmit_lock_key;
static struct lock_class_key nfp_repr_netdev_addr_lock_key;

static void nfp_repr_set_lockdep_class_one(struct net_device *dev,
					   struct netdev_queue *txq,
					   void *_unused)
{
	lockdep_set_class(&txq->_xmit_lock, &nfp_repr_netdev_xmit_lock_key);
}

static void nfp_repr_set_lockdep_class(struct net_device *dev)
{
	lockdep_set_class(&dev->addr_list_lock, &nfp_repr_netdev_addr_lock_key);
	netdev_for_each_tx_queue(dev, nfp_repr_set_lockdep_class_one, NULL);
}

int nfp_repr_init(struct nfp_app *app, struct net_device *netdev,
		  u32 cmsg_port_id, struct nfp_port *port,
		  struct net_device *pf_netdev)
{
	struct nfp_repr *repr = netdev_priv(netdev);
	struct nfp_net *nn = netdev_priv(pf_netdev);
	u32 repr_cap = nn->tlv_caps.repr_cap;
	int err, i;

	nfp_repr_set_lockdep_class(netdev);

	repr->port = port;
	repr->dst = metadata_dst_alloc(0, METADATA_HW_PORT_MUX, GFP_KERNEL);
	if (!repr->dst)
		return -ENOMEM;
	repr->dst->u.port_info.port_id = cmsg_port_id;
	repr->dst->u.port_info.lower_dev = pf_netdev;

	if (nfp_app_is_sgw(app)) {
		for (i = 0; i < NFP_REPR_RING_NUM_MAX; i++)
			spin_lock_init(&repr->xmit_lock[i]);

		netdev->netdev_ops = &nfp_sgw_repr_netdev_ops;
	} else {
		netdev->netdev_ops = &nfp_repr_netdev_ops;
		netdev->ethtool_ops = &nfp_port_ethtool_ops;
	}

	netdev->max_mtu = pf_netdev->max_mtu;

#if VER_NON_RHEL_LT(5, 1) || VER_RHEL_LT(8, 2)
	SWITCHDEV_SET_OPS(netdev, &nfp_port_switchdev_ops);
#endif
	/* Set features the lower device can support with representors */
	if (repr_cap & NFP_NET_CFG_CTRL_LIVE_ADDR)
		netdev->priv_flags |= IFF_LIVE_ADDR_CHANGE;

	netdev->hw_features = NETIF_F_HIGHDMA;
	if (!nfp_app_is_sgw(app) && (repr_cap & NFP_NET_CFG_CTRL_RXCSUM_ANY))
		netdev->hw_features |= NETIF_F_RXCSUM;
	if (repr_cap & NFP_NET_CFG_CTRL_TXCSUM)
		netdev->hw_features |= NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM;
	if (repr_cap & NFP_NET_CFG_CTRL_GATHER)
		netdev->hw_features |= NETIF_F_SG;
	if ((repr_cap & NFP_NET_CFG_CTRL_LSO && nn->fw_ver.major > 2) ||
	    repr_cap & NFP_NET_CFG_CTRL_LSO2)
		netdev->hw_features |= NETIF_F_TSO | NETIF_F_TSO6;
	if (repr_cap & NFP_NET_CFG_CTRL_RSS_ANY)
		netdev->hw_features |= NETIF_F_RXHASH;
	if (repr_cap & NFP_NET_CFG_CTRL_VXLAN) {
		if (repr_cap & NFP_NET_CFG_CTRL_LSO)
			netdev->hw_features |= NETIF_F_GSO_UDP_TUNNEL;
	}
	if (repr_cap & NFP_NET_CFG_CTRL_NVGRE) {
		if (repr_cap & NFP_NET_CFG_CTRL_LSO)
			netdev->hw_features |= NETIF_F_GSO_GRE;
	}
	if (repr_cap & (NFP_NET_CFG_CTRL_VXLAN | NFP_NET_CFG_CTRL_NVGRE))
		netdev->hw_enc_features = netdev->hw_features;

	netdev->vlan_features = netdev->hw_features;

	if (repr_cap & NFP_NET_CFG_CTRL_RXVLAN_ANY)
		netdev->hw_features |= NETIF_F_HW_VLAN_CTAG_RX;
	if (repr_cap & NFP_NET_CFG_CTRL_TXVLAN_ANY) {
		if (repr_cap & NFP_NET_CFG_CTRL_LSO2)
			netdev_warn(netdev, "Device advertises both TSO2 and TXVLAN. Refusing to enable TXVLAN.\n");
		else
			netdev->hw_features |= NETIF_F_HW_VLAN_CTAG_TX;
	}
	if (repr_cap & NFP_NET_CFG_CTRL_CTAG_FILTER)
		netdev->hw_features |= NETIF_F_HW_VLAN_CTAG_FILTER;
	if (repr_cap & NFP_NET_CFG_CTRL_RXQINQ)
		netdev->hw_features |= NETIF_F_HW_VLAN_STAG_RX;

	netdev->features = netdev->hw_features;

	/* C-Tag strip and S-Tag strip can't be supported simultaneously,
	 * so enable C-Tag strip and disable S-Tag strip by default.
	 */
	netdev->features &= ~NETIF_F_HW_VLAN_STAG_RX;
	netif_set_tso_max_segs(netdev, NFP_NET_LSO_MAX_SEGS);

	netdev->priv_flags |= IFF_NO_QUEUE | IFF_DISABLE_NETPOLL;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
	netdev->lltx |= true;
#else
	netdev->features |= NETIF_F_LLTX;
#endif

	if (!nfp_app_is_sgw(app) && nfp_app_has_tc(app)) {
		netdev->features |= NETIF_F_HW_TC;
		netdev->hw_features |= NETIF_F_HW_TC;
	}

	err = nfp_app_repr_init(app, netdev);
	if (err)
		goto err_clean;

	err = register_netdev(netdev);
	if (err)
		goto err_repr_clean;

	return 0;

err_repr_clean:
	nfp_app_repr_clean(app, netdev);
err_clean:
	dst_release((struct dst_entry *)repr->dst);
	return err;
}

static void __nfp_repr_free(struct nfp_repr *repr)
{
	free_percpu(repr->stats);
	free_netdev(repr->netdev);
}

void nfp_repr_free(struct net_device *netdev)
{
	__nfp_repr_free(netdev_priv(netdev));
}

struct net_device *
nfp_repr_alloc_mqs(struct nfp_app *app, unsigned int txqs, unsigned int rxqs)
{
	struct net_device *netdev;
	struct nfp_repr *repr;

	netdev = alloc_etherdev_mqs(sizeof(*repr), txqs, rxqs);
	if (!netdev)
		return NULL;

	netif_carrier_off(netdev);

	repr = netdev_priv(netdev);
	repr->netdev = netdev;
	repr->app = app;

	repr->stats = netdev_alloc_pcpu_stats(struct nfp_repr_pcpu_stats);
	if (!repr->stats)
		goto err_free_netdev;

	return netdev;

err_free_netdev:
	free_netdev(netdev);
	return NULL;
}

void nfp_repr_clean_and_free(struct nfp_repr *repr)
{
	nfp_info(repr->app->cpp, "Destroying Representor(%s)\n",
		 repr->netdev->name);
	nfp_repr_clean(repr);
	__nfp_repr_free(repr);
}

void nfp_reprs_clean_and_free(struct nfp_app *app, struct nfp_reprs *reprs)
{
	struct net_device *netdev;
	unsigned int i;

	for (i = 0; i < reprs->num_reprs; i++) {
		netdev = nfp_repr_get_locked(app, reprs, i);
		if (netdev)
			nfp_repr_clean_and_free(netdev_priv(netdev));
	}

	kfree(reprs);
}

void
nfp_reprs_clean_and_free_by_type(struct nfp_app *app, enum nfp_repr_type type)
{
	struct net_device *netdev;
	struct nfp_reprs *reprs;
	int i;

	reprs = rcu_dereference_protected(app->reprs[type],
					  nfp_app_is_locked(app));
	if (!reprs)
		return;

	/* Preclean must happen before we remove the reprs reference from the
	 * app below.
	 */
	for (i = 0; i < reprs->num_reprs; i++) {
		netdev = nfp_repr_get_locked(app, reprs, i);
		if (netdev)
			nfp_app_repr_preclean(app, netdev);
	}

	reprs = nfp_app_reprs_set(app, type, NULL);

	synchronize_rcu();
	nfp_reprs_clean_and_free(app, reprs);
}

struct nfp_reprs *nfp_reprs_alloc(unsigned int num_reprs)
{
	struct nfp_reprs *reprs;

	reprs = kzalloc(struct_size(reprs, reprs, num_reprs), GFP_KERNEL);
	if (!reprs)
		return NULL;
	reprs->num_reprs = num_reprs;

	return reprs;
}

int nfp_reprs_resync_phys_ports(struct nfp_app *app)
{
	struct net_device *netdev;
	struct nfp_reprs *reprs;
	struct nfp_repr *repr;
	int i;

	reprs = nfp_reprs_get_locked(app, NFP_REPR_TYPE_PHYS_PORT);
	if (!reprs)
		return 0;

	for (i = 0; i < reprs->num_reprs; i++) {
		netdev = nfp_repr_get_locked(app, reprs, i);
		if (!netdev)
			continue;

		repr = netdev_priv(netdev);
		if (repr->port->type != NFP_PORT_INVALID)
			continue;

		nfp_app_repr_preclean(app, netdev);
		rtnl_lock();
		rcu_assign_pointer(reprs->reprs[i], NULL);
		rtnl_unlock();
		synchronize_rcu();
		nfp_repr_clean(repr);
	}

	return 0;
}
