// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright (C) 2017-2018 Netronome Systems, Inc. */

#include "nfpcore/kcompat.h"

#include <linux/bottom_half.h>
#include <linux/if_arp.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/rcupdate.h>

#include "nfp_app.h"
#include "nfp_main.h"

static bool nfp_ctrl_debug;
#if defined(CONFIG_NFP_NET_PF) && defined(CONFIG_NFP_USER_SPACE_CPP)
module_param(nfp_ctrl_debug, bool, 0444);
MODULE_PARM_DESC(nfp_ctrl_debug, "Create debug netdev for sniffing and injecting FW control messages (default = false)");
#endif

struct nfp_ctrl_debug_netdev {
	struct nfp_app *app;
};

static int nfp_ctrl_debug_netdev_open(struct net_device *netdev)
{
	return 0;
}

static int nfp_ctrl_debug_netdev_close(struct net_device *netdev)
{
	return 0;
}

void nfp_ctrl_debug_rx(struct nfp_pf *pf, struct sk_buff *skb)
{
	struct net_device *netdev;

	if (!nfp_ctrl_debug)
		return;

	rcu_read_lock();
	netdev = rcu_dereference(pf->debug_ctrl_netdev);
	if (!netdev || !netif_running(netdev))
		goto exit_unlock_rcu;

	skb = skb_clone(skb, GFP_ATOMIC);
	if (skb) {
		skb->dev = netdev;
		netif_rx(skb);
		netdev->stats.rx_packets++;
		netdev->stats.rx_bytes += skb->len;
	} else {
		netdev->stats.rx_dropped++;
	}

exit_unlock_rcu:
	rcu_read_unlock();
}

void nfp_ctrl_debug_deliver_tx(struct nfp_pf *pf, struct sk_buff *skb)
{
	struct net_device *netdev;

	if (!nfp_ctrl_debug)
		return;

	rcu_read_lock();
	netdev = rcu_dereference(pf->debug_ctrl_netdev);
	if (!netdev || !netif_running(netdev))
		goto exit_unlock_rcu;

	skb->dev = netdev;
	skb->skb_iif = netdev->ifindex;

	local_bh_disable();
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 7, 0)
	dev_queue_xmit_nit(skb, netdev);
#else
	/* Since old kernels don't expose dev_queue_xmit_nit(), mark
	 * the packet and queue it up as if we were to transmit it.
	 */
	skb->mark = ~0;
	dev_queue_xmit(skb);
#endif
	local_bh_enable();
exit_unlock_rcu:
	rcu_read_unlock();
}

static int nfp_ctrl_debug_tx(struct sk_buff *skb, struct net_device *netdev)
{
	struct nfp_ctrl_debug_netdev *ncd = netdev_priv(netdev);

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 7, 0)
	if (skb->mark == ~0) {
		dev_kfree_skb_any(skb);
		return NETDEV_TX_OK;
	}
#endif
	trace_devlink_hwmsg(priv_to_devlink(ncd->app->pf), false, 0,
			    skb->data, skb->len);
	nfp_ctrl_tx(ncd->app->ctrl, skb);

	netdev->stats.tx_packets++;
	netdev->stats.tx_bytes += skb->len;

	return NETDEV_TX_OK;
}

static const struct net_device_ops nfp_ctrl_debug_netdev_ops = {
	.ndo_open		= nfp_ctrl_debug_netdev_open,
	.ndo_stop		= nfp_ctrl_debug_netdev_close,
	.ndo_start_xmit		= nfp_ctrl_debug_tx,
};

static void nfp_ctrl_debug_setup(struct net_device *dev)
{
	dev->type = ARPHRD_NONE;
	dev->hard_header_len = 0;
	dev->header_ops = NULL;
	dev->addr_len = 0;
	dev->tx_queue_len = 16;
	dev->mtu = 1024;
	dev->flags = IFF_POINTOPOINT | IFF_NOARP;

	dev->netdev_ops = &nfp_ctrl_debug_netdev_ops;
}

int nfp_ctrl_debug_start(struct nfp_pf *pf)
{
	struct nfp_ctrl_debug_netdev *ncd;
	struct net_device *netdev;
	int err;

	if (!nfp_ctrl_debug)
		return 0;

	netdev = alloc_netdev(sizeof(struct nfp_ctrl_debug_netdev),
			      "ncd%d", NET_NAME_UNKNOWN, nfp_ctrl_debug_setup);
	if (!netdev)
		return -ENOMEM;

	ncd = netdev_priv(netdev);
	ncd->app = pf->app;

	err = register_netdev(netdev);
	if (err)
		goto err_free;

	rcu_assign_pointer(pf->debug_ctrl_netdev, netdev);

	return 0;

err_free:
	free_netdev(netdev);
	return err;
}

void nfp_ctrl_debug_stop(struct nfp_pf *pf)
{
	struct net_device *netdev;

	if (!nfp_ctrl_debug)
		return;

	netdev = rcu_dereference_protected(pf->debug_ctrl_netdev, true);
	rcu_assign_pointer(pf->debug_ctrl_netdev, NULL);

	synchronize_rcu();
	unregister_netdev(netdev);
	free_netdev(netdev);
}
