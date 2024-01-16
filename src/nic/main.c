// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright (C) 2017 Netronome Systems, Inc. */

#include "../nfpcore/nfp_cpp.h"
#include "../nfpcore/nfp_nsp.h"
#include "../nfp_app.h"
#include "../nfp_main.h"
#include "../nfp_net.h"
#include "../nfp_port.h"
#include "main.h"

static int nfp_nic_init(struct nfp_app *app)
{
	struct nfp_pf *pf = app->pf;

	if (pf->eth_tbl && pf->max_data_vnics != pf->eth_tbl->count &&
	    !pf->multi_pf.en) {
		nfp_err(pf->cpp, "ETH entries don't match vNICs (%d vs %d)\n",
			pf->max_data_vnics, pf->eth_tbl->count);
		return -EINVAL;
	}

	return 0;
}

static int nfp_nic_sriov_enable(struct nfp_app *app, int num_vfs)
{
	return 0;
}

static void nfp_nic_sriov_disable(struct nfp_app *app)
{
}

static int nfp_nic_vnic_init(struct nfp_app *app, struct nfp_net *nn)
{
	struct nfp_port *port = nn->port;

	if (port->type == NFP_PORT_PHYS_PORT) {
		/* Enable PHY state here, and its state doesn't change in
		 * pace with the port upper state by default. The behavior
		 * can be modified by ethtool private flag "link_state_detach".
		 */
		int err = nfp_eth_set_configured(app->cpp,
						 port->eth_port->index,
						 true);
		if (err >= 0)
			port->eth_forced = true;
	}

	return nfp_nic_dcb_init(nn);
}

static void nfp_nic_vnic_clean(struct nfp_app *app, struct nfp_net *nn)
{
	struct nfp_port *port = nn->port;

	if (port->type == NFP_PORT_PHYS_PORT)
		nfp_eth_set_configured(app->cpp, port->eth_port->index, false);

	nfp_nic_dcb_clean(nn);
}

static int nfp_nic_vnic_alloc(struct nfp_app *app, struct nfp_net *nn,
			      unsigned int id)
{
	struct nfp_app_nic_private *app_pri = nn->app_priv;
	int err;

	err = nfp_app_nic_vnic_alloc(app, nn, id);
	if (err)
		return err;

	if (sizeof(*app_pri)) {
		nn->app_priv = kzalloc(sizeof(*app_pri), GFP_KERNEL);
		if (!nn->app_priv)
			return -ENOMEM;
	}

	return 0;
}

static void nfp_nic_vnic_free(struct nfp_app *app, struct nfp_net *nn)
{
	kfree(nn->app_priv);
}

static int nfp_nic_select_tclass(struct nfp_app *app, struct nfp_net *nn,
				 struct sk_buff *skb)
{
	return nfp_dcb_select_tclass(app, nn, skb);
}

static bool nfp_nic_pfc_is_enable(struct nfp_app *app, struct nfp_net *nn)
{
	return nfp_dcb_pfc_is_enable(app, nn);
}

int nfp_configure_tc_ring(struct nfp_net *nn)
{
	struct nfp_net_dp *dp;

	dp = nfp_net_clone_dp(nn);
	if (!dp)
		return -ENOMEM;

	return nfp_net_ring_reconfig(nn, dp, NULL);
}

static int nfp_setup_tc_mqprio_channel(struct nfp_net *nn, u8 tc,
				       struct tc_mqprio_qopt *qopt)
{
	unsigned int max_qcount;
	int i;

	max_qcount = nn->dp.num_stack_tx_rings;
	if (qopt->offset[0] != 0 || qopt->num_tc < 1 ||
			qopt->num_tc > TC_MAX_QUEUE)
		return -EINVAL;

	for (i = 0; i < TC_MAX_QUEUE; i++) {
		if (max_qcount < (qopt->offset[i] + qopt->count[i]))
			return -EINVAL;

		nn->tc_config[i].offset = qopt->offset[i];
		nn->tc_config[i].count = qopt->count[i];
	}
	return nfp_configure_tc_ring(nn);
}

static int nfp_setup_tc_mqprio(struct nfp_net *nn, void *type_data)
{
	struct tc_mqprio_qopt_offload *mqprio_qopt = type_data;
	struct tc_mqprio_qopt *qopt = &mqprio_qopt->qopt;
	u8 num_tc;
	int ret;

	if (!(nn->cap_w1 & NFP_NET_CFG_CTRL_TC_MQPRIO))
		return -EOPNOTSUPP;

	num_tc = qopt->num_tc;

	if (!qopt->hw)
		return -EOPNOTSUPP;

	switch (mqprio_qopt->mode) {
	case TC_MQPRIO_MODE_DCB:
		ret = nfp_setup_tc_mqprio_dcb(nn, num_tc);
		break;
	case TC_MQPRIO_MODE_CHANNEL:
		ret = nfp_setup_tc_mqprio_channel(nn, num_tc, qopt);
		break;
	default:
		ret = -EOPNOTSUPP;
		break;
	}

	return ret;
}

static int nfp_nic_setup_tc(struct nfp_app *app, struct net_device *netdev,
			    enum tc_setup_type type, void *type_data)
{
	struct nfp_net *nn = netdev_priv(netdev);

	if (type == TC_SETUP_QDISC_MQPRIO)
		return nfp_setup_tc_mqprio(nn, type_data);

	return -EOPNOTSUPP;
}

const struct nfp_app_type app_nic = {
	.id		= NFP_APP_CORE_NIC,
	.name		= "nic",

	.init		= nfp_nic_init,
	.vnic_alloc	= nfp_nic_vnic_alloc,
	.vnic_free	= nfp_nic_vnic_free,
	.sriov_enable	= nfp_nic_sriov_enable,
	.sriov_disable	= nfp_nic_sriov_disable,

	.setup_tc	= nfp_nic_setup_tc,
	.pfc_is_enable  = nfp_nic_pfc_is_enable,
	.select_tclass  = nfp_nic_select_tclass,
	.vnic_init      = nfp_nic_vnic_init,
	.vnic_clean     = nfp_nic_vnic_clean,
};
