// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright (C) 2023 Corigine, Inc. */

#include <linux/device.h>
#include <linux/netdevice.h>
#include <net/dcbnl.h>
#include <net/dsfield.h>

#include "../nfp_app.h"
#include "../nfp_net.h"
#include "../nfp_main.h"
#include "../nfpcore/nfp_cpp.h"
#include "../nfpcore/nfp_nffw.h"
#include "../nfp_net_sriov.h"
#include "../nfp_port.h"
#include "main.h"

#define NFP_DCB_TRUST_PCP	1
#define NFP_DCB_TRUST_DSCP	2
#define NFP_DCB_TRUST_INVALID	0xff

#define NFP_DCB_TSA_VENDOR	1
#define NFP_DCB_TSA_STRICT	2
#define NFP_DCB_TSA_ETS		3

#define NFP_CEE_STATE_UP    1
#define NFP_CEE_STATE_DOWN  0
#define NFP_NET_CEE_MAX_PRIO CEE_DCBX_MAX_PRIO
#define NFP_NET_CEE_MAX_PGS  CEE_DCBX_MAX_PGS

#define NFP_DCB_GBL_ENABLE	BIT(0)
#define NFP_DCB_QOS_ENABLE	BIT(1)
#define NFP_DCB_PFC_ENABLE	BIT(2)
#define NFP_DCB_DISABLE		0
#define NFP_DCB_ALL_QOS_ENABLE	(NFP_DCB_GBL_ENABLE | NFP_DCB_QOS_ENABLE)
#define NFP_DCB_ALL_PFC_ENABLE	(NFP_DCB_GBL_ENABLE | NFP_DCB_PFC_ENABLE | NFP_DCB_QOS_ENABLE)

#define NFP_DCB_UPDATE_MSK_SZ	4
#define NFP_DCB_TC_RATE_MAX	0xffff

#define NFP_DCB_DATA_OFF_DSCP2IDX	0
#define NFP_DCB_DATA_OFF_PCP2IDX	64
#define NFP_DCB_DATA_OFF_TSA		80
#define NFP_DCB_DATA_OFF_IDX_BW_PCT	88
#define NFP_DCB_DATA_OFF_RATE		96
#define NFP_DCB_DATA_OFF_CAP		112
#define NFP_DCB_DATA_OFF_ENABLE		116
#define NFP_DCB_DATA_OFF_TRUST		120

#define NFP_DCB_DATA_OFF_PFC_CAP    121
#define NFP_DCB_DATA_OFF_PFC        122
#define NFP_DCB_DATA_OFF_DELAY      123
#define NFP_DCB_DATA_OFF_MBC        125

#define NFP_DCB_DATA_OFF_REQUEST     128
#define NFP_DCB_DATA_OFF_INDICATIONS 192

#define NFP_DCB_MSG_MSK_ENABLE	BIT(31)
#define NFP_DCB_MSG_MSK_TRUST	BIT(30)
#define NFP_DCB_MSG_MSK_TSA	BIT(29)
#define NFP_DCB_MSG_MSK_DSCP	BIT(28)
#define NFP_DCB_MSG_MSK_PCP	BIT(27)
#define NFP_DCB_MSG_MSK_RATE	BIT(26)
#define NFP_DCB_MSG_MSK_PCT	BIT(25)
#define NFP_DCB_MSG_MSK_PFC_CAP BIT(24)
#define NFP_DCB_MSG_MSK_PFC	BIT(23)
#define NFP_DCB_MSG_MSK_DELAY	BIT(22)
#define NFP_DCB_MSG_MSK_MBC	BIT(21)

#ifndef IEEE_8021QAZ_APP_SEL_DSCP
#define IEEE_8021QAZ_APP_SEL_DSCP       5
#endif

#define NFP_DCB_STATUS_SUCCESS	0
#define NFP_DCB_STATUS_ERROR	1
#define NFP_MAX_TRAFFIC_CLASS	0x80

static struct nfp_dcb *get_dcb_priv(struct nfp_net *nn)
{
	struct nfp_dcb *dcb = &((struct nfp_app_nic_private *)nn->app_priv)->dcb;

	return dcb;
}

static u8 nfp_tsa_ieee2nfp(u8 tsa)
{
	switch (tsa) {
	case IEEE_8021QAZ_TSA_STRICT:
		return NFP_DCB_TSA_STRICT;
	case IEEE_8021QAZ_TSA_ETS:
		return NFP_DCB_TSA_ETS;
	default:
		return NFP_DCB_TSA_VENDOR;
	}
}

static int nfp_nic_dcbnl_ieee_getets(struct net_device *dev,
				     struct ieee_ets *ets)
{
	struct nfp_net *nn = netdev_priv(dev);
	struct nfp_dcb *dcb;
	unsigned int i;

	dcb = get_dcb_priv(nn);

	for (i = 0; i < IEEE_8021QAZ_MAX_TCS; i++) {
		ets->prio_tc[i] = dcb->prio2tc[i];
		ets->tc_tx_bw[i] = dcb->tc_tx_pct[i];
		ets->tc_tsa[i] = dcb->tc_tsa[i];
	}

	return 0;
}

static bool nfp_refresh_tc2idx(struct nfp_net *nn)
{
	u8 tc2idx[IEEE_8021QAZ_MAX_TCS];
	bool change = false;
	struct nfp_dcb *dcb;
	int maxstrict = 0;
	unsigned int i, j;

	dcb = get_dcb_priv(nn);

	for (i = 0; i < IEEE_8021QAZ_MAX_TCS; i++) {
		tc2idx[i] = i;
		if (dcb->tc_tsa[i] == IEEE_8021QAZ_TSA_STRICT)
			maxstrict = i;
	}

	if (maxstrict > 0 && dcb->tc_tsa[0] != IEEE_8021QAZ_TSA_STRICT) {
		tc2idx[0] = maxstrict;
		tc2idx[maxstrict] = 0;
	}

	for (j = 0; j < IEEE_8021QAZ_MAX_TCS; j++) {
		if (dcb->tc2idx[j] != tc2idx[j]) {
			change = true;
			dcb->tc2idx[j] = tc2idx[j];
		}
	}

	return change;
}

static int nfp_fill_maxrate(struct nfp_net *nn, u64 *max_rate_array)
{
	struct nfp_app *app  = nn->app;
	struct nfp_dcb *dcb;
	unsigned int i;
	u32 ratembps;

	dcb = get_dcb_priv(nn);

	for (i = 0; i < IEEE_8021QAZ_MAX_TCS; i++) {
		/* Convert bandwidth from kbps to mbps. */
		ratembps = max_rate_array[i] / 1024;

		/* Reject input values >= NFP_DCB_TC_RATE_MAX */
		if (ratembps >= NFP_DCB_TC_RATE_MAX) {
			nfp_warn(app->cpp, "ratembps(%d) must less than %d.",
				 ratembps, NFP_DCB_TC_RATE_MAX);
			return -EINVAL;
		}
		/* Input value 0 mapped to NFP_DCB_TC_RATE_MAX for firmware. */
		if (ratembps == 0)
			ratembps = NFP_DCB_TC_RATE_MAX;

		writew((u16)ratembps, dcb->dcbcfg_tbl +
		       dcb->cfg_offset + NFP_DCB_DATA_OFF_RATE + dcb->tc2idx[i] * 2);
		/* for rate value from user space, need to sync to dcb structure */
		if (dcb->tc_maxrate != max_rate_array)
			dcb->tc_maxrate[i] = max_rate_array[i];
	}

	return 0;
}

static int update_dscp_maxrate(struct net_device *dev, u32 *update)
{
	struct nfp_net *nn = netdev_priv(dev);
	struct nfp_dcb *dcb;
	unsigned int i;
	int err;

	dcb = get_dcb_priv(nn);

	err = nfp_fill_maxrate(nn, dcb->tc_maxrate);
	if (err)
		return err;

	*update |= NFP_DCB_MSG_MSK_RATE;

	/* We only refresh dscp in dscp trust mode. */
	if (dcb->dscp_cnt > 0) {
		for (i = 0; i < NFP_NET_MAX_DSCP; i++) {
			writeb(dcb->tc2idx[dcb->prio2tc[dcb->dscp2prio[i]]],
			       dcb->dcbcfg_tbl + dcb->cfg_offset +
			       NFP_DCB_DATA_OFF_DSCP2IDX + i);
		}
		*update |= NFP_DCB_MSG_MSK_DSCP;
	}

	return 0;
}

static void nfp_nic_set_trust(struct nfp_net *nn, u32 *update)
{
	struct nfp_dcb *dcb;
	u8 trust;

	dcb = get_dcb_priv(nn);

	if (dcb->trust_status != NFP_DCB_TRUST_INVALID)
		return;

	trust = dcb->dscp_cnt > 0 ? NFP_DCB_TRUST_DSCP : NFP_DCB_TRUST_PCP;
	writeb(trust, dcb->dcbcfg_tbl + dcb->cfg_offset +
	       NFP_DCB_DATA_OFF_TRUST);

	dcb->trust_status = trust;
	*update |= NFP_DCB_MSG_MSK_TRUST;
}

static void nfp_nic_set_enable(struct nfp_net *nn, u32 enable, u32 *update)
{
	struct nfp_dcb *dcb;
	u32 value = 0;

	dcb = get_dcb_priv(nn);

	value = readl(dcb->dcbcfg_tbl + dcb->cfg_offset +
		      NFP_DCB_DATA_OFF_ENABLE);
	if (value != enable) {
		writel(enable, dcb->dcbcfg_tbl + dcb->cfg_offset +
		       NFP_DCB_DATA_OFF_ENABLE);
		*update |= NFP_DCB_MSG_MSK_ENABLE;
	}
}

static int dcb_ets_check(struct net_device *dev, struct ieee_ets *ets)
{
	struct nfp_net *nn = netdev_priv(dev);
	struct nfp_app *app = nn->app;
	bool ets_exists = false;
	unsigned int i;
	int sum = 0;

	for (i = 0; i < IEEE_8021QAZ_MAX_TCS; i++) {
		/* For ets mode, check bw percentage sum. */
		if (ets->tc_tsa[i] == IEEE_8021QAZ_TSA_ETS) {
			ets_exists = true;
			sum += ets->tc_tx_bw[i];
		} else if (ets->tc_tx_bw[i]) {
			nfp_warn(app->cpp, "ETS BW for strict/vendor TC must be 0.");
			return -EINVAL;
		}
	}

	if (ets_exists && sum != 100) {
		nfp_warn(app->cpp, "Failed to validate ETS BW: sum must be 100.");
		return -EINVAL;
	}

	return 0;
}

static void nfp_nic_fill_ets(struct nfp_net *nn)
{
	struct nfp_dcb *dcb;
	unsigned int i;

	dcb = get_dcb_priv(nn);

	for (i = 0; i < IEEE_8021QAZ_MAX_TCS; i++) {
		writeb(dcb->tc2idx[dcb->prio2tc[i]],
		       dcb->dcbcfg_tbl + dcb->cfg_offset + NFP_DCB_DATA_OFF_PCP2IDX + i);
		writeb(dcb->tc_tx_pct[i], dcb->dcbcfg_tbl +
		       dcb->cfg_offset + NFP_DCB_DATA_OFF_IDX_BW_PCT + dcb->tc2idx[i]);
		writeb(nfp_tsa_ieee2nfp(dcb->tc_tsa[i]), dcb->dcbcfg_tbl +
		       dcb->cfg_offset + NFP_DCB_DATA_OFF_TSA + dcb->tc2idx[i]);
	}
}

static void nfp_nic_ets_init(struct nfp_net *nn, u32 *update)
{
	struct nfp_dcb *dcb = get_dcb_priv(nn);

	if (dcb->ets_init)
		return;

	nfp_nic_fill_ets(nn);
	dcb->ets_init = true;
	*update |= NFP_DCB_MSG_MSK_TSA | NFP_DCB_MSG_MSK_PCT | NFP_DCB_MSG_MSK_PCP;
}

static int nfp_nic_dcbnl_ieee_setets(struct net_device *dev,
				     struct ieee_ets *ets)
{
	const u32 cmd = NFP_NET_CFG_MBOX_CMD_DCB_UPDATE;
	struct nfp_net *nn = netdev_priv(dev);
	struct nfp_app *app = nn->app;
	struct nfp_dcb *dcb;
	unsigned int i;
	u32 update = 0;
	bool change;
	int err;

	err = dcb_ets_check(dev, ets);
	if (err)
		return err;

	dcb = get_dcb_priv(nn);

	for (i = 0; i < IEEE_8021QAZ_MAX_TCS; i++) {
		dcb->prio2tc[i] = ets->prio_tc[i];
		dcb->tc_tx_pct[i] = ets->tc_tx_bw[i];
		dcb->tc_tsa[i] = ets->tc_tsa[i];
	}

	change = nfp_refresh_tc2idx(nn);
	nfp_nic_fill_ets(nn);
	dcb->ets_init = true;
	if (change || !dcb->rate_init) {
		err = update_dscp_maxrate(dev, &update);
		if (err) {
			nfp_warn(app->cpp,
				 "nfp dcbnl ieee setets ERROR:%d.",
				 err);
			return err;
		}

		dcb->rate_init = true;
	}
	nfp_nic_set_enable(nn, NFP_DCB_ALL_QOS_ENABLE, &update);
	nfp_nic_set_trust(nn, &update);
	err = nfp_net_mbox_lock(nn, NFP_DCB_UPDATE_MSK_SZ);
	if (err)
		return err;

	nn_writel(nn, nn->tlv_caps.mbox_off + NFP_NET_CFG_MBOX_SIMPLE_VAL,
		  update | NFP_DCB_MSG_MSK_TSA | NFP_DCB_MSG_MSK_PCT |
		  NFP_DCB_MSG_MSK_PCP);

	return nfp_net_mbox_reconfig_and_unlock(nn, cmd);
}

static int nfp_nic_dcbnl_ieee_getmaxrate(struct net_device *dev,
					 struct ieee_maxrate *maxrate)
{
	struct nfp_net *nn = netdev_priv(dev);
	struct nfp_dcb *dcb;
	unsigned int i;

	dcb = get_dcb_priv(nn);

	for (i = 0; i < IEEE_8021QAZ_MAX_TCS; i++)
		maxrate->tc_maxrate[i] = dcb->tc_maxrate[i];

	return 0;
}

static int nfp_nic_dcbnl_ieee_setmaxrate(struct net_device *dev,
					 struct ieee_maxrate *maxrate)
{
	const u32 cmd = NFP_NET_CFG_MBOX_CMD_DCB_UPDATE;
	struct nfp_net *nn = netdev_priv(dev);
	struct nfp_app *app = nn->app;
	struct nfp_dcb *dcb;
	u32 update = 0;
	int err;

	err = nfp_fill_maxrate(nn, maxrate->tc_maxrate);
	if (err) {
		nfp_warn(app->cpp,
			 "nfp dcbnl ieee setmaxrate ERROR:%d.",
			 err);
		return err;
	}

	dcb = get_dcb_priv(nn);

	dcb->rate_init = true;
	nfp_nic_set_enable(nn, NFP_DCB_ALL_QOS_ENABLE, &update);
	nfp_nic_set_trust(nn, &update);
	nfp_nic_ets_init(nn, &update);

	err = nfp_net_mbox_lock(nn, NFP_DCB_UPDATE_MSK_SZ);
	if (err)
		return err;

	nn_writel(nn, nn->tlv_caps.mbox_off + NFP_NET_CFG_MBOX_SIMPLE_VAL,
		  update | NFP_DCB_MSG_MSK_RATE);

	return nfp_net_mbox_reconfig_and_unlock(nn, cmd);
}

static int nfp_nic_set_trust_status(struct nfp_net *nn, u8 status)
{
	const u32 cmd = NFP_NET_CFG_MBOX_CMD_DCB_UPDATE;
	struct nfp_dcb *dcb;
	u32 update = 0;
	int err;

	dcb = get_dcb_priv(nn);
	if (!dcb->rate_init) {
		err = nfp_fill_maxrate(nn, dcb->tc_maxrate);
		if (err)
			return err;

		update |= NFP_DCB_MSG_MSK_RATE;
		dcb->rate_init = true;
	}

	err = nfp_net_mbox_lock(nn, NFP_DCB_UPDATE_MSK_SZ);
	if (err)
		return err;

	nfp_nic_ets_init(nn, &update);
	writeb(status, dcb->dcbcfg_tbl + dcb->cfg_offset +
	       NFP_DCB_DATA_OFF_TRUST);
	nfp_nic_set_enable(nn, NFP_DCB_ALL_QOS_ENABLE, &update);
	nn_writel(nn, nn->tlv_caps.mbox_off + NFP_NET_CFG_MBOX_SIMPLE_VAL,
		  update | NFP_DCB_MSG_MSK_TRUST);

	err = nfp_net_mbox_reconfig_and_unlock(nn, cmd);
	if (err)
		return err;

	dcb->trust_status = status;

	return 0;
}

static int nfp_nic_set_dscp2prio(struct nfp_net *nn, u8 dscp, u8 prio)
{
	const u32 cmd = NFP_NET_CFG_MBOX_CMD_DCB_UPDATE;
	struct nfp_dcb *dcb;
	u8 idx, tc;
	int err;

	err = nfp_net_mbox_lock(nn, NFP_DCB_UPDATE_MSK_SZ);
	if (err)
		return err;

	dcb = get_dcb_priv(nn);

	tc = dcb->prio2tc[prio];
	idx = dcb->tc2idx[tc];

	writeb(idx, dcb->dcbcfg_tbl + dcb->cfg_offset +
	       NFP_DCB_DATA_OFF_DSCP2IDX + dscp);

	nn_writel(nn, nn->tlv_caps.mbox_off +
		  NFP_NET_CFG_MBOX_SIMPLE_VAL, NFP_DCB_MSG_MSK_DSCP);

	err = nfp_net_mbox_reconfig_and_unlock(nn, cmd);
	if (err)
		return err;

	dcb->dscp2prio[dscp] = prio;

	return 0;
}

static int nfp_nic_dcbnl_ieee_setapp(struct net_device *dev,
				     struct dcb_app *app)
{
	struct nfp_net *nn = netdev_priv(dev);
	struct dcb_app old_app;
	struct nfp_dcb *dcb;
	bool is_new;
	int err;

	if (app->selector != IEEE_8021QAZ_APP_SEL_DSCP)
		return -EINVAL;

	dcb = get_dcb_priv(nn);

	/* Save the old entry info */
	old_app.selector = IEEE_8021QAZ_APP_SEL_DSCP;
	old_app.protocol = app->protocol;
	old_app.priority = dcb->dscp2prio[app->protocol];

	/* Check trust status */
	if (!dcb->dscp_cnt) {
		err = nfp_nic_set_trust_status(nn, NFP_DCB_TRUST_DSCP);
		if (err)
			return err;
	}

	/* Check if the new mapping is same as old or in init stage */
	if (app->priority != old_app.priority || app->priority == 0) {
		err = nfp_nic_set_dscp2prio(nn, app->protocol, app->priority);
		if (err)
			return err;
	}

	/* Delete the old entry if exists */
	is_new = !!dcb_ieee_delapp(dev, &old_app);

	/* Add new entry and update counter */
	err = dcb_ieee_setapp(dev, app);
	if (err)
		return err;

	if (is_new)
		dcb->dscp_cnt++;

	return 0;
}

static int nfp_nic_dcbnl_ieee_delapp(struct net_device *dev,
				     struct dcb_app *app)
{
	struct nfp_net *nn = netdev_priv(dev);
	struct nfp_dcb *dcb;
	int err;

	if (app->selector != IEEE_8021QAZ_APP_SEL_DSCP)
		return -EINVAL;

	dcb = get_dcb_priv(nn);

	/* Check if the dcb_app param match fw */
	if (app->priority != dcb->dscp2prio[app->protocol])
		return -ENOENT;

	/* Set fw dscp mapping to 0 */
	err = nfp_nic_set_dscp2prio(nn, app->protocol, 0);
	if (err)
		return err;

	/* Delete app from dcb list */
	err = dcb_ieee_delapp(dev, app);
	if (err)
		return err;

	/* Decrease dscp counter */
	dcb->dscp_cnt--;

	/* If no dscp mapping is configured, trust pcp */
	if (dcb->dscp_cnt == 0)
		return nfp_nic_set_trust_status(nn, NFP_DCB_TRUST_PCP);

	return 0;
}

int nfp_setup_tc_mqprio_dcb(struct nfp_net *nn, u8 tc)
{
	unsigned int i;

	if (tc && tc != NFP_NET_MAX_TC)
		return -EINVAL;

	for (i = 0; i < tc; i++) {
		nn->tc_config[i].offset = i;
		nn->tc_config[i].count = 1;
	}
	return nfp_configure_tc_ring(nn);
}

static int nfp_dcb_config_num_tc(struct nfp_net *nn, struct nfp_dcb *dcb, struct ieee_pfc *pfc)
{
	u8 num_pfc_tc = 0;
	int tc_pfc_offset;
	unsigned int i;
	u16 qcount;

	dcb->pfc_en = pfc->pfc_en;
	for (i = 0; i < NFP_NET_MAX_PRIO; i++) {
		if (BIT(i) & pfc->pfc_en)
			num_pfc_tc |= BIT(dcb->prio2tc[i]);
	}
	tc_pfc_offset = NFP_NET_MAX_PFC_QUEUE_NUM;
	qcount = nn->dp.num_stack_tx_rings;
	if (qcount <= NFP_NET_MAX_PFC_QUEUE_NUM)
		return -EOPNOTSUPP;

	for (i = 0; i < IEEE_8021QAZ_MAX_TCS; i++) {
		if (BIT(i) & num_pfc_tc) {
			if (tc_pfc_offset < 0)
				tc_pfc_offset = 0;
			else
				tc_pfc_offset--;
			nn->tc_config[i].count = 1;
			nn->tc_config[i].offset = tc_pfc_offset;
		} else {
			nn->tc_config[i].count = qcount - NFP_NET_MAX_PFC_QUEUE_NUM;
			nn->tc_config[i].offset = NFP_NET_MAX_PFC_QUEUE_NUM;
		}
	}
	return 0;
}

static int nfp_dcb_config_default_set_tc(struct nfp_net *nn,
					 struct nfp_dcb *dcb, struct ieee_pfc *pfc)
{
	unsigned int i;
	u16 qcount;

	if (!(nn->cap_w1 & NFP_NET_CFG_CTRL_TC_MQPRIO))
		return nfp_dcb_config_num_tc(nn, dcb, pfc);

	qcount = nn->dp.num_stack_tx_rings;
	if (qcount <= NFP_NET_MAX_PFC_QUEUE_NUM)
		return -EOPNOTSUPP;

	for (i = 0; i < IEEE_8021QAZ_MAX_TCS; i++) {
		nn->tc_config[i].count = 1;
		nn->tc_config[i].offset = i;
		if (i == IEEE_8021QAZ_MAX_TCS - 1)
			nn->tc_config[i].count = qcount - i;
	}
	return nfp_configure_tc_ring(nn);
}

static int nfp_nic_dcbnl_ieee_getpfc(struct net_device *dev, struct ieee_pfc *pfc)
{
	struct nfp_net *nn = netdev_priv(dev);
	struct nfp_port *port;
	struct nfp_dcb *dcb;
	u8 *base_offset;
	unsigned int i;

	static int nfp_mac_pfc_pause_off[IEEE_8021QAZ_MAX_TCS * 2] = {
		NFP_MAC_STATS_RX_PAUSE_FRAMES_CLASS0,
		NFP_MAC_STATS_RX_PAUSE_FRAMES_CLASS1,
		NFP_MAC_STATS_RX_PAUSE_FRAMES_CLASS2,
		NFP_MAC_STATS_RX_PAUSE_FRAMES_CLASS3,
		NFP_MAC_STATS_RX_PAUSE_FRAMES_CLASS4,
		NFP_MAC_STATS_RX_PAUSE_FRAMES_CLASS5,
		NFP_MAC_STATS_RX_PAUSE_FRAMES_CLASS6,
		NFP_MAC_STATS_RX_PAUSE_FRAMES_CLASS7,
		NFP_MAC_STATS_TX_PAUSE_FRAMES_CLASS0,
		NFP_MAC_STATS_TX_PAUSE_FRAMES_CLASS1,
		NFP_MAC_STATS_TX_PAUSE_FRAMES_CLASS2,
		NFP_MAC_STATS_TX_PAUSE_FRAMES_CLASS3,
		NFP_MAC_STATS_TX_PAUSE_FRAMES_CLASS4,
		NFP_MAC_STATS_TX_PAUSE_FRAMES_CLASS5,
		NFP_MAC_STATS_TX_PAUSE_FRAMES_CLASS6,
		NFP_MAC_STATS_TX_PAUSE_FRAMES_CLASS7,
	};

	port = nfp_port_from_netdev(dev);
	if (!nfp_port_get_eth_port(port) || !port->eth_stats)
		return -EOPNOTSUPP;

	dcb = get_dcb_priv(nn);
	if (!(dcb->dcb_cap & NFP_DCB_PFC_ENABLE))
		return -EOPNOTSUPP;

	base_offset = dcb->dcbcfg_tbl + dcb->cfg_offset;
	pfc->pfc_cap = IEEE_8021QAZ_MAX_TCS;
	pfc->pfc_en  = readb(base_offset + NFP_DCB_DATA_OFF_PFC);
	pfc->mbc     = readb(base_offset + NFP_DCB_DATA_OFF_MBC);
	pfc->delay   = readw(base_offset + NFP_DCB_DATA_OFF_DELAY);
	dcb->pfc_en  = pfc->pfc_en;

	for (i = 0; i < IEEE_8021QAZ_MAX_TCS; i++) {
		pfc->requests[i] = readq(port->eth_stats + nfp_mac_pfc_pause_off[i]);
		pfc->indications[i] =
			readq(port->eth_stats + nfp_mac_pfc_pause_off[i + IEEE_8021QAZ_MAX_TCS]);
	}
	return 0;
}

static int nfp_nic_dcbnl_ieee_setpfc(struct net_device *dev, struct ieee_pfc *pfc)
{
	const u32 cmd = NFP_NET_CFG_MBOX_CMD_DCB_UPDATE;
	struct nfp_net *nn = netdev_priv(dev);
	struct nfp_dcb *dcb;
	u8 *base_offset;
	u32 update = 0;
	int err = 0;

	dcb = get_dcb_priv(nn);
	if (!(dcb->dcb_cap & NFP_DCB_PFC_ENABLE))
		return -EOPNOTSUPP;

	err = nfp_net_mbox_lock(nn, NFP_DCB_UPDATE_MSK_SZ);
	if (err)
		return err;

	base_offset = dcb->dcbcfg_tbl + dcb->cfg_offset;
	writeb(pfc->pfc_en, base_offset + NFP_DCB_DATA_OFF_PFC);
	writew(pfc->delay, base_offset + NFP_DCB_DATA_OFF_DELAY);
	writeb(pfc->mbc, base_offset + NFP_DCB_DATA_OFF_MBC);

	update = NFP_DCB_MSG_MSK_MBC | NFP_DCB_MSG_MSK_DELAY | NFP_DCB_MSG_MSK_PFC;
	nfp_nic_set_enable(nn, NFP_DCB_ALL_PFC_ENABLE, &update);
	nn_writel(nn, nn->tlv_caps.mbox_off + NFP_NET_CFG_MBOX_SIMPLE_VAL, update);
	err = nfp_net_mbox_reconfig_and_unlock(nn, cmd);
	if (err)
		return err;

	return nfp_dcb_config_default_set_tc(nn, dcb, pfc);
}

static int nfp_nic_ieee_ets_init(struct nfp_net *nn, struct nfp_dcb *dcb)
{
	const u32 cmd = NFP_NET_CFG_MBOX_CMD_DCB_UPDATE;
	u32 update = 0;
	int err;

	if (!nfp_refresh_tc2idx(nn))
		return 0;

	nfp_nic_fill_ets(nn);
	dcb->ets_init = true;
	nfp_nic_set_enable(nn, NFP_DCB_ALL_QOS_ENABLE, &update);
	nfp_nic_set_trust(nn, &update);
	err = nfp_net_mbox_lock(nn, NFP_DCB_UPDATE_MSK_SZ);
	if (err)
		return err;

	nn_writel(nn, nn->tlv_caps.mbox_off + NFP_NET_CFG_MBOX_SIMPLE_VAL,
		  update | NFP_DCB_MSG_MSK_TSA | NFP_DCB_MSG_MSK_PCT |
		  NFP_DCB_MSG_MSK_PCP);

	return nfp_net_mbox_reconfig_and_unlock(nn, cmd);
}

#if VER_NON_RHEL_GE(4, 19) || VER_RHEL_GE(8, 0)
static int nfp_get_dscp_priority(struct sk_buff *skb, struct nfp_dcb *dcb)
{
	int dscp = 0;

	if (skb->protocol == htons(ETH_P_IP))
		dscp = ipv4_get_dsfield(ip_hdr(skb)) >> 2;
	else if (skb->protocol == htons(ETH_P_IPV6))
		dscp = ipv6_get_dsfield(ipv6_hdr(skb)) >> 2;

	return dcb->dscp2prio[dscp];
}

static int nfp_get_priority(struct nfp_net *nn, struct sk_buff *skb, struct nfp_dcb *dcb)
{
	if (dcb->trust_status == NFP_DCB_TRUST_DSCP)
		return nfp_get_dscp_priority(skb, dcb);
	if (skb_vlan_tag_present(skb))
		return skb_vlan_tag_get_prio(skb);
	return 0;
}

int nfp_dcb_select_tclass(struct nfp_app *app, struct nfp_net *nn,
			  struct sk_buff *skb)
{
	struct nfp_dcb *dcb;
	int priority;

	dcb = get_dcb_priv(nn);
	if ((dcb->dcb_cap & NFP_DCB_PFC_ENABLE) && dcb->pfc_en) {
		priority = nfp_get_priority(nn, skb, dcb);
		if (priority >= NFP_NET_MAX_PRIO)
			return -EINVAL;

		return dcb->prio2tc[priority];
	}
	return -EOPNOTSUPP;
}
#else
int nfp_dcb_select_tclass(struct nfp_app *app, struct nfp_net *nn,
			  struct sk_buff *skb)
{
	return -EOPNOTSUPP;
}
#endif

bool nfp_dcb_pfc_is_enable(struct nfp_app *app, struct nfp_net *nn)
{
	struct nfp_dcb *dcb;

	dcb = get_dcb_priv(nn);
	return dcb->pfc_en;
}

static u8 nfp_nic_dcbnl_cee_getstate(struct net_device *dev)
{
	struct nfp_net *nn = netdev_priv(dev);
	struct nfp_dcb *dcb;

	dcb = get_dcb_priv(nn);
	return dcb->dcb_cee_state;
}

static u8 nfp_nic_dcbnl_cee_setstate(struct net_device *dev, u8 state)
{
	struct nfp_net *nn = netdev_priv(dev);
	struct nfp_dcb *dcb;

	dcb = get_dcb_priv(nn);
	dcb->dcb_cee_state = state;
	return 0;
}

static u8 nfp_nic_dcbnl_setall(struct net_device *dev)
{
	struct nfp_net *nn = netdev_priv(dev);
	struct nfp_app *app = nn->app;
	struct ieee_ets ets = {};
	struct ieee_pfc pfc = {};
	struct nfp_dcb *dcb;
	int err, i;

	dcb = get_dcb_priv(nn);

	if (!dcb->dcb_cee_state) {
		nfp_warn(app->cpp,
			 "Failed to set CEE, the state is off");
		return NFP_DCB_STATUS_ERROR;
	}
	/* Set ets configure */
	ets.ets_cap = IEEE_8021QAZ_MAX_TCS;
	for (i = 0; i < NFP_NET_CEE_MAX_PGS; i++) {
		ets.tc_tx_bw[i] = dcb->tc_tx_pct[i];
		ets.prio_tc[i]  = dcb->prio2tc[i];
		ets.tc_tsa[i]   = IEEE_8021QAZ_TSA_ETS;
	}
	err = nfp_nic_dcbnl_ieee_setets(dev, &ets);
	if (err) {
		nfp_warn(app->cpp, "Failed to set CEE ETS:%d.", err);
		return err;
	}

	/* Set pfc configure */
	pfc.pfc_en = dcb->pfc_en;
	err = nfp_nic_dcbnl_ieee_setpfc(dev, &pfc);
	if (err) {
		nfp_warn(app->cpp, "Failed to set CEE PFC:%d.", err);
		return err;
	}
	return 0;
}

static void nfp_nic_dcbnl_setpgtccfgtx(struct net_device *dev,
				       int priority, u8 prio_type,
				       u8 pgid, u8 bw_pct, u8 up_map)
{
	struct nfp_net *nn = netdev_priv(dev);
	struct nfp_dcb *dcb;

	if (priority >= NFP_NET_CEE_MAX_PRIO || pgid >= NFP_NET_CEE_MAX_PGS)
		return;

	dcb = get_dcb_priv(nn);
	dcb->prio2tc[priority] = pgid;
	dcb->tc_tx_pct[pgid] = bw_pct;
}

static void nfp_nic_dcbnl_getpgtccfgtx(struct net_device *dev,
				       int priority, u8 *prio_type,
				       u8 *pgid, u8 *bw_pct, u8 *up_map)
{
	struct nfp_net *nn = netdev_priv(dev);
	struct nfp_dcb *dcb;

	if (priority >= NFP_NET_CEE_MAX_PRIO)
		return;

	dcb = get_dcb_priv(nn);
	*prio_type = 0;
	*pgid = dcb->prio2tc[priority];
	*bw_pct = dcb->tc_tx_pct[*pgid];
	*up_map = 0;
}

static void nfp_nic_dcbnl_setpgbwgcfgtx(struct net_device *dev,
					int pgid, u8 bw_pct)
{
	struct nfp_net *nn = netdev_priv(dev);
	struct nfp_dcb *dcb;

	dcb = get_dcb_priv(nn);

	if (pgid >= NFP_NET_CEE_MAX_PGS)
		return;

	dcb->tc_tx_pct[pgid] = bw_pct;
}

static void nfp_nic_dcbnl_getpgbwgcfgtx(struct net_device *dev,
					int pgid, u8 *bw_pct)
{
	struct nfp_net *nn = netdev_priv(dev);
	struct nfp_dcb *dcb;

	dcb = get_dcb_priv(nn);

	if (pgid >= NFP_NET_CEE_MAX_PGS)
		return;

	*bw_pct = dcb->tc_tx_pct[pgid];
}

static void nfp_nic_dcbnl_setpfccfg(struct net_device *dev,
				    int priority, u8 setting)
{
	struct nfp_net *nn = netdev_priv(dev);
	struct nfp_dcb *dcb;

	dcb = get_dcb_priv(nn);
	if (!(dcb->dcb_cap & NFP_DCB_PFC_ENABLE) || priority >= NFP_NET_CEE_MAX_PRIO)
		return;

	if (setting)
		dcb->pfc_en |= BIT(priority);
	else
		dcb->pfc_en &= ~BIT(priority);
}

static void nfp_nic_dcbnl_getpfccfg(struct net_device *dev,
				    int priority, u8 *setting)
{
	struct nfp_net *nn = netdev_priv(dev);
	struct nfp_dcb *dcb;

	dcb = get_dcb_priv(nn);
	if (!(dcb->dcb_cap & NFP_DCB_PFC_ENABLE) || priority >= NFP_NET_CEE_MAX_PRIO)
		return;

	*setting = (dcb->pfc_en >> priority) & 0x1;
}

static u8 nfp_nic_dcbnl_getcap(struct net_device *dev,
			       int capid, u8 *cap)
{
	int ret = 0;

	switch (capid) {
	case DCB_CAP_ATTR_PG:
	case DCB_CAP_ATTR_PFC:
	case DCB_CAP_ATTR_UP2TC:
		*cap = true;
		break;
	case DCB_CAP_ATTR_PG_TCS:
	case DCB_CAP_ATTR_PFC_TCS:
		*cap = NFP_MAX_TRAFFIC_CLASS;
		break;
	case DCB_CAP_ATTR_GSP:
	case DCB_CAP_ATTR_BCN:
		*cap = false;
		break;
	case DCB_CAP_ATTR_DCBX:
		*cap = DCB_CAP_DCBX_VER_CEE |
		       DCB_CAP_DCBX_VER_IEEE;
		break;
	default:
		*cap = false;
		ret = EOPNOTSUPP;
		break;
	}
	return ret;
}

static int nfp_nic_dcbnl_getnumtcs(struct net_device *dev,
				   int tcs_id, u8 *num)
{
	switch (tcs_id) {
	case DCB_NUMTCS_ATTR_PG:
	case DCB_NUMTCS_ATTR_PFC:
		*num = NFP_NET_CEE_MAX_PGS;
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

static u8 nfp_nic_dcbnl_getpfcstate(struct net_device *dev)
{
	struct nfp_net *nn = netdev_priv(dev);
	struct nfp_dcb *dcb;
	u8 *base_offset;
	u8 pfc_en;

	dcb = get_dcb_priv(nn);
	if (!(dcb->dcb_cap & NFP_DCB_PFC_ENABLE))
		return NFP_CEE_STATE_DOWN;

	base_offset = dcb->dcbcfg_tbl + dcb->cfg_offset;
	pfc_en  = readb(base_offset + NFP_DCB_DATA_OFF_PFC);
	return pfc_en ? NFP_CEE_STATE_UP : NFP_CEE_STATE_DOWN;
}

static u8 nfp_nic_dcbnl_getdcbx(struct net_device *dev)
{
	struct nfp_net *nn = netdev_priv(dev);
	struct nfp_dcb *dcb;

	dcb = get_dcb_priv(nn);
	return dcb->dcbx_cap;
}

/**
 * set required DCBx capability
 * @netdev: the corresponding netdev
 * @mode: new DCB mode managed or CEE+IEEE
 *
 * Set DCBx capability features
 **/
static u8 nfp_nic_dcbnl_setdcbx(struct net_device *dev, u8 mode)
{
	struct nfp_net *nn = netdev_priv(dev);
	struct nfp_dcb *dcb;

	dcb = get_dcb_priv(nn);
	/* No support for LLD MANAGED */
	if (mode & DCB_CAP_DCBX_LLD_MANAGED)
		return NFP_DCB_STATUS_ERROR;

	dcb->dcbx_cap = mode;
	return NFP_DCB_STATUS_SUCCESS;
}

static const struct dcbnl_rtnl_ops nfp_nic_dcbnl_ops = {
	/* ieee 802.1Qaz std */
	.ieee_getets	= nfp_nic_dcbnl_ieee_getets,
	.ieee_setets	= nfp_nic_dcbnl_ieee_setets,
	.ieee_getmaxrate = nfp_nic_dcbnl_ieee_getmaxrate,
	.ieee_setmaxrate = nfp_nic_dcbnl_ieee_setmaxrate,
	.ieee_getpfc	= nfp_nic_dcbnl_ieee_getpfc,
	.ieee_setpfc	= nfp_nic_dcbnl_ieee_setpfc,
	.ieee_setapp	= nfp_nic_dcbnl_ieee_setapp,
	.ieee_delapp	= nfp_nic_dcbnl_ieee_delapp,

	/* CEE std */
	.getstate	= nfp_nic_dcbnl_cee_getstate,
	.setstate	= nfp_nic_dcbnl_cee_setstate,
	.setall		= nfp_nic_dcbnl_setall,
	.setpgtccfgtx	= nfp_nic_dcbnl_setpgtccfgtx,
	.getpgtccfgtx	= nfp_nic_dcbnl_getpgtccfgtx,
	.setpgbwgcfgtx	= nfp_nic_dcbnl_setpgbwgcfgtx,
	.getpgbwgcfgtx	= nfp_nic_dcbnl_getpgbwgcfgtx,
	.setpfccfg	= nfp_nic_dcbnl_setpfccfg,
	.getpfccfg	= nfp_nic_dcbnl_getpfccfg,
	.getcap		= nfp_nic_dcbnl_getcap,
	.getnumtcs	= nfp_nic_dcbnl_getnumtcs,
	.getpfcstate	= nfp_nic_dcbnl_getpfcstate,
	.getdcbx	= nfp_nic_dcbnl_getdcbx,
	.setdcbx	= nfp_nic_dcbnl_setdcbx,
};

int nfp_nic_dcb_init(struct nfp_net *nn)
{
	struct nfp_app *app = nn->app;
	struct nfp_dcb *dcb;
	unsigned int i;
	int err;

	dcb = get_dcb_priv(nn);
	dcb->cfg_offset = NFP_DCB_CFG_STRIDE * nn->id;
	dcb->dcbcfg_tbl = nfp_pf_map_rtsym(app->pf, "net.dcbcfg_tbl",
					   "_abi_dcb_cfg",
					   dcb->cfg_offset, &dcb->dcbcfg_tbl_area);
	if (IS_ERR(dcb->dcbcfg_tbl)) {
		if (PTR_ERR(dcb->dcbcfg_tbl) != -ENOENT) {
			err = PTR_ERR(dcb->dcbcfg_tbl);
			dcb->dcbcfg_tbl = NULL;
			nfp_err(app->cpp,
				"Failed to map dcbcfg_tbl area, min_size %u.\n",
				dcb->cfg_offset);
			return err;
		}
		dcb->dcbcfg_tbl = NULL;
	}

	if (dcb->dcbcfg_tbl) {
		for (i = 0; i < IEEE_8021QAZ_MAX_TCS; i++) {
			dcb->prio2tc[i] = i;
			dcb->tc2idx[i] = i;
			dcb->tc_tx_pct[i] = 0;
			dcb->tc_maxrate[i] = 0;
			dcb->tc_tsa[i] = IEEE_8021QAZ_TSA_STRICT;
		}
		err = nfp_nic_ieee_ets_init(nn, dcb);
		if (err)
			dcb->ets_init = false;
		dcb->dcbx_cap = DCB_CAP_DCBX_VER_CEE | DCB_CAP_DCBX_HOST |
				DCB_CAP_DCBX_VER_IEEE;
		dcb->trust_status = NFP_DCB_TRUST_INVALID;
		dcb->rate_init = false;
		dcb->dcb_cap = readb(dcb->dcbcfg_tbl + dcb->cfg_offset + NFP_DCB_DATA_OFF_CAP);
		nn->dp.netdev->dcbnl_ops = &nfp_nic_dcbnl_ops;
	}

	return 0;
}

void nfp_nic_dcb_clean(struct nfp_net *nn)
{
	struct nfp_dcb *dcb;

	dcb = get_dcb_priv(nn);
	if (dcb->dcbcfg_tbl_area)
		nfp_cpp_area_release_free(dcb->dcbcfg_tbl_area);
}
