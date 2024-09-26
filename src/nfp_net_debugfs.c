// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright (C) 2015-2019 Netronome Systems, Inc. */

#include "nfp_net_compat.h"

#include <linux/debugfs.h>
#include <linux/module.h>
#include <linux/rtnetlink.h>

#include "nfp_main.h"
#include "nfp_net.h"
#include "nfp_net_dp.h"
#include "nfpcore/nfp_cpp.h"

#ifdef CONFIG_DCB
#include "nfp_app.h"
#include "nic/main.h"
#endif

static struct dentry *nfp_dir;

#ifdef CONFIG_DCB
static int nfp_lldp_dcbx_show(struct seq_file *file, void *data)
{
	struct nfp_dcbx_config *remote_dcbcfg;
	struct nfp_net *nn = file->private;
	struct nfp_dcb *dcb;
	int i;

	remote_dcbcfg = &((struct nfp_app_nic_private *)nn->app_priv)->remote_dcbx;
	dcb = &((struct nfp_app_nic_private *)nn->app_priv)->dcb;

	rtnl_lock();

	/* local ets configuration */
	for (i = 0; i < NFP_NET_MAX_TC; i++) {
		seq_printf(file, "port ets_rec : %d dscp2prio: %d prio_tc=%d \
			   tc_index=%d tc_maxrate %llu tx_pct = %d tctsa=%d\n",
			   i, dcb->dscp2prio[i], dcb->prio2tc[i],
			   dcb->tc2idx[i], dcb->tc_maxrate[i],
			   dcb->tc_tx_pct[i], dcb->tc_tsa[i]);
	}

	/* Peer TLV DCBX data of ets */
	seq_printf(file, "remote port ets_cfg: willing=%d cbs=%d, maxtcs=%d\n",
		   remote_dcbcfg->etscfg.willing, remote_dcbcfg->etscfg.cbs,
		   remote_dcbcfg->etscfg.maxtcs);

	for (i = 0; i < NFP_NET_MAX_TC; i++) {
		seq_printf(file, "remote port ets_cfg: %d prio_tc=%d tcbw=%d tctsa=%d\n",
			   i, remote_dcbcfg->etscfg.prioritytable[i],
			   remote_dcbcfg->etscfg.tcbwtable[i],
			   remote_dcbcfg->etscfg.tsatable[i]);
	}

	for (i = 0; i < NFP_NET_MAX_TC; i++) {
		seq_printf(file, "remote port ets_rec: %d prio_tc=%d tcbw=%d tctsa=%d\n",
			   i, remote_dcbcfg->etsrec.prioritytable[i],
			   remote_dcbcfg->etsrec.tcbwtable[i],
			   remote_dcbcfg->etsrec.tsatable[i]);
	}

	/* Peer TLV DCBX data of pfc */
	seq_printf(file, "remote port pfc_cfg: willing=%d mbc=%d, pfccap=%d pfcenable=0x%x\n",
		   remote_dcbcfg->pfc.willing, remote_dcbcfg->pfc.mbc, remote_dcbcfg->pfc.pfccap,
		   remote_dcbcfg->pfc.pfcenable);

	/* Peer TLV DCBX data of app */
	seq_printf(file, "remote port app_table: num_apps=%d\n",
		   remote_dcbcfg->numapps);
	for (i = 0; i < remote_dcbcfg->numapps; i++) {
		seq_printf(file, "remote port app_table: %d prio=%d selector=%d protocol=0x%x\n",
			   i, remote_dcbcfg->app[i].priority,
			   remote_dcbcfg->app[i].selector,
			   remote_dcbcfg->app[i].protocolid);
	}
	seq_putc(file, '\n');
	rtnl_unlock();
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(nfp_lldp_dcbx);
#endif

static int nfp_rx_q_show(struct seq_file *file, void *data)
{
	struct nfp_net_r_vector *r_vec = file->private;
	struct nfp_net_rx_ring *rx_ring;
	int fl_rd_p, fl_wr_p, rxd_cnt;
	struct nfp_net_rx_desc *rxd;
	struct nfp_net *nn;
	void *frag;
	int i;

	rtnl_lock();

	if (!r_vec->nfp_net || !r_vec->rx_ring)
		goto out;
	nn = r_vec->nfp_net;
	rx_ring = r_vec->rx_ring;
	if (!nfp_net_running(nn))
		goto out;

	rxd_cnt = rx_ring->cnt;

	fl_rd_p = nfp_qcp_rd_ptr_read(rx_ring->qcp_fl);
	fl_wr_p = nfp_qcp_wr_ptr_read(rx_ring->qcp_fl);

	seq_printf(file, "RX[%02d,%02d]: cnt=%u dma=%pad host=%p   H_RD=%u H_WR=%u FL_RD=%u FL_WR=%u\n",
		   rx_ring->idx, rx_ring->fl_qcidx,
		   rx_ring->cnt, &rx_ring->dma, rx_ring->rxds,
		   rx_ring->rd_p, rx_ring->wr_p, fl_rd_p, fl_wr_p);

	for (i = 0; i < rxd_cnt; i++) {
		rxd = &rx_ring->rxds[i];
		seq_printf(file, "%04d: 0x%08x 0x%08x", i,
			   rxd->vals[0], rxd->vals[1]);

		if (!r_vec->xsk_pool) {
			frag = READ_ONCE(rx_ring->rxbufs[i].frag);
			if (frag)
				seq_printf(file, " frag=%p", frag);

			if (rx_ring->rxbufs[i].dma_addr)
				seq_printf(file, " dma_addr=%pad",
					   &rx_ring->rxbufs[i].dma_addr);
		} else {
			if (rx_ring->xsk_rxbufs[i].dma_addr)
				seq_printf(file, " dma_addr=%pad",
					   &rx_ring->xsk_rxbufs[i].dma_addr);
		}

		if (i == rx_ring->rd_p % rxd_cnt)
			seq_puts(file, " H_RD ");
		if (i == rx_ring->wr_p % rxd_cnt)
			seq_puts(file, " H_WR ");
		if (i == fl_rd_p % rxd_cnt)
			seq_puts(file, " FL_RD");
		if (i == fl_wr_p % rxd_cnt)
			seq_puts(file, " FL_WR");

		seq_putc(file, '\n');
	}
out:
	rtnl_unlock();
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(nfp_rx_q);

static int nfp_tx_q_show(struct seq_file *file, void *data);
DEFINE_SHOW_ATTRIBUTE(nfp_tx_q);

static int nfp_tx_q_show(struct seq_file *file, void *data)
{
	struct nfp_net_r_vector *r_vec = file->private;
	struct nfp_net_tx_ring *tx_ring;
	struct nfp_net *nn;
	int d_rd_p, d_wr_p;

	rtnl_lock();

	if (debugfs_real_fops(file->file) == &nfp_tx_q_fops)
		tx_ring = r_vec->tx_ring;
	else
		tx_ring = r_vec->xdp_ring;
	if (!r_vec->nfp_net || !tx_ring)
		goto out;
	nn = r_vec->nfp_net;
	if (!nfp_net_running(nn))
		goto out;

	d_rd_p = nfp_qcp_rd_ptr_read(tx_ring->qcp_q);
	d_wr_p = nfp_qcp_wr_ptr_read(tx_ring->qcp_q);

	seq_printf(file, "TX[%02d,%02d%s]: cnt=%u dma=%pad host=%p   H_RD=%u H_WR=%u D_RD=%u D_WR=%u",
		   tx_ring->idx, tx_ring->qcidx,
		   tx_ring == r_vec->tx_ring ? "" : "xdp",
		   tx_ring->cnt, &tx_ring->dma, tx_ring->txds,
		   tx_ring->rd_p, tx_ring->wr_p, d_rd_p, d_wr_p);
	if (tx_ring->txrwb)
		seq_printf(file, " TXRWB=%llu", *tx_ring->txrwb);
	seq_putc(file, '\n');

	nfp_net_debugfs_print_tx_descs(file, &nn->dp, r_vec, tx_ring,
				       d_rd_p, d_wr_p);
out:
	rtnl_unlock();
	return 0;
}

#if COMPAT__HAVE_XDP
static int nfp_xdp_q_show(struct seq_file *file, void *data)
{
	return nfp_tx_q_show(file, data);
}
DEFINE_SHOW_ATTRIBUTE(nfp_xdp_q);
#endif

void nfp_net_debugfs_vnic_add(struct nfp_net *nn, struct dentry *ddir)
{
	struct dentry *queues, *tx, *rx, *xdp;
	char name[20];
	int i;

	if (IS_ERR_OR_NULL(nfp_dir))
		return;

#ifdef CONFIG_DCB
	debugfs_create_file("lldp-dcbx", 0400, ddir, nn, &nfp_lldp_dcbx_fops);
#endif

	if (nfp_net_is_data_vnic(nn))
		sprintf(name, "vnic%d", nn->id);
	else
		strcpy(name, "ctrl-vnic");
	nn->debugfs_dir = debugfs_create_dir(name, ddir);
	if (IS_ERR_OR_NULL(nn->debugfs_dir))
		return;

	/* Create queue debugging sub-tree */
	queues = debugfs_create_dir("queue", nn->debugfs_dir);
	if (IS_ERR_OR_NULL(queues))
		return;

	rx = debugfs_create_dir("rx", queues);
	tx = debugfs_create_dir("tx", queues);
	xdp = debugfs_create_dir("xdp", queues);
	if (IS_ERR_OR_NULL(rx) || IS_ERR_OR_NULL(tx) || IS_ERR_OR_NULL(xdp))
		return;

	for (i = 0; i < min(nn->max_rx_rings, nn->max_r_vecs); i++) {
		sprintf(name, "%d", i);
		debugfs_create_file(name, 0400, rx,
				    &nn->r_vecs[i], &nfp_rx_q_fops);
#if COMPAT__HAVE_XDP
		debugfs_create_file(name, 0400, xdp,
				    &nn->r_vecs[i], &nfp_xdp_q_fops);
#endif
	}

	for (i = 0; i < min(nn->max_tx_rings, nn->max_r_vecs); i++) {
		sprintf(name, "%d", i);
		debugfs_create_file(name, 0400, tx,
				    &nn->r_vecs[i], &nfp_tx_q_fops);
	}
}

static ssize_t nfp_dev_cpp_read_state(struct file *file, char __user *buffer,
				      size_t count, loff_t *ppos)
{
	struct nfp_pf *pf = file->private_data;
	int bytes_not_copied;
	char buf[8];
	int len;

	/* don't allow partial reads */
	if (*ppos != 0)
		return 0;

	/* Return boolean state to user */
	len = snprintf(buf, sizeof(buf), "%u\n", !!pf->nfp_dev_cpp);
	bytes_not_copied = copy_to_user(buffer, buf, len);

	if (bytes_not_copied)
		return -EFAULT;

	*ppos = len;
	return len;
}

static ssize_t nfp_dev_cpp_set_state(struct file *file,
				     const char __user *buffer,
				     size_t count, loff_t *ppos)
{
	struct nfp_pf *pf = file->private_data;
	bool cpp_requested;
	int err;

	/* Don't allow partial writes */
	if (*ppos != 0)
		return 0;

	err = kstrtobool_from_user(buffer, count, &cpp_requested);
	if (err)
		return err;

	if (cpp_requested && !pf->nfp_dev_cpp) {
		pf->nfp_dev_cpp = nfp_platform_device_register(pf->cpp, NFP_DEV_CPP_TYPE);
	} else if (!cpp_requested && pf->nfp_dev_cpp) {
		nfp_platform_device_unregister(pf->nfp_dev_cpp);
		pf->nfp_dev_cpp = NULL;
	}

	return count;
}

static const struct file_operations nfp_dev_cpp_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = nfp_dev_cpp_read_state,
	.write = nfp_dev_cpp_set_state,
};

struct dentry *nfp_net_debugfs_device_add(struct pci_dev *pdev,
					  struct nfp_pf *pf)
{
	struct dentry *dev_dir;

	if (IS_ERR_OR_NULL(nfp_dir))
		return NULL;

	dev_dir = debugfs_create_dir(pci_name(pdev), nfp_dir);
	if (IS_ERR_OR_NULL(dev_dir))
		return NULL;

	if (pf)
		debugfs_create_file("nfp_dev_cpp", 0600, dev_dir, pf,
				    &nfp_dev_cpp_fops);

	return dev_dir;
}

void nfp_net_debugfs_dir_clean(struct dentry **dir)
{
	debugfs_remove_recursive(*dir);
	*dir = NULL;
}

void nfp_net_debugfs_create(void)
{
	nfp_dir = debugfs_create_dir("nfp_net", NULL);
}

void nfp_net_debugfs_destroy(void)
{
	debugfs_remove_recursive(nfp_dir);
	nfp_dir = NULL;
}
