/*
 * Copyright (c) 2015, Netronome, Inc. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <linux/module.h>
#include <linux/idr.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/pci.h>

#include <rdma/ib_verbs.h>
#include <rdma/ib_user_verbs.h>

#include "nfp_roce.h"
#include "netro_ib.h"
#include "netro_hw.h"
#include "netro_verbs.h"
#include "netro_ucif.h"
#include "netro_util.h"
#include "nfp_plat.h"

#define DRV_NAME	NETRO_IB_HCA_DRV_NAME
#define DRV_VERSION	"0.5"
#define DRV_RELDATE	"May 5, 2022"

MODULE_AUTHOR("Netronome Inc.");
MODULE_DESCRIPTION("Netronome NFP RoCEv2 HCA provider driver");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_VERSION(DRV_VERSION);

static DEFINE_IDR(netro_dev_id);
static const char netro_version[] =
	DRV_NAME ": Netronome NFP RoCEv2 HCA provider driver"
	DRV_VERSION " (" DRV_RELDATE ")\n";

/*
 * Prior to having working/integrated EQ interrupts use the following
 * flag to control using event driven command mode.
 *
 * NOTE: For delivery 2, it is sufficient for the NFP driver to just
 * allocate additional MSI vectors to then set this variable. When
 * we convert to MSI-X we will need the new registration interface.
 */
static bool have_interrupts = false;
module_param(have_interrupts, bool, 0444);
MODULE_PARM_DESC(have_interrupts, "During bring-up, allows selective use of "
		"event driven command mode (default: false)");

/**
 * Load device capabilities/attributes.
 *
 * @ndev: The RoCE IB device.
 *
 * Returns 0 on success, otherwise an error.
 */
static int netro_load_hca_attr(struct netro_ibdev *ndev)
{
	struct netro_query_ucode_attr	attr;
	struct netro_dev_cap_param	*cap;
	int ret;

	/*
	 * We execute a microcode no-op command here just to verify
	 * the operation of the command interface with microcode
	 * without using mailboxes.
	 */
	ret = netro_noop(ndev);
	if (ret) {
		netro_dev_info(ndev, "Ucode command I/F not working %d", ret);
		return ret;
	}

	ret = netro_query_ucode(ndev, &attr);
	if (ret) {
		netro_dev_info(ndev, "Query ucode cmd failed %d\n", ret);
		return ret;
	}

	/*
	* Initialize microcode supported capabilities for the device,
	* noting and setting reasonable limit over-rides during
	* the development process.
	*/
	ndev->cap.cmdif_abi_rev = le16_to_cpu(attr.cmd_abi_rev);
	ndev->cap.build_id = ((u64) le32_to_cpu(attr.build_id_high)) << 32 |
			le32_to_cpu(attr.build_id_low);
	ndev->cap.uc_maj_rev = le16_to_cpu(attr.maj_rev);
	ndev->cap.uc_min_rev = le16_to_cpu(attr.min_rev);
	ndev->cap.max_cmds_out = le16_to_cpu(attr.max_cmds_out);
	if (ndev->cap.max_cmds_out <= 0) {
		netro_dev_err(ndev, "Microcode must support > 0 commands\n");
		return -EINVAL;
	}
	ndev->cap.uc_mhz_clock = le32_to_cpu(attr.mhz_clock);
	netro_dev_info(ndev, "UCode firmware:%d.%d\n",
			ndev->cap.uc_maj_rev, ndev->cap.uc_min_rev);

	cap = kmalloc(sizeof(*cap), GFP_KERNEL);
	if (!cap) {
		netro_dev_info(ndev, "kmalloc failure\n");
		return -ENOMEM;
	}

	/* Get dev capacity from firmware */
	ret = netro_query_dev_cap(ndev, cap);
	if (ret) {
		netro_dev_info(ndev, "Query device capabilities"
			       " cmd failed %d\n", ret);
		goto free_mem;
	}

	ndev->cap.opt_flags = cap->flags;

	if (ndev->cap.opt_flags & NETRO_DEV_CAP_FLAG_RC)
		netro_dev_info(ndev, "RC supported in ucode\n");
	if (ndev->cap.opt_flags & NETRO_DEV_CAP_FLAG_UD)
		netro_dev_info(ndev, "UD supported in ucode\n");
	if (ndev->cap.opt_flags & NETRO_DEV_CAP_FLAG_UC)
		netro_dev_info(ndev, "UC supported in ucode\n");
	if (ndev->cap.opt_flags & NETRO_DEV_CAP_FLAG_XRC)
		netro_dev_info(ndev, "XRC supported in ucode\n");
	if (ndev->cap.opt_flags & NETRO_DEV_CAP_FLAG_PHYS)
		netro_dev_info(ndev, "PHYS supported in ucode\n");
	if (ndev->cap.opt_flags & NETRO_DEV_CAP_FLAG_FRMR)
		netro_dev_info(ndev, "FRMR supported in ucode\n");
	if (ndev->cap.opt_flags & NETRO_DEV_CAP_FLAG_MW)
		netro_dev_info(ndev, "MW supported in ucode\n");
	if (ndev->cap.opt_flags & NETRO_DEV_CAP_FLAG_SRQ)
		netro_dev_info(ndev, "SRQ supported in ucode\n");

	ndev->cap.n_ports = (cap->ports_rsvd >> NETRO_DEV_CAP_PORT_SHIFT) &
				NETRO_DEV_CAP_PORT_MASK;
	/*
     * NFP Ethernet only supports 1 port right now so we restrict
     * microcode to a single port.
    */
	if (ndev->cap.n_ports > 1) {
		netro_dev_warn(ndev, "Limiting port count from %d to %d\n",
						ndev->cap.n_ports, 1);
		ndev->cap.n_ports = 1;
	}

	ndev->cap.bs_size_mb = le16_to_cpu(cap->req_bs_size_mb);

	if (ndev->cap.bs_size_mb < 1) {
		netro_dev_err(ndev, "Specified BS size %d MB < 1 MB\n",
				ndev->cap.bs_size_mb);
		ret = -EINVAL;
		goto free_mem;
	}

	if (cap->max_mpt <= 0) {
		netro_dev_err(ndev, "Specified Max MPT %d < 1\n",
				cap->max_mpt);
		ret = -EINVAL;
		goto free_mem;
	}
	ndev->cap.max_mpt = cap->max_mpt;

	if (cap->max_mtt <= 0) {
		netro_warn("Specified Max MTT %d < 1\n", cap->max_mtt);
		ret = -EINVAL;
		goto free_mem;
	}
	ndev->cap.max_mtt = cap->max_mtt;

	ndev->cap.vlan_table_size = 1 << cap->vlan_table_size_log2;

	/* Must have at least 1 source MAC */
	if (cap->smac_table_size < 1) {
		netro_dev_err(ndev, "Specified SMAC table size %d < 1\n",
						cap->smac_table_size);
		ret = -EINVAL;
		goto free_mem;
	}
	ndev->cap.smac_table_size = cap->smac_table_size;

	if (cap->sgid_table_size < 2) {
		netro_dev_err(ndev, "Specified source GID table size "
			       "%d < 2\n", cap->sgid_table_size);
		ret = -EINVAL;
		goto free_mem;
	}
	ndev->cap.sgid_table_size = cap->sgid_table_size;

	if (ndev->cap.sgid_table_size > NETRO_IB_MAX_GID_TABLE_SIZE) {
		netro_warn("Specified SGID table size capped to %d entries\n",
				NETRO_IB_MAX_GID_TABLE_SIZE);
		ndev->cap.sgid_table_size = NETRO_IB_MAX_GID_TABLE_SIZE;
	}

	if (cap->max_uar_pages_log2 < 1) {
		netro_dev_err(ndev, "Specified UAR pages log2 %d < %d\n",
				cap->max_uar_pages_log2, 1);
		ret = -EINVAL;
		goto free_mem;
	}

	ndev->cap.max_uar_pages = 1 << cap->max_uar_pages_log2;
	ndev->cap.min_page_size = 1 << cap->min_page_size_log2;
	ndev->cap.max_swqe_size = 1 << cap->max_swqe_size_log2;
	ndev->cap.max_rwqe_size = 1 << cap->max_rwqe_size_log2;
	ndev->cap.max_srq_rwqe_size = 1 << cap->max_srq_wr_log2;

	if (cap->rsvd_qp < ndev->cap.n_ports) {
		netro_dev_err(ndev, "Reserved QP count %d < port count  %d\n",
				cap->rsvd_qp, ndev->cap.n_ports);
		ret = -EINVAL;
		goto free_mem;
	}
	ndev->cap.rsvd_qp = cap->rsvd_qp;

	if (cap->max_eq_log2 > 3) {
		netro_warn("Specified max EQ log2 numer %d capped to %d\n",
				cap->max_eq_log2, 3);
		cap->max_eq_log2 = 3;
	}
	if (cap->max_eq_log2 < 0) {
		netro_dev_err(ndev, "Specified max EQ log2 %d less than 0\n",
				cap->max_eq_log2);
		ret = -EINVAL;
		goto free_mem;
	}
	ndev->cap.max_eq = 1 << cap->max_eq_log2;

	if (cap->cqe_size_log2 != 5) {
		netro_dev_err(ndev, "Specified CQE size log2 incorrect: %d\n",
				cap->cqe_size_log2);
		ret = -EINVAL;
		goto free_mem;
	}

	ndev->cap.cqe_size = 1 << cap->cqe_size_log2;

	/*
	 * Microcode is setting the maximum EQ log2 num entries too small,
	 * adjust to something reasonable.  This should be removed when
	 * microcode correctly sets a reasonable value.
	 */
	if (cap->max_eqe_log2 < 12) {
		netro_warn("Specified max EQE log2 size unreasonable: %d, "
				"adjusting to %d\n", cap->cqe_size_log2, 12);
		cap->max_eqe_log2 = 12;
	}

	if (cap->max_eqe_log2 < 12) {
		netro_dev_err(ndev, "Specified EQE log2 size %d too small\n",
				cap->max_eqe_log2);
		ret = -EINVAL;
		goto free_mem;
	}
	ndev->cap.max_eqe = 1 << cap->max_eqe_log2;

	if (cap->eqe_size_log2 != 4) {
		netro_dev_err(ndev, "Specified EQE size log2 incorrect: %d\n",
				cap->eqe_size_log2);
		ret = -EINVAL;
		goto free_mem;
	}
	ndev->cap.eqe_size = 1 << cap->eqe_size_log2;

	ndev->cap.max_inline_data = le16_to_cpu(cap->max_inline_data);
	ndev->cap.ib.fw_ver = ((u64)ndev->cap.uc_maj_rev) << 32 |
			ndev->cap.uc_min_rev;
	ndev->cap.ib.hw_ver = 0;

	netro_mac_to_guid(ndev->nfp_info->def_mac, 0xFFFF,
			(u8 *)&ndev->cap.ib.sys_image_guid);
	ndev->cap.ib.max_mr_size = 1ull << cap->max_mr_size_log2;
	ndev->cap.ib.vendor_id = ndev->nfp_info->pdev->vendor;
	ndev->cap.ib.vendor_part_id = ndev->nfp_info->pdev->device;
	ndev->cap.ib.page_size_cap = 0x0ffff000ull; /* 4K to 16M */

	ndev->cap.ib.device_cap_flags = IB_DEVICE_RC_RNR_NAK_GEN |
				IB_DEVICE_SHUTDOWN_PORT |
				IB_DEVICE_SYS_IMAGE_GUID |
				IB_DEVICE_MEM_MGT_EXTENSIONS;

	ndev->cap.ib.max_qp = 1 << cap->max_qp_log2;
	ndev->cap.ib.max_qp_wr = 1 << cap->max_qp_wr_log2;
	ndev->cap.ib.max_send_sge = cap->max_sq_sge;
	ndev->cap.ib.max_recv_sge = cap->max_sq_sge;
	ndev->cap.ib.max_sge_rd = cap->max_rq_sge;
	ndev->cap.ib.max_cq = 1 << cap->max_cq_log2;

	if (cap->max_cqe_log2 < 12) {
		netro_dev_err(ndev, "Specified max CQE log2 %d < %d\n",
				cap->max_cqe_log2, 12);
		ret = -EINVAL;
		goto free_mem;
	}

	ndev->cap.ib.max_cqe = 1 << cap->max_cqe_log2;
	ndev->cap.ib.max_mr = cap->max_mpt;
	ndev->cap.ib.max_pd = NETRO_IB_MAX_PD;
	ndev->cap.ib.max_qp_rd_atom = 1 << cap->max_qp_rsp_res_log2;
	ndev->cap.ib.max_ee_rd_atom = 0;
	ndev->cap.ib.max_res_rd_atom =  1 << cap->max_rdma_res_log2;
	ndev->cap.ib.max_qp_init_rd_atom = 1 << cap->max_qp_req_res_log2;
	ndev->cap.ib.max_ee_init_rd_atom = 0;

	/* No support for atomics in initial release */
	ndev->cap.ib.atomic_cap = 0;
	ndev->cap.ib.masked_atomic_cap = 0;

	ndev->cap.ib.max_ee = 0;
	ndev->cap.ib.max_rdd = 0;
	ndev->cap.ib.max_mw = 0;
	ndev->cap.ib.max_raw_ipv6_qp = 0;
	ndev->cap.ib.max_raw_ethy_qp = 0;

	ndev->cap.ib.max_mcast_grp = 1 << cap->max_mcg_log2;
	ndev->cap.ib.max_mcast_qp_attach = 1 << cap->max_mcg_qp_log2;

	/*
	 * TODO: circle back with microcode and see if we need to
	 * to add this limit or if it is grp*qp.
	 */
	ndev->cap.ib.max_total_mcast_qp_attach = ndev->cap.ib.max_mcast_grp *
				ndev->cap.ib.max_mcast_qp_attach;

	ndev->cap.ib.max_ah = NETRO_IB_MAX_AH;

#if (!(VER_NON_RHEL_GE(5,8) || VER_RHEL_GE(8,0)))
	/* Don't support old style fast memory registration */
	ndev->cap.ib.max_fmr = 0;
	ndev->cap.ib.max_map_per_fmr = 0;
#endif

	ndev->cap.ib.max_srq = 1 << cap->max_srq_log2;
	ndev->cap.ib.max_srq_wr = 1 << cap->max_srq_wr_log2;
	ndev->cap.ib.max_srq_sge = ndev->cap.ib.max_sge_rd;

	/*
	 * TODO: circle back with microcode, probably need to add
	 * a maximum to device capabilities that they will support.
	 * Although I could also calculate from SWQE size.
	 */
	ndev->cap.ib.max_fast_reg_page_list_len = 0;

	ndev->cap.ib.max_pkeys = NETRO_IB_MAX_PKEY;

	/*
	 * TODO: Either agree with microcode what this value will
	 * be or add it to device capabilities. Delay value is
	 * computed as 4.096us * 2^(local_ca_ack_delay), and
	 * represents the expected maximum time for timeouts.
	 */
	ndev->cap.ib.local_ca_ack_delay = 4;

	/* Get hardware board/build ID */
	ret = netro_query_nic(ndev, &ndev->cap.board_id);
	if (ret)
		netro_dev_info(ndev, "Query nic cmd failed %d\n", ret);

free_mem:
	kfree(cap);
	return ret;
}

/**
 * Create microcode backing store memory.
 *
 * @ndev: The RoCE IB device.
 *
 * Returns 0 on success, otherwise an error.
 */
static int netro_create_bs(struct netro_ibdev *ndev)
{
	struct netro_mem *bs_mem;
	int ret;

	netro_dev_info(ndev, "Ucode requested %d MBytes of BS\n",
			ndev->cap.bs_size_mb);

	/* Non-coherent memory for use by microcode */
	bs_mem = netro_alloc_dma_mem(ndev, false, NETRO_MEM_DEFAULT_ORDER,
			ndev->cap.bs_size_mb << 20);
	if (IS_ERR(bs_mem)) {
		netro_dev_err(ndev, "Unable to allocate BS memory\n");
		return -ENOMEM;
	}
	ndev->bs_mem = bs_mem;

	netro_info("BS size       %d\n", bs_mem->tot_len);
	netro_info("BS num allocs %d\n", bs_mem->num_allocs);
	netro_info("BS min order  %d\n", bs_mem->min_order);
	netro_info("BS num SG     %d\n", bs_mem->num_sg);
	netro_info("BS needs      %d MTT entries\n", bs_mem->num_mtt);
	netro_info("BS MTT ndx    %d\n", bs_mem->base_mtt_ndx);

	/*
	 * It is a requirement that backing store entries start at the
	 * base of the MTT entries, i.e. backing store must be the
	 * first allocation.
	 */
	if (bs_mem->base_mtt_ndx) {
		netro_err("BS MTT base index must be 0, base %d\n",
				bs_mem->base_mtt_ndx);
		ret = -EINVAL;
		goto free_mem;
	}

	/*
	 * Set backing store parameters in microcode, reserving MTT
	 * entries. Write MTT for backing store translation and enable
	 * backing store.
	 */
	ret = netro_set_bs_mem_size(ndev, bs_mem->num_mtt,
			bs_mem->min_order, bs_mem->tot_len >> 20);
	if (ret) {
		netro_info("netro_set_bs_mem_size returned %d\n", ret);
		goto free_mem;
	}

	ret = netro_mtt_write_sg(ndev, bs_mem->alloc, bs_mem->num_sg,
			bs_mem->base_mtt_ndx, bs_mem->num_mtt,
			bs_mem->min_order + PAGE_SHIFT,
			bs_mem->num_sg, 0);
	if (ret) {
		netro_info("netro_mtt_write_sg returned %d\n", ret);
		goto free_mem;
	}

	netro_info("SG virtual addr for alloc 0:%p\n",
			sg_virt(&bs_mem->alloc[0]));
	ret = netro_bs_map_mem(ndev,  (0xFF8ull << 48),
			bs_mem->tot_len >> 20, bs_mem->num_mtt,
			bs_mem->min_order);
	if (ret) {
		netro_info("netro_map_bs_mem returned %d\n", ret);
		goto free_mem;
	}
	return 0;

free_mem:
	netro_free_dma_mem(ndev, ndev->bs_mem);
	ndev->bs_mem = NULL;
	return ret;
}

/**
 * Cleanup microcode backing store memory.
 *
 * @ndev: The RoCE IB device.
 *
 * Returns 0 on success, otherwise an error.
 */
static void netro_cleanup_bs(struct netro_ibdev *ndev)
{
	int ret;

	/*
	 * Notify microcode to no longer access backing store memory,
	 * then free the physical pages backing it. An error would only
	 * occur if microcode was non-operational.
	 */
	ret = netro_bs_unmap_mem(ndev);
	if (ret)
		netro_dev_warn(ndev, "netro_unmap_bs_mem cmd error %d\n", ret);

	netro_free_dma_mem(ndev, ndev->bs_mem);
	ndev->bs_mem = NULL;
	return;
}

/**
 * Shutdown EQ's and release EQ resources.
 *
 * @ndev: The RoCE IB device.
 *
 * Returns 0 on success, otherwise an error.
 */
static void netro_free_eqs(struct netro_ibdev *ndev)
{
	int i;

	for (i = 0; i < ndev->eq_table.num_eq; i++)
		netro_cleanup_eq(ndev, i);

	ndev->eq_table.num_eq = 0;
	kfree(ndev->eq_table.eq);
	return;
}

/**
 * Allocate EQ table and initial EQ's.
 *
 * @ndev: The RoCE IB device.
 *
 * Returns 0 on success, otherwise an error.
 */
static int netro_create_eqs(struct netro_ibdev *ndev)
{
	int num_eq;
	u32 events;
	int err;
	int i;

	/*
	 * The maximum number of EQ is limited by:
	 *   1. MSI/MSI-X vectors available.
	 *   2. Number of on-line CPUs.
	 *   3. The maximum number supported by microcode load.
	 */
	num_eq =  min_t(u32, ndev->nfp_info->num_vectors, num_online_cpus());
	num_eq = min_t(u32, num_eq, ndev->cap.max_eq);

	netro_info("Number of EQ to be used %d\n", num_eq);

	ndev->eq_table.eq = kcalloc(num_eq, sizeof(struct netro_eq),
				GFP_KERNEL);
	if (!ndev->eq_table.eq) {
		netro_warn("Unable to allocate EQ table memory\n");
		return -ENOMEM;
	}

	for (i = 0; i < num_eq; i++) {
		events = (i == 0) ? NETRO_EQ_ASYNC_EVENTS : 0;
		if (num_eq == 1 || i > 0)
			events |= NETRO_EQ_COMPLETION_EVENTS;

		/* Pass device interrupt and OS vector */
		err = netro_init_eq(ndev, i, NETRO_EQ_ENTRIES_LOG2,
				ndev->nfp_info->msix[i].entry,
				ndev->nfp_info->msix[i].vector,
				events);
		if (err)
			goto free_eq;
		ndev->eq_table.num_eq++;
	}
	return 0;

free_eq:
	/* netro_free_eqs only frees allocated EQs */
	netro_free_eqs(ndev);
	return err;
}

static ssize_t show_hca_type(struct device *device,
		struct device_attribute *attr, char *buf)
{
	struct netro_ibdev *ndev = dev_get_drvdata(device);

	return scnprintf(buf, PAGE_SIZE, "0x%08X\n", ndev->nfp_info->model);
}

static ssize_t show_hw_rev(struct device *device,
		struct device_attribute *attr, char *buf)
{
	struct netro_ibdev *ndev = dev_get_drvdata(device);

	return scnprintf(buf, PAGE_SIZE, "%d\n", ndev->nfp_info ?
                    ndev->nfp_info->model : 0);
}

static ssize_t show_board(struct device *device, struct device_attribute *attr,
			  char *buf)
{
	struct netro_ibdev *ndev = dev_get_drvdata(device);
	return scnprintf(buf, PAGE_SIZE, "%d\n", ndev->cap.board_id);
}

static ssize_t exec_command_db(struct device *device,
		struct device_attribute *attr, const char *buf, size_t count)
{
	struct netro_ibdev *ndev = dev_get_drvdata(device);
	corigine_set_cq_db(ndev, 0, false);
	return count;
}

static ssize_t dump_uc_gid(struct device *device,
                struct device_attribute *attr, char *buf)
{
	struct netro_ibdev *ndev = dev_get_drvdata(device);
	struct netro_gid_entry *entries;
	struct netro_gid_entry *entry;
	size_t cnt = 0;
	int i, j;
	int err;

	netro_info("Dump UCODE GID Entries (Table Size %d)\n",
					ndev->port[0].gid_table_size);

	entries = kcalloc(ndev->port[0].gid_table_size,
					sizeof(*entry), GFP_KERNEL);
	if (!entries)
		goto out;

	err = netro_read_sgid_table(ndev, 1, entries,
					ndev->port[0].gid_table_size);
	if (err)
		goto free_mem;

	for (i = 0, entry = entries; i < ndev->port[0].gid_table_size;
					i++, entry++) {
		cnt += scnprintf(buf + cnt, PAGE_SIZE - cnt,
						"%d: Valid (%d), Type: (%d) GID: (", i,
						entry->valid, entry->type);

		for (j = 0; j < 16; j++)
			cnt += scnprintf(buf + cnt, PAGE_SIZE - cnt, "%02X",
							entry->gid.raw[j]);
		cnt += scnprintf(buf + cnt, PAGE_SIZE - cnt, ")%s", "\n");
	}
free_mem:
        kfree(entries);
out:
        return cnt;
}

/**
 * Debug helper to initiate commands through sysfs
 *
 * Echo "opcode" to file /sys/class/infiniband/netro_#/command
 */
static ssize_t exec_command(struct device *device,
		struct device_attribute *attr, const char *buf, size_t count)
{
	struct netro_ibdev *ndev = dev_get_drvdata(device);
	struct netro_query_ucode_attr ucode_attr;
	struct netro_dev_cap_param *cap;
	int opcode;
	int err;
	int i;
	uint32_t outparm;

	netro_info("Issue hard-coded command %s\n", buf);
	err = kstrtoint(buf, 0, &opcode);
	if (err) {
		netro_warn("%s is not valid form\n", buf);
		return -EINVAL;
	}
	switch (opcode) {
	case NETRO_CMD_NO_OP:
		netro_info("%s supported\n", netro_opcode_to_str(opcode));
		err = netro_noop(ndev);
		break;
	case NETRO_CMD_QUERY_UCODE:
		netro_info("%s supported\n", netro_opcode_to_str(opcode));
		err = netro_query_ucode(ndev, &ucode_attr);
		break;
	case NETRO_CMD_QUERY_DEV_CAP:
		netro_info("%s supported\n", netro_opcode_to_str(opcode));
		cap = kmalloc(sizeof(*cap), GFP_KERNEL);
		if (!cap) {
			netro_info("kmalloc failure\n");
			return -ENOMEM;
		}
		err = netro_query_dev_cap(ndev, cap);
		kfree(cap);
		break;
	case NETRO_CMD_QUERY_NIC:
		netro_info("%s supported\n", netro_opcode_to_str(opcode));
		err = netro_query_nic(ndev, &outparm);
		break;
	case NETRO_CMD_SET_BS_HOST_MEM_SIZE:
	case NETRO_CMD_MAP_BS_HOST_MEM:
	case NETRO_CMD_MTT_WRITE:
	case NETRO_CMD_UNMAP_BS_HOST_MEM:
		netro_info("%s not directly supported, use "
				"NETRO_CMD_SET_BS_HOST_MEM_SIZE\n",
				netro_opcode_to_str(opcode));
		break;
	case NETRO_CMD_HCA_ENABLE:
		netro_info("%s supported\n", netro_opcode_to_str(opcode));
		err = netro_hca_enable(ndev);
		break;
	case NETRO_CMD_HCA_DISABLE:
		netro_info("%s supported\n", netro_opcode_to_str(opcode));
		netro_hca_disable(ndev);
		err = 0;
		break;
	case NETRO_CMD_ROCE_PORT_ENABLE:
		netro_info("%s supported\n", netro_opcode_to_str(opcode));
		for (i = 0, err = 0; i < ndev->cap.n_ports && !err; i++)
			err = netro_port_enable_cmd(ndev, i);
		break;
	case NETRO_CMD_ROCE_PORT_DISABLE:
		netro_info("%s supported\n", netro_opcode_to_str(opcode));
		for (i = 0; i < ndev->cap.n_ports; i++)
			netro_port_disable_cmd(ndev, i);
		err = 0;
		break;
	case 0xCD:
		netro_info("Initiate test EQ enqueue command test\n");
		err = netro_test_eq_enqueue(ndev, 1, 20);
		break;
	default:
		netro_warn("%s is not supported\n",
				netro_opcode_to_str(opcode));
		return -EINVAL;
	}
	netro_info("%s returned %d\n", netro_opcode_to_str(opcode), err);
	return count;
}

static DEVICE_ATTR(hw_rev,   S_IRUGO, show_hw_rev,    NULL);
static DEVICE_ATTR(hca_type, S_IRUGO, show_hca_type,    NULL);
static DEVICE_ATTR(board_id, S_IRUGO, show_board,  NULL);
static DEVICE_ATTR(command,  S_IWUSR | S_IWGRP, NULL, exec_command);
static DEVICE_ATTR(testdb,   S_IWUSR | S_IWGRP, NULL, exec_command_db);
static DEVICE_ATTR(uc_gid, S_IRUGO, dump_uc_gid, NULL);

static struct device_attribute *netro_class_attrs[] = {
	&dev_attr_hw_rev,
	&dev_attr_hca_type,
	&dev_attr_board_id,
	&dev_attr_testdb,
	&dev_attr_command,
	&dev_attr_uc_gid,
};

static int netro_init_maps(struct netro_ibdev *ndev)
{
	if (netro_init_bitmap(&ndev->uar_map, 0,
				ndev->cap.max_uar_pages - 1)) {
		netro_dev_info(ndev, "Unable to allocate UAR map\n");
		return -ENOMEM;
	}
	netro_info("Allocate UAR bitmap min %d, max %d\n",
		0, ndev->cap.max_uar_pages - 1);

	if (netro_init_bitmap(&ndev->mpt_map, 0, ndev->cap.max_mpt - 1)) {
		netro_dev_info(ndev, "Unable to allocate MPT map\n");
		goto cleanup_uar;
	}
	netro_info("Allocate MPT bitmap min %d, max %d\n",
		0, ndev->cap.max_mpt - 1);

	if (netro_init_bitmap(&ndev->mtt_map, 0, ndev->cap.max_mtt - 1)) {
		netro_dev_info(ndev, "Unable to allocate MTT map\n");
		goto cleanup_mpt;
	}
	netro_info("Allocate MTT bitmap min %d, max %d\n",
		0, ndev->cap.max_mtt - 1);

	/* Start at PD index value of 1 */
	if (netro_init_bitmap(&ndev->pd_map, 1, ndev->cap.ib.max_pd - 1)) {
		netro_dev_info(ndev, "Unable to allocate PD map\n");
		goto cleanup_mtt;
	}
	netro_info("Allocate PD bitmap min %d, max %d\n",
		0, ndev->cap.ib.max_pd - 1);

	/* Start at CQ index value of 1 */
	if (netro_init_bitmap(&ndev->cq_map, 1, ndev->cap.ib.max_cq - 1)) {
		netro_dev_info(ndev, "Unable to allocate CQ map\n");
		goto cleanup_pd;
	}
	netro_info("Allocate CQ bitmap min %d, max %d\n",
		1, ndev->cap.ib.max_cq - 1);
	ndev->cq_table = kcalloc(ndev->cap.ib.max_cq,
				sizeof(struct netro_cq *), GFP_KERNEL);
	if (!ndev->cq_table) {
		netro_dev_info(ndev, "Unable to allocate CQ ID to CQ map\n");
		goto cleanup_cq;
	}

	/*
     * Skip over QP numbers reserved for special QP use and/or special
     * QP numbers reserved for SMI/GSI.
     */
	if (netro_init_bitmap(&ndev->qp_map,
				max(2, ndev->cap.rsvd_qp),
				ndev->cap.ib.max_qp - 1)) {
		netro_dev_info(ndev, "Unable to allocate QP map\n");
		goto cleanup_cq_mem;
	}
	netro_info("Allocate QP bitmap min %d, max %d\n",
		2, ndev->cap.ib.max_qp - 1);
	INIT_RADIX_TREE(&ndev->qp_tree, GFP_ATOMIC);

	return 0;

cleanup_cq_mem:
	kfree(ndev->cq_table);
cleanup_cq:
	netro_cleanup_bitmap(&ndev->cq_map);
cleanup_pd:
	netro_cleanup_bitmap(&ndev->pd_map);
cleanup_mtt:
	netro_cleanup_bitmap(&ndev->mtt_map);
cleanup_mpt:
	netro_cleanup_bitmap(&ndev->mpt_map);
cleanup_uar:
	netro_cleanup_bitmap(&ndev->uar_map);
	return -ENOMEM;
}

static void netro_cleanup_maps(struct netro_ibdev *ndev)
{
	netro_info("=== netro_cleanup_maps ===  \n");
	netro_info("Cleanup QP bitmap \n");
	netro_cleanup_bitmap(&ndev->qp_map);
	netro_info("Free CQ Table \n");
	kfree(ndev->cq_table);
	netro_info("Cleanup CQ bitmap \n");
	netro_cleanup_bitmap(&ndev->cq_map);
	netro_info("Cleanup PD bitmap \n");
	netro_cleanup_bitmap(&ndev->pd_map);
	netro_info("Cleanup MTT bitmap \n");
	netro_cleanup_bitmap(&ndev->mtt_map);
	netro_info("Cleanup MAPT bitmap \n");
	netro_cleanup_bitmap(&ndev->mpt_map);
	netro_info("Cleanup UAR bitmap \n");
	netro_cleanup_bitmap(&ndev->uar_map);
	netro_info("=== netro_cleanup_maps done===  \n");
	return;
}

/**
 * Initialize state of HCA port
 *
 * @ndev: The RoCE IB device.
 * @port_num: The port number to initialize [1 based].
 *
 * Returns 0 on success, other wise error code.
 */
static int netro_init_port(struct netro_ibdev *ndev, int port_num)
{
	struct netro_port *port = &ndev->port[port_num];

	netro_debug("Initialize netro device port %d\n", port_num + 1);

	if (port_num >= NETRO_MAX_PORTS) {
		netro_dev_warn(ndev, "Port number out of range: %d\n",
						port_num);
		return -EINVAL;
	}
	port->netdev = ndev->nfp_info->netdev[port_num];
	if (!port->netdev) {
		netro_dev_warn(ndev, "net_device not set: %d\n",
						port_num);
		return -EINVAL;
	}
	port->gid_table_size = ndev->cap.sgid_table_size;
	port->mac_table_size = ndev->cap.smac_table_size;

	/* Initialize the port's address tables */
	spin_lock_init(&port->table_lock);
	memcpy(port->mac, port->netdev->dev_addr, ETH_ALEN);
	netro_init_sgid_table(ndev, port_num);
	netro_init_smac_table(ndev, port_num);

	spin_lock_init(&port->qp1_lock);
	return 0;
}

/**
 * Cleanup state of HCA port
 *
 * @ndev: The RoCE IB device.
 * @port_num: The port number to cleanup [0 based].
 */
static void netro_cleanup_port(struct netro_ibdev *ndev, int port_num)
{
	netro_debug("Cleanup netro port %d\n", port_num);
	return;
}

/**
 * Initialize HCA
 *
 * @ndev: The RoCE IB device.
 *
 * Returns 0 on success, otherwise an error.
 */
static int netro_init_hca(struct netro_ibdev *ndev)
{
	int	ret;
	int port;
	int j;

	INIT_LIST_HEAD(&ndev->ctxt_list);
	spin_lock_init(&ndev->ctxt_lock);
	ndev->numa_node = dev_to_node(&ndev->nfp_info->pdev->dev);

	ret = netro_acquire_pci_resources(ndev);
	if (ret)
		return ret;

	if (netro_init_cmdif(ndev))
		goto free_pci_resources;

	if (netro_load_hca_attr(ndev))
		goto free_pci_resources;

	if (netro_init_maps(ndev))
		goto free_pci_resources;

	/*
	 * For some chipset families the first UAR is required for
	 * EQ doorbells so allocate it now.  Also allocate a second
	 * UAR for priveleged SQ/CQ usage.
	 */
	spin_lock_init(&ndev->priv_uar_lock);
	if (netro_alloc_uar(ndev, &ndev->priv_eq_uar))
		goto cleanup_maps;
	netro_info("Reserved EQ UAR page index: %d\n", ndev->priv_eq_uar.index);
	ndev->priv_eq_uar.map = ioremap(ndev->db_paddr + (PAGE_SIZE *
					ndev->priv_eq_uar.index), PAGE_SIZE);
	if (!ndev->priv_eq_uar.map)
		goto cleanup_maps;
	netro_info("Reserved EQ UAR mapped addr: %p\n", ndev->priv_eq_uar.map);

	if (NFP_CPP_MODEL_IS_3800(ndev->nfp_info->model)) {
		ndev->priv_uar.index = ndev->priv_eq_uar.index;
		ndev->priv_uar.map = ndev->priv_eq_uar.map;
	} else {
		if (netro_alloc_uar(ndev, &ndev->priv_uar))
			goto cleanup_eq_uar;
		ndev->priv_uar.map = ioremap(ndev->db_paddr + (PAGE_SIZE *
						ndev->priv_uar.index), PAGE_SIZE);
		if (!ndev->priv_uar.map)
			goto cleanup_eq_uar;
	}
	netro_info("Reserved SQ/CQ UAR page %d\n", ndev->priv_uar.index);
	netro_info("Reserved UAR mapped: %p\n", ndev->priv_uar.map);
	if (netro_hca_enable(ndev))
		goto cleanup_uar;
	if (netro_create_bs(ndev))
		goto hca_disable;
	if (netro_create_eqs(ndev))
		goto free_bs;
	if (netro_init_event_cmdif(ndev))
		goto free_eqs;

	ndev->ibdev.phys_port_cnt = ndev->cap.n_ports;
	for (port = 0; port < ndev->cap.n_ports; port++)
		if (netro_init_port(ndev, port))
				goto cleanup_ports;

	return 0;

cleanup_ports:
	for (j = 0; j < port; j++)
		netro_cleanup_port(ndev, j);
free_eqs:
	netro_free_eqs(ndev);
free_bs:
	netro_cleanup_bs(ndev);
hca_disable:
	netro_hca_disable(ndev);
cleanup_uar:
        if (NFP_CPP_MODEL_IS_3800(ndev->nfp_info->model)) {
            ndev->priv_uar.map = NULL;
            ndev->priv_uar.index = 0;
        } else {
            netro_free_uar(ndev, &ndev->priv_uar);
        }
cleanup_eq_uar:
	netro_free_uar(ndev, &ndev->priv_eq_uar);
cleanup_maps:
	netro_cleanup_maps(ndev);
free_pci_resources:
	netro_free_pci_resources(ndev);
	return -1;
}

/**
 * Final cleanup of HCA resources.
 *
 * @ndev: The RoCE IB device.
 */
static void netro_cleanup_hca(struct netro_ibdev *ndev)
{
	int ret;
	int port;

	netro_info("Cleanup HCA\n");

	for (port = 0; port < ndev->cap.n_ports; port++)
		netro_cleanup_port(ndev, port);

	/*
	 * Turn-off event driven commands and shutdown EQ processing before
	 * releasing EQ resources
	 */
	netro_cleanup_event_cmdif(ndev);
	netro_free_eqs(ndev);

	if (ndev->bs_mem)
		netro_cleanup_bs(ndev);

	ret = netro_hca_disable(ndev);
	if (ret)
		netro_warn("HCA disable failed\n");

	if (NFP_CPP_MODEL_IS_3800(ndev->nfp_info->model)) {
		ndev->priv_uar.map = NULL;
		ndev->priv_uar.index = 0;
	} else {
		netro_free_uar(ndev, &ndev->priv_uar);
	}
	netro_free_uar(ndev, &ndev->priv_eq_uar);
	netro_cleanup_maps(ndev);
	netro_free_pci_resources(ndev);
}

/**
 * Create an netro IB device for the NFP device information
 * provided.
 *
 * @info: Pointer to the NFP NIC provided device/RoCE information.
 *
 * Returns the new netro RoCE IB device, or NULL on error.
 */
static struct netro_ibdev *netro_add_dev(struct nfp_roce_info *info)
{
	struct netro_ibdev *ndev;
	int size;
	int i;
	int j;

	pr_info("netro_add_dev: info %p\n", info);

	/* The following test is for initial bring-up only, then remove */
	if (unlikely(!info)) {
		netro_err("Null NFP info passed\n");
		return NULL;
	}
	size = sizeof(*info) + info->num_vectors *
				sizeof(struct msix_entry);

	/*
	 * The following test is for initial bring-up only, then remove.
	 * Note: right now not all parameters are provided.
	 */
	if (!info->pdev || !info->cmdif || info->db_base == 0) {
		netro_err("Required NFP info parameter is NULL\n");
		return NULL;
	}

	ndev = (struct netro_ibdev *) ib_alloc_device(
				sizeof(struct netro_ibdev));
	if (!ndev) {
		netro_err("IB device allocation failed\n");
		return NULL;
	}
	ndev->nfp_info = kmalloc(size, GFP_KERNEL);
	if (!ndev->nfp_info) {
		netro_err("NFP Information memory allocation failed\n");
		goto err_free_dev;
	}
	memcpy(ndev->nfp_info, info, size);

	netro_info("info->ndetdev[0] = %p\n", ndev->nfp_info->netdev[0]);
	netro_info("info->num_vectors = %d\n", ndev->nfp_info->num_vectors);
	netro_dev_info(ndev, "NFP PCI device %p\n", ndev->nfp_info->pdev);
	netro_info("PCIDev->dma_mask:0x%016llx\n",
			ndev->nfp_info->pdev->dma_mask);
	netro_info("PCIDev->msix_enabled:%d\n",
			ndev->nfp_info->pdev->msix_enabled);
	netro_info("PCIDev->msi_enabled:%d\n",
			ndev->nfp_info->pdev->msi_enabled);
	netro_info("PCIDev->irq:%d\n", ndev->nfp_info->pdev->irq);
	ndev->have_interrupts = have_interrupts;

	ndev->id = idr_alloc(&netro_dev_id, NULL, 0, 0, GFP_KERNEL);
	if (ndev->id < 0)
		goto err_free_info;

	if (netro_set_chip_details(ndev, ndev->nfp_info->model))
		goto err_free_idr;

	if (netro_init_hca(ndev))
		goto  err_free_idr;

	ndev->ibdev.phys_port_cnt = ndev->cap.n_ports;
	
	if (netro_register_verbs(ndev))
		goto err_cleanup_hca;

	if (netro_init_net_notifiers(ndev))
		goto err_unregister_verbs;

	for (i = 0; i < ARRAY_SIZE(netro_class_attrs); i++)
		if (device_create_file(&ndev->ibdev.dev, netro_class_attrs[i]))
			goto err_sysfs;
	return ndev;

err_sysfs:
	for (j = 0; j < i; j++)
		device_remove_file(&ndev->ibdev.dev, netro_class_attrs[j]);
	netro_cleanup_net_notifiers(ndev);
err_unregister_verbs:
	netro_unregister_verbs(ndev);
err_cleanup_hca:
	netro_cleanup_hca(ndev);
err_free_idr:
	idr_remove(&netro_dev_id, ndev->id);
err_free_info:
	kfree(ndev->nfp_info);
err_free_dev:
	ib_dealloc_device(&ndev->ibdev);
	return NULL;
}

static void netro_remove_dev(struct netro_ibdev *ndev)
{
	int i;

	pr_info("netro_remove_dev: ndev %p\n", ndev);

	for (i = 0; i < ARRAY_SIZE(netro_class_attrs); i++)
		device_remove_file(&ndev->ibdev.dev, netro_class_attrs[i]);

	netro_cleanup_net_notifiers(ndev);
	netro_unregister_verbs(ndev);
	netro_cleanup_hca(ndev);
	idr_remove(&netro_dev_id, ndev->id);
	kfree(ndev->nfp_info);
	ib_dealloc_device(&ndev->ibdev);
}

/**
 * NFP Notifier callback event handler.
 *
 * @ndev: The RoCE IB device.
 * @port: Port number associated with event.
 * @state: The state associated with the event.
 */
static void netro_event_notifier(struct netro_ibdev *ndev,
			int port, u32 state)
{
	if (!ndev)
		return;

	netro_dev_info(ndev, "NFP Event, port %d, state %d\n",
			port, state);
}

static struct nfp_roce_drv netro_drv = {
	.abi_version	= NETRO_ROCE_ABI_VERSION,
	.add_device	= netro_add_dev,
	.remove_device	= netro_remove_dev,
	.event_notifier	= netro_event_notifier,
};

static int __init netro_init(void)
{
	pr_info("netro_init: calling nfp_register_roce_driver\n");
	return nfp_register_roce_driver(&netro_drv);
}

static void __exit netro_cleanup(void)
{
	pr_info("netro_init: calling nfp_unregister_roce_driver\n");
	nfp_unregister_roce_driver(&netro_drv);
	return;
}

module_init(netro_init);
module_exit(netro_cleanup);
