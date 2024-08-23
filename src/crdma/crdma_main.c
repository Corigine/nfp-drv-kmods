// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright (C) 2023 Corigine, Inc. */

#include <linux/module.h>
#include <linux/idr.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/pci.h>
#include <net/addrconf.h>

#ifdef KERNEL_SUPPORT_AUXI
#include <linux/auxiliary_bus.h>
#endif

#include <rdma/ib_verbs.h>
#include <rdma/ib_user_verbs.h>

#include "nfpcore/nfp_roce.h"
#include "crdma_ib.h"
#include "crdma_hw.h"
#include "crdma_verbs.h"
#include "crdma_ucif.h"
#include "crdma_util.h"
#include "crdma_bond.h"

#define DRV_NAME	CRDMA_IB_HCA_DRV_NAME
#define DRV_VERSION	"0.5"
#define DRV_RELDATE	"May 5, 2022"

MODULE_AUTHOR("Corigine Inc.");
MODULE_DESCRIPTION("Corigine NFP RoCEv2 HCA provider driver");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_VERSION(DRV_VERSION);

static DEFINE_IDR(crdma_dev_id);

DEFINE_MUTEX(crdma_global_mutex);

#ifdef KERNEL_SUPPORT_AUXI
LIST_HEAD(rdma_device_list);
static DEFINE_MUTEX(rdma_device_list_mutex);
#endif

/*
 * Prior to having working/integrated EQ interrupts use the following
 * flag to control using event driven command mode.
 *
 * NOTE: For delivery 2, it is sufficient for the NFP driver to just
 * allocate additional MSI vectors to then set this variable. When
 * we convert to MSI-X we will need the new registration interface.
 */
static bool have_interrupts = true;
module_param(have_interrupts, bool, 0444);
MODULE_PARM_DESC(have_interrupts, "During bring-up, allows selective use of event driven command mode (default: false)");

/*
 * DCQCN is a typical congestion control protocol used for RoCEv2,
 * which can promote RoCEv2's performance when traffic crowds.
 */
bool dcqcn_enable;
module_param(dcqcn_enable, bool, 0444);
MODULE_PARM_DESC(dcqcn_enable, "During bring-up, allows selective use of setting dcqcn enable (default: false)");

/*
 * OOO retransmit for RoCEv2.
 */
bool retrans_ooo_enable = true;
module_param(retrans_ooo_enable, bool, 0444);
MODULE_PARM_DESC(retrans_ooo_enable, "During bring-up, allows selective use of setting ooo retransmit enable (default: true)");

/*
 * Timeout retransmit for RoCEv2.
 */
bool retrans_timeout_enable = true;
module_param(retrans_timeout_enable, bool, 0444);
MODULE_PARM_DESC(retrans_timeout_enable, "During bring-up, allows selective use of setting timeout retransmit enable (default: true)");

/*
 * High performance of bidirectional READ for RoCEv2.
 */
bool high_perf_read_enable = false;
module_param(high_perf_read_enable, bool, 0444);
MODULE_PARM_DESC(high_perf_read_enable, "During bring-up, allows high performance of bidirectional READ(default: false)");

/**
 * Load device capabilities/attributes.
 *
 * @dev: The RoCE IB device.
 *
 * Returns 0 on success, otherwise an error.
 */
static int crdma_load_hca_attr(struct crdma_ibdev *dev)
{
	struct crdma_query_ucode_attr	attr;
	struct crdma_dev_cap_param	*cap;
	int ret;

	/*
	 * We execute a microcode no-op command here just to verify
	 * the operation of the command interface with microcode
	 * without using mailboxes.
	 */
	ret = crdma_noop(dev);
	if (ret) {
		crdma_dev_info(dev, "Ucode command I/F not working %d", ret);
		return ret;
	}

	ret = crdma_query_ucode(dev, &attr);
	if (ret) {
		crdma_dev_info(dev, "Query ucode cmd failed %d\n", ret);
		return ret;
	}

	/*
	 * Initialize microcode supported capabilities for the device,
	 * noting and setting reasonable limit over-rides during
	 * the development process.
	 */
	dev->cap.cmdif_abi_rev = le16_to_cpu(attr.cmd_abi_rev);
	dev->cap.build_id = ((u64) le32_to_cpu(attr.build_id_high)) << 32 |
			le32_to_cpu(attr.build_id_low);
	dev->cap.uc_maj_rev = le16_to_cpu(attr.maj_rev);
	dev->cap.uc_min_rev = le16_to_cpu(attr.min_rev);
	dev->cap.max_cmds_out = le16_to_cpu(attr.max_cmds_out);
	if (dev->cap.max_cmds_out <= 0) {
		crdma_dev_err(dev, "Microcode must support > 0 commands\n");
		return -EINVAL;
	}
	dev->cap.uc_mhz_clock = le32_to_cpu(attr.mhz_clock);

	cap = kzalloc(sizeof(*cap), GFP_KERNEL);
	if (!cap)
		return -ENOMEM;

	/* Get dev capacity from firmware */
	ret = crdma_query_dev_cap(dev, cap);
	if (ret) {
		crdma_dev_warn(dev, "Query device capabilities failed %d\n",
			ret);
		goto free_mem;
	}

	dev->cap.opt_flags = cap->flags;
	dev->cap.n_ports = (cap->ports_rsvd >> CRDMA_DEV_CAP_PORT_SHIFT) &
				CRDMA_DEV_CAP_PORT_MASK;
	/*
	 * NFP Ethernet only supports 1 port right now so we restrict
	 * microcode to a single port.
	 */
	if (dev->cap.n_ports > 1) {
		crdma_dev_warn(dev, "Limiting port count from %d to %d\n",
						dev->cap.n_ports, 1);
		dev->cap.n_ports = 1;
	}

	dev->cap.bs_size_mb = le16_to_cpu(cap->req_bs_size_mb);

	if (dev->cap.bs_size_mb < 1) {
		crdma_dev_err(dev, "Specified BS size %d MB < 1 MB\n",
				dev->cap.bs_size_mb);
		ret = -EINVAL;
		goto free_mem;
	}

	if (cap->max_mpt <= 0) {
		crdma_dev_err(dev, "Specified Max MPT %d < 1\n",
				cap->max_mpt);
		ret = -EINVAL;
		goto free_mem;
	}
	dev->cap.max_mpt = cap->max_mpt;

	if (cap->max_mtt <= 0) {
		crdma_dev_warn(dev, "Specified Max MTT %d < 1\n",
			cap->max_mtt);
		ret = -EINVAL;
		goto free_mem;
	}
	dev->cap.max_mtt = cap->max_mtt;

	dev->cap.vlan_table_size = 1 << cap->vlan_table_size_log2;

	/* Must have at least 1 source MAC */
	if (cap->smac_table_size < 1) {
		crdma_dev_err(dev, "Specified SMAC table size %d < 1\n",
						cap->smac_table_size);
		ret = -EINVAL;
		goto free_mem;
	}
	dev->cap.smac_table_size = cap->smac_table_size;

	if (cap->sgid_table_size < 2) {
		crdma_dev_err(dev, "Specified source GID table size %d < 2\n",
			cap->sgid_table_size);
		ret = -EINVAL;
		goto free_mem;
	}
	dev->cap.sgid_table_size = cap->sgid_table_size;

	if (dev->cap.sgid_table_size > CRDMA_IB_MAX_GID_TABLE_SIZE) {
		crdma_dev_warn(dev, "Specified SGID table size capped to %d\n",
				CRDMA_IB_MAX_GID_TABLE_SIZE);
		dev->cap.sgid_table_size = CRDMA_IB_MAX_GID_TABLE_SIZE;
	}

	if (cap->max_uar_pages_log2 < 1) {
		crdma_dev_err(dev, "Specified UAR pages log2 %d < %d\n",
				cap->max_uar_pages_log2, 1);
		ret = -EINVAL;
		goto free_mem;
	}
	/* For single PF card, the roce firmware split
	 * the doorbell space (64 pages total) equally
	 * to each vnic(32 pages per vnic) and the doorbell
	 * page number is used to determine which vnic generated
	 * doorbell. This wil result the wrong PF no in roce
	 * firmware for multi PF card, so reduce the uar pages to
	 * compatibility the single PF for multi PF card.
	 */
	if (dev->info->pdev->multifunction)
		dev->cap.max_uar_pages = 1 << (cap->max_uar_pages_log2 - 1);
	else
		dev->cap.max_uar_pages = 1 << cap->max_uar_pages_log2;
	dev->cap.min_page_size = 1 << cap->min_page_size_log2;
	dev->cap.max_swqe_size = 1 << cap->max_swqe_size_log2;
	dev->cap.max_rwqe_size = 1 << cap->max_rwqe_size_log2;
	dev->cap.max_srq_rwqe_size = 1 << cap->max_srq_wr_log2;

	if (cap->rsvd_qp < dev->cap.n_ports) {
		crdma_dev_err(dev, "Reserved QP count %d < port count  %d\n",
				cap->rsvd_qp, dev->cap.n_ports);
		ret = -EINVAL;
		goto free_mem;
	}
	dev->cap.rsvd_qp = cap->rsvd_qp;

	if (cap->max_eq_log2 > 3) {
		crdma_dev_warn(dev,
			"Specified max EQ log2 numer %d capped to %d\n",
			cap->max_eq_log2, 3);
		cap->max_eq_log2 = 3;
	}

	dev->cap.max_eq = 1 << cap->max_eq_log2;

	if (cap->cqe_size_log2 != 5) {
		crdma_dev_err(dev,
			"Specified CQE size log2 incorrect: %d\n",
			cap->cqe_size_log2);
		ret = -EINVAL;
		goto free_mem;
	}

	dev->cap.cqe_size = 1 << cap->cqe_size_log2;
	dev->cap.max_eqe = 1 << cap->max_eqe_log2;

	if (cap->eqe_size_log2 != 4) {
		crdma_dev_err(dev, "Specified EQE size log2 incorrect: %d\n",
				cap->eqe_size_log2);
		ret = -EINVAL;
		goto free_mem;
	}
	dev->cap.eqe_size = 1 << cap->eqe_size_log2;

	dev->cap.max_inline_data = le16_to_cpu(cap->max_inline_data);
	dev->cap.ib.fw_ver = ((u64)dev->cap.uc_maj_rev) << 32 |
			dev->cap.uc_min_rev;
	dev->cap.ib.hw_ver = 0;

	addrconf_addr_eui48((u8 *)&dev->cap.ib.sys_image_guid,
				dev->info->netdev->dev_addr);
	dev->cap.ib.max_mr_size = 1ull << cap->max_mr_size_log2;
	dev->cap.ib.vendor_id = dev->info->pdev->vendor;
	dev->cap.ib.vendor_part_id = dev->info->pdev->device;
	dev->cap.ib.page_size_cap = 0x0ffff000ull; /* 4K to 16M */

	/*
	 * TODO: By now, all capacities listed is not supported by CRDMA, so
	 * we remove these. In future, the capacity supported will be added
	 * one by one.
	 */
	dev->cap.ib.device_cap_flags = IB_DEVICE_MEM_MGT_EXTENSIONS;

	dev->cap.ib.max_qp = 1 << cap->max_qp_log2;
	dev->cap.ib.max_qp_wr = 1 << cap->max_qp_wr_log2;
#if (VER_NON_RHEL_LT(4, 19) || VER_RHEL_EQ(7, 6))
	dev->cap.ib.max_sge = cap->max_sq_sge;
#else
	dev->cap.ib.max_send_sge = cap->max_sq_sge;
	dev->cap.ib.max_recv_sge = cap->max_sq_sge;
#endif
	dev->cap.ib.max_sge_rd = cap->max_rq_sge;
	dev->cap.ib.max_cq = 1 << cap->max_cq_log2;

	if (cap->max_cqe_log2 < 12) {
		crdma_dev_err(dev, "Specified max CQE log2 %d < %d\n",
				cap->max_cqe_log2, 12);
		ret = -EINVAL;
		goto free_mem;
	}

	dev->cap.ib.max_cqe = 1 << cap->max_cqe_log2;
	dev->cap.ib.max_mr = cap->max_mpt;
	dev->cap.ib.max_qp_rd_atom = 1 << cap->max_qp_rsp_res_log2;
	dev->cap.ib.max_ee_rd_atom = 0;
	dev->cap.ib.max_res_rd_atom =  1 << cap->max_rdma_res_log2;
	dev->cap.ib.max_qp_init_rd_atom = 1 << cap->max_qp_req_res_log2;
	dev->cap.ib.max_ee_init_rd_atom = 0;

	/* No support for atomics in initial release */
	dev->cap.ib.atomic_cap = 0;
	dev->cap.ib.masked_atomic_cap = 0;

	dev->cap.ib.max_ee = 0;
	dev->cap.ib.max_rdd = 0;
	dev->cap.ib.max_mw = 0;
	dev->cap.ib.max_raw_ipv6_qp = 0;
	dev->cap.ib.max_raw_ethy_qp = 0;

	/* Mcast is not supported */
	dev->cap.ib.max_mcast_grp = 0;
	dev->cap.ib.max_mcast_qp_attach = 0;
	dev->cap.ib.max_total_mcast_qp_attach = 0;

	/* Stored in driver not firmware, so specify these in driver side*/
	dev->cap.ib.max_pd = CRDMA_IB_MAX_PD;
	dev->cap.ib.max_ah = CRDMA_IB_MAX_AH;

#if (!(VER_NON_RHEL_GE(5, 8) || VER_RHEL_GE(8, 0)))
	/* Don't support old style fast memory registration */
	dev->cap.ib.max_fmr = 0;
	dev->cap.ib.max_map_per_fmr = 0;
#endif
	/* SRQ is supported */
	dev->cap.ib.max_srq = 1 << cap->max_srq_log2;
	dev->cap.ib.max_srq_wr = 1 << cap->max_srq_wr_log2;
	dev->cap.ib.max_srq_sge = 1 << cap->max_srq_rwqe_size_log2;

	/*
	 * TODO: circle back with microcode, probably need to add
	 * a maximum to device capabilities that they will support.
	 * Although I could also calculate from SWQE size.
	 */
	dev->cap.ib.max_fast_reg_page_list_len = CRDMA_IB_MAX_FAST_REG_PAGES;

	dev->cap.ib.max_pkeys = CRDMA_IB_MAX_PKEY_TABLE_SIZE;

	/*
	 * TODO: Either agree with microcode what this value will
	 * be or add it to device capabilities. Delay value is
	 * computed as 4.096us * 2^(local_ca_ack_delay), and
	 * represents the expected maximum time for timeouts.
	 */
	dev->cap.ib.local_ca_ack_delay = 4;

	/* Get hardware board/build ID */
	ret = crdma_query_nic(dev, &dev->cap.board_id);
	if (ret)
		crdma_dev_warn(dev, "Query nic cmd failed %d\n", ret);
free_mem:
	kfree(cap);
	return ret;
}

/**
 * Shutdown EQ's and release EQ resources.
 *
 * @dev: The RoCE IB device.
 *
 * Returns 0 on success, otherwise an error.
 */
static void crdma_free_eqs(struct crdma_ibdev *dev)
{
	int i;

	for (i = 0; i < dev->eq_table.num_eq; i++)
		crdma_cleanup_eq(dev, i);

	dev->eq_table.num_eq = 0;
	kfree(dev->eq_table.eq);
}

/**
 * Allocate EQ table and initial EQ's.
 *
 * @dev: The RoCE IB device.
 *
 * Returns 0 on success, otherwise an error.
 */
static int crdma_create_eqs(struct crdma_ibdev *dev)
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
	num_eq =  min_t(u32, dev->info->num_vectors, num_online_cpus());
	num_eq = min_t(u32, num_eq, dev->cap.max_eq);

	dev->eq_table.eq = kcalloc(num_eq, sizeof(struct crdma_eq),
				GFP_KERNEL);
	if (!dev->eq_table.eq)
		return -ENOMEM;

	for (i = 0; i < num_eq; i++) {
		events = (i == 0) ? CRDMA_EQ_ASYNC_EVENTS : 0;
		if (num_eq == 1 || i > 0)
			events |= CRDMA_EQ_COMPLETION_EVENTS;

		/* Pass device interrupt and OS vector */
		err = crdma_init_eq(dev, i, CRDMA_EQ_ENTRIES_LOG2,
				dev->info->msix[i].entry,
				dev->info->msix[i].vector,
				events);
		if (err)
			goto free_eq;
		dev->eq_table.num_eq++;
	}
	return 0;

free_eq:
	/* crdma_free_eqs only frees allocated EQs */
	crdma_free_eqs(dev);
	return err;
}

static ssize_t hca_type_show(struct device *device,
			     struct device_attribute *attr, char *buf)
{
#if (VER_NON_RHEL_OR_KYL_GE(5, 2) || VER_RHEL_GE(8, 0) || VER_KYL_GE(10, 3))
	struct ib_device *ibdev = container_of(device, struct ib_device, dev);
	struct crdma_ibdev *dev = to_crdma_ibdev(ibdev);
#else
	struct crdma_ibdev *dev = dev_get_drvdata(device);
#endif
	return scnprintf(buf, PAGE_SIZE, "0x%08X\n",
		dev->info->pdev->device);
}

static ssize_t hw_rev_show(struct device *device,
			   struct device_attribute *attr,
			   char *buf)
{
#if (VER_NON_RHEL_OR_KYL_GE(5, 2) || VER_RHEL_GE(8, 0) || VER_KYL_GE(10, 3))
	struct ib_device *ibdev = container_of(device, struct ib_device, dev);
	struct crdma_ibdev *dev = to_crdma_ibdev(ibdev);
#else
	struct crdma_ibdev *dev = dev_get_drvdata(device);
#endif
	return scnprintf(buf, PAGE_SIZE, "0x%x\n",
		dev->info->pdev->vendor);
}

static ssize_t board_id_show(struct device *device,
			     struct device_attribute *attr,
			     char *buf)
{
#if (VER_NON_RHEL_OR_KYL_GE(5, 2) || VER_RHEL_GE(8, 0) || VER_KYL_GE(10, 3))
	struct ib_device *ibdev = container_of(device, struct ib_device, dev);
	struct crdma_ibdev *dev = to_crdma_ibdev(ibdev);
#else
	struct crdma_ibdev *dev = dev_get_drvdata(device);
#endif
	return scnprintf(buf, PAGE_SIZE, "%d\n", dev->cap.board_id);
}

static unsigned int db_offset;
static unsigned int db_value;

static ssize_t doorbell_show(struct device *device,
			     struct device_attribute *attr,
			     char *buf)
{
	ssize_t off = 0;

	off += scnprintf(buf, PAGE_SIZE,
			"doorbell offset: 0x%x, doorbell value: 0x%x.\n",
			 db_offset, db_value);
	return off;
}

static ssize_t doorbell_store(struct device *device,
			      struct device_attribute *attr,
			      const char *buf, size_t size)
{
#if (VER_NON_RHEL_OR_KYL_GE(5, 2) || VER_RHEL_GE(8, 0) || VER_KYL_GE(10, 3))
	struct ib_device *ibdev = container_of(device, struct ib_device, dev);
	struct crdma_ibdev *cdev = to_crdma_ibdev(ibdev);
#else
	struct crdma_ibdev *cdev = dev_get_drvdata(device);
#endif
	sscanf(buf, "%x %x", &db_offset, &db_value);
	crdma_ring_db32(cdev, db_value, db_offset);
	return size;
}

static ssize_t uc_gid_show(struct device *device,
			   struct device_attribute *attr, char *buf)
{
	struct crdma_gid_entry *entries;
	struct crdma_gid_entry *entry;
	size_t cnt = 0;
	int i, j;
	int err;

#if (VER_NON_RHEL_OR_KYL_GE(5, 2) || VER_RHEL_GE(8, 0) || VER_KYL_GE(10, 3))
	struct ib_device *ibdev = container_of(device, struct ib_device, dev);
	struct crdma_ibdev *dev = to_crdma_ibdev(ibdev);
#else
	struct crdma_ibdev *dev = dev_get_drvdata(device);
#endif

	crdma_info("Dump UCODE GID Entries (Table Size %d)\n",
					dev->port.gid_table_size);

	entries = kcalloc(dev->port.gid_table_size,
					sizeof(*entry), GFP_KERNEL);
	if (!entries)
		goto out;

	err = crdma_read_sgid_table(dev, 0, entries,
					dev->port.gid_table_size);
	if (err)
		goto free_mem;

	for (i = 0, entry = entries; i < dev->port.gid_table_size;
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

static ssize_t dcqcn_enable_show(struct device *device,
		struct device_attribute *attr, char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "0x%x\n", dcqcn_enable);
}

static int crdma_init_dcqcn(struct crdma_ibdev *dev)
{
	return crdma_dcqcn_enable_cmd(dev, dcqcn_enable);
}

static ssize_t retrans_ooo_enable_show(struct device *device,
		struct device_attribute *attr, char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "0x%x\n", retrans_ooo_enable);
}

static ssize_t retrans_timeout_enable_show(struct device *device,
		struct device_attribute *attr, char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "0x%x\n", retrans_timeout_enable);
}

static int crdma_init_retrans(struct crdma_ibdev *dev)
{
	u8 retrans_enable = (retrans_ooo_enable << 4) | retrans_timeout_enable;
	return crdma_retrans_enable_cmd(dev, retrans_enable);
}

static ssize_t high_perf_read_enable_show(struct device *device,
		struct device_attribute *attr, char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "0x%x\n", high_perf_read_enable);
}

static int crdma_init_high_perf_read(struct crdma_ibdev *dev)
{
	return crdma_high_perf_read_enable_cmd(dev, high_perf_read_enable);
}

/**
 * Debug helper to initiate commands through sysfs
 *
 * Echo "opcode" to file /sys/class/infiniband/crdma_#/command
 */
static ssize_t command_store(struct device *device,
			     struct device_attribute *attr,
			     const char *buf, size_t count)
{
	struct crdma_query_ucode_attr ucode_attr;
	struct crdma_dev_cap_param *cap;
	uint32_t outparm;
	int opcode;
	int err;
	int i;

#if (VER_NON_RHEL_OR_KYL_GE(5, 2) || VER_RHEL_GE(8, 0) || VER_KYL_GE(10, 3))
	struct ib_device *ibdev = container_of(device, struct ib_device, dev);
	struct crdma_ibdev *dev = to_crdma_ibdev(ibdev);
#else
	struct crdma_ibdev *dev = dev_get_drvdata(device);
#endif
	err = kstrtoint(buf, 0, &opcode);
	if (err) {
		crdma_warn("%s is not valid form\n", buf);
		return -EINVAL;
	}
	switch (opcode) {
	case CRDMA_CMD_NO_OP:
		err = crdma_noop(dev);
		break;
	case CRDMA_CMD_QUERY_UCODE:
		err = crdma_query_ucode(dev, &ucode_attr);
		break;
	case CRDMA_CMD_QUERY_DEV_CAP:
		cap = kzalloc(sizeof(*cap), GFP_KERNEL);
		if (!cap)
			return -ENOMEM;
		err = crdma_query_dev_cap(dev, cap);
		kfree(cap);
		break;
	case CRDMA_CMD_QUERY_NIC:
		err = crdma_query_nic(dev, &outparm);
		break;
	case CRDMA_CMD_MTT_WRITE:
		crdma_info("%s not directly supported\n",
			   crdma_opcode_to_str(opcode));
		break;
	case CRDMA_CMD_HCA_ENABLE:
		err = crdma_hca_enable(dev);
		break;
	case CRDMA_CMD_HCA_DISABLE:
		crdma_hca_disable(dev);
		err = 0;
		break;
	case CRDMA_CMD_ROCE_PORT_ENABLE:
		for (i = 0, err = 0; i < dev->cap.n_ports && !err; i++)
			err = crdma_port_enable_cmd(dev, i);
		break;
	case CRDMA_CMD_ROCE_PORT_DISABLE:
		for (i = 0; i < dev->cap.n_ports; i++)
			crdma_port_disable_cmd(dev, i);
		err = 0;
		break;
	case 0xCD:
		err = crdma_test_eq_enqueue(dev, 1, 20);
		break;
	default:
		crdma_warn("%s is not supported\n",
				crdma_opcode_to_str(opcode));
		return -EINVAL;
	}

	crdma_dev_info(dev, "%s returned %d\n",
		crdma_opcode_to_str(opcode), err);

	return count;
}

static DEVICE_ATTR_RO(hw_rev);
static DEVICE_ATTR_RO(hca_type);
static DEVICE_ATTR_RO(board_id);
static DEVICE_ATTR(command,  0200, NULL, command_store);
static DEVICE_ATTR(doorbell, 0444, doorbell_show, doorbell_store);
static DEVICE_ATTR_RO(uc_gid);
static DEVICE_ATTR_RO(dcqcn_enable);
static DEVICE_ATTR_RO(retrans_ooo_enable);
static DEVICE_ATTR_RO(retrans_timeout_enable);
static DEVICE_ATTR_RO(high_perf_read_enable);

static struct device_attribute *crdma_class_attrs[] = {
	&dev_attr_hw_rev,
	&dev_attr_hca_type,
	&dev_attr_board_id,
	&dev_attr_doorbell,
	&dev_attr_command,
	&dev_attr_uc_gid,
	&dev_attr_dcqcn_enable,
	&dev_attr_retrans_ooo_enable,
	&dev_attr_retrans_timeout_enable,
	&dev_attr_high_perf_read_enable,
};

static int crdma_init_maps(struct crdma_ibdev *dev)
{
	if (crdma_init_bitmap(&dev->uar_map, 0,
				dev->cap.max_uar_pages - 1)) {
		crdma_dev_warn(dev, "Unable to allocate UAR map\n");
		return -ENOMEM;
	}

	if (crdma_init_bitmap(&dev->mpt_map, 0, dev->cap.max_mpt - 1)) {
		crdma_dev_warn(dev, "Unable to allocate MPT map\n");
		goto cleanup_uar;
	}

	if (crdma_init_bitmap(&dev->mtt_map, 0, dev->cap.max_mtt - 1)) {
		crdma_dev_warn(dev, "Unable to allocate MTT map\n");
		goto cleanup_mpt;
	}

	/* Start at PD index value of 1 */
	if (crdma_init_bitmap(&dev->pd_map, 1, dev->cap.ib.max_pd - 1)) {
		crdma_dev_warn(dev, "Unable to allocate PD map\n");
		goto cleanup_mtt;
	}

	/* Start at CQ index value of 1 */
	if (crdma_init_bitmap(&dev->cq_map, 1, dev->cap.ib.max_cq - 1)) {
		crdma_dev_warn(dev, "Unable to allocate CQ map\n");
		goto cleanup_pd;
	}
	dev->cq_table = kcalloc(dev->cap.ib.max_cq,
				sizeof(struct crdma_cq *), GFP_KERNEL);
	if (!dev->cq_table)
		goto cleanup_cq;

	/*
	 * Skip over QP numbers reserved for special QP use and/or special
	 * QP numbers reserved for SMI/GSI.
	 */
	if (crdma_init_bitmap(&dev->qp_map,
				max(2, dev->cap.rsvd_qp),
				dev->cap.ib.max_qp - 1)) {
		crdma_dev_warn(dev, "Unable to allocate QP map\n");
		goto cleanup_cq_mem;
	}

	if (crdma_init_bitmap(&dev->srq_map, 1, dev->cap.ib.max_srq - 1)) {
		crdma_dev_warn(dev, "Unable to allocate SRQ map\n");
		goto cleanup_qp_mem;
	}

	INIT_RADIX_TREE(&dev->qp_tree, GFP_ATOMIC);

	return 0;

cleanup_qp_mem:
	crdma_cleanup_bitmap(&dev->qp_map);
cleanup_cq_mem:
	kfree(dev->cq_table);
cleanup_cq:
	crdma_cleanup_bitmap(&dev->cq_map);
cleanup_pd:
	crdma_cleanup_bitmap(&dev->pd_map);
cleanup_mtt:
	crdma_cleanup_bitmap(&dev->mtt_map);
cleanup_mpt:
	crdma_cleanup_bitmap(&dev->mpt_map);
cleanup_uar:
	crdma_cleanup_bitmap(&dev->uar_map);
	return -ENOMEM;
}

static void crdma_cleanup_maps(struct crdma_ibdev *dev)
{
	crdma_cleanup_bitmap(&dev->qp_map);
	kfree(dev->cq_table);
	crdma_cleanup_bitmap(&dev->cq_map);
	crdma_cleanup_bitmap(&dev->pd_map);
	crdma_cleanup_bitmap(&dev->mtt_map);
	crdma_cleanup_bitmap(&dev->mpt_map);
	crdma_cleanup_bitmap(&dev->uar_map);
	crdma_cleanup_bitmap(&dev->srq_map);
}

/**
 * Initialize state of HCA port
 *
 * @dev: The RoCE IB device.
 *
 * Returns 0 on success, other wise error code.
 */
static int crdma_init_port(struct crdma_ibdev *dev)
{
	struct crdma_port *port = &dev->port;

	port->netdev = dev->info->netdev;
	if (!port->netdev) {
		crdma_dev_warn(dev, "net_device not set\n");
		return -EINVAL;
	}

	port->gid_table_size = dev->cap.sgid_table_size;
	port->mac_table_size = dev->cap.smac_table_size;

	/* Initialize the port's address tables */
	spin_lock_init(&port->table_lock);
	memcpy(port->mac, port->netdev->dev_addr, ETH_ALEN);
	crdma_init_smac_table(dev, 0);
	crdma_set_port_mtu_cmd(dev, 0, port->netdev->mtu);

	crdma_dev_info(dev, "The default MTU of %s is %d\n",
			port->netdev->name, port->netdev->mtu);
	return 0;
}

/**
 * Cleanup state of HCA port
 *
 * @dev: The RoCE IB device.
 * @port_num: The port number to cleanup [0 based].
 */
static void crdma_cleanup_port(struct crdma_ibdev *dev)
{
}

/**
 * Initialize HCA
 *
 * @dev: The RoCE IB device.
 *
 * Returns 0 on success, otherwise an error.
 */
static int crdma_init_hca(struct crdma_ibdev *dev)
{
	int	ret;

	INIT_LIST_HEAD(&dev->ctxt_list);
	spin_lock_init(&dev->ctxt_lock);

	ret = crdma_acquire_pci_resources(dev);
	if (ret)
		return ret;

	if (crdma_init_cmdif(dev))
		goto free_pci_resources;

	if (crdma_load_hca_attr(dev))
		goto free_pci_resources;

	if (crdma_init_maps(dev))
		goto free_pci_resources;

	/*
	 * For some chipset families the first UAR is required for
	 * EQ doorbells so allocate it now.  Also allocate a second
	 * UAR for priveleged SQ/CQ usage.
	 */
	spin_lock_init(&dev->priv_uar_lock);
	if (crdma_alloc_uar(dev, &dev->priv_eq_uar))
		goto cleanup_maps;
	dev->priv_eq_uar.map = ioremap(dev->db_paddr + (PAGE_SIZE *
					dev->priv_eq_uar.index), PAGE_SIZE);
	if (!dev->priv_eq_uar.map)
		goto cleanup_maps;

	dev->priv_uar.index = dev->priv_eq_uar.index;
	dev->priv_uar.map = dev->priv_eq_uar.map;

	if (crdma_hca_enable(dev))
		goto cleanup_uar;
	if (crdma_create_eqs(dev))
		goto hca_disable;
	if (crdma_init_event_cmdif(dev))
		goto free_eqs;

	dev->ibdev.phys_port_cnt = 1; /*only support 1 port*/
	if (crdma_init_port(dev))
		goto cleanup_ports;

	return 0;

cleanup_ports:
	crdma_cleanup_port(dev);
free_eqs:
	crdma_free_eqs(dev);
hca_disable:
	crdma_hca_disable(dev);
cleanup_uar:
	dev->priv_uar.map = NULL;
	dev->priv_uar.index = 0;
cleanup_maps:
	crdma_cleanup_maps(dev);
free_pci_resources:
	crdma_free_pci_resources(dev);
	return -1;
}

/**
 * Final cleanup of HCA resources.
 *
 * @dev: The RoCE IB device.
 */
static void crdma_cleanup_hca(struct crdma_ibdev *dev)
{
	int ret;

	crdma_cleanup_port(dev);

	/*
	 * Turn-off event driven commands and shutdown EQ processing before
	 * releasing EQ resources
	 */
	crdma_cleanup_event_cmdif(dev);
	crdma_free_eqs(dev);

	ret = crdma_hca_disable(dev);
	if (ret)
		crdma_warn("HCA disable failed\n");

	dev->priv_uar.map = NULL;
	dev->priv_uar.index = 0;

	crdma_free_uar(dev, &dev->priv_eq_uar);
	crdma_cleanup_maps(dev);
	crdma_cleanup_cmdif(dev);
	crdma_free_pci_resources(dev);
}

/**
 * Create an crdma IB device for the NFP device information
 * provided.
 *
 * @info: Pointer to the NFP NIC provided device/RoCE information.
 *
 * Returns the new crdma RoCE IB device, or NULL on error.
 */
struct crdma_ibdev *crdma_add_dev(struct crdma_res_info *info)
{
	struct crdma_ibdev *dev;
	int i;
	int j;

	/*
	 * The following test is for initial bring-up only, then remove.
	 * Note: right now not all parameters are provided.
	 */
	if (!info->pdev || !info->cmdif || info->db_base == 0) {
		crdma_err("Required NFP info parameter is NULL\n");
		return NULL;
	}

#if (VER_NON_RHEL_OR_KYL_GE(5, 1) || VER_RHEL_GE(8, 1) || VER_KYL_GE(10, 3))
	dev = ib_alloc_device(crdma_ibdev, ibdev);
#else
	dev = (struct crdma_ibdev *) ib_alloc_device(
				sizeof(struct crdma_ibdev));
#endif
	if (!dev) {
		crdma_err("IB device allocation failed\n");
		return NULL;
	}

	dev->info = info;
	crdma_dev_info(dev, "Number of Vectors       %d\n",
		dev->info->num_vectors);
	crdma_dev_info(dev, "DMA Mask                0x%016llx\n",
		dev->info->pdev->dma_mask);
	crdma_dev_info(dev, "Configure IOMEM address %p\n",
		dev->info->cmdif);
	crdma_dev_info(dev, "Doorbell DMA address    0x%016llX\n",
		dev->info->db_base);

	dev->have_interrupts = have_interrupts;

	spin_lock_init(&dev->qp_lock);

	dev->id = idr_alloc(&crdma_dev_id, NULL, 0, 0, GFP_KERNEL);
	if (dev->id < 0)
		goto err_free_dev;

	if (crdma_init_hca(dev))
		goto err_free_idr;

	if (crdma_init_net_notifiers(dev))
		goto err_cleanup_hca;
	dev->ibdev.phys_port_cnt = dev->cap.n_ports;

#if (VER_NON_RHEL_OR_KYL_GE(5, 1) || VER_RHEL_GE(8, 2) || VER_KYL_GE(10, 3))
	if (ib_device_set_netdev(&dev->ibdev, dev->info->netdev, 1))
		goto err_cleanup_net_notifiers;
#endif

	if (crdma_register_verbs(dev))
		goto err_cleanup_net_notifiers;

	if (crdma_init_dcqcn(dev))
		goto err_unregister_verbs;

	if (crdma_init_retrans(dev))
		goto err_unregister_verbs;

	if (crdma_init_high_perf_read(dev))
		goto err_unregister_verbs;

	for (i = 0; i < ARRAY_SIZE(crdma_class_attrs); i++)
		if (device_create_file(&dev->ibdev.dev, crdma_class_attrs[i]))
			goto err_sysfs;
	return dev;

err_sysfs:
	for (j = 0; j < i; j++)
		device_remove_file(&dev->ibdev.dev, crdma_class_attrs[j]);
err_unregister_verbs:
	crdma_unregister_verbs(dev);
err_cleanup_net_notifiers:
	crdma_cleanup_net_notifiers(dev);
err_cleanup_hca:
	crdma_cleanup_hca(dev);
err_free_idr:
	idr_remove(&crdma_dev_id, dev->id);
err_free_dev:
	ib_dealloc_device(&dev->ibdev);
	return NULL;
}

void crdma_remove_dev(struct crdma_ibdev *dev)
{
	int i;

	crdma_dev_info(dev, "netdev(%p) is removing.\n",
		dev->info->netdev);

	for (i = 0; i < ARRAY_SIZE(crdma_class_attrs); i++)
		device_remove_file(&dev->ibdev.dev, crdma_class_attrs[i]);

	crdma_cleanup_net_notifiers(dev);
	crdma_unregister_verbs(dev);
	crdma_cleanup_hca(dev);
	idr_remove(&crdma_dev_id, dev->id);
	ib_dealloc_device(&dev->ibdev);
}

static u32 crdma_gen_dev_pci(const struct crdma_res_info *info)
{
	struct pci_dev *pdev;

	pdev = info->pdev;
	return (u32)((pci_domain_nr(pdev->bus) << 16) |
		     (pdev->bus->number << 8) |
		     PCI_SLOT(pdev->devfn));
}

struct crdma_bond *crdma_bond_fetch_bdev(struct crdma_device_node *node)
{
	struct crdma_device_node *tmp_node;

	list_for_each_entry(tmp_node, &rdma_device_list, list) {
		if ((tmp_node == node) ||
		    (crdma_gen_dev_pci(tmp_node->info) !=
		    crdma_gen_dev_pci(node->info)) ||
		    !tmp_node->bdev)
			continue;

		return tmp_node->bdev;
	}

	return NULL;
}

#ifdef KERNEL_SUPPORT_AUXI
static const struct auxiliary_device_id crdma_auxiliary_id_table[] = {
	{.name = "nfp.roce", },
	{.name = "corigine.roce", },
	{},
};

static int crdma_probe(struct auxiliary_device *aux_dev,
		       const struct auxiliary_device_id *id)
{
	struct crdma_auxiliary_device *cadev;
	struct crdma_device_node *dev_node;
	struct crdma_ibdev *crdma_dev;
	struct crdma_res_info *info;
	int size;
	int ret;

	cadev = container_of(aux_dev, struct crdma_auxiliary_device, adev);
	if (!cadev->info) {
		pr_err("cadev->info is NULL");
		return -ENOMEM;
	}

	pr_info("crdma_probe is adding, %p\n", cadev->info->netdev);

	size = sizeof(*info) + cadev->info->num_vectors *
				sizeof(struct msix_entry);
	info = kzalloc(size, GFP_KERNEL);
	if (!info)
		return -ENOMEM;

	memcpy(info, cadev->info, size);

	dev_node = kzalloc(sizeof(*dev_node), GFP_KERNEL);
	if (!dev_node) {
		kfree(info);
		return -ENOMEM;
	}
	dev_node->info = info;

	crdma_dev = crdma_add_dev(info);
	if (!crdma_dev) {
		kfree(info);
		kfree(dev_node);
		return -ENOMEM;
	}
	dev_node->crdma_dev = crdma_dev;
	crdma_dev->dev_node = dev_node;

	ret = crdma_bond_add_ibdev(dev_node);
	if (ret) {
		crdma_remove_dev(dev_node->crdma_dev);
		kfree(info);
		kfree(dev_node);
		return -ENOMEM;
	}

	mutex_lock(&rdma_device_list_mutex);
	list_add_tail(&dev_node->list, &rdma_device_list);
	mutex_unlock(&rdma_device_list_mutex);

	dev_set_drvdata(&aux_dev->dev, dev_node);

	return 0;
}

#ifdef COMPAT__AUXI_INT_REMOVE
static int crdma_remove(struct auxiliary_device *aux_dev)
#else
static void crdma_remove(struct auxiliary_device *aux_dev)
#endif
{
	struct crdma_device_node *dev_node;

	dev_node = dev_get_drvdata(&aux_dev->dev);

	pr_info("crdma_remove is removing, %p,%p\n",
		dev_node, dev_node->info->netdev);

	crdma_remove_dev(dev_node->crdma_dev);
	crdma_bond_del_ibdev(dev_node);
	mutex_lock(&rdma_device_list_mutex);
	list_del(&dev_node->list);
	mutex_unlock(&rdma_device_list_mutex);
	kfree(dev_node->info);
	kfree(dev_node);

#ifdef COMPAT__AUXI_INT_REMOVE
	return 0;
#endif
}

MODULE_DEVICE_TABLE(auxiliary, crdma_auxiliary_id_table);

static struct auxiliary_driver crdma_auxiliary_drv = {
	.id_table = crdma_auxiliary_id_table,
	.probe = crdma_probe,
	.remove = crdma_remove,
};

static int crdma_auxi_client_init_module(void)
{
	int ret;

	WARN_ON(!list_empty(&rdma_device_list));

	ret = auxiliary_driver_register(&crdma_auxiliary_drv);
	if (ret) {
		pr_err("Failed auxiliary_driver_register() ret=%d\n", ret);
		return ret;
	}

	return 0;
}

static void crdma_auxi_client_exit_module(void)
{
	auxiliary_driver_unregister(&crdma_auxiliary_drv);
	WARN_ON(!list_empty(&rdma_device_list));
}

#else
/**
 * NFP Notifier callback event handler.
 *
 * @dev: The RoCE IB device.
 * @port: Port number associated with event.
 * @state: The state associated with the event.
 */
static void crdma_event_notifier(struct crdma_ibdev *dev,
			int port, u32 state)
{
	if (!dev)
		return;
}

static struct nfp_roce_drv crdma_drv = {
	.abi_version	= NFP_ROCE_ABI_VERSION,
	.add_device	= crdma_add_dev,
	.remove_device	= crdma_remove_dev,
	.event_notifier	= crdma_event_notifier,
	.bond_add_ibdev	= crdma_bond_add_ibdev,
	.bond_del_ibdev	= crdma_bond_del_ibdev,
};
#endif

static int __init crdma_init(void)
{
#ifdef KERNEL_SUPPORT_AUXI
	crdma_auxi_client_init_module();
#else
	/* Use callback way */
	nfp_register_roce_driver(&crdma_drv);
#endif
	return 0;
}

static void __exit crdma_cleanup(void)
{
	mutex_lock(&crdma_global_mutex);
#ifdef KERNEL_SUPPORT_AUXI
	crdma_auxi_client_exit_module();
#else
	/* Use callback way */
	nfp_unregister_roce_driver(&crdma_drv);
#endif
	mutex_unlock(&crdma_global_mutex);
}

module_init(crdma_init);
module_exit(crdma_cleanup);
