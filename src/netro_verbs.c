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
 *	copyright notice, this list of conditions and the following
 *	disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *	copyright notice, this list of conditions and the following
 *	disclaimer in the documentation and/or other materials
 *	provided with the distribution.
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
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/scatterlist.h>
#include <linux/workqueue.h>
#include <asm/byteorder.h>

#include <rdma/ib_verbs.h>
#include <rdma/ib_user_verbs.h>
#include <rdma/ib_mad.h>
#include <rdma/ib_addr.h>

#include "netro_ib.h"
#include "netro_abi.h"
#include "netro_verbs.h"


static bool mad_cq_event_wa = false;
module_param(mad_cq_event_wa, bool, 0444);
MODULE_PARM_DESC(mad_cq_event_wa, "Enables a temporary work around to support "
		"QP1 interface testing while ucode CQ event notification is "
		"not implemented (default: false");

static bool send_loopback = false;
module_param(send_loopback, bool, 0444);
MODULE_PARM_DESC(send_loopback, "A development test only parameter to set "
		"the internal loop-back flag on kernel QP post sends "
		"(default: false)");

/*
 * UAR pages and work queue memory are allocated in the kernel and
 * then mapped into the user context virtual address space via mmap
 * calls. The following helpers keep a list of pending mmaps; this list
 * should remain short since once a verbs QP, CQ, SRQ is created, the
 * user library immediately turns around and mmaps the queues.
 */
struct netro_mmap_req {
	struct list_head	entry;
	u64			paddr;
	u64			length;
};

/**
 * Add a pending mmap request to the user context.
 *
 * uctxt: The netro RDMA verbs user space context.
 * paddr: The physical address for the backing.
 * length: The length of the physical address space.
 *
 * Returns 0 on success, otherwise -ENOMEM;
 */
static int netro_add_mmap_req(struct netro_ucontext *uctxt, u64 paddr,
			u64 length)
{
	struct netro_mmap_req *req;
#if 0
	netro_info("Add a mmap_req: 0x%016llX, length: %lld\n",
			paddr, length);
#endif
	req = kmalloc(sizeof(*req), GFP_KERNEL);
	if (!req)
		return -ENOMEM;

	req->paddr = paddr;
	req->length = length;
	INIT_LIST_HEAD(&req->entry);

	mutex_lock(&uctxt->mmap_pending_lock);
	list_add_tail(&req->entry, &uctxt->mmap_pending);
	mutex_unlock(&uctxt->mmap_pending_lock);
	return 0;
}

/**
 * Remove a pending mmap request from the user context.
 *
 * @uctxt: The netro RDMA verbs user space context.
 * @paddr: The physical address for the backing to remove.
 * @length: The length of the physical address space being removed.
 */
static void netro_remove_mmap_req(struct netro_ucontext *uctxt, u64 paddr,
				u64 length)
{
	struct netro_mmap_req *req, *tmp;

	mutex_lock(&uctxt->mmap_pending_lock);
	list_for_each_entry_safe(req, tmp, &uctxt->mmap_pending, entry) {
		if ((req->paddr != paddr) || (req->length < length))
			continue;
		list_del(&req->entry);
		kfree(req);
		break;
	}
	mutex_unlock(&uctxt->mmap_pending_lock);

	return;
}

/**
 * Allocate host DMA memory for a RDMA microcode/provider shared queue and
 * add update the allocated MTT entries.
 *
 * @ndev: The RoCEE IB device.
 * @length: The minimum length of the queue.
 *
 * Returns the DMA memory to back the queue, or ERR_PTR on error.
 */
static struct netro_mem *netro_alloc_hw_queue(struct netro_ibdev *ndev,
		unsigned long length)
{
	struct netro_mem *mem;
	int err;

	mem = netro_alloc_dma_mem(ndev, true,
			NETRO_MEM_DEFAULT_ORDER, length);
	if (IS_ERR(mem)) {
		netro_dev_err(ndev, "Unable to allocate queue memory\n");
		return mem;
	}

	netro_info("netro_alloc_hw_queue dump: \n");
	pr_info("HWQ memory size        %d\n", mem->tot_len);
	pr_info("HWQ num allocs         %d\n", mem->num_allocs);
	pr_info("HWQ min order          %d\n", mem->min_order);
	pr_info("HWQ num SG             %d\n", mem->num_sg);
	pr_info("HWQ needs              %d MTT entries\n", mem->num_mtt);
	pr_info("HWQ base_mtt_ndx       %d\n", mem->base_mtt_ndx);

	err = netro_mtt_write_sg(ndev, mem->alloc, mem->num_sg,
			mem->base_mtt_ndx, mem->num_mtt,
			mem->min_order + PAGE_SHIFT,
			mem->num_sg, 0);
	if (err) {
		netro_info("netro_mmt_write_sg failed for HWQ, %d\n", err);
		netro_free_dma_mem(ndev, mem);
		return ERR_PTR(-ENOMEM); 
	}
	return mem;
}

/**
 * Free host DMA memory for a RDMA microcode/provider shared queue.
 *
 * @ndev: The RoCEE IB device.
 * @mem: The memory allocated with netro_alloc_hw_queue().
 */
static void netro_free_hw_queue(struct netro_ibdev *ndev,
		struct netro_mem *mem)
{
	return netro_free_dma_mem(ndev, mem);
}

/**
 * Find the compound page order for a umem defined memory area.
 *
 * @umem: The user memory area initialized by ib_umem_get().
 * @start: The start address.
 * @count: The total number of PAGE_SIZE pages.
 * @num_comp: Set to the total number of compound pages.
 * @comp_shift: Set to the largest compound page shift that can be used.
 * @comp_order: Set to the order of the largest compound page that can be used.
 */
static void netro_compound_order(struct ib_umem *umem, u64 start,
			int *count, int *num_comp, int *comp_shift,
			int *comp_order)
{
	struct scatterlist *sg;
	u64 pfn;
	u64 base = 0;
#if (VER_NON_RHEL_GE(5,3) || VER_RHEL_GE(8,0))
	unsigned long page_shift = PAGE_SHIFT;
#else
	unsigned long page_shift = umem->page_shift;
#endif
	unsigned long pfn_bits;
	unsigned long order;
	int entry;
	int tot_pages = 0;
	int comp_pages = 0;
	int comp_mask;
	int pages;
	int k;

	/*
	 * Start with a compound page size based on the alignment of
	 * the user memory address and reduce order as needed.
	 */
	netro_debug("start 0x%016llx, page_shift: %ld\n",
			start, page_shift);
	pfn_bits = (unsigned long)(start >> page_shift);
	netro_debug("pfn_bits: 0%lx\n", pfn_bits);
	order = __ffs(pfn_bits);
	netro_debug("find_first_bit returned: %ld\n", order);
	comp_mask = (1 << order) - 1;
	netro_debug("Alignment comp_mask: 0x%08X\n", comp_mask);

	/*
	 * Go through the memory reducing the alignment to the smallest
	 * order found in the region.
	 */
	for_each_sg(umem->sg_head.sgl, sg, umem->nmap, entry) {
		pages = sg_dma_len(sg) >> page_shift;
		pfn = sg_dma_address(sg) >> page_shift;

		for (k = 0; k < pages; k++) {
			if (!(tot_pages & comp_mask)) {
				/*
				 * The start of a compound page, calculate
				 * the order based on the alignment.
				 */
				pfn_bits = (unsigned long)pfn;
				order =  min(order, __ffs(pfn_bits));
				comp_mask = (1 << order) - 1;
				base = pfn;
				comp_pages = 0;
				netro_debug("new page: pfn_bits: 0x%lx, "
					"order: %ld, comp_mask: 0x%08X\n",
					pfn_bits, order, comp_mask);
			} else if (base + comp_pages != pfn) {
				/*
				 * Non compound pages, reset the new
				 * compound mask based on the alignment.
				 */
				netro_debug("PFN mismatch\n");
				pfn_bits = (unsigned long)comp_pages;
				order =  min(order, __ffs(pfn_bits));
				comp_mask = (1 << order) - 1;
				base = pfn;
				comp_pages = 0;
			}
			comp_pages++;
			tot_pages++;
		}
	}

	if (tot_pages) {
		netro_debug("Determine order, tot_pages: %d, order: %ld\n",
				tot_pages, order);

		order = min_t(unsigned long,
				ilog2(roundup_pow_of_two(tot_pages)),
				order);
		if (comp_order)
			*comp_order = order;
		netro_debug("order: %d\n", *comp_order);

		*num_comp = DIV_ROUND_UP(tot_pages, (1 << order));
		netro_debug("num_comp: %d\n", *num_comp);
	} else {
		order = 0;
		if (comp_order)
			*comp_order = 0;
		*num_comp = 0;
	}
	*comp_shift = page_shift + order;
	*count = tot_pages;
	return;
}

/**
 * Initialize a RDMA Verbs work completion structure from a CQE which has
 * an error completion status.
 *
 * @cqe: Pointer to the CQE that reported a completion with error.
 * @wc: Pointer to the verbs work completion to fill in.
 */
static void netro_process_err_cqe(struct netro_cqe *cqe, struct ib_wc *wc)
{
	static const unsigned cqe_sts_to_wc_syn[] = {
		[NETRO_CQE_NO_ERR]		= IB_WC_SUCCESS,
		[NETRO_CQE_BAD_RESPONSE_ERR]	= IB_WC_BAD_RESP_ERR,
		[NETRO_CQE_LOCAL_LENGTH_ERR]	= IB_WC_LOC_LEN_ERR,
		[NETRO_CQE_LOCAL_ACCESS_ERR]	= IB_WC_LOC_ACCESS_ERR,
		[NETRO_CQE_LOCAL_QP_PROT_ERR]	= IB_WC_LOC_PROT_ERR,
		[NETRO_CQE_LOCAL_QP_OP_ERR]	= IB_WC_LOC_QP_OP_ERR,
		[NETRO_CQE_MEMORY_MGMT_OP_ERR]	= IB_WC_MW_BIND_ERR,
		[NETRO_CQE_REMOTE_ACCESS_ERR]	= IB_WC_REM_ACCESS_ERR,
		[NETRO_CQE_REMOTE_INV_REQ_ERR]	= IB_WC_REM_INV_REQ_ERR,
		[NETRO_CQE_REMOTE_OP_ERR]	= IB_WC_REM_OP_ERR,
		[NETRO_CQE_RNR_RETRY_ERR]       = IB_WC_RNR_RETRY_EXC_ERR,
		[NETRO_CQE_TRANSPORT_RETRY_ERR]	= IB_WC_RETRY_EXC_ERR,
		[NETRO_CQE_ABORTED_ERR]		= IB_WC_REM_ABORT_ERR,
		[NETRO_CQE_FLUSHED_ERR]		= IB_WC_WR_FLUSH_ERR
	};

	if (cqe->status < (sizeof(cqe_sts_to_wc_syn) / sizeof(unsigned)))
		wc->status = cqe_sts_to_wc_syn[cqe->status];
	else
		wc->status = IB_WC_GENERAL_ERR;
	return;
}

/**
 * Process a CQE as part of CQ poll operation.
 *
 * @ncq: Pointer to the netro CQ.
 * @cqe: Pointer to the CQE to process.
 * @last_qp: Address of pointer that is set to the QP associated with
 * the CQE being processed. It is used to avoid lookups when making
 * successive calls for the same CQ.
 * @wc: Pointer to the IB work completion to update.
 *
 * Returns: 0 if CQE processed.
 *          1 if CQE was stale and skipped.
 *          < 0 if there was an error processing the CQE.
 */
static int netro_process_cqe(struct netro_cq *ncq, struct netro_cqe *cqe,
		struct netro_qp **last_qp, struct ib_wc *wc)
{
	struct netro_ibdev *ndev = to_netro_ibdev(ncq->ib_cq.device);
	struct netro_hw_workq *wq;
	u32 qpn_index = le32_to_cpu(cqe->qpn & NETRO_CQE_QPN_MASK);
	u16 wqe_index;

	/*
	 * Stale CQE's are marked with a QP of -1 when the QP associated with
	 * the CQE has been destroyed.
	 */
	if (qpn_index == 0x00FFFFFF)
		return 1;

	if (!*last_qp || (qpn_index != (*last_qp)->qp_index)) {
		/*
		 * NOTE that the qp_lock is not required since CQs will
		 * be locked while QPs are removed.
		 */
		*last_qp = radix_tree_lookup(&ndev->qp_tree, qpn_index);
		if (unlikely(!last_qp)) {
			netro_info("Unknown QP 0x%08X in CQE\n", qpn_index);
			return -EINVAL;
		}
	}

	/*
	 * For test purposes we zero the WC, however we should
	 * set all the fields that are appropriate based on type.
	 * Verify that operation prior to deleting this memset.
	 */
	memset(wc, 0, sizeof(*wc));
	wc->qp = &(*last_qp)->ib_qp;

	if (cqe->flags & NETRO_CQE_SENDQ_FLAG_BIT) {
		wq = &(*last_qp)->sq;
		wqe_index = le16_to_cpu(cqe->wqe_index);
		netro_debug("CQE Send WQE index %d WQ head %d\n",
				wqe_index, wq->head);
		/* Advance the SQ head to this work request */
		wq->head = wqe_index;
		wc->wr_id = wq->wrid_map[wq->head & wq->mask];
		wq->head = (wq->head + 1) & wq->mask;
		netro_debug("New Send WQ head %d\n", wq->head);
	} else {
		/*
		 * TODO: We will need to handle the case where
		 * the QP is attached to a SRQ here, once SRQ
		 * are implemented.
		 */
		wq = &(*last_qp)->rq;
		wc->wr_id = wq->wrid_map[wq->head & wq->mask];
		wq->head = (wq->head + 1) & wq->mask;
		netro_debug("New Recv WQ head %d\n", wq->head);
	}

	/*
	 * If the CQE indicates an error completion, process and return
	 * error WC entry.
	 */
	if (cqe->status) {
		netro_debug("Error CQE %d\n", cqe->status);
		netro_process_err_cqe(cqe, wc);
		return 0;
	}

	wc->status = IB_WC_SUCCESS;
	wc->wc_flags = 0;

	if (cqe->flags & NETRO_CQE_SENDQ_FLAG_BIT) {

		switch (cqe->opcode) {

		case NETRO_WQE_RDMA_WRITE_WITH_IMM_OP:
			wc->wc_flags |= IB_WC_WITH_IMM;
			/* Fall through */
		case NETRO_WQE_RDMA_WRITE_OP:
			wc->opcode = IB_WC_RDMA_WRITE;
			break;

		case NETRO_WQE_RDMA_READ_OP:
			wc->opcode = IB_WC_RDMA_READ;
			wc->byte_len = le32_to_cpu(cqe->byte_count);
			break;

		case NETRO_WQE_SEND_WITH_IMM_OP:
			wc->wc_flags |= IB_WC_WITH_IMM;
			/* Fall through */
		case NETRO_WQE_SEND_OP:
			/* Fall through */
		default:
			wc->opcode = IB_WC_SEND;
			break;
		}
	} else {

		switch (cqe->opcode) {

		case NETRO_WQE_RDMA_WRITE_WITH_IMM_OP:
			wc->opcode = IB_WC_RECV_RDMA_WITH_IMM;
			wc->wc_flags |= IB_WC_WITH_IMM;
			/* Swap immediate data to undo hardware swap */
			wc->ex.imm_data = __swab32(cqe->imm_inval);
			break;

		case NETRO_WQE_SEND_WITH_IMM_OP:
			wc->wc_flags |= IB_WC_WITH_IMM;
			/* Swap immediate data to undo hardware swap */
			wc->ex.imm_data = __swab32(cqe->imm_inval);
			/* Fall through */
		case NETRO_WQE_SEND_OP:
		default:
			wc->opcode = IB_WC_RECV;
			break;
		}

		wc->src_qp = le32_to_cpu(cqe->rem_qpn) & NETRO_CQE_REM_QPN_MASK;
		wc->byte_len = le32_to_cpu(cqe->byte_count);
		wc->slid = 0;
		wc->dlid_path_bits = 0;
		wc->pkey_index = cqe->pkey_index;
		wc->wc_flags |= cqe->flags & NETRO_CQE_GRH_FLAG_BIT ?
					IB_WC_GRH : 0;
		if ((*last_qp)->ib_qp.qp_type != IB_QPT_RC) {
#if 0 /* Don't turn on until verified operation */
			netro_mac_swap(wc->smac, cqe->smac);
#else
			wc->smac[0] = cqe->smac[3];
			wc->smac[1] = cqe->smac[2];
			wc->smac[2] = cqe->smac[1];
			wc->smac[3] = cqe->smac[0];
			wc->smac[4] = cqe->smac[5];
			wc->smac[5] = cqe->smac[4];
#endif
			/* No VLAN support yet, otherwise pull from sl_vid */
			wc->vlan_id = 0xFFFF;
			wc->wc_flags |= IB_WC_WITH_VLAN | IB_WC_WITH_SMAC;
		}

		/*
		 * XXX: Assume for now upper 3-bits of VLAN define
		 * the SL for now.
		 */
		wc->sl  = le16_to_cpu(cqe->sl_vid) >> 13;
	}
	netro_debug("IB WC:\n");
	netro_debug("      WRID: 0x%016llX\n", wc->wr_id);
	netro_debug("    status: %d\n", wc->status);
	netro_debug("    opcode: %d\n", wc->opcode);
	netro_debug("        QP: %p\n", wc->qp);
	netro_debug("     flags: 0x%X\n", wc->wc_flags);
	if (!(cqe->flags & NETRO_CQE_SENDQ_FLAG_BIT)) {
		netro_debug("  byte len: %d\n", wc->byte_len);
		netro_debug("   src QPN: 0x%08X\n", wc->src_qp);
		netro_debug("      smac: %02x:%02x:%02x:%02x:%02x:%02x\n",
				wc->smac[0], wc->smac[1], wc->smac[2],
				wc->smac[3], wc->smac[4], wc->smac[5]);
	}
	return 0;
}

/*
 * The following static functions implement the Netro IB
 * device OFA RDMA Verbs API entry points.
 */

static int netro_query_device(struct ib_device *ibdev,
			struct ib_device_attr *dev_attr,
			struct ib_udata *uhw)
{
	struct netro_ibdev *ndev = to_netro_ibdev(ibdev);

	netro_info("netro_query_device\n");
	memcpy(dev_attr, &ndev->cap.ib, sizeof(*dev_attr));

	if (uhw->inlen || uhw->outlen)
		return -EINVAL;

	/*
	 * Adjust shared queue size limits exposed to consumer to
	 * account for entries used for driver overhead.
	 */
	dev_attr->max_qp_wr -= NETRO_WQ_WQE_SPARES;
	dev_attr->max_cqe--;
	if (dev_attr->max_srq_wr)
		dev_attr->max_srq_wr -= NETRO_WQ_WQE_SPARES;

	return 0;
}

static int netro_query_port(struct ib_device *ibdev, u8 port_num,
			struct ib_port_attr *port_attr)
{
	struct netro_ibdev *ndev = to_netro_ibdev(ibdev);
	struct net_device *netdev;

	netro_info("netro_query_port: %d\n", port_num);

	if (port_num < 1 || port_num > ndev->cap.n_ports) {
		netro_dev_warn(ndev, "invalid port=%d\n", port_num);
		return -EINVAL;
	}

	netdev = ndev->nfp_info->netdev[port_num - 1];
	/*
	 * The following code exist for early integration and is
	 * not the final query port code. TODO: get correct netdev
	 * and use it netif_oper_up ?.
	 */
	if (netif_running(netdev) && netif_carrier_ok(netdev)) {
		port_attr->state = IB_PORT_ACTIVE;
		port_attr->phys_state = 5;
	} else {
		port_attr->state = IB_PORT_DOWN;
		port_attr->phys_state = 3;
	}

	/*
	* Initially microcode only supports a 2K MTU, since headers plus MTU
	* packet data for a 4K MTU would exceed the maximum 4K packet buffer.
	*/
	port_attr->max_mtu      = IB_MTU_4096;

	/* Limit active IB MTU to Ethernet MTU */
	port_attr->active_mtu   = iboe_get_mtu(netdev->mtu);

	port_attr->lid		= 0;
	port_attr->lmc		= 0;
	port_attr->sm_lid	= 0;
	port_attr->sm_sl	= 0;

	port_attr->port_cap_flags = IB_PORT_CM_SUP |
	                            IB_PORT_REINIT_SUP |
			                    IB_PORT_VENDOR_CLASS_SUP;
	port_attr->gid_tbl_len	= ndev->cap.sgid_table_size;
	port_attr->pkey_tbl_len	= 1;
	port_attr->bad_pkey_cntr = 0;
	port_attr->qkey_viol_cntr = 0;

	/* TODO:  We will really need a way to determine actual link speed  */
	port_attr->active_speed	= IB_SPEED_QDR;
	port_attr->active_width	= IB_WIDTH_4X;

	port_attr->max_msg_sz	= NETRO_MAX_MSG_SIZE;

	/* TODO:  Must really determine value for max virtual lanes */
	port_attr->max_vl_num	= 4;

	return 0;
}

struct net_device *netro_get_netdev(struct ib_device *ibdev, u8 port_num)
{
	struct netro_ibdev *netro_dev = to_netro_ibdev(ibdev);
	struct net_device *netdev;

	netro_info("netro_get_netdev: %d\n", port_num);

	if (port_num < 1 || port_num > netro_dev->cap.n_ports) {
		netro_dev_warn(netro_dev, "invalid port=%d\n", port_num);
		return NULL;
	}

	rcu_read_lock();
	netdev = netro_dev->nfp_info->netdev[port_num - 1];
	if (netdev)
		dev_hold(netdev);

	rcu_read_unlock();
	return netdev;
}

int netro_get_port_immutable(struct ib_device *ibdev, u8 port_num,
			       struct ib_port_immutable *immutable)
{
	struct ib_port_attr port_attr;

	if (netro_query_port(ibdev, port_num, &port_attr))
		return -EINVAL;

	immutable->pkey_tbl_len    = port_attr.pkey_tbl_len;
	immutable->gid_tbl_len     = port_attr.gid_tbl_len;
	immutable->core_cap_flags  = RDMA_CORE_PORT_IBA_ROCE;
	immutable->core_cap_flags |= RDMA_CORE_CAP_PROT_ROCE_UDP_ENCAP;
	immutable->max_mad_size    = IB_MGMT_MAD_SIZE;

	return 0;
}

void netro_get_dev_fw_str(struct ib_device *ibdev, char *str)
{
	struct netro_ibdev *ndev = to_netro_ibdev(ibdev);

	snprintf(str, IB_FW_VERSION_NAME_MAX, "%d.%d",
		 ndev->cap.uc_maj_rev, ndev->cap.uc_min_rev);
	netro_info("netro_get_dev_fw_str: %s\n", str);

	return;
}

static enum rdma_link_layer netro_get_link_layer(
			struct ib_device *ibdev, u8 port_num)
{
	return IB_LINK_LAYER_ETHERNET;
}

static int netro_query_gid(struct ib_device *ibdev, u8 port_num,
			int index, union ib_gid *gid)
{
	struct netro_ibdev *ndev = to_netro_ibdev(ibdev);

	netro_info("netro_query_gid\n");

	if (port_num > ndev->cap.n_ports ||
		index >= ndev->cap.sgid_table_size)
        return -EINVAL;

	*gid = ndev->port[port_num - 1].gid_table_entry[index].gid;
	return 0;
}

static int netro_query_pkey(struct ib_device *ibdev, u8 port_num,
			u16 index, u16 *pkey)
{
	struct netro_ibdev *ndev = to_netro_ibdev(ibdev);

	netro_info("netro_query_pkey\n");
	if (port_num > ndev->cap.n_ports) {
		netro_dev_warn(ndev, "invalid IB port=%d\n", port_num);
		return -EINVAL;
	}

	if (index > 0) {
		netro_dev_warn(ndev, "invalid pkey index=%d\n", index);
		return -EINVAL;
	}
	*pkey = 0xFFFF;
	return 0;
}

static int netro_modify_device(struct ib_device *ibdev, int dev_mod_mask,
			struct ib_device_modify *dev_modify)
{
	netro_info("netro_modify_device not implemented\n");
	return 0;
}

static int netro_modify_port(struct ib_device *ibdev, u8 port_num,
			int port_mod_mask, struct ib_port_modify *port_modify)
{
	netro_info("netro_modify_port not implemented\n");
	return 0;
}

static struct ib_ucontext * netro_alloc_ucontext(struct ib_device *ibdev,
				struct ib_udata *udata)
{
	struct netro_ibdev *ndev = to_netro_ibdev(ibdev);
	struct netro_ucontext *netro_uctxt;
	struct netro_ib_alloc_ucontext_resp resp;
	int err;

	netro_info("netro_alloc_ucontext\n");

	/*
	 * Inform the library provider of the chip-set family we
	 * are working with.
	 */
	resp.model = ndev->nfp_info->model;
	resp.max_qp = ndev->cap.ib.max_qp - ndev->cap.rsvd_qp;

	netro_uctxt = kmalloc(sizeof(*netro_uctxt), GFP_KERNEL);
	if (!netro_uctxt)
		return ERR_PTR(-ENOMEM);

	/*
	 * Each user context maintains a list of memory areas waiting to
	 * be mapped into the user context virtual address space.
	 */
	INIT_LIST_HEAD(&netro_uctxt->mmap_pending);
	mutex_init(&netro_uctxt->mmap_pending_lock);

	err = netro_alloc_uar(ndev, &netro_uctxt->uar);
	if (err)
		goto free_uctxt;

	err = ib_copy_to_udata(udata, &resp, sizeof(resp));
	if (err)
		goto free_uar;

	return &netro_uctxt->ib_uctxt;

free_uar:
	netro_free_uar(ndev, &netro_uctxt->uar);
free_uctxt:
	kfree(netro_uctxt);
	return ERR_PTR(err);
}

static int netro_dealloc_ucontext(struct ib_ucontext *ib_uctxt)
{
	struct netro_ibdev *ndev = to_netro_ibdev(ib_uctxt->device);
	struct netro_ucontext *netro_uctxt = to_netro_uctxt(ib_uctxt);
	struct netro_mmap_req *mm, *tmp;

	netro_info("netro_dealloc_ucontext\n");

	netro_free_uar(ndev, &netro_uctxt->uar);

	/* Release any pending mmap definitions */
	list_for_each_entry_safe(mm, tmp, &netro_uctxt->mmap_pending, entry) {
		list_del(&mm->entry);
		kfree(mm);
	}

	kfree(netro_uctxt);
	return 0;
}

/**
 * map physical memory into user context virtual address space.
 *
 * ib_uctxt: The IB user context.
 * vma: The virtual memory area.
 *
 * Returns 0 on success, otherwise error.
 */
static int netro_mmap(struct ib_ucontext *ib_uctxt,
			struct vm_area_struct *vma)
{
	struct netro_ibdev *ndev = to_netro_ibdev(ib_uctxt->device);
	struct netro_ucontext *netro_uctxt = to_netro_uctxt(ib_uctxt);
	struct netro_mmap_req *req, *tmp;
	u64 offset = vma->vm_pgoff << PAGE_SHIFT;
	u64 length = vma->vm_end - vma->vm_start;

	netro_info("mmap uctxt: 0x%p\n", netro_uctxt);
	pr_info("  vma->vm_pgoff = %ld\n", vma->vm_pgoff);
	pr_info("  offset = 0x%016llX\n", offset);
	pr_info("  length = 0x%lld\n", length);

	if (vma->vm_start & (PAGE_SIZE -1))
		return -EINVAL;

	/* First page offset is for user context UAR used for doorbells */
	if (vma->vm_pgoff == 0) {
		netro_info("Map user context UAR, index: %d\n", netro_uctxt->uar.index);
		vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);

		return io_remap_pfn_range(vma, vma->vm_start,
				netro_uar_pfn(ndev, &netro_uctxt->uar),
				PAGE_SIZE, vma->vm_page_prot);
	}

	/* A request to mmap a kernel allocated QP, SRQ, or CQ queue */
	mutex_lock(&netro_uctxt->mmap_pending_lock);
	list_for_each_entry_safe(req, tmp, &netro_uctxt->mmap_pending, entry) {
#if 0
		netro_info("Pending paddr:0x%016llX, len:%lld\n",
				req->paddr, req->length);
		netro_info("Test paddr:0x%016llX, len:%lld\n",
				offset, length);
#endif
		if ((req->paddr != offset) || (req->length < length))
			continue;
#if 0
		netro_info("mmap found, mapping\n");
#endif
		list_del(&req->entry);
		kfree(req);
		mutex_unlock(&netro_uctxt->mmap_pending_lock);
		return remap_pfn_range(vma, vma->vm_start, vma->vm_pgoff,
				length, vma->vm_page_prot);
	}
	netro_warn("No pending mmap found\n");
	mutex_unlock(&netro_uctxt->mmap_pending_lock);
	return -EINVAL;
}

static struct ib_pd *netro_alloc_pd(struct ib_device *ibdev,
			struct ib_ucontext *ib_uctxt,
			struct ib_udata *udata)
{
	struct netro_ibdev *ndev = to_netro_ibdev(ibdev);
	struct netro_pd *pd;
	int err;

	netro_info("netro_alloc_pd\n");
	pd = kmalloc(sizeof(*pd), GFP_KERNEL);
	if (!pd)
		return ERR_PTR(-ENOMEM);

	pd->pd_index = netro_alloc_bitmap_index(&ndev->pd_map);
	if (pd->pd_index < 0) {
		err = -ENOMEM;
		goto free_mem;
	}

	netro_info("PD Index %d\n", pd->pd_index);
	if (ib_uctxt) {
		err = ib_copy_to_udata(udata, &pd->pd_index, sizeof(u32));
		if (err)
			goto free_pd;
	}
	return &pd->ib_pd;

free_pd:
	netro_free_bitmap_index(&ndev->pd_map, pd->pd_index);
free_mem:
	kfree(pd);
	return ERR_PTR(err);
}

static int netro_dealloc_pd(struct ib_pd *pd)
{
	struct netro_ibdev *ndev = to_netro_ibdev(pd->device);
	struct netro_pd *npd = to_netro_pd(pd);

	netro_info("netro_dealloc_pd, PD Index %d\n", npd->pd_index);
	netro_free_bitmap_index(&ndev->pd_map, npd->pd_index);
	kfree(pd);
	return 0;
}

static struct ib_ah *netro_create_ah(struct ib_pd *pd,
			struct rdma_ah_attr *ah_attr,
			struct ib_udata *uhw)
{
	struct netro_ibdev *ndev = to_netro_ibdev(pd->device);
	struct netro_ah *nah;
	struct in6_addr in6;
	u8 d_mac[ETH_ALEN];

	netro_info("netro_create_ah\n");

	if (!(ah_attr->ah_flags & IB_AH_GRH)) {
			netro_info("RoCE requires GRH\n");
			return ERR_PTR(-EINVAL);
	}
	if (pd->uobject) {
			netro_warn("Invocation of kernel only implementation\n");
			return ERR_PTR(-EINVAL);
	}

	if (ah_attr->grh.sgid_index >= ndev->cap.sgid_table_size) {
			netro_info("Invalid SGID Index %d\n", ah_attr->grh.sgid_index);
			return ERR_PTR(-EINVAL);
	}

	nah = kzalloc(sizeof(*nah), GFP_ATOMIC);
	if (!nah)
			return ERR_PTR(-ENOMEM);

	memcpy(&in6, ah_attr->grh.dgid.raw, sizeof(in6));
	if (rdma_is_multicast_addr(&in6))
			rdma_get_mcast_mac(&in6, d_mac);
	else
			memcpy(d_mac, ah_attr->roce.dmac, ETH_ALEN);

	netro_info("D_MAC:%02X:%02X:%02X:%02X:%02X:%02X\n",
					d_mac[0], d_mac[1], d_mac[2], d_mac[3],
					d_mac[4], d_mac[5]);

#if 0 /* Don't turn on until verified operation */
	netro_mac_swap(nah->av.d_mac, d_mac);
#else
	nah->av.d_mac[0] = d_mac[3];
	nah->av.d_mac[1] = d_mac[2];
	nah->av.d_mac[2] = d_mac[1];
	nah->av.d_mac[3] = d_mac[0];
	nah->av.d_mac[4] = d_mac[5];
	nah->av.d_mac[5] = d_mac[4];
#endif

	netro_info("AV D_MAC:%02X:%02X:%02X:%02X:%02X:%02X\n",
					nah->av.d_mac[0], nah->av.d_mac[1],
					nah->av.d_mac[2], nah->av.d_mac[3],
					nah->av.d_mac[4], nah->av.d_mac[5]);

	nah->av.port = ah_attr->port_num - 1;
	nah->av.service_level = ah_attr->sl;
	nah->av.s_gid_ndx = ah_attr->grh.sgid_index;
	nah->av.hop_limit = ah_attr->grh.hop_limit;

	/* Always swap to account for hardware bus swap */
	nah->av.flow_label = __swab32(ah_attr->grh.flow_label);

	/*
	* RoCEv2 GID type determines RoCEv1 or RoCEv2 (we only support
	* v2 so we further define it to indicate to microcode if the GID
	* is IPv6 or v4 mapped.
	*/
	if (ipv6_addr_v4mapped((struct in6_addr *)ah_attr->grh.dgid.raw))
		nah->av.gid_type = NETRO_AV_ROCE_V2_IPV4_GID_TYPE;
	else
		nah->av.gid_type = NETRO_AV_ROCE_V2_IPV6_GID_TYPE;

	/* For now using maximum rate, no IPD */
	nah->av.ib_sr_ipd = cpu_to_le32((0 << NETRO_AV_IBSR_IPD_SHIFT) |
					(to_netro_pd(pd)->pd_index & NETRO_AV_PD_MASK));

	/*
	* Maintain destination GID byte swapped on 32-bit boundary
	* so that it need not be done each time the address handle
	* is used in a work request.
	*/
#if defined(__BIG_ENDIAN)
	nah->av.d_gid_word[0] =
			__swab32(ah_attr->grh.dgid.global.subnet_prefix >> 32);
	nah->av.d_gid_word[1] =
			__swab32(ah_attr->grh.dgid.global.subnet_prefix & 0x0FFFFFFFF);
	nah->av.d_gid_word[2] =
			__swab32(ah_attr->grh.dgid.global.interface_id >> 32);
	nah->av.d_gid_word[3] =
			__swab32(ah_attr->grh.dgid.global.interface_id & 0x0FFFFFFFF);
#elif defined(__LITTLE_ENDIAN)
	nah->av.d_gid_word[0] =
			__swab32(ah_attr->grh.dgid.global.subnet_prefix & 0x0FFFFFFFF);
	nah->av.d_gid_word[1] =
			__swab32(ah_attr->grh.dgid.global.subnet_prefix >> 32);
	nah->av.d_gid_word[2] =
			__swab32(ah_attr->grh.dgid.global.interface_id & 0x0FFFFFFFF);
	nah->av.d_gid_word[3] =
			__swab32(ah_attr->grh.dgid.global.interface_id >> 32);
#else
#error Host endianness not defined
#endif
	return &nah->ib_ah;
}

static int netro_query_ah(struct ib_ah *ah, struct rdma_ah_attr *ah_attr)
{
	struct netro_ah *nah = to_netro_ah(ah);

	netro_info("netro_query_ah\n");

	memset(ah_attr, 0, sizeof(*ah_attr));
	ah_attr->sl = nah->av.service_level;
	ah_attr->port_num = nah->av.port + 1;
	ah_attr->grh.sgid_index = nah->av.s_gid_ndx;
	ah_attr->grh.hop_limit = nah->av.hop_limit;
	ah_attr->grh.flow_label = __swab32(nah->av.flow_label);

	/* TODO: IPD  not implemented yet, assumes static rate is 0 */

#if defined(__BIG_ENDIAN)
	ah_attr->grh.dgid.global.subnet_prefix =
			((u64)__swab32(nah->av.d_gid_word[0]) << 32) |
			__swab32(nah->av.d_gid_word[1]);
	ah_attr->grh.dgid.global.interface_id =
			((u64)__swab32(nah->av.d_gid_word[2]) << 32) |
			__swab32(nah->av.d_gid_word[3]);
#elif defined(__LITTLE_ENDIAN)
	ah_attr->grh.dgid.global.subnet_prefix =
			((u64)__swab32(nah->av.d_gid_word[1]) << 32) |
			__swab32(nah->av.d_gid_word[0]);
	ah_attr->grh.dgid.global.interface_id =
			((u64)__swab32(nah->av.d_gid_word[3]) << 32) |
			__swab32(nah->av.d_gid_word[2]);
#else
#error Host endianness not defined
#endif
	return 0;
}

static int netro_destroy_ah(struct ib_ah *ah)
{
	netro_info("netro_destroy_ah\n");
	kfree(to_netro_ah(ah));
	return 0;
}

static struct ib_srq *netro_create_srq(struct ib_pd *pd,
			struct ib_srq_init_attr *srq_init_attr,
			struct ib_udata *udata)
{
	netro_warn("netro_create_srq not implemented\n");
	return ERR_PTR(-ENOMEM);
}

static int netro_modify_srq(struct ib_srq *srq,
			struct ib_srq_attr *srq_attr,
			enum ib_srq_attr_mask srq_attr_mask,
			struct ib_udata *udata)
{
	netro_warn("netro_modify_srq not implemented\n");
	return 0;
}

static int netro_query_srq(struct ib_srq *srq,
			struct ib_srq_attr *srq_attr)
{
	netro_warn("netro_query_srq not implemented\n");
	return 0;
}

static int netro_destroy_srq(struct ib_srq *srq)
{
	netro_warn("netro_destroy_srq not implemented\n");
	return 0;
}

static int netro_post_srq_recv(struct ib_srq *srq, const struct ib_recv_wr *wr,
			           const struct ib_recv_wr **bad_recv_wr)
{
	netro_warn("netro_post_srq_recv not implemented\n");
	return 0;
}

static int netro_qp_val_check(struct netro_ibdev *ndev,
		struct ib_qp_cap *cap, bool use_srq)
{
	/* Note we advertise 1 less than actual hardware maximum */
	if (cap->max_send_wr >= ndev->cap.ib.max_qp_wr) {
		netro_info("Send WR entries requested > max %d\n",
				ndev->cap.ib.max_qp_wr);
		return -EINVAL;
	}

	if (cap->max_send_sge < 1 ||
			cap->max_send_sge > ndev->cap.ib.max_send_sge) {
		netro_info("Send SG entries requested invalid %d\n",
				cap->max_send_sge);
		return -EINVAL;
	}

	if (!use_srq) {
		/* Note we advertise 1 less than actual hardware maximum */
		if (cap->max_recv_wr >= ndev->cap.ib.max_qp_wr) {
			netro_info("Recv WR entries requested > max %d\n",
					ndev->cap.ib.max_qp_wr);
			return -EINVAL;
		}
		if (cap->max_recv_sge < 1 ||
				cap->max_recv_sge > ndev->cap.ib.max_sge_rd) {
			netro_info("Receive SG entries requested > max %d\n",
					ndev->cap.ib.max_sge_rd);
			return -EINVAL;
		}
	} else {
		if (cap->max_recv_wr) {
			netro_info("Recv WR must be 0 when using SRQ\n");
			return -EINVAL;
		}
		netro_warn("SRQ not yet supported\n");
		return -EINVAL;
	}

	if (cap->max_inline_data > ndev->cap.max_inline_data) {
		netro_info("Max inline data requested > max %d\n",
				ndev->cap.max_inline_data);
		return -EINVAL;
	}
	return 0;
}

static int netro_qp_set_wq_sizes(struct netro_ibdev *ndev,
			struct netro_qp *qp, struct ib_qp_init_attr *attr)
{
	/*
	 * Transport specific information and then space for the requested
	 * number of gather entries and in-line data.
	 */
	qp->sq.wqe_size = sizeof(struct netro_swqe_ctrl);
	qp->sq.wqe_size += (attr->qp_type == IB_QPT_RC) ?
				sizeof(struct netro_rc_swqe) :
				sizeof(struct netro_ud_swqe);
	qp->sq.wqe_size += max((u32)(sizeof(struct netro_wqe_sge) *
				attr->cap.max_send_sge),
				attr->cap.max_inline_data);
	qp->sq.wqe_size = roundup_pow_of_two(qp->sq.wqe_size);

	if (qp->sq.wqe_size > ndev->cap.max_swqe_size) {
		netro_info("Required SWQE size %d exceeds max %d\n",
				qp->sq.wqe_size, ndev->cap.max_swqe_size);
		return -EINVAL;
	}

	qp->sq.wqe_cnt =roundup_pow_of_two(attr->cap.max_send_wr +
					NETRO_WQ_WQE_SPARES);
	qp->sq.max_sg = attr->cap.max_send_sge;
	qp->max_inline = attr->cap.max_inline_data;

	/* Receive work queue, only valid if no SRQ */
	if (!attr->srq) {
		/*
		 * Control information and space for the requested maximum
		 * number of scatter entries.
		 */
		qp->rq.wqe_size =  sizeof(struct netro_rwqe) +
					sizeof(struct netro_wqe_sge) *
					attr->cap.max_recv_sge;
		qp->rq.wqe_size = roundup_pow_of_two(qp->rq.wqe_size);
		qp->rq.wqe_cnt =roundup_pow_of_two(attr->cap.max_recv_wr +
						NETRO_WQ_WQE_SPARES);
		qp->rq.max_sg = attr->cap.max_recv_sge;
		if (qp->rq.wqe_size > ndev->cap.max_rwqe_size) {
			netro_info("Required RWQE size %d exceeds max %d\n",
				qp->rq.wqe_size, ndev->cap.max_rwqe_size);
			return -EINVAL;
		}
	}

	qp->sq.length = qp->sq.wqe_size * qp->sq.wqe_cnt;
	qp->rq.length = qp->rq.wqe_size * qp->rq.wqe_cnt;
	if (qp->sq.length >= qp->rq.length) {
		qp->sq_offset = 0;
		qp->rq_offset =  attr->srq ? 0 : qp->sq.length;
	} else {
		qp->rq_offset = 0;
		qp->sq_offset = qp->rq.length;
	}

	netro_info("Set WQ sizes\n");
	pr_info("SQ WQE size %d\n", qp->sq.wqe_size);
	pr_info("SQ WQE count %d\n", qp->sq.wqe_cnt);
	pr_info("SQ WQE num SG %d\n", qp->sq.max_sg);
	pr_info("SQ byte length %d\n", qp->sq.length);
	pr_info("RQ WQE size %d\n", qp->rq.wqe_size);
	pr_info("RQ WQE count %d\n", qp->rq.wqe_cnt);
	pr_info("RQ WQE num SG %d\n", qp->rq.max_sg);
	pr_info("RQ byte length %d\n", qp->rq.length);

	return 0;
}

/**
 * Initialize the WQEs in a work queue to software ownership.
 *
 * @mem: The DMA memory backing the work queues.
 * @offset: Offset into the memory to start the initialization.
 * @wqe_cnt: The number of WQE to set to software ownership.
 * @wqe_size: The size of each WQE.
 */
static void netro_init_wq_ownership(struct netro_mem *mem, u32 offset,
			u32 wqe_cnt, u32 wqe_size)
{
	u32 *ownership = sg_virt(mem->alloc) + offset;
	int i;

	/* We only support a virtually contiguous work queue for now */
	for (i = 0; i < wqe_cnt; i++) {
		*ownership = 0xFFFFFFFF;
		ownership += (wqe_size >> 2);
	}
	return;
}

/**
 * Temporary work around to periodically kick start special QP1
 * CQ event notification. This is only to support testing of
 * QP1 via MAD sub-system prior to support of CQ notification
 * interrupts by microcode.
 */
static void netro_qp1_work(struct work_struct *work)
{
	struct delayed_work *delay = to_delayed_work(work);
	struct netro_port *port;
	struct netro_cq *ncq;
	unsigned long flags;

	if (!mad_cq_event_wa) {
		pr_warn("QP1 work around, should not be called\n");
		return;
	}

	port = container_of(delay, typeof(*port), qp1_cq_dwork);
	if (!port) {
		pr_warn("QP1 work around, invalid port\n");
		return;
	}

	if (!port->qp1_send_ncq || !port->qp1_recv_ncq) {
		pr_warn("QP1 work around, CQ not defined\n");
		return;
	}

	ncq = port->qp1_send_ncq;

	ncq->arm_seqn++;
	atomic_inc(&ncq->ref_cnt);
	if (ncq->ib_cq.comp_handler)
		ncq->ib_cq.comp_handler(&ncq->ib_cq, ncq->ib_cq.cq_context);

	if (ncq != port->qp1_recv_ncq) {
		if (atomic_dec_and_test(&ncq->ref_cnt))
			complete(&ncq->free);

		ncq = port->qp1_recv_ncq;
		ncq->arm_seqn++;
		atomic_inc(&ncq->ref_cnt);

		if (ncq->ib_cq.comp_handler)
			ncq->ib_cq.comp_handler(&ncq->ib_cq,
					ncq->ib_cq.cq_context);
	}

	if (atomic_dec_and_test(&ncq->ref_cnt))
		complete(&ncq->free);

	spin_lock_irqsave(&port->qp1_lock, flags);
	if (port->qp1_created) {
		INIT_DELAYED_WORK(&port->qp1_cq_dwork, netro_qp1_work);
		schedule_delayed_work(&port->qp1_cq_dwork,
				msecs_to_jiffies(100));
	}
	spin_unlock_irqrestore(&port->qp1_lock, flags);

	return;
}

/**
 * Verify the QP1 port is unused, initialize and update.
 *
 * @ndev: The RoCEE IB device.
 * @nqp: The netro QP associated with the QP1.
 * @port_num: The physical port number to be associated with this QP1 (0 based).
 *
 * Returns 0 on success, otherwise an error if it can not be set.
 */
static int netro_set_qp1_port(struct netro_ibdev *ndev, struct netro_qp *nqp,
				int port_num)
{
	struct netro_port *port = &ndev->port[port_num];
	unsigned long flags;

	netro_debug("Setting QP1 physical port number %d, %p\n",
			port_num, port);

	spin_lock_irqsave(&port->qp1_lock, flags);
	if (port->qp1_created) {
		spin_unlock_irqrestore(&port->qp1_lock, flags);

		return -EINVAL;
	}
	nqp->qp1_port = port_num;
	port->qp1_created = true;

	/* XXX: Temporary work around to enable testing */
	if (mad_cq_event_wa) {
		port->qp1_send_ncq = ndev->cq_table[nqp->send_cqn];
		port->qp1_recv_ncq = ndev->cq_table[nqp->recv_cqn];
		netro_info("QP1 WA send_ncq %p, recv_ncq %p",
				port->qp1_send_ncq, port->qp1_recv_ncq);
		INIT_DELAYED_WORK(&port->qp1_cq_dwork, netro_qp1_work);
		schedule_delayed_work(&port->qp1_cq_dwork,
					msecs_to_jiffies(100));
	}
	spin_unlock_irqrestore(&port->qp1_lock, flags);

	return 0;
}

/**
 * Indicate that QP1 is not in use for a physical port.
 *
 * @ndev: The RoCEE IB device.
 * @port_num: The physical port number associated with this QP1 (0 based).
 */
static void netro_clear_qp1_port(struct netro_ibdev *ndev, int port_num)
{
	struct netro_port *port = &ndev->port[port_num];
	unsigned long flags;

	netro_debug("Clearing QP1 physical port number %d\n", port_num);

	spin_lock_irqsave(&port->qp1_lock, flags);
	if (port->qp1_created) {
		port->qp1_created = false;
		spin_unlock_irqrestore(&port->qp1_lock, flags);

		if (mad_cq_event_wa) {
			cancel_delayed_work_sync(&port->qp1_cq_dwork);
			port->qp1_send_ncq = NULL;
			port->qp1_recv_ncq = NULL;
		}
	} else
		spin_unlock_irqrestore(&port->qp1_lock, flags);
	return;
}

static struct ib_qp *netro_create_qp(struct ib_pd *pd,
			struct ib_qp_init_attr *qp_init_attr,
			struct ib_udata *udata)
{
	struct netro_ibdev *ndev = to_netro_ibdev(pd->device);
	struct netro_qp *nqp;
	int err;

	netro_info("netro_create_qp\n");

	if (qp_init_attr->qp_type != IB_QPT_UD &&
			qp_init_attr->qp_type != IB_QPT_RC &&
			qp_init_attr->qp_type != IB_QPT_GSI) {
		netro_info("Unsupported QP type %d\n", qp_init_attr->qp_type);
		return ERR_PTR(-EINVAL);
	}

	if (udata && qp_init_attr->qp_type == IB_QPT_GSI) {
		netro_info("QP1 create restricted to kernel\n");
		return ERR_PTR(-EINVAL);
	}

	if (netro_qp_val_check(ndev, &qp_init_attr->cap,
				qp_init_attr->srq != NULL)) {
		netro_info("QP init attribute validation failed\n");
		return ERR_PTR(-EINVAL);
	}

	nqp = kzalloc(sizeof(*nqp), GFP_KERNEL);
	if (!nqp)
		return ERR_PTR(-ENOMEM);

	mutex_init(&nqp->mutex);
	spin_lock_init(&nqp->sq.lock);
	spin_lock_init(&nqp->rq.lock);
	nqp->qp_state = IB_QPS_RESET;
	nqp->pdn = pd ? to_netro_pd(pd)->pd_index : 0;
	nqp->send_cqn = qp_init_attr->send_cq ?
		to_netro_cq(qp_init_attr->send_cq)->cqn : 0;
	nqp->recv_cqn = qp_init_attr->recv_cq ?
		to_netro_cq(qp_init_attr->recv_cq)->cqn : 0;
	nqp->srqn = qp_init_attr->srq ?
		to_netro_srq(qp_init_attr->srq)->srq_index : 0;

	nqp->sq_sig_type = qp_init_attr->sq_sig_type;

	/* Handle speical QP1 requirements */
	if (qp_init_attr->qp_type == IB_QPT_GSI) {
		netro_debug("Creating Special QP1\n");
		err = netro_set_qp1_port(ndev, nqp,
				qp_init_attr->port_num - 1);
		if (err) {
			netro_info("Error %d setting QP1 port number\n", err);
			err = -EINVAL;
			goto free_mem;
		}
	}

	/* Set the actual number and sizes of the QP work requests */
	err = netro_qp_set_wq_sizes(ndev, nqp, qp_init_attr);
	if (err) {
		err = -EINVAL;
		goto clear_port;
	}

	/* Allocate resource index for the QP control object */
	nqp->qp_index = qp_init_attr->qp_type == IB_QPT_GSI ?
		qp_init_attr->port_num - 1 :
		netro_alloc_bitmap_index(&ndev->qp_map);
	if (nqp->qp_index < 0) {
		netro_info("No QP index available\n");
		err = -ENOMEM;
		goto clear_port;
	}

	/* Kernel always allocates QP memory, user contexts will mmap it */
	nqp->mem = netro_alloc_hw_queue(ndev, nqp->sq.length + nqp->rq.length);
	if (IS_ERR(nqp->mem)) {
		netro_dev_err(ndev, "Unable to allocate QP HW queue\n");
		err = -ENOMEM;
		goto free_qp_index;
	}

	netro_init_wq_ownership(nqp->mem, nqp->sq_offset,
				nqp->sq.wqe_cnt, nqp->sq.wqe_size);
	netro_init_wq_ownership(nqp->mem, nqp->rq_offset,
				nqp->rq.wqe_cnt, nqp->rq.wqe_size);

	/* Add to Radix tree for lookups */
	spin_lock_irq(&ndev->qp_lock);
	err = radix_tree_insert(&ndev->qp_tree, nqp->qp_index, nqp);
	spin_unlock_irq(&ndev->qp_lock);
	if (err) {
		netro_dev_err(ndev, "Unable to insert QP tree\n");
		goto free_dma_memory;
	}

	nqp->ib_qp.qp_num = qp_init_attr->qp_type == IB_QPT_GSI ?
			1 : nqp->qp_index;

	/* return response */
	if (udata) {
		struct netro_ucontext *netro_uctxt =
				to_netro_uctxt(pd->uobject->context);
		struct netro_ib_create_qp_resp resp;

		resp.wq_base_addr = sg_dma_address(nqp->mem->alloc);
		resp.wq_size = nqp->mem->tot_len;
		if (nqp->sq.length >= nqp->rq.length) {
			resp.sq_offset = 0;
			resp.rq_offset = nqp->sq.length;
		} else {
			resp.sq_offset = 0;
			resp.rq_offset = nqp->sq.length;
		}
		resp.swqe_size = nqp->sq.wqe_size;
		resp.num_swqe = nqp->sq.wqe_cnt;
		resp.rwqe_size = nqp->rq.wqe_size;
		resp.num_rwqe = nqp->rq.wqe_cnt;
		resp.spares = NETRO_WQ_WQE_SPARES;

		err = ib_copy_to_udata(udata, &resp, sizeof(resp));
		if (err) {
			netro_info("Copy of UDATA failed, %d\n", err);
			goto delete_qp;
		}

		err = netro_add_mmap_req(netro_uctxt, resp.wq_base_addr,
				nqp->mem->tot_len);
		if (err) {
			netro_info("Failed to add pending mmap, %d\n", err);
			goto delete_qp;
		}
	} else {
		if (qp_init_attr->qp_type != IB_QPT_GSI) {
			netro_info("Only Kernel QP1 supported now\n");
			err = -ENOMEM;
			goto delete_qp;
		}
		nqp->sq.buf = sg_virt(nqp->mem->alloc) + nqp->sq_offset;
		nqp->sq.mask = nqp->sq.wqe_cnt - 1;
		nqp->sq.wqe_size_log2 = ilog2(nqp->sq.wqe_size);

		nqp->sq.wrid_map = kcalloc(nqp->sq.wqe_cnt, sizeof(u64),
						GFP_KERNEL);
		if (!nqp->sq.wrid_map) {
			netro_info("Could not allocate SQ WRID map\n");
			err = -ENOMEM;
			goto delete_qp;
		}

		nqp->rq.buf = sg_virt(nqp->mem->alloc) + nqp->rq_offset;
		nqp->rq.mask = nqp->rq.wqe_cnt - 1;
		nqp->rq.wqe_size_log2 = ilog2(nqp->rq.wqe_size);

		nqp->rq.wrid_map = kcalloc(nqp->rq.wqe_cnt, sizeof(u64),
						GFP_KERNEL);
		if (!nqp->rq.wrid_map) {
			netro_info("Could not allocate RQ WRID map\n");
			err = -ENOMEM;
			kfree(nqp->sq.wrid_map);
			goto delete_qp;
		}
	}
	atomic_set(&nqp->ref_cnt, 1);
	init_completion(&nqp->free);
	return &nqp->ib_qp;

delete_qp:
	spin_lock_irq(&ndev->qp_lock);
	radix_tree_delete(&ndev->qp_tree, nqp->qp_index);
	spin_unlock_irq(&ndev->qp_lock);
free_dma_memory:
	netro_free_hw_queue(ndev, nqp->mem);
free_qp_index:
	if (qp_init_attr->qp_type != IB_QPT_GSI)
		netro_free_bitmap_index(&ndev->qp_map, nqp->qp_index);
clear_port:
	if (qp_init_attr->qp_type == IB_QPT_GSI)
		netro_clear_qp1_port(ndev, nqp->qp1_port);
free_mem:
	kfree(nqp);

	/*
	 * XXX: For development only to catch error codes that are not
     * set properly. This should be removed ultimately.
     */
	if (err >= 0) {
		netro_warn("Error not set correctly, %d\n", err);
		err = -ENOMEM;
	}
	return ERR_PTR(err);
}

static int netro_modify_qp(struct ib_qp *qp, struct ib_qp_attr *qp_attr,
			int qp_attr_mask, struct ib_udata *udata)
{
	struct netro_ibdev *ndev = to_netro_ibdev(qp->device);
	struct netro_ucontext *netro_uctxt =
				to_netro_uctxt(qp->uobject->context);
	struct netro_qp *nqp = to_netro_qp(qp);
	enum ib_qp_state cur_state;
	enum ib_qp_state new_state;
	int ret;

	netro_info("netro_modify_qp: attr_mask 0x%08X\n", qp_attr_mask);
	netro_info("qp_type %d\n", qp->qp_type);

	mutex_lock(&nqp->mutex);
	cur_state = nqp->qp_state;
	new_state = qp_attr_mask & IB_QP_STATE ? qp_attr->qp_state : cur_state;

	netro_info("curr_state %d, new_state %d\n", cur_state, new_state);

	/* State transition attribute/transport type validation */
	ret = -EINVAL;
#if (VER_NON_RHEL_GE(4,20) || VER_RHEL_GE(8,0))
	if (!ib_modify_qp_is_ok(cur_state, new_state,
			qp->qp_type, qp_attr_mask)) {
#else
	if (!ib_modify_qp_is_ok(cur_state, new_state,
			qp->qp_type, qp_attr_mask, IB_LINK_LAYER_ETHERNET)) {
#endif
		netro_info("QPN %d, invalid attribute mask specified "
				"for transition %d to %d. qp_type %d, "
				"attr_mask 0x%08X\n",
				qp->qp_num, cur_state, new_state,
				qp->qp_type, qp_attr_mask);
		goto out;
	}

	/* Requester resources can't be larger than device allows for QP */
	if (qp_attr_mask & IB_QP_MAX_QP_RD_ATOMIC && (qp_attr->max_rd_atomic >
							ndev->cap.ib.max_qp_init_rd_atom)) {
		netro_info("QPN %d, max_rd_atomic %d too large\n",
						qp->qp_num, qp_attr->max_rd_atomic);
		goto out;
	}

	/* Perform validation of the requested attributes */
	if ((qp_attr_mask & IB_QP_PORT) && (qp_attr->port_num == 0 ||
							qp_attr->port_num > ndev->cap.n_ports)) {
		netro_info("Invalid port number %d\n", qp_attr->port_num);
		goto out;
	}

	if ((qp_attr_mask & IB_QP_PKEY_INDEX) && (qp_attr->pkey_index > 0)) {
		netro_info("Invalid PKEY index %d\n", qp_attr->pkey_index);
		goto out;
	}

	/* Requester resources can't be larger than device allows for QP */
	if (qp_attr_mask & IB_QP_MAX_QP_RD_ATOMIC && (qp_attr->max_rd_atomic >
							ndev->cap.ib.max_qp_init_rd_atom)) {
		netro_info("QPN %d, max_rd_atomic %d too large\n",
						qp->qp_num, qp_attr->max_rd_atomic);
		goto out;
	}

	/* Responder resources can't be larger than device allows for QP */
	if (qp_attr_mask & IB_QP_MAX_DEST_RD_ATOMIC &&
					(qp_attr->max_dest_rd_atomic >
					ndev->cap.ib.max_qp_rd_atom)) {
		netro_info("QPN %d, max_dest_rd_atomic %d too large\n",
						qp->qp_num, qp_attr->max_rd_atomic);
		goto out;
	}

	/*
	 * If we are in RESET and staying in RESET then do not
	 * send a command to microcode, while the QP control object
	 * is assigned, it is under software ownership.
	 */
	if (cur_state == IB_QPS_RESET && new_state == IB_QPS_RESET){
		ret = 0;
		goto out;
	}

	ret = netro_qp_modify_cmd(ndev, nqp, udata ?
			&netro_uctxt->uar : &ndev->priv_uar,
			qp_attr, qp_attr_mask, cur_state, new_state);
	if (ret) {
		netro_info("Microcode QP_MODIFY error, %d\n", ret);
		ret = -EINVAL;
	}

out:
	mutex_unlock(&nqp->mutex);
	return ret;
}

static int netro_query_qp(struct ib_qp *qp, struct ib_qp_attr *qp_attr,
			int qp_attr_mask, struct ib_qp_init_attr *qp_init_attr)
{
	struct netro_ibdev *ndev = to_netro_ibdev(qp->device);
	struct netro_qp *nqp = to_netro_qp(qp);
	int ret = 0;

	netro_info("netro_query_qp\n");
	mutex_lock(&nqp->mutex);

	/* If we are in RESET state then no attributes are assigned */
	if (nqp->qp_state == IB_QPS_RESET) {
		qp_attr->qp_state = IB_QPS_RESET;
		goto out;
	}

	ret = netro_qp_query_cmd(ndev, nqp, qp_attr, qp_attr_mask);
	if (ret) {
		netro_info("Microcode QP_QUERY error, %d\n", ret);
		ret = -EINVAL;
		goto out;
	}

	qp_attr->cur_qp_state = qp_attr->qp_state;
	qp_attr->cap.max_recv_wr = nqp->rq.wqe_cnt;
	qp_attr->cap.max_recv_sge = nqp->rq.max_sg;
	qp_attr->cap.max_send_wr = nqp->sq.wqe_cnt;
	qp_attr->cap.max_send_sge = nqp->sq.max_sg;
	qp_attr->cap.max_inline_data = nqp->max_inline;
	qp_init_attr->sq_sig_type = nqp->sq_sig_type;
	qp_init_attr->qp_type = nqp->ib_qp.qp_type;
	qp_init_attr->cap = qp_attr->cap;
out:
	mutex_unlock(&nqp->mutex);
	return ret;
}

static int netro_destroy_qp(struct ib_qp *qp)
{
	struct netro_ibdev *ndev = to_netro_ibdev(qp->device);
	struct netro_qp *nqp = to_netro_qp(qp);
	int err;

	netro_info("netro_destroy_qp\n");

	if (nqp->qp_state != IB_QPS_RESET) {
		err = netro_qp_destroy_cmd(ndev, nqp);
		if (err) {
			/*
			 * XXX: We should consider a BUG_ON here, to
			 * continue puts microcode and the driver in different
			 * states. This error needs not to happen.
			 */
			netro_err("Microcode destroy QP command failed\n");
		}
	}

	spin_lock_irq(&ndev->qp_lock);
	radix_tree_delete(&ndev->qp_tree, nqp->qp_index);
	spin_unlock_irq(&ndev->qp_lock);

	/* Free resources specific to kernel based QP */
	if (!qp->uobject) {
		if (!nqp->rq.wrid_map)
			netro_warn("RQ WRID map memory NULL\n");
		else
			kfree(nqp->rq.wrid_map);
		if (!nqp->sq.wrid_map)
			netro_warn("SQ WRID map memory NULL\n");
		else
			kfree(nqp->sq.wrid_map);
	}

	netro_free_hw_queue(ndev, nqp->mem);
	if (nqp->ib_qp.qp_type != IB_QPT_GSI)
		netro_free_bitmap_index(&ndev->qp_map, nqp->qp_index);
	else
		netro_clear_qp1_port(ndev, nqp->qp1_port);
	kfree(nqp);
	return 0;
}
#if 0
/**
 * Set the WQE index for a QP work queue to be in software ownership.
 * The WQE index will be masked to stay within the bounds of the WQ.
 *
 * @wq: Pointer to the work queue (SQ, RQ).
 * @wqe_index: The WQE index for which ownership is to be set.
 */
static void set_wqe_sw_ownership(struct netro_hw_workq *wq,
                                u32 wqe_index)
{
	u32 *ownership;

	wqe_index &= wq->mask;
	ownership = wq->buf + (wqe_index << wq->wqe_size_log2);
	netro_debug("Set ownership for WQE index %d, %p\n",
					wqe_index, ownership);
	*ownership = 0xFFFFFFFF;
	return;
}
#endif
/**
 * Copy work request data to SWQE in-line data.
 *
 * @data: Pointer to the in-line data SWQE structure.
 * @wr: Pointer to the work request.
 * @max: The maximum amount of data that can be copied into the in-line
 * structure.
 *
 * Returns 0 on success, otherwise NOMEM.
 */
static inline int netro_copy_inline(struct netro_swqe_inline *data,
                        struct ib_send_wr *wr, int max)
{
	struct ib_sge *sg;
	int i;
	int length = 0;

	netro_debug("wr->num_sge %d, max = %d\n", wr->num_sge, max);

	for (i = 0, sg = wr->sg_list; i < wr->num_sge; i++, sg++) {
		netro_debug("sg->length %d total length %d\n",
						sg->length, length);

		if (length + sg->length > max)
				return ENOMEM;
		memcpy(&data->data[length], (void *)(uintptr_t)sg->addr,
						sg->length);
		length += sg->length;
	}
	data->byte_count = cpu_to_le16((uint16_t)length);
	return 0;
}

/**
 * Set WQE SGE data.
 *
 * @wqe_sg: Pointer to the SWQE scatter/gather structure to initialize.
 * @num_sge: Number of SGE entries to set.
 * @sge_list: Address of the work request SGE entries.
 */
static inline void netro_set_wqe_sge(struct netro_wqe_sge *wqe_sg, int num_sge,
                                struct ib_sge *sge_list)
{
	int i;

	netro_debug("num_sge %d, wqe_sg %p, sge_list %p\n",
					num_sge, wqe_sg, sge_list);
	for (i = 0; i < num_sge; i++, sge_list++, wqe_sg++) {
		wqe_sg->io_addr_h = cpu_to_le32(sge_list->addr >> 32);
		wqe_sg->io_addr_l = cpu_to_le32(sge_list->addr &
										0x0FFFFFFFFull);
		wqe_sg->l_key = cpu_to_le32(sge_list->lkey);
		wqe_sg->byte_count = cpu_to_le32(sge_list->length);
		netro_debug("SGE %d addr_h 0x%08X, addr_l 0x%08X\n",
						i, wqe_sg->io_addr_h, wqe_sg->io_addr_l);
		netro_debug("       l_key 0x%08X, byte_count 0x%08X\n",
						wqe_sg->l_key, wqe_sg->byte_count);
	}
	return;
}

#if 0
/**
 * Get the address of the SQ SWQE located at the queue producer tail
 * position.
 *
 * The QP SQ lock should be held outside of this call.
 *
 * @qp: The QP to return the next SWQE to use.
 *
 * Returns the SWQE on on success, otherwise NULL if an
 * overflow SQ is detected.
 */
static struct netro_swqe *get_sq_tail(struct netro_qp *nqp)
{
	uint32_t next = (nqp->sq.tail + NETRO_WQ_WQE_SPARES) & nqp->sq.mask;
	unsigned long flags;

	/*
		* If it looks like an overflow allow for any active CQ
		* processing to complete and look again.
		*/
	if (next == nqp->sq.head) {
		struct netro_cq *ncq = to_netro_cq(nqp->ib_qp.send_cq);

		spin_lock_irqsave(&ncq->lock, flags);
		next = (nqp->sq.tail + NETRO_WQ_WQE_SPARES) & nqp->sq.mask;
		spin_unlock_irqrestore(&ncq->lock, flags);
		if (next == nqp->sq.head)
				return NULL;
	}

	/* Post SWQE at the software producer tail */
	netro_debug("Use SWQE Index %d\n", nqp->sq.tail);
	return nqp->sq.buf + (nqp->sq.tail << nqp->sq.wqe_size_log2);
}
#endif
#define NETRO_SQ_DB_READY_RETRIES              20

static int netro_post_send(struct ib_qp *qp, const struct ib_send_wr *wr,
			const struct ib_send_wr **bad_wr)
{
	/*Stage1 we do not cosider ib_post_send*/
	netro_warn("netro_post_send in kernel is not surpported\n");
	return 0;
#if 0
	struct netro_ibdev *ndev = to_netro_ibdev(qp->device);
	struct netro_qp *nqp = to_netro_qp(qp);
	struct netro_swqe *swqe;
	struct netro_swqe_inline *inline_data;
	struct netro_wqe_sge *sg;
	struct netro_swqe_owner owner;
	int wr_cnt = 0;
	int ret = 0;
	u8 flags;
	u32 fin_state;
	u32 qpn = qp->qp_type == IB_QPT_GSI ? nqp->qp1_port : nqp->qp_index;
	int cnt = 0;

	spin_lock(&nqp->sq.lock);
	while (wr) {
		if (wr->num_sge > nqp->sq.max_sg) {
			netro_info("WR num_sge too large %d\n", wr->num_sge);
			*bad_wr = wr;
			ret = -EINVAL;
			goto out;
		}

		/* Post new SWQE's at the software tail, NULL if SQ full */
		swqe = get_sq_tail(nqp);
		if (!swqe) {
			netro_info("SQ Overflow\n");
			*bad_wr = wr;
			ret = -ENOMEM;
			goto out;
		}

		netro_debug(">>> SWQE Addr %p\n", swqe);

		if (wr->opcode == IB_WR_SEND_WITH_IMM ||
				wr->opcode == IB_WR_RDMA_WRITE_WITH_IMM)
			swqe->ctrl.imm_inval = __swab32(wr->ex.imm_data);
		else
			swqe->ctrl.imm_inval = 0;

		switch (qp->qp_type) {
		case IB_QPT_UD:
		case IB_QPT_GSI:
			if (wr->opcode != IB_WR_SEND &&
				wr->opcode != IB_WR_SEND_WITH_IMM) {
				netro_info("Only UD SEND, SEND w/IMM "
						"supported %d\n", wr->opcode);
				*bad_wr = wr;
				ret = -EINVAL;
				goto out;
			}

			/* Set the UD address vector */
			memcpy(&swqe->ud.addr.av,
					&to_netro_ah(wr->wr.ud.ah)->av,
					sizeof(struct netro_av));
			swqe->ud.addr.dest_qpn =
					cpu_to_le32(wr->wr.ud.remote_qpn);
			swqe->ud.addr.qkey = cpu_to_le32(wr->wr.ud.remote_qkey);
			inline_data = &swqe->ud.inline_data;
			sg = &swqe->ud.sg[0];
			break;

		case IB_QPT_RC:
			/* Add remote address if required */
			switch (wr->opcode) {
			case IB_WR_RDMA_READ:
			case IB_WR_RDMA_WRITE:
			case IB_WR_RDMA_WRITE_WITH_IMM:
				swqe->rc.rem_addr.rem_io_addr_h =
					cpu_to_le32(wr->wr.rdma.remote_addr >>
							32);
				swqe->rc.rem_addr.rem_io_addr_l =
					cpu_to_le32(wr->wr.rdma.remote_addr &
							0x0FFFFFFFFLL);
				swqe->rc.rem_addr.r_key =
					cpu_to_le32(wr->wr.rdma.rkey);
				swqe->rc.rem_addr.rsvd = 0;
				break;

			default:
				break;
			}
			inline_data = &swqe->rc.inline_data;
			sg = &swqe->rc.sg[0];
			break;

		default:
			netro_info("Only UD and RC QP supported %d\n",
				qp->qp_type);
			*bad_wr = wr;
			ret = -EINVAL;
			goto out;
		}

		owner.word = 0;
		if (send_loopback)
			flags = NETRO_WQE_CTRL_LOOPBACK_BIT;
		else
			flags = wr->send_flags & NETRO_IB_SEND_LOOPBACK ?
					NETRO_WQE_CTRL_LOOPBACK_BIT : 0;
		if (wr->send_flags & IB_SEND_INLINE) {
			flags |= NETRO_WQE_CTRL_INLINE_DATA_BIT;
			ret = netro_copy_inline(inline_data, wr,
						nqp->max_inline);
			if (ret) {
				*bad_wr = wr;
				goto out;
			}
		} else {
			owner.num_sg = wr->num_sge;
			netro_set_wqe_sge(sg, wr->num_sge, wr->sg_list);
		}
		nqp->sq.wrid_map[nqp->sq.tail] = wr->wr_id;

		/* Write ownership control word last */
		owner.opcode = wr->opcode;
		owner.flags  = flags |
				(wr->send_flags & IB_SEND_FENCE ?
					NETRO_WQE_CTRL_FENCE_BIT : 0) |
				(wr->send_flags & IB_SEND_SIGNALED ?
					NETRO_WQE_CTRL_SIGNAL_BIT : 0) |
				(wr->send_flags & IB_SEND_SOLICITED ?
					NETRO_WQE_CTRL_SOLICITED_BIT : 0) |
				(qp->qp_type == IB_QPT_GSI ?
					NETRO_WQE_CTRL_GSI_BIT : 0);
		wmb();
		swqe->ctrl.owner.word = owner.word;

#if 1 /* Extra debug only */
		print_hex_dump(KERN_DEBUG, "SWQE:", DUMP_PREFIX_OFFSET, 8, 1,
			swqe, 128, 0);
#endif

		/* Advance to the next SWQE to consume */
		wr_cnt++;
		nqp->sq.tail = (nqp->sq.tail + 1) & nqp->sq.mask;
		wr = wr->next;

		/*
		 * If there are more WQE to post, update the WQE
		 * ownership stamp of the last spare.  If this is the
		 * last work request or there was only one work request,
		 * wait until after ringing the doorbell to update the
		 * ownership.
		 */
		if (wr)
			set_wqe_sw_ownership(&nqp->sq, nqp->sq.tail +
					NETRO_WQ_WQE_SPARES);
	}

out:
	if (wr_cnt) {
		while (cnt++ < NETRO_SQ_DB_READY_RETRIES) {
			fin_state = le32_to_cpu(__raw_readl(
					ndev->priv_uar.map +
					NETRO_DB_SQ_ADDR_OFFSET));
			if (!(fin_state & NETRO_DB_FIN_BIT))
				break;
		}

		if (cnt >= NETRO_SQ_DB_READY_RETRIES)
			netro_warn(">>>>>> SQ doorbell unresponsive\n");

		/*
		 * Make sure last control word has been written, and we have
		 * and the read check has completed  before the doorbell
		 * is written
		 */
		mb();
		netro_debug("Write priv UAR SQ DB\n");
		__raw_writel((__force u32) cpu_to_le32(NETRO_DB_FIN_BIT |
					(qpn & NETRO_DB_SQ_MASK)),
				ndev->priv_uar.map + NETRO_DB_WA_BIT +
				NETRO_DB_SQ_ADDR_OFFSET);

		netro_debug("SQ doorbell address %p\n",
				ndev->priv_uar.map + NETRO_DB_WA_BIT +
				NETRO_DB_SQ_ADDR_OFFSET);

		netro_debug("SQ doorbell written 0x%08X\n",
				cpu_to_le32(NETRO_DB_FIN_BIT |
					(qpn & NETRO_DB_SQ_MASK)));
		netro_debug("SQ doorbell contents 0x%08X\n",
				le32_to_cpu(__raw_readl(ndev->priv_uar.map +
					NETRO_DB_SQ_ADDR_OFFSET)));

		/*
		 * Make sure the last spare request is set to software
		 * ownership.
		 */
		set_wqe_sw_ownership(&nqp->sq, nqp->sq.tail +
				NETRO_WQ_WQE_SPARES);
	}
	spin_unlock(&nqp->sq.lock);

	return 0;
#endif
}
#if 0
/**
 * Get the address of the RQ RWQE located at the queue producer tail
 * position.
 *
 * The QP RQ lock should be held outside of this call.
 *
 * @qp: The QP to return the next RWQE to use.
 *
 * Returns the RWQE on on success, otherwise NULL if an RQ
 * overflow is detected or the QP is attached to an SRQ.
 */
static struct netro_rwqe *get_rq_tail(struct netro_qp *nqp)
{
	u32 next = (nqp->rq.tail + NETRO_WQ_WQE_SPARES) & nqp->rq.mask;
	unsigned long flags;

	/*
	 * If it looks like an overflow allow for any active CQ
	 * processing to complete and look again.
	 */
	if (next == nqp->rq.head) {
		struct netro_cq *ncq = to_netro_cq(nqp->ib_qp.recv_cq);

		spin_lock_irqsave(&ncq->lock, flags);
		next = (nqp->rq.tail + NETRO_WQ_WQE_SPARES) & nqp->rq.mask;
		spin_unlock_irqrestore(&ncq->lock, flags);
		if (next == nqp->rq.head)
			return NULL;
	}

	/* Post RWQE at the software producer tail */
	netro_debug("Use RWQE Index %d\n", nqp->rq.tail);
	return nqp->rq.buf + (nqp->rq.tail << nqp->rq.wqe_size_log2);
}
#endif
static int netro_post_recv(struct ib_qp *qp, const struct ib_recv_wr *wr,
			const struct ib_recv_wr **bad_wr)
{
	/*Stage1 we do not cosider netro_post_recv*/
	netro_warn("netro_post_recv in kernel is not surpported\n");
	return 0;

#if 0
	struct netro_qp *nqp = to_netro_qp(qp);
	struct netro_rwqe *rwqe;
	int ret = 0;

	spin_lock(&nqp->rq.lock);
	while(wr) {
		if (wr->num_sge > nqp->rq.max_sg) {
			netro_info("RQ work request SG entries too large %d\n",
					wr->num_sge);
			*bad_wr = wr;
			ret = -EINVAL;
			break;
		}

		rwqe = get_rq_tail(nqp);
		if (!rwqe) {
			netro_info("RQ overflow\n");
			*bad_wr = wr;
			ret = -ENOMEM;
			break;
		}

		netro_debug("RWQE Addr %p\n", rwqe);

		/*
		 * Build the RWQE making sure not to clear the software
		 * ownership word prior to all of the rest of the WQE
		 * being written.
		 */
		netro_set_wqe_sge(&rwqe->sg[0], wr->num_sge, wr->sg_list);
		rwqe->ctrl.num_sge = wr->num_sge;
		rwqe->ctrl.next_srq_wqe_ndx = 0;
		nqp->rq.wrid_map[nqp->rq.tail] = wr->wr_id;
		wmb();

		rwqe->ctrl.ownership = 0;

		/*
		 * We maintain a sliding block of spare RWQE so that there
		 * is always more than one RWQE in software ownership, allowing
		 * the new RWQE to be added prior to updating the last
		 * RWQE in the sliding block to indicate software ownership.
		 */
		set_wqe_sw_ownership(&nqp->rq, nqp->rq.tail +
				NETRO_WQ_WQE_SPARES);
		nqp->rq.tail = (nqp->rq.tail + 1) & nqp->rq.mask;
		wr = wr->next;
	}
	spin_unlock(&nqp->rq.lock);

	return ret;
#endif
}

static struct ib_cq *netro_create_cq(struct ib_device *ibdev, const struct ib_cq_init_attr *attr,
				  struct ib_ucontext *ib_uctxt, struct ib_udata *udata)
{
	struct netro_ibdev *ndev = to_netro_ibdev(ibdev);
	struct netro_cq *ncq;
	struct netro_cqe *cqe;
	unsigned int num_cqe = attr->cqe;
	int comp_vector = attr->comp_vector;
	int err;
	int i;

	netro_info("=== netro_create_cq ib_uctxt %p ===\n", ib_uctxt);

	if (num_cqe < 1 || num_cqe > ndev->cap.ib.max_cqe - 1) {
		netro_info("Too many CQE requested %d\n", num_cqe);
		return ERR_PTR(-EINVAL);
	}

	ncq = kzalloc(sizeof(*ncq), GFP_KERNEL);
	if (!ncq)
		return ERR_PTR(-ENOMEM);

	spin_lock_init(&ncq->lock);
	ncq->num_cqe = roundup_pow_of_two(num_cqe + 1);
	ncq->ib_cq.cqe = ncq->num_cqe - 1;

#if NETRO_DETAIL_INFO_DEBUG_FLAG
	netro_info("Rounded up CQE count %d\n", ncq->num_cqe);
#endif

	/* Allocate resource index for the CQ control object */
	ncq->cqn = netro_alloc_bitmap_index(&ndev->cq_map);
	if (ncq->cqn < 0) {
		netro_info("No CQ index available\n");
		err = -ENOMEM;
		goto free_mem;
	}

	/* Kernel allocates CQ memory, user contexts will mmap it */
	ncq->mem = netro_alloc_hw_queue(ndev,
				ncq->num_cqe * ndev->cap.cqe_size);
	if (IS_ERR(ncq->mem)) {
		netro_dev_err(ndev, "Unable to allocate CQ HW queue\n");
		err = -ENOMEM;
		goto free_cq;
	}

	/*
	 * Hardware CQE ownership is initially indicated by 0, and alternates
	 * between 1 and 0 for each reuse of the CQE. Set kernel virtual
	 * address and initialize to indicate invalid CQE.
	 */
	ncq->cqe_buf = sg_virt(ncq->mem->alloc);
	for (i = 0, cqe = ncq->cqe_buf; i < ncq->num_cqe; i++, cqe++)
		cqe->owner = 0;

	/*
	 * We are currently just allocating a page for each CQ
	 * for the consumer state mailbox. We should modify this later to
	 * have multiple CQ mailboxes for the same context share pages
	 * to reduce overhead.
	 */
	ncq->ci_mbox = dma_alloc_coherent(&ndev->nfp_info->pdev->dev,
			PAGE_SIZE, &ncq->ci_mbox_paddr, GFP_KERNEL);
	if (!ncq->ci_mbox) {
		netro_info("ci_mbox allocation failed\n");
		err = -ENOMEM;
		goto free_queue_mem;
	}
	netro_debug("CQ CI mailbox DMA addr 0x%016llX\n", ncq->ci_mbox_paddr);
	ncq->ci_mbox->ci = 0;
	ncq->ci_mbox->last_db_state = 0;
	wmb();

	/* Assign CQ to MSI-X EQ based on completion vector */
	ncq->eq_num = ndev->eq_table.num_eq > 1 ? 1 + comp_vector %
			(ndev->eq_table.num_eq - 1) : 0;
	ndev->cq_table[ncq->cqn] = ncq;

	if (ib_uctxt) {
		struct netro_ucontext *netro_uctxt = to_netro_uctxt(ib_uctxt);
		struct netro_ib_create_cq_resp resp;

		err = netro_cq_create_cmd(ndev, ncq, &netro_uctxt->uar);
		if (err) {
			netro_info("Microcode error creating CQ, %d\n", err);
			goto cmd_fail;
		}
		resp.cq_base_addr = sg_dma_address(ncq->mem->alloc);
		resp.cq_size = ncq->mem->tot_len;
		resp.ci_mbox_base_addr = ncq->ci_mbox_paddr;
		resp.ci_mbox_size = PAGE_SIZE;
		resp.cqn = ncq->cqn;
		resp.num_cqe = ncq->num_cqe;
		netro_debug("CQ buffer paddr 0x%016llX\n", resp.cq_base_addr);
		netro_debug("CI mbox paddr 0x%016llX\n",
				resp.ci_mbox_base_addr);

		err = ib_copy_to_udata(udata, &resp, sizeof(resp));
		if (err) {
			netro_info("Copy of UDATA failed, %d\n", err);
			goto cq_destroy;
		}

		err = netro_add_mmap_req(netro_uctxt, resp.cq_base_addr,
				ncq->mem->tot_len);
		if (err) {
			netro_info("Failed to add pending mmap, %d\n", err);
			goto cq_destroy;
		}
		err = netro_add_mmap_req(netro_uctxt, resp.ci_mbox_base_addr,
				PAGE_SIZE);
		if (err) {
			netro_info("Failed to add mbox pending mmap, %d\n",
					err);
			netro_remove_mmap_req(netro_uctxt, resp.cq_base_addr,
					ncq->mem->tot_len);
			goto cq_destroy;
		}
	} else {
		err = netro_cq_create_cmd(ndev, ncq, &ndev->priv_uar);
		if (err) {
			netro_info("Microcode error creating CQ, %d\n", err);
			goto cmd_fail;
		}
		ncq->mask = ncq->num_cqe - 1;
		ncq->arm_seqn = 1;
		while ((1 << ncq->num_cqe_log2) < ncq->num_cqe)
			ncq->num_cqe_log2++;
	}

	atomic_set(&ncq->ref_cnt, 1);
	init_completion(&ncq->free);

	return &ncq->ib_cq;

cq_destroy:
	netro_cq_destroy_cmd(ndev, ncq);
cmd_fail:
	ndev->cq_table[ncq->cqn] = NULL;
	dma_free_coherent(&ndev->nfp_info->pdev->dev, PAGE_SIZE,
			ncq->ci_mbox, ncq->ci_mbox_paddr);
free_queue_mem:
	netro_free_hw_queue(ndev, ncq->mem);
free_cq:
	netro_free_bitmap_index(&ndev->cq_map, ncq->cqn);
free_mem:
	kfree(ncq);

	/*
	 * XXX: For development only to catch error codes that are not
	 * set properly. This should be removed ultimately.
	 */
	if (err >= 0) {
		netro_warn("Error not set correctly, %d\n", err);
		err = -ENOMEM;
	}
	return ERR_PTR(err);
}

static int netro_modify_cq(struct ib_cq *cq, u16 cq_count, u16 cq_period)
{
	netro_warn("netro_modify_cq not implemented\n");
	return 0;
}

static int netro_destroy_cq(struct ib_cq *cq)
{
	struct netro_ibdev *ndev = to_netro_ibdev(cq->device);
	struct netro_cq *ncq = to_netro_cq(cq);
	int err;

	netro_info("netro_destroy_cq cqn =  %d\n", ncq->cqn);

	err = netro_cq_destroy_cmd(ndev, ncq);
	if (err) {
		/*
		 * TODO: Determine best course of action here, if we
		 * ignore and continue we can not free the resource
		 * because microcode will believe it is still in use.
		 */
		netro_warn("Microcode destroy CQ command failed\n");
		return -EINVAL;
	}

	if (ndev->have_interrupts)
		synchronize_irq(ndev->eq_table.eq[ncq->eq_num].vector);

	ndev->cq_table[ncq->cqn] = NULL;

	if (atomic_dec_and_test(&ncq->ref_cnt))
		complete(&ncq->free);
	wait_for_completion(&ncq->free);

	dma_free_coherent(&ndev->nfp_info->pdev->dev, PAGE_SIZE,
			ncq->ci_mbox, ncq->ci_mbox_paddr);
	netro_free_hw_queue(ndev, ncq->mem);
	netro_free_bitmap_index(&ndev->cq_map, ncq->cqn);
	kfree(ncq);
	netro_info("netro_destroy_cq done\n");
	return 0;
}

static int netro_resize_cq(struct ib_cq *ibcq, int cqe,
			struct ib_udata *udata)
{
	netro_warn("netro_resize_cq not implemented\n");
	return 0;
}

static inline struct netro_cqe *netro_cq_head(struct netro_cq *ncq)
{
	struct netro_cqe *cqe = NULL;

	cqe = &ncq->cqe_buf[ncq->consumer_cnt & ncq->mask];

	/*
	 * Microcode alternates writing 1 or 0 in the CQE ownership
	 * bit every pass through the CQ memory, starting with writing
	 * a 1 on the first pass.
	 */
	if (!!(cqe->owner & NETRO_CQE_OWNERSHIP_BIT) ==
			!!(ncq->consumer_cnt & (1 << ncq->num_cqe_log2)))
			return NULL;

	/*
	 * Make sure no CQE reads will be issued prior to validation
	 * that the CQE has been set to software ownership microcode.
	 */
	rmb();
	return cqe;
}

#define NETRO_CQ_DB_READY_RETRIES	       20

static int netro_poll_cq(struct ib_cq *cq, int num_entries,
			struct ib_wc *wc)
{
	struct netro_cq	*ncq = to_netro_cq(cq);
	struct netro_cqe *cqe;
	struct netro_qp *last_qp = NULL;
	unsigned long	flags;
	int polled = 0;
	int ret = 0;

	spin_lock_irqsave(&ncq->lock, flags);
	while (polled < num_entries) {
		cqe = netro_cq_head(ncq);
		if (!cqe)
			break;
		/*
		 * If we already have pulled at least one CQE, update
		 * the CQ consumer index so that a false overflow
		 * will not be detected by microcode.
		 */
		if (polled)
			ncq->ci_mbox->ci = cpu_to_le32(ncq->consumer_cnt &
					NETRO_CQ_MBOX_CONSUMER_NDX_MASK);

		ncq->consumer_cnt++;

#if 1 /* Extra debug only */
		print_hex_dump(KERN_DEBUG, "CQE:", DUMP_PREFIX_OFFSET, 8, 1,
			cqe, 32, 0);
#endif
		ret = netro_process_cqe(ncq, cqe, &last_qp, &wc[polled]);
		if (ret == 0)
			polled++;
		else if (ret < 0)
			break;
	}

	/* Update the state of the consumer index shared with microcode */
	ncq->ci_mbox->ci = cpu_to_le32(ncq->consumer_cnt &
					NETRO_CQ_MBOX_CONSUMER_NDX_MASK);
	spin_unlock_irqrestore(&ncq->lock, flags);

	return ret < 0 ? ret : polled;
}

static int netro_req_notify_cq(struct ib_cq *cq,
			enum ib_cq_notify_flags flags)
{
	struct netro_ibdev *ndev = to_netro_ibdev(cq->device);
	struct netro_cq *ncq = to_netro_cq(cq);
	u32 arm;
	u32 state;
	u32 db[2];
	int cnt = 0;
	u32 fin_state;

	arm = (ncq->arm_seqn << NETRO_DB_CQ_SEQ_SHIFT) |
		((flags & IB_CQ_SOLICITED_MASK) == IB_CQ_SOLICITED ?
			0 : NETRO_DB_CQ_ARM_ANY_BIT) |
		(ncq->cqn & NETRO_DB_CQN_MASK);
	db[0] = cpu_to_le32(arm);
	db[1] = cpu_to_le32(NETRO_DB_FIN_BIT | (ncq->consumer_cnt &
				NETRO_DB_CQ_CONS_MASK));

	/* Update state and ensure in memory before ringing CQ doorbell */
	state = (arm & ~NETRO_DB_CQN_MASK) | (ncq->consumer_cnt &
				NETRO_DB_CQ_CONS_MASK);
	ncq->ci_mbox->last_db_state = cpu_to_le32(state);
	wmb();

	/*
	 * During integration we are verifying that the doorbell
	 * logic has captured any previous CQ doorbell before writing
	 * a second.
	 */
	while (cnt++ < NETRO_CQ_DB_READY_RETRIES) {
		fin_state = le32_to_cpu(__raw_readl(
					ndev->priv_uar.map +
					NETRO_DB_CQCI_ADDR_OFFSET));
		if (!(fin_state & NETRO_DB_FIN_BIT))
			break;
	}

	if (cnt >= NETRO_CQ_DB_READY_RETRIES)
		netro_warn(">>>>>> CQ doorbell unresponsive\n");

	if (!mad_cq_event_wa) {
		netro_debug("CQ Doorbell[0] = 0x%08X\n", db[0]);
		netro_debug("CQ Doorbell[1] = 0x%08X\n", db[1]);
	}

	netro_write64_db(ndev, db, NETRO_DB_WA_BIT + NETRO_DB_CQ_ADDR_OFFSET);
	return 0;
}

static struct ib_mr *netro_get_dma_mr(struct ib_pd *pd, int access_flags)
{
	struct netro_ibdev *ndev = to_netro_ibdev(pd->device);
	struct netro_mr *nmr;
	int err;

	netro_info("netro_get_dma_mr not surpported\n");
	return ERR_PTR(-ENOMEM);

	netro_info("netro_get_dma_mr\n");

	nmr = kmalloc(sizeof(*nmr), GFP_KERNEL);
	if (!nmr) {
		netro_info("No memory for MR object\n");
		return ERR_PTR(-ENOMEM);
	}

	nmr->mpt_index = netro_alloc_bitmap_index(&ndev->mpt_map);
	if (nmr->mpt_index < 0) {
		err = -ENOMEM;
		goto free_mem;
	}
	netro_info("DMA MPT Index %d\n", nmr->mpt_index);

	nmr->umem = NULL;
	nmr->pdn = to_netro_pd(pd)->pd_index;
	nmr->io_vaddr = 0;
	nmr->len = ~0ull;
	nmr->access = access_flags;
	nmr->page_shift = 0;
	nmr->mpt_order = 0;

	nmr->key = nmr->mpt_index;
	nmr->ib_mr.rkey = nmr->ib_mr.lkey = nmr->key;

	if (netro_init_mpt(ndev, nmr, 0, 0)) {
		netro_info("init_mpt failed\n");
		err = -ENOMEM;
		goto free_mpt;
	}

	return &nmr->ib_mr;

free_mpt:
	netro_free_bitmap_index(&ndev->mpt_map, nmr->mpt_index);
free_mem:
	kfree(nmr);
	return ERR_PTR(err);
}

static struct ib_mr *netro_reg_user_mr(struct ib_pd *pd, u64 start,
			u64 length, u64 virt_addr, int access_flags,
			struct ib_udata *udata)
{
	struct netro_ibdev *ndev = to_netro_ibdev(pd->device);
	struct netro_mr *nmr;
	int count, num_comp, shift, order, log2_page_sz;
	int err;

	netro_info("netro_reg_user_mr\n");
	netro_info("parameter: start=0x%llu, length=0x%llu, virt_addr=0x%llu\n",
		start, length, virt_addr);

	nmr = kmalloc(sizeof(*nmr), GFP_KERNEL);
	if (!nmr) {
		netro_info("No memory for MR object\n");
		return ERR_PTR(-ENOMEM);
	}

	nmr->mpt_index = netro_alloc_bitmap_index(&ndev->mpt_map);
	if (nmr->mpt_index < 0) {
		err = -ENOMEM;
		goto free_mem;
	}
	netro_info("MPT Index %d\n", nmr->mpt_index);

	nmr->umem = ib_umem_get(pd->uobject->context, start, length,
			access_flags, 0);
	if (IS_ERR(nmr->umem)) {
		err = PTR_ERR(nmr->umem);
		netro_info("ib_umem_get() failed %d\n", err);
		goto free_mpt;
	}

	netro_info("User Memory hugetlb %d\n", nmr->umem->hugetlb);

#if (VER_NON_RHEL_GE(5,3) || VER_RHEL_GE(8,0))
	log2_page_sz = PAGE_SHIFT;
#else
	log2_page_sz = nmr->umem->page_shift;
#endif
	netro_info("User Memory Page Size %d\n", log2_page_sz);
	netro_info("User Memory Num Pages %d\n",
				ib_umem_page_count(nmr->umem));
	/*
	 * Find the largest compound page size that can be used
	 * for the physical page list, limiting to the supported
	 * microcode maximum.
	 */
	netro_compound_order(nmr->umem, start, &count, &num_comp,
			&shift, &order);
	netro_info("User Memory Pages %d\n", count);
	netro_info("User Memory Compound Pages %d\n", num_comp);
	netro_info("User Memory Compound Page Shift %d\n", shift);
	netro_info("User Memory Compound Page Order %d\n", order);

	if (order + log2_page_sz > NETRO_MTT_MAX_PAGESIZE_LOG2) {
		num_comp <<= order  + log2_page_sz -
				NETRO_MTT_MAX_PAGESIZE_LOG2;
		order -=  order + log2_page_sz -
				NETRO_MTT_MAX_PAGESIZE_LOG2;
	}
	netro_info("Adjusted number of compound pages %d\n", num_comp);
	netro_info("Adjusted compound order %d\n", order);

	nmr->pdn = to_netro_pd(pd)->pd_index;
	nmr->io_vaddr = virt_addr;
	nmr->len = length;
	nmr->access = access_flags;
#if (VER_NON_RHEL_GE(5,3) || VER_RHEL_GE(8,0))
	nmr->page_shift = PAGE_SHIFT;
#else
	nmr->page_shift = nmr->umem->page_shift;
#endif
	nmr->mpt_order = order;

	nmr->key = nmr->mpt_index;
	nmr->ib_mr.rkey = nmr->ib_mr.lkey = nmr->key;

	if (netro_init_mpt(ndev, nmr, num_comp, order)) {
		netro_info("init_mpt failed\n");
		err = -ENOMEM;
		goto release_umem;
	}

	return &nmr->ib_mr;

release_umem:
	ib_umem_release(nmr->umem);
free_mpt:
	netro_free_bitmap_index(&ndev->mpt_map, nmr->mpt_index);
free_mem:
	kfree(nmr);
	return ERR_PTR(err);
}

static int netro_dereg_mr(struct ib_mr *mr)
{
	struct netro_ibdev *ndev = to_netro_ibdev(mr->device);
	struct netro_mr *nmr = to_netro_mr(mr);

	netro_cleanup_mpt(ndev, nmr);
	netro_free_bitmap_index(&ndev->mpt_map, nmr->mpt_index);

	if (nmr->umem)
		ib_umem_release(nmr->umem);

	kfree(nmr);
	return 0;
}

static struct ib_mr *netro_alloc_mr(struct ib_pd *pd,
			enum ib_mr_type mr_type, u32 max_num_sg)
{
	netro_warn("netro_alloc_frmr not implemented\n");
	return ERR_PTR(-ENOMEM);
}


static int netro_attach_mcast(struct ib_qp *qp, union ib_gid *gid, u16 lid)
{
	netro_warn("netro_attach_mcast not implemented\n");
	return 0;
}

static int netro_detach_mcast(struct ib_qp *qp, union ib_gid *gid, u16 lid)
{
	netro_warn("netro_detach_mcast not implemented\n");
	return 0;
}

int netro_register_verbs(struct netro_ibdev *ndev)
{
	int ret;

	strlcpy(ndev->ibdev.name, "corigine_%d", IB_DEVICE_NAME_MAX);
	ndev->ibdev.owner = THIS_MODULE;
	ndev->ibdev.node_type = RDMA_NODE_IB_CA;
	memcpy(ndev->ibdev.node_desc, NETRO_IB_NODE_DESC,
			sizeof(NETRO_IB_NODE_DESC));
	netro_mac_to_guid(ndev->nfp_info->def_mac, 0xFFFF,
		(u8 *)&ndev->ibdev.node_guid);
	ndev->ibdev.phys_port_cnt = ndev->cap.n_ports;

	/* If more than one EQ, then EQ 0 is reserved for async events */
	ndev->ibdev.num_comp_vectors = ndev->eq_table.num_eq > 1 ?
				ndev->eq_table.num_eq - 1 : 1;

	/* Currently do not support local DMA key */
	ndev->ibdev.local_dma_lkey = 0;

	ndev->ibdev.uverbs_abi_ver = NETRO_UVERBS_ABI_VERSION;
	ndev->ibdev.uverbs_cmd_mask =
		(1ull << IB_USER_VERBS_CMD_GET_CONTEXT)		|
                (1ull << IB_USER_VERBS_CMD_QUERY_DEVICE)        |
                (1ull << IB_USER_VERBS_CMD_QUERY_PORT)          |
                (1ull << IB_USER_VERBS_CMD_ALLOC_PD)            |
                (1ull << IB_USER_VERBS_CMD_DEALLOC_PD)          |
                (1ull << IB_USER_VERBS_CMD_REG_MR)              |
                (1ull << IB_USER_VERBS_CMD_DEREG_MR)            |
                (1ull << IB_USER_VERBS_CMD_CREATE_COMP_CHANNEL) |
                (1ull << IB_USER_VERBS_CMD_CREATE_CQ)           |
                (1ull << IB_USER_VERBS_CMD_RESIZE_CQ)           |
                (1ull << IB_USER_VERBS_CMD_DESTROY_CQ)          |
                (1ull << IB_USER_VERBS_CMD_CREATE_QP)           |
                (1ull << IB_USER_VERBS_CMD_MODIFY_QP)           |
                (1ull << IB_USER_VERBS_CMD_QUERY_QP)            |
                (1ull << IB_USER_VERBS_CMD_DESTROY_QP)          |
                (1ull << IB_USER_VERBS_CMD_ATTACH_MCAST)        |
                (1ull << IB_USER_VERBS_CMD_DETACH_MCAST)        |
                (1ull << IB_USER_VERBS_CMD_CREATE_SRQ)          |
                (1ull << IB_USER_VERBS_CMD_MODIFY_SRQ)          |
                (1ull << IB_USER_VERBS_CMD_QUERY_SRQ)           |
                (1ull << IB_USER_VERBS_CMD_CREATE_AH)           |
                (1ull << IB_USER_VERBS_CMD_QUERY_AH)            |
                (1ull << IB_USER_VERBS_CMD_DESTROY_AH)          |
                (1ull << IB_USER_VERBS_CMD_DESTROY_SRQ);

	ndev->ibdev.query_device	= netro_query_device;
	ndev->ibdev.query_port		= netro_query_port;
	ndev->ibdev.get_link_layer	= netro_get_link_layer;
	ndev->ibdev.query_gid		= netro_query_gid;
	ndev->ibdev.query_pkey		= netro_query_pkey;
	ndev->ibdev.get_netdev		= netro_get_netdev;
	ndev->ibdev.modify_device	= netro_modify_device;
	ndev->ibdev.modify_port		= netro_modify_port;
	ndev->ibdev.alloc_ucontext	= netro_alloc_ucontext;
	ndev->ibdev.dealloc_ucontext	= netro_dealloc_ucontext;
	ndev->ibdev.mmap		= netro_mmap;
	ndev->ibdev.alloc_pd		= netro_alloc_pd;
	ndev->ibdev.dealloc_pd		= netro_dealloc_pd;
	ndev->ibdev.create_ah		= netro_create_ah;
	ndev->ibdev.query_ah		= netro_query_ah;
	ndev->ibdev.destroy_ah		= netro_destroy_ah;
	ndev->ibdev.create_srq		= netro_create_srq;
	ndev->ibdev.modify_srq		= netro_modify_srq;
	ndev->ibdev.query_srq		= netro_query_srq;
	ndev->ibdev.destroy_srq		= netro_destroy_srq;
	ndev->ibdev.post_srq_recv	= netro_post_srq_recv;
	ndev->ibdev.create_qp		= netro_create_qp;
	ndev->ibdev.modify_qp		= netro_modify_qp;
	ndev->ibdev.query_qp		= netro_query_qp;
	ndev->ibdev.destroy_qp		= netro_destroy_qp;
	ndev->ibdev.post_send		= netro_post_send;
	ndev->ibdev.post_recv		= netro_post_recv;
	ndev->ibdev.create_cq		= netro_create_cq;
	ndev->ibdev.modify_cq		= netro_modify_cq;
	ndev->ibdev.resize_cq		= netro_resize_cq;
	ndev->ibdev.destroy_cq		= netro_destroy_cq;
	ndev->ibdev.poll_cq		= netro_poll_cq;
	ndev->ibdev.req_notify_cq	= netro_req_notify_cq;
	ndev->ibdev.get_dma_mr		= netro_get_dma_mr;
	ndev->ibdev.reg_user_mr		= netro_reg_user_mr;
	ndev->ibdev.dereg_mr		= netro_dereg_mr;
	ndev->ibdev.attach_mcast	= netro_attach_mcast;
	ndev->ibdev.detach_mcast	= netro_detach_mcast;
	ndev->ibdev.alloc_mr	        = netro_alloc_mr;
	ndev->ibdev.get_port_immutable  = netro_get_port_immutable;
	ndev->ibdev.get_dev_fw_str      = netro_get_dev_fw_str;
	ndev->ibdev.driver_id           = RDMA_DRIVER_CORIGINE;
	ndev->ibdev.dev.parent          = &ndev->nfp_info->pdev->dev;

	netro_dev_info(ndev, "ib_register_device begin\n");
	ret = ib_register_device(&ndev->ibdev, NULL);
	netro_dev_info(ndev, "ib_register_device: status: %d\n", ret);
	return ret;
}

void netro_unregister_verbs(struct netro_ibdev *ndev)
{
	ib_unregister_device(&ndev->ibdev);
	return;
}
