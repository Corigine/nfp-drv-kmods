/*
 * Copyright (c) 2015, Netronome, Inc. All rights reserved.
 * Copyright (C) 2022-2025 Corigine, Inc. All rights reserved.
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
#include <rdma/uverbs_ioctl.h>

#include "crdma_ib.h"
#include "crdma_abi.h"
#include "crdma_verbs.h"


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
struct crdma_mmap_req {
	struct list_head	entry;
	u64			paddr;
	u64			length;
};

/**
 * Add a pending mmap request to the user context.
 *
 * uctxt: The crdma RDMA verbs user space context.
 * paddr: The physical address for the backing.
 * length: The length of the physical address space.
 *
 * Returns 0 on success, otherwise -ENOMEM;
 */
static int crdma_add_mmap_req(struct crdma_ucontext *uctxt, u64 paddr,
			u64 length)
{
	struct crdma_mmap_req *req;
#if 0
	crdma_info("Add a mmap_req: 0x%016llX, length: %lld\n",
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
 * @uctxt: The crdma RDMA verbs user space context.
 * @paddr: The physical address for the backing to remove.
 * @length: The length of the physical address space being removed.
 */
static void crdma_remove_mmap_req(struct crdma_ucontext *uctxt, u64 paddr,
				u64 length)
{
	struct crdma_mmap_req *req, *tmp;

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
 * @dev: The RoCEE IB device.
 * @length: The minimum length of the queue.
 *
 * Returns the DMA memory to back the queue, or ERR_PTR on error.
 */
static struct crdma_mem *crdma_alloc_hw_queue(struct crdma_ibdev *dev,
		unsigned long length)
{
	struct crdma_mem *mem;
	int err;

	mem = crdma_alloc_dma_mem(dev, true,
			CRDMA_MEM_DEFAULT_ORDER, length);
	if (IS_ERR(mem)) {
		crdma_dev_err(dev, "Unable to allocate queue memory\n");
		return mem;
	}

	crdma_info("crdma_alloc_hw_queue dump: \n");
	pr_info("HWQ memory size        %d\n", mem->tot_len);
	pr_info("HWQ num allocs         %d\n", mem->num_allocs);
	pr_info("HWQ min order          %d\n", mem->min_order);
	pr_info("HWQ num SG             %d\n", mem->num_sg);
	pr_info("HWQ needs              %d MTT entries\n", mem->num_mtt);
	pr_info("HWQ base_mtt_ndx       %d\n", mem->base_mtt_ndx);

	err = crdma_mtt_write_sg(dev, mem->alloc, mem->num_sg,
			mem->base_mtt_ndx, mem->num_mtt,
			mem->min_order + PAGE_SHIFT,
			mem->num_sg, 0);
	if (err) {
		crdma_info("crdma_mmt_write_sg failed for HWQ, %d\n", err);
		crdma_free_dma_mem(dev, mem);
		return ERR_PTR(-ENOMEM); 
	}
	return mem;
}

/**
 * Free host DMA memory for a RDMA microcode/provider shared queue.
 *
 * @dev: The RoCEE IB device.
 * @mem: The memory allocated with crdma_alloc_hw_queue().
 */
static void crdma_free_hw_queue(struct crdma_ibdev *dev,
		struct crdma_mem *mem)
{
	return crdma_free_dma_mem(dev, mem);
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
static void crdma_compound_order(struct ib_umem *umem, u64 start,
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
	crdma_debug("start 0x%016llx, page_shift: %ld\n",
			start, page_shift);
	pfn_bits = (unsigned long)(start >> page_shift);
	crdma_debug("pfn_bits: 0%lx\n", pfn_bits);
	order = __ffs(pfn_bits);
	crdma_debug("find_first_bit returned: %ld\n", order);
	comp_mask = (1 << order) - 1;
	crdma_debug("Alignment comp_mask: 0x%08X\n", comp_mask);

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
				crdma_debug("new page: pfn_bits: 0x%lx, "
					"order: %ld, comp_mask: 0x%08X\n",
					pfn_bits, order, comp_mask);
			} else if (base + comp_pages != pfn) {
				/*
				 * Non compound pages, reset the new
				 * compound mask based on the alignment.
				 */
				crdma_debug("PFN mismatch\n");
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
		crdma_debug("Determine order, tot_pages: %d, order: %ld\n",
				tot_pages, order);

		order = min_t(unsigned long,
				ilog2(roundup_pow_of_two(tot_pages)),
				order);
		if (comp_order)
			*comp_order = order;
		crdma_debug("order: %d\n", *comp_order);

		*num_comp = DIV_ROUND_UP(tot_pages, (1 << order));
		crdma_debug("num_comp: %d\n", *num_comp);
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
static void crdma_process_err_cqe(struct crdma_cqe *cqe, struct ib_wc *wc)
{
	static const unsigned cqe_sts_to_wc_syn[] = {
		[CRDMA_CQE_NO_ERR]		= IB_WC_SUCCESS,
		[CRDMA_CQE_BAD_RESPONSE_ERR]	= IB_WC_BAD_RESP_ERR,
		[CRDMA_CQE_LOCAL_LENGTH_ERR]	= IB_WC_LOC_LEN_ERR,
		[CRDMA_CQE_LOCAL_ACCESS_ERR]	= IB_WC_LOC_ACCESS_ERR,
		[CRDMA_CQE_LOCAL_QP_PROT_ERR]	= IB_WC_LOC_PROT_ERR,
		[CRDMA_CQE_LOCAL_QP_OP_ERR]	= IB_WC_LOC_QP_OP_ERR,
		[CRDMA_CQE_MEMORY_MGMT_OP_ERR]	= IB_WC_MW_BIND_ERR,
		[CRDMA_CQE_REMOTE_ACCESS_ERR]	= IB_WC_REM_ACCESS_ERR,
		[CRDMA_CQE_REMOTE_INV_REQ_ERR]	= IB_WC_REM_INV_REQ_ERR,
		[CRDMA_CQE_REMOTE_OP_ERR]	= IB_WC_REM_OP_ERR,
		[CRDMA_CQE_RNR_RETRY_ERR]       = IB_WC_RNR_RETRY_EXC_ERR,
		[CRDMA_CQE_TRANSPORT_RETRY_ERR]	= IB_WC_RETRY_EXC_ERR,
		[CRDMA_CQE_ABORTED_ERR]		= IB_WC_REM_ABORT_ERR,
		[CRDMA_CQE_FLUSHED_ERR]		= IB_WC_WR_FLUSH_ERR
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
 * @ncq: Pointer to the crdma CQ.
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
static int crdma_process_cqe(struct crdma_cq *ncq, struct crdma_cqe *cqe,
		struct crdma_qp **last_qp, struct ib_wc *wc)
{
	struct crdma_ibdev *dev = to_crdma_ibdev(ncq->ib_cq.device);
	struct crdma_hw_workq *wq;
	u32 qpn_index = le32_to_cpu(cqe->qpn & CRDMA_CQE_QPN_MASK);
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
		*last_qp = radix_tree_lookup(&dev->qp_tree, qpn_index);
		if (unlikely(!last_qp)) {
			crdma_info("Unknown QP 0x%08X in CQE\n", qpn_index);
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

	if (cqe->flags & CRDMA_CQE_SENDQ_FLAG_BIT) {
		wq = &(*last_qp)->sq;
		wqe_index = le16_to_cpu(cqe->wqe_index);
		crdma_debug("CQE Send WQE index %d WQ head %d\n",
				wqe_index, wq->head);
		/* Advance the SQ head to this work request */
		wq->head = wqe_index;
		wc->wr_id = wq->wrid_map[wq->head & wq->mask];
		wq->head = (wq->head + 1) & wq->mask;
		crdma_debug("New Send WQ head %d\n", wq->head);
	} else {
		/*
		 * TODO: We will need to handle the case where
		 * the QP is attached to a SRQ here, once SRQ
		 * are implemented.
		 */
		wq = &(*last_qp)->rq;
		wc->wr_id = wq->wrid_map[wq->head & wq->mask];
		wq->head = (wq->head + 1) & wq->mask;
		crdma_debug("New Recv WQ head %d\n", wq->head);
	}

	/*
	 * If the CQE indicates an error completion, process and return
	 * error WC entry.
	 */
	if (cqe->status) {
		crdma_debug("Error CQE %d\n", cqe->status);
		crdma_process_err_cqe(cqe, wc);
		return 0;
	}

	wc->status = IB_WC_SUCCESS;
	wc->wc_flags = 0;

	if (cqe->flags & CRDMA_CQE_SENDQ_FLAG_BIT) {

		switch (cqe->opcode) {

		case CRDMA_WQE_RDMA_WRITE_WITH_IMM_OP:
			wc->wc_flags |= IB_WC_WITH_IMM;
			/* Fall through */
		case CRDMA_WQE_RDMA_WRITE_OP:
			wc->opcode = IB_WC_RDMA_WRITE;
			break;

		case CRDMA_WQE_RDMA_READ_OP:
			wc->opcode = IB_WC_RDMA_READ;
			wc->byte_len = le32_to_cpu(cqe->byte_count);
			break;

		case CRDMA_WQE_SEND_WITH_IMM_OP:
			wc->wc_flags |= IB_WC_WITH_IMM;
			/* Fall through */
		case CRDMA_WQE_SEND_OP:
			/* Fall through */
		default:
			wc->opcode = IB_WC_SEND;
			break;
		}
	} else {

		switch (cqe->opcode) {

		case CRDMA_WQE_RDMA_WRITE_WITH_IMM_OP:
			wc->opcode = IB_WC_RECV_RDMA_WITH_IMM;
			wc->wc_flags |= IB_WC_WITH_IMM;
			/* Swap immediate data to undo hardware swap */
			wc->ex.imm_data = __swab32(cqe->imm_inval);
			break;

		case CRDMA_WQE_SEND_WITH_IMM_OP:
			wc->wc_flags |= IB_WC_WITH_IMM;
			/* Swap immediate data to undo hardware swap */
			wc->ex.imm_data = __swab32(cqe->imm_inval);
			/* Fall through */
		case CRDMA_WQE_SEND_OP:
		default:
			wc->opcode = IB_WC_RECV;
			break;
		}

		wc->src_qp = le32_to_cpu(cqe->rem_qpn) & CRDMA_CQE_REM_QPN_MASK;
		wc->byte_len = le32_to_cpu(cqe->byte_count);
		wc->slid = 0;
		wc->dlid_path_bits = 0;
		wc->pkey_index = cqe->pkey_index;
		wc->wc_flags |= cqe->flags & CRDMA_CQE_GRH_FLAG_BIT ?
					IB_WC_GRH : 0;
		if ((*last_qp)->ib_qp.qp_type != IB_QPT_RC) {
#if 0 /* Don't turn on until verified operation */
			crdma_mac_swap(wc->smac, cqe->smac);
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
	crdma_debug("IB WC:\n");
	crdma_debug("      WRID: 0x%016llX\n", wc->wr_id);
	crdma_debug("    status: %d\n", wc->status);
	crdma_debug("    opcode: %d\n", wc->opcode);
	crdma_debug("        QP: %p\n", wc->qp);
	crdma_debug("     flags: 0x%X\n", wc->wc_flags);
	if (!(cqe->flags & CRDMA_CQE_SENDQ_FLAG_BIT)) {
		crdma_debug("  byte len: %d\n", wc->byte_len);
		crdma_debug("   src QPN: 0x%08X\n", wc->src_qp);
		crdma_debug("      smac: %02x:%02x:%02x:%02x:%02x:%02x\n",
				wc->smac[0], wc->smac[1], wc->smac[2],
				wc->smac[3], wc->smac[4], wc->smac[5]);
	}
	return 0;
}

/*
 * The following static functions implement the CRDMA IB
 * device OFA RDMA Verbs API entry points.
 */

static int crdma_query_device(struct ib_device *ibdev,
			struct ib_device_attr *dev_attr,
			struct ib_udata *uhw)
{
	struct crdma_ibdev *dev = to_crdma_ibdev(ibdev);

	crdma_info("crdma_query_device\n");
	memcpy(dev_attr, &dev->cap.ib, sizeof(*dev_attr));

	if (uhw->inlen || uhw->outlen)
		return -EINVAL;

	/*
	 * Adjust shared queue size limits exposed to consumer to
	 * account for entries used for driver overhead.
	 */
	dev_attr->max_qp_wr -= CRDMA_WQ_WQE_SPARES;
	dev_attr->max_cqe--;
	if (dev_attr->max_srq_wr)
		dev_attr->max_srq_wr -= CRDMA_WQ_WQE_SPARES;

	return 0;
}

static int crdma_query_port(struct ib_device *ibdev, u8 port_num,
			struct ib_port_attr *port_attr)
{
	struct crdma_ibdev *dev = to_crdma_ibdev(ibdev);
	struct net_device *netdev;

	crdma_info("crdma_query_port: %d\n", port_num);

	if (port_num != 1) {
		crdma_dev_warn(dev, "invalid port=%d\n", port_num);
		return -EINVAL;
	}

	netdev = dev->nfp_info->netdev;
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
	port_attr->gid_tbl_len	= dev->cap.sgid_table_size;
	port_attr->pkey_tbl_len	= 1;
	port_attr->bad_pkey_cntr = 0;
	port_attr->qkey_viol_cntr = 0;

	/* TODO:  We will really need a way to determine actual link speed  */
	port_attr->active_speed	= IB_SPEED_QDR;
	port_attr->active_width	= IB_WIDTH_4X;

	port_attr->max_msg_sz	= CRDMA_MAX_MSG_SIZE;

	/* TODO:  Must really determine value for max virtual lanes */
	port_attr->max_vl_num	= 4;

	return 0;
}

struct net_device *crdma_get_netdev(struct ib_device *ibdev, u8 port_num)
{
	struct crdma_ibdev *crdma_dev = to_crdma_ibdev(ibdev);
	struct net_device *netdev;

	crdma_info("crdma_get_netdev: %d\n", port_num);

	if (port_num != 1) {
		crdma_dev_warn(crdma_dev, "invalid port=%d\n", port_num);
		return NULL;
	}

	rcu_read_lock();
	netdev = crdma_dev->nfp_info->netdev;
	if (netdev)
		dev_hold(netdev);

	rcu_read_unlock();
	return netdev;
}

int crdma_get_port_immutable(struct ib_device *ibdev, u8 port_num,
			       struct ib_port_immutable *immutable)
{
	struct ib_port_attr port_attr;

	if (crdma_query_port(ibdev, port_num, &port_attr))
		return -EINVAL;

	immutable->pkey_tbl_len    = port_attr.pkey_tbl_len;
	immutable->gid_tbl_len     = port_attr.gid_tbl_len;
	immutable->core_cap_flags  = RDMA_CORE_PORT_IBA_ROCE;
	immutable->core_cap_flags |= RDMA_CORE_CAP_PROT_ROCE_UDP_ENCAP;
	immutable->max_mad_size    = IB_MGMT_MAD_SIZE;

	return 0;
}

void crdma_get_dev_fw_str(struct ib_device *ibdev, char *str)
{
	struct crdma_ibdev *dev = to_crdma_ibdev(ibdev);

	snprintf(str, IB_FW_VERSION_NAME_MAX, "%d.%d",
		 dev->cap.uc_maj_rev, dev->cap.uc_min_rev);
	crdma_info("crdma_get_dev_fw_str: %s\n", str);

	return;
}

static enum rdma_link_layer crdma_get_link_layer(
			struct ib_device *ibdev, u8 port_num)
{
	return IB_LINK_LAYER_ETHERNET;
}

static int crdma_query_gid(struct ib_device *ibdev, u8 port_num,
			int index, union ib_gid *gid)
{
	struct crdma_ibdev *dev = to_crdma_ibdev(ibdev);

	crdma_info("crdma_query_gid\n");

	if (port_num != 1 ||
		index >= dev->cap.sgid_table_size)
        return -EINVAL;

	*gid = dev->port.gid_table_entry[index].gid;
	return 0;
}

static int crdma_query_pkey(struct ib_device *ibdev, u8 port_num,
			u16 index, u16 *pkey)
{
	struct crdma_ibdev *dev = to_crdma_ibdev(ibdev);

	crdma_info("crdma_query_pkey\n");
	if (port_num != 1) {
		crdma_dev_warn(dev, "invalid IB port=%d\n", port_num);
		return -EINVAL;
	}

	if (index > 0) {
		crdma_dev_warn(dev, "invalid pkey index=%d\n", index);
		return -EINVAL;
	}
	*pkey = 0xFFFF;
	return 0;
}

static int crdma_modify_device(struct ib_device *ibdev, int dev_mod_mask,
			struct ib_device_modify *dev_modify)
{
	crdma_info("crdma_modify_device not implemented\n");
	return 0;
}

static int crdma_modify_port(struct ib_device *ibdev, u8 port_num,
			int port_mod_mask, struct ib_port_modify *port_modify)
{
	crdma_info("crdma_modify_port not implemented\n");
	return 0;
}

#if (VER_NON_RHEL_GE(5,1) || VER_RHEL_GE(8,0))
static int crdma_alloc_ucontext(struct ib_ucontext *ib_uctxt,
				struct ib_udata *udata)
{
	struct ib_device *ibdev = ib_uctxt->device;
	struct crdma_ucontext *crdma_uctxt;
	struct crdma_ibdev *dev = to_crdma_ibdev(ibdev);
	struct crdma_ib_alloc_ucontext_resp resp;
	int err;

	crdma_info("crdma_alloc_ucontext\n");

	/*
	 * Inform the library provider of the chip-set family we
	 * are working with.
	 */
	resp.max_qp = dev->cap.ib.max_qp - dev->cap.rsvd_qp;

#if (VER_NON_RHEL_GE(5,1) || VER_RHEL_GE(8,0))
	crdma_uctxt = container_of(ib_uctxt, struct crdma_ucontext, ib_uctxt);
#else
	crdma_uctxt = kmalloc(sizeof(*crdma_uctxt), GFP_KERNEL);
#endif
	if (!crdma_uctxt)
		return -ENOMEM;

	/*
	 * Each user context maintains a list of memory areas waiting to
	 * be mapped into the user context virtual address space.
	 */
	INIT_LIST_HEAD(&crdma_uctxt->mmap_pending);
	mutex_init(&crdma_uctxt->mmap_pending_lock);

	err = crdma_alloc_uar(dev, &crdma_uctxt->uar);
	if (err)
		goto free_uctxt;

	err = ib_copy_to_udata(udata, &resp, sizeof(resp));
	if (err)
		goto free_uar;

	return 0;

free_uar:
	crdma_free_uar(dev, &crdma_uctxt->uar);
free_uctxt:
	kfree(crdma_uctxt);
	return err;
}

#else
static struct ib_ucontext * crdma_alloc_ucontext(struct ib_device *ibdev,
				struct ib_udata *udata)
{
	struct crdma_ibdev *dev = to_crdma_ibdev(ibdev);
	struct crdma_ucontext *crdma_uctxt;
	struct crdma_ib_alloc_ucontext_resp resp;
	int err;

	crdma_info("crdma_alloc_ucontext\n");

	/*
	 * Inform the library provider of the chip-set family we
	 * are working with.
	 */
	resp.max_qp = dev->cap.ib.max_qp - dev->cap.rsvd_qp;

	crdma_uctxt = kmalloc(sizeof(*crdma_uctxt), GFP_KERNEL);
	if (!crdma_uctxt)
		return ERR_PTR(-ENOMEM);

	/*
	 * Each user context maintains a list of memory areas waiting to
	 * be mapped into the user context virtual address space.
	 */
	INIT_LIST_HEAD(&crdma_uctxt->mmap_pending);
	mutex_init(&crdma_uctxt->mmap_pending_lock);

	err = crdma_alloc_uar(dev, &crdma_uctxt->uar);
	if (err)
		goto free_uctxt;

	err = ib_copy_to_udata(udata, &resp, sizeof(resp));
	if (err)
		goto free_uar;

	return &crdma_uctxt->ib_uctxt;

free_uar:
	crdma_free_uar(dev, &crdma_uctxt->uar);
free_uctxt:
	kfree(crdma_uctxt);
	return ERR_PTR(err);
}
#endif

#if (VER_NON_RHEL_GE(5,1) || VER_RHEL_GE(8,0))
static void crdma_dealloc_ucontext(struct ib_ucontext *ib_uctxt)
#else
static int crdma_dealloc_ucontext(struct ib_ucontext *ib_uctxt)
#endif
{
	struct crdma_ibdev *dev = to_crdma_ibdev(ib_uctxt->device);
	struct crdma_ucontext *crdma_uctxt = to_crdma_uctxt(ib_uctxt);
	struct crdma_mmap_req *req, *tmp;

	crdma_info("crdma_dealloc_ucontext\n");

	crdma_free_uar(dev, &crdma_uctxt->uar);

	/* Release any pending mmap definitions */
	mutex_lock(&crdma_uctxt->mmap_pending_lock);
	list_for_each_entry_safe(req, tmp, &crdma_uctxt->mmap_pending, entry) {
		list_del(&req->entry);
		kfree(req);
	}
	mutex_unlock(&crdma_uctxt->mmap_pending_lock);

#if (!(VER_NON_RHEL_GE(5,1) || VER_RHEL_GE(8,0)))
	kfree(crdma_uctxt);
	return 0;
#endif
}

/**
 * map physical memory into user context virtual address space.
 *
 * ib_uctxt: The IB user context.
 * vma: The virtual memory area.
 *
 * Returns 0 on success, otherwise error.
 */
static int crdma_mmap(struct ib_ucontext *ib_uctxt,
			struct vm_area_struct *vma)
{
	struct crdma_ibdev *dev = to_crdma_ibdev(ib_uctxt->device);
	struct crdma_ucontext *crdma_uctxt = to_crdma_uctxt(ib_uctxt);
	struct crdma_mmap_req *req, *tmp;
	u64 offset = vma->vm_pgoff << PAGE_SHIFT;
	u64 length = vma->vm_end - vma->vm_start;

	crdma_info("mmap uctxt: 0x%p\n", crdma_uctxt);
	pr_info("  vma->vm_pgoff = %ld\n", vma->vm_pgoff);
	pr_info("  offset = 0x%016llX\n", offset);
	pr_info("  length = 0x%lld\n", length);

	if (vma->vm_start & (PAGE_SIZE -1))
		return -EINVAL;

	/* First page offset is for user context UAR used for doorbells */
	if (vma->vm_pgoff == 0) {
		crdma_info("Map user context UAR, index: %d\n", crdma_uctxt->uar.index);
		vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);

		return io_remap_pfn_range(vma, vma->vm_start,
				crdma_uar_pfn(dev, &crdma_uctxt->uar),
				PAGE_SIZE, vma->vm_page_prot);
	}

	/* A request to mmap a kernel allocated QP, SRQ, or CQ queue */
	mutex_lock(&crdma_uctxt->mmap_pending_lock);
	list_for_each_entry_safe(req, tmp, &crdma_uctxt->mmap_pending, entry) {
#if 0
		crdma_info("Pending paddr:0x%016llX, len:%lld\n",
				req->paddr, req->length);
		crdma_info("Test paddr:0x%016llX, len:%lld\n",
				offset, length);
#endif
		if ((req->paddr != offset) || (req->length < length))
			continue;
#if 0
		crdma_info("mmap found, mapping\n");
#endif
		list_del(&req->entry);
		kfree(req);
		mutex_unlock(&crdma_uctxt->mmap_pending_lock);
		return remap_pfn_range(vma, vma->vm_start, vma->vm_pgoff,
				length, vma->vm_page_prot);
	}
	crdma_warn("No pending mmap found\n");
	mutex_unlock(&crdma_uctxt->mmap_pending_lock);
	return -EINVAL;
}

#if (VER_NON_RHEL_GE(5,2) || VER_RHEL_GE(8,0))
static int crdma_alloc_pd(struct ib_pd *ibpd, struct ib_udata *udata)
{
	struct ib_device *ibdev = ibpd->device;
	struct crdma_pd *pd = container_of(ibpd, struct crdma_pd, ib_pd);
	struct crdma_ibdev *dev = to_crdma_ibdev(ibdev);
	int err;

	crdma_info("crdma_alloc_pd\n");
	pd->pd_index = crdma_alloc_bitmap_index(&dev->pd_map);
	if (pd->pd_index < 0) {
		err = -ENOMEM;
		goto free_mem;
	}

	crdma_info("PD Index %d\n", pd->pd_index);
	if(udata) {
		err = ib_copy_to_udata(udata, &pd->pd_index, sizeof(u32));
		if (err)
			goto free_pd;
	}
	return 0;

free_pd:
	crdma_free_bitmap_index(&dev->pd_map, pd->pd_index);
free_mem:
	return err;
}
#else
static struct ib_pd *crdma_alloc_pd(struct ib_device *ibdev,
			struct ib_ucontext *ib_uctxt,
			struct ib_udata *udata)
{
	struct crdma_ibdev *dev = to_crdma_ibdev(ibdev);
	struct crdma_pd *pd;
	int err;

	crdma_info("crdma_alloc_pd\n");
	pd = kmalloc(sizeof(*pd), GFP_KERNEL);
	if (!pd)
		return ERR_PTR(-ENOMEM);

	pd->pd_index = crdma_alloc_bitmap_index(&dev->pd_map);
	if (pd->pd_index < 0) {
		err = -ENOMEM;
		goto free_mem;
	}

	crdma_info("PD Index %d\n", pd->pd_index);
	if (ib_uctxt) {
		err = ib_copy_to_udata(udata, &pd->pd_index, sizeof(u32));
		if (err)
			goto free_pd;
	}
	return &pd->ib_pd;

free_pd:
	crdma_free_bitmap_index(&dev->pd_map, pd->pd_index);
free_mem:
	kfree(pd);
	return ERR_PTR(err);
}
#endif

#if (VER_NON_RHEL_GE(5,10) || VER_RHEL_GE(8,0))
static int crdma_dealloc_pd(struct ib_pd *pd, struct ib_udata *udata)
#else
static int crdma_dealloc_pd(struct ib_pd *pd)
#endif
{
	struct crdma_ibdev *dev = to_crdma_ibdev(pd->device);
	struct crdma_pd *npd = to_crdma_pd(pd);

	crdma_info("crdma_dealloc_pd, PD Index %d\n", npd->pd_index);
	crdma_free_bitmap_index(&dev->pd_map, npd->pd_index);

#if (!(VER_NON_RHEL_GE(5,10) || VER_RHEL_GE(8,0)))
	kfree(pd);
#endif
	return 0;
}

#if (VER_NON_RHEL_GE(5,8) || VER_RHEL_GE(8,0))
static int crdma_create_ah(struct ib_ah *ah, struct rdma_ah_init_attr *init_attr,
			struct ib_udata *udata)
{
	struct ib_pd *pd = ah->pd;
	struct rdma_ah_attr *ah_attr = init_attr->ah_attr;
	struct crdma_ibdev *dev = to_crdma_ibdev(ah->device);
	struct crdma_ah *nah = to_crdma_ah(ah);
	struct in6_addr in6;
	u8 d_mac[ETH_ALEN];

	crdma_info("crdma_create_ah\n");

	if (!(ah_attr->ah_flags & IB_AH_GRH)) {
			crdma_info("RoCE requires GRH\n");
			return -EINVAL;
	}
	if (pd->uobject) {
			crdma_warn("Invocation of kernel only implementation\n");
			return -EINVAL;
	}

	if (ah_attr->grh.sgid_index >= dev->cap.sgid_table_size) {
			crdma_info("Invalid SGID Index %d\n", ah_attr->grh.sgid_index);
			return -EINVAL;
	}

	memcpy(&in6, ah_attr->grh.dgid.raw, sizeof(in6));
	if (rdma_is_multicast_addr(&in6))
			rdma_get_mcast_mac(&in6, d_mac);
	else
			memcpy(d_mac, ah_attr->roce.dmac, ETH_ALEN);

	crdma_info("D_MAC:%02X:%02X:%02X:%02X:%02X:%02X\n",
					d_mac[0], d_mac[1], d_mac[2], d_mac[3],
					d_mac[4], d_mac[5]);

#if 0 /* Don't turn on until verified operation */
	crdma_mac_swap(nah->av.d_mac, d_mac);
#else
	nah->av.d_mac[0] = d_mac[3];
	nah->av.d_mac[1] = d_mac[2];
	nah->av.d_mac[2] = d_mac[1];
	nah->av.d_mac[3] = d_mac[0];
	nah->av.d_mac[4] = d_mac[5];
	nah->av.d_mac[5] = d_mac[4];
#endif

	crdma_info("AV D_MAC:%02X:%02X:%02X:%02X:%02X:%02X\n",
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
		nah->av.gid_type = CRDMA_AV_ROCE_V2_IPV4_GID_TYPE;
	else
		nah->av.gid_type = CRDMA_AV_ROCE_V2_IPV6_GID_TYPE;

	/* For now using maximum rate, no IPD */
	nah->av.ib_sr_ipd = cpu_to_le32((0 << CRDMA_AV_IBSR_IPD_SHIFT) |
					(to_crdma_pd(pd)->pd_index & CRDMA_AV_PD_MASK));

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
	return 0;
}
#else
static struct ib_ah *crdma_create_ah(struct ib_pd *pd,
			struct rdma_ah_attr *ah_attr,
			struct ib_udata *uhw)
{
	struct crdma_ibdev *dev = to_crdma_ibdev(pd->device);
	struct crdma_ah *nah;
	struct in6_addr in6;
	u8 d_mac[ETH_ALEN];

	crdma_info("crdma_create_ah\n");

	if (!(ah_attr->ah_flags & IB_AH_GRH)) {
			crdma_info("RoCE requires GRH\n");
			return ERR_PTR(-EINVAL);
	}
	if (pd->uobject) {
			crdma_warn("Invocation of kernel only implementation\n");
			return ERR_PTR(-EINVAL);
	}

	if (ah_attr->grh.sgid_index >= dev->cap.sgid_table_size) {
			crdma_info("Invalid SGID Index %d\n", ah_attr->grh.sgid_index);
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

	crdma_info("D_MAC:%02X:%02X:%02X:%02X:%02X:%02X\n",
					d_mac[0], d_mac[1], d_mac[2], d_mac[3],
					d_mac[4], d_mac[5]);

#if 0 /* Don't turn on until verified operation */
	crdma_mac_swap(nah->av.d_mac, d_mac);
#else
	nah->av.d_mac[0] = d_mac[3];
	nah->av.d_mac[1] = d_mac[2];
	nah->av.d_mac[2] = d_mac[1];
	nah->av.d_mac[3] = d_mac[0];
	nah->av.d_mac[4] = d_mac[5];
	nah->av.d_mac[5] = d_mac[4];
#endif

	crdma_info("AV D_MAC:%02X:%02X:%02X:%02X:%02X:%02X\n",
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
		nah->av.gid_type = CRDMA_AV_ROCE_V2_IPV4_GID_TYPE;
	else
		nah->av.gid_type = CRDMA_AV_ROCE_V2_IPV6_GID_TYPE;

	/* For now using maximum rate, no IPD */
	nah->av.ib_sr_ipd = cpu_to_le32((0 << CRDMA_AV_IBSR_IPD_SHIFT) |
					(to_crdma_pd(pd)->pd_index & CRDMA_AV_PD_MASK));

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
#endif

static int crdma_query_ah(struct ib_ah *ah, struct rdma_ah_attr *ah_attr)
{
	struct crdma_ah *nah = to_crdma_ah(ah);

	crdma_info("crdma_query_ah\n");

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

#if (VER_NON_RHEL_GE(5,0) || VER_RHEL_GE(8,0))
static int crdma_destroy_ah(struct ib_ah *ah, u32 flags)
#else
static int crdma_destroy_ah(struct ib_ah *ah)
#endif
{
	crdma_info("crdma_destroy_ah\n");
	kfree(to_crdma_ah(ah));
	return 0;
}

#if (VER_NON_RHEL_GE(5,2) || VER_RHEL_GE(8,0))
static int crdma_create_srq(struct ib_srq *srq,
			struct ib_srq_init_attr *srq_init_attr,
			struct ib_udata *udata)
{
	crdma_warn("crdma_create_srq not implemented\n");
	return -ENOMEM;
}
#else
static struct ib_srq *crdma_create_srq(struct ib_pd *pd,
			struct ib_srq_init_attr *srq_init_attr,
			struct ib_udata *udata)
{
	crdma_warn("crdma_create_srq not implemented\n");
	return ERR_PTR(-ENOMEM);
}
#endif

static int crdma_modify_srq(struct ib_srq *srq,
			struct ib_srq_attr *srq_attr,
			enum ib_srq_attr_mask srq_attr_mask,
			struct ib_udata *udata)
{
	crdma_warn("crdma_modify_srq not implemented\n");
	return 0;
}

static int crdma_query_srq(struct ib_srq *srq,
			struct ib_srq_attr *srq_attr)
{
	crdma_warn("crdma_query_srq not implemented\n");
	return 0;
}

#if (VER_NON_RHEL_GE(5,10) || VER_RHEL_GE(8,0))
static int crdma_destroy_srq(struct ib_srq *srq, struct ib_udata *udata)
#else
static int crdma_destroy_srq(struct ib_srq *srq)
#endif
{
	crdma_warn("crdma_destroy_srq not implemented\n");
	return 0;
}

static int crdma_post_srq_recv(struct ib_srq *srq, const struct ib_recv_wr *wr,
			           const struct ib_recv_wr **bad_recv_wr)
{
	crdma_warn("crdma_post_srq_recv not implemented\n");
	return 0;
}

static int crdma_qp_val_check(struct crdma_ibdev *dev,
		struct ib_qp_cap *cap, bool use_srq)
{
	/* Note we advertise 1 less than actual hardware maximum */
	if (cap->max_send_wr >= dev->cap.ib.max_qp_wr) {
		crdma_info("Send WR entries requested > max %d\n",
				dev->cap.ib.max_qp_wr);
		return -EINVAL;
	}

	if (cap->max_send_sge < 1 ||
			cap->max_send_sge > dev->cap.ib.max_send_sge) {
		crdma_info("Send SG entries requested invalid %d\n",
				cap->max_send_sge);
		return -EINVAL;
	}

	if (!use_srq) {
		/* Note we advertise 1 less than actual hardware maximum */
		if (cap->max_recv_wr >= dev->cap.ib.max_qp_wr) {
			crdma_info("Recv WR entries requested > max %d\n",
					dev->cap.ib.max_qp_wr);
			return -EINVAL;
		}
		if (cap->max_recv_sge < 1 ||
				cap->max_recv_sge > dev->cap.ib.max_sge_rd) {
			crdma_info("Receive SG entries requested > max %d\n",
					dev->cap.ib.max_sge_rd);
			return -EINVAL;
		}
	} else {
		if (cap->max_recv_wr) {
			crdma_info("Recv WR must be 0 when using SRQ\n");
			return -EINVAL;
		}
		crdma_warn("SRQ not yet supported\n");
		return -EINVAL;
	}

	if (cap->max_inline_data > dev->cap.max_inline_data) {
		crdma_info("Max inline data requested > max %d\n",
				dev->cap.max_inline_data);
		return -EINVAL;
	}
	return 0;
}

static int crdma_qp_set_wq_sizes(struct crdma_ibdev *dev,
			struct crdma_qp *qp, struct ib_qp_init_attr *attr)
{
	/*
	 * Transport specific information and then space for the requested
	 * number of gather entries and in-line data.
	 */
	qp->sq.wqe_size = sizeof(struct crdma_swqe_ctrl);
	qp->sq.wqe_size += (attr->qp_type == IB_QPT_RC) ?
				sizeof(struct crdma_rc_swqe) :
				sizeof(struct crdma_ud_swqe);
	qp->sq.wqe_size += max((u32)(sizeof(struct crdma_wqe_sge) *
				attr->cap.max_send_sge),
				attr->cap.max_inline_data);
	qp->sq.wqe_size = roundup_pow_of_two(qp->sq.wqe_size);

	if (qp->sq.wqe_size > dev->cap.max_swqe_size) {
		crdma_info("Required SWQE size %d exceeds max %d\n",
				qp->sq.wqe_size, dev->cap.max_swqe_size);
		return -EINVAL;
	}

	qp->sq.wqe_cnt =roundup_pow_of_two(attr->cap.max_send_wr +
					CRDMA_WQ_WQE_SPARES);
	qp->sq.max_sg = attr->cap.max_send_sge;
	qp->max_inline = attr->cap.max_inline_data;

	/* Receive work queue, only valid if no SRQ */
	if (!attr->srq) {
		/*
		 * Control information and space for the requested maximum
		 * number of scatter entries.
		 */
		qp->rq.wqe_size =  sizeof(struct crdma_rwqe) +
					sizeof(struct crdma_wqe_sge) *
					attr->cap.max_recv_sge;
		qp->rq.wqe_size = roundup_pow_of_two(qp->rq.wqe_size);
		qp->rq.wqe_cnt =roundup_pow_of_two(attr->cap.max_recv_wr +
						CRDMA_WQ_WQE_SPARES);
		qp->rq.max_sg = attr->cap.max_recv_sge;
		if (qp->rq.wqe_size > dev->cap.max_rwqe_size) {
			crdma_info("Required RWQE size %d exceeds max %d\n",
				qp->rq.wqe_size, dev->cap.max_rwqe_size);
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

	crdma_info("Set WQ sizes\n");
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
static void crdma_init_wq_ownership(struct crdma_mem *mem, u32 offset,
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
static void crdma_qp1_work(struct work_struct *work)
{
	struct delayed_work *delay = to_delayed_work(work);
	struct crdma_port *port;
	struct crdma_cq *ncq;
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
		INIT_DELAYED_WORK(&port->qp1_cq_dwork, crdma_qp1_work);
		schedule_delayed_work(&port->qp1_cq_dwork,
				msecs_to_jiffies(100));
	}
	spin_unlock_irqrestore(&port->qp1_lock, flags);

	return;
}

/**
 * Verify the QP1 port is unused, initialize and update.
 *
 * @dev: The RoCEE IB device.
 * @nqp: The crdma QP associated with the QP1.
 * @port_num: The physical port number to be associated with this QP1 (0 based).
 *
 * Returns 0 on success, otherwise an error if it can not be set.
 */
static int crdma_set_qp1_port(struct crdma_ibdev *dev, struct crdma_qp *nqp,
				int port_num)
{
	struct crdma_port *port = &dev->port;
	unsigned long flags;

	crdma_debug("Setting QP1 physical port number %d, %p\n",
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
		port->qp1_send_ncq = dev->cq_table[nqp->send_cqn];
		port->qp1_recv_ncq = dev->cq_table[nqp->recv_cqn];
		crdma_info("QP1 WA send_ncq %p, recv_ncq %p",
				port->qp1_send_ncq, port->qp1_recv_ncq);
		INIT_DELAYED_WORK(&port->qp1_cq_dwork, crdma_qp1_work);
		schedule_delayed_work(&port->qp1_cq_dwork,
					msecs_to_jiffies(100));
	}
	spin_unlock_irqrestore(&port->qp1_lock, flags);

	return 0;
}

/**
 * Indicate that QP1 is not in use for a physical port.
 *
 * @dev: The RoCEE IB device.
 * @port_num: The physical port number associated with this QP1 (0 based).
 */
static void crdma_clear_qp1_port(struct crdma_ibdev *dev, int port_num)
{
	struct crdma_port *port = &dev->port;
	unsigned long flags;

	crdma_debug("Clearing QP1 physical port number %d\n", port_num);

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

static struct ib_qp *crdma_create_qp(struct ib_pd *pd,
			struct ib_qp_init_attr *qp_init_attr,
			struct ib_udata *udata)
{
	struct crdma_ibdev *dev = to_crdma_ibdev(pd->device);
	struct crdma_qp *nqp;
	int err;

	crdma_info("crdma_create_qp\n");

	if (qp_init_attr->qp_type != IB_QPT_UD &&
			qp_init_attr->qp_type != IB_QPT_RC &&
			qp_init_attr->qp_type != IB_QPT_GSI) {
		crdma_info("Unsupported QP type %d\n", qp_init_attr->qp_type);
		return ERR_PTR(-EINVAL);
	}

	if (udata && qp_init_attr->qp_type == IB_QPT_GSI) {
		crdma_info("QP1 create restricted to kernel\n");
		return ERR_PTR(-EINVAL);
	}

	if (crdma_qp_val_check(dev, &qp_init_attr->cap,
				qp_init_attr->srq != NULL)) {
		crdma_info("QP init attribute validation failed\n");
		return ERR_PTR(-EINVAL);
	}

	nqp = kzalloc(sizeof(*nqp), GFP_KERNEL);
	if (!nqp)
		return ERR_PTR(-ENOMEM);

	mutex_init(&nqp->mutex);
	spin_lock_init(&nqp->sq.lock);
	spin_lock_init(&nqp->rq.lock);
	nqp->qp_state = IB_QPS_RESET;
	nqp->pdn = pd ? to_crdma_pd(pd)->pd_index : 0;
	nqp->send_cqn = qp_init_attr->send_cq ?
		to_crdma_cq(qp_init_attr->send_cq)->cqn : 0;
	nqp->recv_cqn = qp_init_attr->recv_cq ?
		to_crdma_cq(qp_init_attr->recv_cq)->cqn : 0;
	nqp->srqn = qp_init_attr->srq ?
		to_crdma_srq(qp_init_attr->srq)->srq_index : 0;

	nqp->sq_sig_type = qp_init_attr->sq_sig_type;

	/* Handle speical QP1 requirements */
	if (qp_init_attr->qp_type == IB_QPT_GSI) {
		crdma_debug("Creating Special QP1\n");
		err = crdma_set_qp1_port(dev, nqp,
				qp_init_attr->port_num - 1);
		if (err) {
			crdma_info("Error %d setting QP1 port number\n", err);
			err = -EINVAL;
			goto free_mem;
		}
	}

	/* Set the actual number and sizes of the QP work requests */
	err = crdma_qp_set_wq_sizes(dev, nqp, qp_init_attr);
	if (err) {
		err = -EINVAL;
		goto clear_port;
	}

	/* Allocate resource index for the QP control object */
	nqp->qp_index = qp_init_attr->qp_type == IB_QPT_GSI ?
		qp_init_attr->port_num - 1 :
		crdma_alloc_bitmap_index(&dev->qp_map);
	if (nqp->qp_index < 0) {
		crdma_info("No QP index available\n");
		err = -ENOMEM;
		goto clear_port;
	}

	/* Kernel always allocates QP memory, user contexts will mmap it */
	nqp->mem = crdma_alloc_hw_queue(dev, nqp->sq.length + nqp->rq.length);
	if (IS_ERR(nqp->mem)) {
		crdma_dev_err(dev, "Unable to allocate QP HW queue\n");
		err = -ENOMEM;
		goto free_qp_index;
	}

	crdma_init_wq_ownership(nqp->mem, nqp->sq_offset,
				nqp->sq.wqe_cnt, nqp->sq.wqe_size);
	crdma_init_wq_ownership(nqp->mem, nqp->rq_offset,
				nqp->rq.wqe_cnt, nqp->rq.wqe_size);

	/* Add to Radix tree for lookups */
	spin_lock_irq(&dev->qp_lock);
	err = radix_tree_insert(&dev->qp_tree, nqp->qp_index, nqp);
	spin_unlock_irq(&dev->qp_lock);
	if (err) {
		crdma_dev_err(dev, "Unable to insert QP tree\n");
		goto free_dma_memory;
	}

	nqp->ib_qp.qp_num = qp_init_attr->qp_type == IB_QPT_GSI ?
			1 : nqp->qp_index;

	/* return response */
	if (udata) {
		struct crdma_ucontext *crdma_uctxt =
				to_crdma_uctxt(pd->uobject->context);
		struct crdma_ib_create_qp_resp resp;

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
		resp.spares = CRDMA_WQ_WQE_SPARES;

		err = ib_copy_to_udata(udata, &resp, sizeof(resp));
		if (err) {
			crdma_info("Copy of UDATA failed, %d\n", err);
			goto delete_qp;
		}

		err = crdma_add_mmap_req(crdma_uctxt, resp.wq_base_addr,
				nqp->mem->tot_len);
		if (err) {
			crdma_info("Failed to add pending mmap, %d\n", err);
			goto delete_qp;
		}
	} else {
		if (qp_init_attr->qp_type != IB_QPT_GSI) {
			crdma_info("Only Kernel QP1 supported now\n");
			err = -ENOMEM;
			goto delete_qp;
		}
		nqp->sq.buf = sg_virt(nqp->mem->alloc) + nqp->sq_offset;
		nqp->sq.mask = nqp->sq.wqe_cnt - 1;
		nqp->sq.wqe_size_log2 = ilog2(nqp->sq.wqe_size);

		nqp->sq.wrid_map = kcalloc(nqp->sq.wqe_cnt, sizeof(u64),
						GFP_KERNEL);
		if (!nqp->sq.wrid_map) {
			crdma_info("Could not allocate SQ WRID map\n");
			err = -ENOMEM;
			goto delete_qp;
		}

		nqp->rq.buf = sg_virt(nqp->mem->alloc) + nqp->rq_offset;
		nqp->rq.mask = nqp->rq.wqe_cnt - 1;
		nqp->rq.wqe_size_log2 = ilog2(nqp->rq.wqe_size);

		nqp->rq.wrid_map = kcalloc(nqp->rq.wqe_cnt, sizeof(u64),
						GFP_KERNEL);
		if (!nqp->rq.wrid_map) {
			crdma_info("Could not allocate RQ WRID map\n");
			err = -ENOMEM;
			kfree(nqp->sq.wrid_map);
			goto delete_qp;
		}
	}
	atomic_set(&nqp->ref_cnt, 1);
	init_completion(&nqp->free);
	return &nqp->ib_qp;

delete_qp:
	spin_lock_irq(&dev->qp_lock);
	radix_tree_delete(&dev->qp_tree, nqp->qp_index);
	spin_unlock_irq(&dev->qp_lock);
free_dma_memory:
	crdma_free_hw_queue(dev, nqp->mem);
free_qp_index:
	if (qp_init_attr->qp_type != IB_QPT_GSI)
		crdma_free_bitmap_index(&dev->qp_map, nqp->qp_index);
clear_port:
	if (qp_init_attr->qp_type == IB_QPT_GSI)
		crdma_clear_qp1_port(dev, nqp->qp1_port);
free_mem:
	kfree(nqp);

	/*
	 * XXX: For development only to catch error codes that are not
     * set properly. This should be removed ultimately.
     */
	if (err >= 0) {
		crdma_warn("Error not set correctly, %d\n", err);
		err = -ENOMEM;
	}
	return ERR_PTR(err);
}

static int crdma_modify_qp(struct ib_qp *qp, struct ib_qp_attr *qp_attr,
			int qp_attr_mask, struct ib_udata *udata)
{
	struct crdma_ibdev *dev = to_crdma_ibdev(qp->device);
	struct crdma_ucontext *crdma_uctxt;
	struct crdma_qp *nqp = to_crdma_qp(qp);
	enum ib_qp_state cur_state;
	enum ib_qp_state new_state;
	int ret;

	crdma_info("crdma_modify_qp: attr_mask 0x%08X\n", qp_attr_mask);
	crdma_info("qp_type %d\n", qp->qp_type);

	mutex_lock(&nqp->mutex);
	cur_state = nqp->qp_state;
	new_state = qp_attr_mask & IB_QP_STATE ? qp_attr->qp_state : cur_state;

	crdma_info("curr_state %d, new_state %d\n", cur_state, new_state);

	/* State transition attribute/transport type validation */
	ret = -EINVAL;
#if (VER_NON_RHEL_GE(4,20) || VER_RHEL_GE(8,0))
	if (!ib_modify_qp_is_ok(cur_state, new_state,
			qp->qp_type, qp_attr_mask)) {
#else
	if (!ib_modify_qp_is_ok(cur_state, new_state,
			qp->qp_type, qp_attr_mask, IB_LINK_LAYER_ETHERNET)) {
#endif
		crdma_info("QPN %d, invalid attribute mask specified "
				"for transition %d to %d. qp_type %d, "
				"attr_mask 0x%08X\n",
				qp->qp_num, cur_state, new_state,
				qp->qp_type, qp_attr_mask);
		goto out;
	}

	/* Requester resources can't be larger than device allows for QP */
	if (qp_attr_mask & IB_QP_MAX_QP_RD_ATOMIC && (qp_attr->max_rd_atomic >
							dev->cap.ib.max_qp_init_rd_atom)) {
		crdma_info("QPN %d, max_rd_atomic %d too large\n",
						qp->qp_num, qp_attr->max_rd_atomic);
		goto out;
	}

	/* Perform validation of the requested attributes */
	if ((qp_attr_mask & IB_QP_PORT) && (qp_attr->port_num == 0 ||
							qp_attr->port_num > dev->cap.n_ports)) {
		crdma_info("Invalid port number %d\n", qp_attr->port_num);
		goto out;
	}

	if ((qp_attr_mask & IB_QP_PKEY_INDEX) && (qp_attr->pkey_index > 0)) {
		crdma_info("Invalid PKEY index %d\n", qp_attr->pkey_index);
		goto out;
	}

	/* Requester resources can't be larger than device allows for QP */
	if (qp_attr_mask & IB_QP_MAX_QP_RD_ATOMIC && (qp_attr->max_rd_atomic >
							dev->cap.ib.max_qp_init_rd_atom)) {
		crdma_info("QPN %d, max_rd_atomic %d too large\n",
						qp->qp_num, qp_attr->max_rd_atomic);
		goto out;
	}

	/* Responder resources can't be larger than device allows for QP */
	if (qp_attr_mask & IB_QP_MAX_DEST_RD_ATOMIC &&
					(qp_attr->max_dest_rd_atomic >
					dev->cap.ib.max_qp_rd_atom)) {
		crdma_info("QPN %d, max_dest_rd_atomic %d too large\n",
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

#if (VER_NON_RHEL_GE(5,6) || VER_RHEL_GE(8,0))
	if (udata) {
		crdma_uctxt = rdma_udata_to_drv_context(
				udata, struct crdma_ucontext, ib_uctxt);
		ret = crdma_qp_modify_cmd(dev, nqp, &crdma_uctxt->uar,
				qp_attr, qp_attr_mask, cur_state, new_state);
	}
#else
	crdma_uctxt = to_crdma_uctxt(qp->uobject->context);
	ret = crdma_qp_modify_cmd(dev, nqp, udata ?
			&crdma_uctxt->uar : &dev->priv_uar,
			qp_attr, qp_attr_mask, cur_state, new_state);
#endif
	if (ret) {
		crdma_info("Microcode QP_MODIFY error, %d\n", ret);
		ret = -EINVAL;
	}

out:
	mutex_unlock(&nqp->mutex);
	return ret;
}

static int crdma_query_qp(struct ib_qp *qp, struct ib_qp_attr *qp_attr,
			int qp_attr_mask, struct ib_qp_init_attr *qp_init_attr)
{
	struct crdma_ibdev *dev = to_crdma_ibdev(qp->device);
	struct crdma_qp *nqp = to_crdma_qp(qp);
	int ret = 0;

	crdma_info("crdma_query_qp\n");
	mutex_lock(&nqp->mutex);

	/* If we are in RESET state then no attributes are assigned */
	if (nqp->qp_state == IB_QPS_RESET) {
		qp_attr->qp_state = IB_QPS_RESET;
		goto out;
	}

	ret = crdma_qp_query_cmd(dev, nqp, qp_attr, qp_attr_mask);
	if (ret) {
		crdma_info("Microcode QP_QUERY error, %d\n", ret);
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

#if (VER_NON_RHEL_GE(5,2) || VER_RHEL_GE(8,0))
static int crdma_destroy_qp(struct ib_qp *qp, struct ib_udata *udata)
#else
static int crdma_destroy_qp(struct ib_qp *qp)
#endif
{
	struct crdma_ibdev *dev = to_crdma_ibdev(qp->device);
	struct crdma_qp *nqp = to_crdma_qp(qp);
	int err;

	crdma_info("crdma_destroy_qp\n");

	if (nqp->qp_state != IB_QPS_RESET) {
		err = crdma_qp_destroy_cmd(dev, nqp);
		if (err) {
			/*
			 * XXX: We should consider a BUG_ON here, to
			 * continue puts microcode and the driver in different
			 * states. This error needs not to happen.
			 */
			crdma_err("Microcode destroy QP command failed\n");
		}
	}

	spin_lock_irq(&dev->qp_lock);
	radix_tree_delete(&dev->qp_tree, nqp->qp_index);
	spin_unlock_irq(&dev->qp_lock);

	/* Free resources specific to kernel based QP */
#if (VER_NON_RHEL_GE(5,2) || VER_RHEL_GE(8,0))
	if (!udata) {
#else
	if (!qp->uobject) {
#endif
		if (!nqp->rq.wrid_map)
			crdma_warn("RQ WRID map memory NULL\n");
		else
			kfree(nqp->rq.wrid_map);
		if (!nqp->sq.wrid_map)
			crdma_warn("SQ WRID map memory NULL\n");
		else
			kfree(nqp->sq.wrid_map);
	}

	crdma_free_hw_queue(dev, nqp->mem);
	if (nqp->ib_qp.qp_type != IB_QPT_GSI)
		crdma_free_bitmap_index(&dev->qp_map, nqp->qp_index);
	else
		crdma_clear_qp1_port(dev, nqp->qp1_port);
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
static void set_wqe_sw_ownership(struct crdma_hw_workq *wq,
                                u32 wqe_index)
{
	u32 *ownership;

	wqe_index &= wq->mask;
	ownership = wq->buf + (wqe_index << wq->wqe_size_log2);
	crdma_debug("Set ownership for WQE index %d, %p\n",
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
static inline int crdma_copy_inline(struct crdma_swqe_inline *data,
                        struct ib_send_wr *wr, int max)
{
	struct ib_sge *sg;
	int i;
	int length = 0;

	crdma_debug("wr->num_sge %d, max = %d\n", wr->num_sge, max);

	for (i = 0, sg = wr->sg_list; i < wr->num_sge; i++, sg++) {
		crdma_debug("sg->length %d total length %d\n",
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
static inline void crdma_set_wqe_sge(struct crdma_wqe_sge *wqe_sg, int num_sge,
                                struct ib_sge *sge_list)
{
	int i;

	crdma_debug("num_sge %d, wqe_sg %p, sge_list %p\n",
					num_sge, wqe_sg, sge_list);
	for (i = 0; i < num_sge; i++, sge_list++, wqe_sg++) {
		wqe_sg->io_addr_h = cpu_to_le32(sge_list->addr >> 32);
		wqe_sg->io_addr_l = cpu_to_le32(sge_list->addr &
										0x0FFFFFFFFull);
		wqe_sg->l_key = cpu_to_le32(sge_list->lkey);
		wqe_sg->byte_count = cpu_to_le32(sge_list->length);
		crdma_debug("SGE %d addr_h 0x%08X, addr_l 0x%08X\n",
						i, wqe_sg->io_addr_h, wqe_sg->io_addr_l);
		crdma_debug("       l_key 0x%08X, byte_count 0x%08X\n",
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
static struct crdma_swqe *get_sq_tail(struct crdma_qp *nqp)
{
	uint32_t next = (nqp->sq.tail + CRDMA_WQ_WQE_SPARES) & nqp->sq.mask;
	unsigned long flags;

	/*
		* If it looks like an overflow allow for any active CQ
		* processing to complete and look again.
		*/
	if (next == nqp->sq.head) {
		struct crdma_cq *ncq = to_crdma_cq(nqp->ib_qp.send_cq);

		spin_lock_irqsave(&ncq->lock, flags);
		next = (nqp->sq.tail + CRDMA_WQ_WQE_SPARES) & nqp->sq.mask;
		spin_unlock_irqrestore(&ncq->lock, flags);
		if (next == nqp->sq.head)
				return NULL;
	}

	/* Post SWQE at the software producer tail */
	crdma_debug("Use SWQE Index %d\n", nqp->sq.tail);
	return nqp->sq.buf + (nqp->sq.tail << nqp->sq.wqe_size_log2);
}
#endif
#define CRDMA_SQ_DB_READY_RETRIES              20

static int crdma_post_send(struct ib_qp *qp, const struct ib_send_wr *wr,
			const struct ib_send_wr **bad_wr)
{
	/*Stage1 we do not cosider ib_post_send*/
	crdma_warn("crdma_post_send in kernel is not surpported\n");
	return 0;
#if 0
	struct crdma_ibdev *dev = to_crdma_ibdev(qp->device);
	struct crdma_qp *nqp = to_crdma_qp(qp);
	struct crdma_swqe *swqe;
	struct crdma_swqe_inline *inline_data;
	struct crdma_wqe_sge *sg;
	struct crdma_swqe_owner owner;
	int wr_cnt = 0;
	int ret = 0;
	u8 flags;
	u32 fin_state;
	u32 qpn = qp->qp_type == IB_QPT_GSI ? nqp->qp1_port : nqp->qp_index;
	int cnt = 0;

	spin_lock(&nqp->sq.lock);
	while (wr) {
		if (wr->num_sge > nqp->sq.max_sg) {
			crdma_info("WR num_sge too large %d\n", wr->num_sge);
			*bad_wr = wr;
			ret = -EINVAL;
			goto out;
		}

		/* Post new SWQE's at the software tail, NULL if SQ full */
		swqe = get_sq_tail(nqp);
		if (!swqe) {
			crdma_info("SQ Overflow\n");
			*bad_wr = wr;
			ret = -ENOMEM;
			goto out;
		}

		crdma_debug(">>> SWQE Addr %p\n", swqe);

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
				crdma_info("Only UD SEND, SEND w/IMM "
						"supported %d\n", wr->opcode);
				*bad_wr = wr;
				ret = -EINVAL;
				goto out;
			}

			/* Set the UD address vector */
			memcpy(&swqe->ud.addr.av,
					&to_crdma_ah(wr->wr.ud.ah)->av,
					sizeof(struct crdma_av));
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
			crdma_info("Only UD and RC QP supported %d\n",
				qp->qp_type);
			*bad_wr = wr;
			ret = -EINVAL;
			goto out;
		}

		owner.word = 0;
		if (send_loopback)
			flags = CRDMA_WQE_CTRL_LOOPBACK_BIT;
		else
			flags = wr->send_flags & CRDMA_IB_SEND_LOOPBACK ?
					CRDMA_WQE_CTRL_LOOPBACK_BIT : 0;
		if (wr->send_flags & IB_SEND_INLINE) {
			flags |= CRDMA_WQE_CTRL_INLINE_DATA_BIT;
			ret = crdma_copy_inline(inline_data, wr,
						nqp->max_inline);
			if (ret) {
				*bad_wr = wr;
				goto out;
			}
		} else {
			owner.num_sg = wr->num_sge;
			crdma_set_wqe_sge(sg, wr->num_sge, wr->sg_list);
		}
		nqp->sq.wrid_map[nqp->sq.tail] = wr->wr_id;

		/* Write ownership control word last */
		owner.opcode = wr->opcode;
		owner.flags  = flags |
				(wr->send_flags & IB_SEND_FENCE ?
					CRDMA_WQE_CTRL_FENCE_BIT : 0) |
				(wr->send_flags & IB_SEND_SIGNALED ?
					CRDMA_WQE_CTRL_SIGNAL_BIT : 0) |
				(wr->send_flags & IB_SEND_SOLICITED ?
					CRDMA_WQE_CTRL_SOLICITED_BIT : 0) |
				(qp->qp_type == IB_QPT_GSI ?
					CRDMA_WQE_CTRL_GSI_BIT : 0);
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
					CRDMA_WQ_WQE_SPARES);
	}

out:
	if (wr_cnt) {
		while (cnt++ < CRDMA_SQ_DB_READY_RETRIES) {
			fin_state = le32_to_cpu(__raw_readl(
					dev->priv_uar.map +
					CRDMA_DB_SQ_ADDR_OFFSET));
			if (!(fin_state & CRDMA_DB_FIN_BIT))
				break;
		}

		if (cnt >= CRDMA_SQ_DB_READY_RETRIES)
			crdma_warn(">>>>>> SQ doorbell unresponsive\n");

		/*
		 * Make sure last control word has been written, and we have
		 * and the read check has completed  before the doorbell
		 * is written
		 */
		mb();
		crdma_debug("Write priv UAR SQ DB\n");
		__raw_writel((__force u32) cpu_to_le32(CRDMA_DB_FIN_BIT |
					(qpn & CRDMA_DB_SQ_MASK)),
				dev->priv_uar.map + CRDMA_DB_WA_BIT +
				CRDMA_DB_SQ_ADDR_OFFSET);

		crdma_debug("SQ doorbell address %p\n",
				dev->priv_uar.map + CRDMA_DB_WA_BIT +
				CRDMA_DB_SQ_ADDR_OFFSET);

		crdma_debug("SQ doorbell written 0x%08X\n",
				cpu_to_le32(CRDMA_DB_FIN_BIT |
					(qpn & CRDMA_DB_SQ_MASK)));
		crdma_debug("SQ doorbell contents 0x%08X\n",
				le32_to_cpu(__raw_readl(dev->priv_uar.map +
					CRDMA_DB_SQ_ADDR_OFFSET)));

		/*
		 * Make sure the last spare request is set to software
		 * ownership.
		 */
		set_wqe_sw_ownership(&nqp->sq, nqp->sq.tail +
				CRDMA_WQ_WQE_SPARES);
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
static struct crdma_rwqe *get_rq_tail(struct crdma_qp *nqp)
{
	u32 next = (nqp->rq.tail + CRDMA_WQ_WQE_SPARES) & nqp->rq.mask;
	unsigned long flags;

	/*
	 * If it looks like an overflow allow for any active CQ
	 * processing to complete and look again.
	 */
	if (next == nqp->rq.head) {
		struct crdma_cq *ncq = to_crdma_cq(nqp->ib_qp.recv_cq);

		spin_lock_irqsave(&ncq->lock, flags);
		next = (nqp->rq.tail + CRDMA_WQ_WQE_SPARES) & nqp->rq.mask;
		spin_unlock_irqrestore(&ncq->lock, flags);
		if (next == nqp->rq.head)
			return NULL;
	}

	/* Post RWQE at the software producer tail */
	crdma_debug("Use RWQE Index %d\n", nqp->rq.tail);
	return nqp->rq.buf + (nqp->rq.tail << nqp->rq.wqe_size_log2);
}
#endif
static int crdma_post_recv(struct ib_qp *qp, const struct ib_recv_wr *wr,
			const struct ib_recv_wr **bad_wr)
{
	/*Stage1 we do not cosider crdma_post_recv*/
	crdma_warn("crdma_post_recv in kernel is not surpported\n");
	return 0;

#if 0
	struct crdma_qp *nqp = to_crdma_qp(qp);
	struct crdma_rwqe *rwqe;
	int ret = 0;

	spin_lock(&nqp->rq.lock);
	while(wr) {
		if (wr->num_sge > nqp->rq.max_sg) {
			crdma_info("RQ work request SG entries too large %d\n",
					wr->num_sge);
			*bad_wr = wr;
			ret = -EINVAL;
			break;
		}

		rwqe = get_rq_tail(nqp);
		if (!rwqe) {
			crdma_info("RQ overflow\n");
			*bad_wr = wr;
			ret = -ENOMEM;
			break;
		}

		crdma_debug("RWQE Addr %p\n", rwqe);

		/*
		 * Build the RWQE making sure not to clear the software
		 * ownership word prior to all of the rest of the WQE
		 * being written.
		 */
		crdma_set_wqe_sge(&rwqe->sg[0], wr->num_sge, wr->sg_list);
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
				CRDMA_WQ_WQE_SPARES);
		nqp->rq.tail = (nqp->rq.tail + 1) & nqp->rq.mask;
		wr = wr->next;
	}
	spin_unlock(&nqp->rq.lock);

	return ret;
#endif
}

#if (VER_NON_RHEL_GE(5,3) || VER_RHEL_GE(8,0))
static int crdma_create_cq(struct ib_cq *cq, const struct ib_cq_init_attr *attr,
				  struct ib_udata *udata)
{
	struct crdma_ibdev *dev = to_crdma_ibdev(cq->device);
	struct crdma_cq *ncq = container_of(cq, struct crdma_cq, ib_cq);
	struct crdma_cqe *cqe;
	unsigned int num_cqe = attr->cqe;
	int comp_vector = attr->comp_vector;
	int err;
	int i;

	if (num_cqe < 1 || num_cqe > dev->cap.ib.max_cqe - 1) {
		crdma_info("Too many CQE requested %d\n", num_cqe);
		return -EINVAL;
	}

	spin_lock_init(&ncq->lock);
	ncq->num_cqe = roundup_pow_of_two(num_cqe + 1);
	ncq->ib_cq.cqe = ncq->num_cqe - 1;

#if CRDMA_DETAIL_INFO_DEBUG_FLAG
	crdma_info("Rounded up CQE count %d\n", ncq->num_cqe);
#endif

	/* Allocate resource index for the CQ control object */
	ncq->cqn = crdma_alloc_bitmap_index(&dev->cq_map);
	if (ncq->cqn < 0) {
		crdma_info("No CQ index available\n");
		err = -ENOMEM;
		goto free_mem;
	}

	/* Kernel allocates CQ memory, user contexts will mmap it */
	ncq->mem = crdma_alloc_hw_queue(dev,
				ncq->num_cqe * dev->cap.cqe_size);
	if (IS_ERR(ncq->mem)) {
		crdma_dev_err(dev, "Unable to allocate CQ HW queue\n");
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
	ncq->ci_mbox = dma_alloc_coherent(&dev->nfp_info->pdev->dev,
			PAGE_SIZE, &ncq->ci_mbox_paddr, GFP_KERNEL);
	if (!ncq->ci_mbox) {
		crdma_info("ci_mbox allocation failed\n");
		err = -ENOMEM;
		goto free_queue_mem;
	}
	crdma_debug("CQ CI mailbox DMA addr 0x%016llX\n", ncq->ci_mbox_paddr);
	ncq->ci_mbox->ci = 0;
	ncq->ci_mbox->last_db_state = 0;
	wmb();

	/* Assign CQ to MSI-X EQ based on completion vector */
	ncq->eq_num = dev->eq_table.num_eq > 1 ? 1 + comp_vector %
			(dev->eq_table.num_eq - 1) : 0;
	dev->cq_table[ncq->cqn] = ncq;

	if (udata) {
		struct crdma_ucontext *crdma_uctxt = rdma_udata_to_drv_context(
				udata, struct crdma_ucontext, ib_uctxt);
		struct crdma_ib_create_cq_resp resp;

		err = crdma_cq_create_cmd(dev, ncq, &crdma_uctxt->uar);
		if (err) {
			crdma_info("Microcode error creating CQ, %d\n", err);
			goto cmd_fail;
		}
		resp.cq_base_addr = sg_dma_address(ncq->mem->alloc);
		resp.cq_size = ncq->mem->tot_len;
		resp.ci_mbox_base_addr = ncq->ci_mbox_paddr;
		resp.ci_mbox_size = PAGE_SIZE;
		resp.cqn = ncq->cqn;
		resp.num_cqe = ncq->num_cqe;
		crdma_debug("CQ buffer paddr 0x%016llX\n", resp.cq_base_addr);
		crdma_debug("CI mbox paddr 0x%016llX\n",
				resp.ci_mbox_base_addr);

		err = ib_copy_to_udata(udata, &resp, sizeof(resp));
		if (err) {
			crdma_info("Copy of UDATA failed, %d\n", err);
			goto cq_destroy;
		}

		err = crdma_add_mmap_req(crdma_uctxt, resp.cq_base_addr,
				ncq->mem->tot_len);
		if (err) {
			crdma_info("Failed to add pending mmap, %d\n", err);
			goto cq_destroy;
		}
		err = crdma_add_mmap_req(crdma_uctxt, resp.ci_mbox_base_addr,
				PAGE_SIZE);
		if (err) {
			crdma_info("Failed to add mbox pending mmap, %d\n",
					err);
			crdma_remove_mmap_req(crdma_uctxt, resp.cq_base_addr,
					ncq->mem->tot_len);
			goto cq_destroy;
		}
	} else {
		err = crdma_cq_create_cmd(dev, ncq, &dev->priv_uar);
		if (err) {
			crdma_info("Microcode error creating CQ, %d\n", err);
			goto cmd_fail;
		}
		ncq->mask = ncq->num_cqe - 1;
		ncq->arm_seqn = 1;
		while ((1 << ncq->num_cqe_log2) < ncq->num_cqe)
			ncq->num_cqe_log2++;
	}

	atomic_set(&ncq->ref_cnt, 1);
	init_completion(&ncq->free);

	return 0;

cq_destroy:
	crdma_cq_destroy_cmd(dev, ncq);
cmd_fail:
	dev->cq_table[ncq->cqn] = NULL;
	dma_free_coherent(&dev->nfp_info->pdev->dev, PAGE_SIZE,
			ncq->ci_mbox, ncq->ci_mbox_paddr);
free_queue_mem:
	crdma_free_hw_queue(dev, ncq->mem);
free_cq:
	crdma_free_bitmap_index(&dev->cq_map, ncq->cqn);
free_mem:

	/*
	 * XXX: For development only to catch error codes that are not
	 * set properly. This should be removed ultimately.
	 */
	if (err >= 0) {
		crdma_warn("Error not set correctly, %d\n", err);
		err = -ENOMEM;
	}
	return err;
}
#else
static struct ib_cq *crdma_create_cq(struct ib_device *ibdev, const struct ib_cq_init_attr *attr,
				  struct ib_ucontext *ib_uctxt, struct ib_udata *udata)
{
	struct crdma_ibdev *dev = to_crdma_ibdev(ibdev);
	struct crdma_cq *ncq;
	struct crdma_cqe *cqe;
	unsigned int num_cqe = attr->cqe;
	int comp_vector = attr->comp_vector;
	int err;
	int i;

	crdma_info("=== crdma_create_cq ib_uctxt %p ===\n", ib_uctxt);

	if (num_cqe < 1 || num_cqe > dev->cap.ib.max_cqe - 1) {
		crdma_info("Too many CQE requested %d\n", num_cqe);
		return ERR_PTR(-EINVAL);
	}

	ncq = kzalloc(sizeof(*ncq), GFP_KERNEL);
	if (!ncq)
		return ERR_PTR(-ENOMEM);

	spin_lock_init(&ncq->lock);
	ncq->num_cqe = roundup_pow_of_two(num_cqe + 1);
	ncq->ib_cq.cqe = ncq->num_cqe - 1;

#if CRDMA_DETAIL_INFO_DEBUG_FLAG
	crdma_info("Rounded up CQE count %d\n", ncq->num_cqe);
#endif

	/* Allocate resource index for the CQ control object */
	ncq->cqn = crdma_alloc_bitmap_index(&dev->cq_map);
	if (ncq->cqn < 0) {
		crdma_info("No CQ index available\n");
		err = -ENOMEM;
		goto free_mem;
	}

	/* Kernel allocates CQ memory, user contexts will mmap it */
	ncq->mem = crdma_alloc_hw_queue(dev,
				ncq->num_cqe * dev->cap.cqe_size);
	if (IS_ERR(ncq->mem)) {
		crdma_dev_err(dev, "Unable to allocate CQ HW queue\n");
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
	ncq->ci_mbox = dma_alloc_coherent(&dev->nfp_info->pdev->dev,
			PAGE_SIZE, &ncq->ci_mbox_paddr, GFP_KERNEL);
	if (!ncq->ci_mbox) {
		crdma_info("ci_mbox allocation failed\n");
		err = -ENOMEM;
		goto free_queue_mem;
	}
	crdma_debug("CQ CI mailbox DMA addr 0x%016llX\n", ncq->ci_mbox_paddr);
	ncq->ci_mbox->ci = 0;
	ncq->ci_mbox->last_db_state = 0;
	wmb();

	/* Assign CQ to MSI-X EQ based on completion vector */
	ncq->eq_num = dev->eq_table.num_eq > 1 ? 1 + comp_vector %
			(dev->eq_table.num_eq - 1) : 0;
	dev->cq_table[ncq->cqn] = ncq;

	if (ib_uctxt) {
		struct crdma_ucontext *crdma_uctxt = to_crdma_uctxt(ib_uctxt);
		struct crdma_ib_create_cq_resp resp;

		err = crdma_cq_create_cmd(dev, ncq, &crdma_uctxt->uar);
		if (err) {
			crdma_info("Microcode error creating CQ, %d\n", err);
			goto cmd_fail;
		}
		resp.cq_base_addr = sg_dma_address(ncq->mem->alloc);
		resp.cq_size = ncq->mem->tot_len;
		resp.ci_mbox_base_addr = ncq->ci_mbox_paddr;
		resp.ci_mbox_size = PAGE_SIZE;
		resp.cqn = ncq->cqn;
		resp.num_cqe = ncq->num_cqe;
		crdma_debug("CQ buffer paddr 0x%016llX\n", resp.cq_base_addr);
		crdma_debug("CI mbox paddr 0x%016llX\n",
				resp.ci_mbox_base_addr);

		err = ib_copy_to_udata(udata, &resp, sizeof(resp));
		if (err) {
			crdma_info("Copy of UDATA failed, %d\n", err);
			goto cq_destroy;
		}

		err = crdma_add_mmap_req(crdma_uctxt, resp.cq_base_addr,
				ncq->mem->tot_len);
		if (err) {
			crdma_info("Failed to add pending mmap, %d\n", err);
			goto cq_destroy;
		}
		err = crdma_add_mmap_req(crdma_uctxt, resp.ci_mbox_base_addr,
				PAGE_SIZE);
		if (err) {
			crdma_info("Failed to add mbox pending mmap, %d\n",
					err);
			crdma_remove_mmap_req(crdma_uctxt, resp.cq_base_addr,
					ncq->mem->tot_len);
			goto cq_destroy;
		}
	} else {
		err = crdma_cq_create_cmd(dev, ncq, &dev->priv_uar);
		if (err) {
			crdma_info("Microcode error creating CQ, %d\n", err);
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
	crdma_cq_destroy_cmd(dev, ncq);
cmd_fail:
	dev->cq_table[ncq->cqn] = NULL;
	dma_free_coherent(&dev->nfp_info->pdev->dev, PAGE_SIZE,
			ncq->ci_mbox, ncq->ci_mbox_paddr);
free_queue_mem:
	crdma_free_hw_queue(dev, ncq->mem);
free_cq:
	crdma_free_bitmap_index(&dev->cq_map, ncq->cqn);
free_mem:
	kfree(ncq);

	/*
	 * XXX: For development only to catch error codes that are not
	 * set properly. This should be removed ultimately.
	 */
	if (err >= 0) {
		crdma_warn("Error not set correctly, %d\n", err);
		err = -ENOMEM;
	}
	return ERR_PTR(err);
}
#endif

static int crdma_modify_cq(struct ib_cq *cq, u16 cq_count, u16 cq_period)
{
	crdma_warn("crdma_modify_cq not implemented\n");
	return 0;
}

#if (VER_NON_RHEL_GE(5,2) || VER_RHEL_GE(8,0))
static int crdma_destroy_cq(struct ib_cq *cq, struct ib_udata *udata)
#else
static int crdma_destroy_cq(struct ib_cq *cq)
#endif
{
	struct crdma_ibdev *dev = to_crdma_ibdev(cq->device);
	struct crdma_cq *ncq = to_crdma_cq(cq);
	int err;

	crdma_info("crdma_destroy_cq cqn =  %d\n", ncq->cqn);

	err = crdma_cq_destroy_cmd(dev, ncq);
	if (err) {
		/*
		 * TODO: Determine best course of action here, if we
		 * ignore and continue we can not free the resource
		 * because microcode will believe it is still in use.
		 */
		crdma_warn("Microcode destroy CQ command failed\n");
		return -EINVAL;
	}

	if (dev->have_interrupts)
		synchronize_irq(dev->eq_table.eq[ncq->eq_num].vector);

	dev->cq_table[ncq->cqn] = NULL;

	if (atomic_dec_and_test(&ncq->ref_cnt))
		complete(&ncq->free);
	wait_for_completion(&ncq->free);

	dma_free_coherent(&dev->nfp_info->pdev->dev, PAGE_SIZE,
			ncq->ci_mbox, ncq->ci_mbox_paddr);
	crdma_free_hw_queue(dev, ncq->mem);
	crdma_free_bitmap_index(&dev->cq_map, ncq->cqn);
#if (!(VER_NON_RHEL_GE(5,2) || VER_RHEL_GE(8,0)))
	kfree(ncq);
#endif
	crdma_info("crdma_destroy_cq done\n");
	return 0;
}

static int crdma_resize_cq(struct ib_cq *ibcq, int cqe,
			struct ib_udata *udata)
{
	crdma_warn("crdma_resize_cq not implemented\n");
	return 0;
}

static inline struct crdma_cqe *crdma_cq_head(struct crdma_cq *ncq)
{
	struct crdma_cqe *cqe = NULL;

	cqe = &ncq->cqe_buf[ncq->consumer_cnt & ncq->mask];

	/*
	 * Microcode alternates writing 1 or 0 in the CQE ownership
	 * bit every pass through the CQ memory, starting with writing
	 * a 1 on the first pass.
	 */
	if (!!(cqe->owner & CRDMA_CQE_OWNERSHIP_BIT) ==
			!!(ncq->consumer_cnt & (1 << ncq->num_cqe_log2)))
			return NULL;

	/*
	 * Make sure no CQE reads will be issued prior to validation
	 * that the CQE has been set to software ownership microcode.
	 */
	rmb();
	return cqe;
}

#define CRDMA_CQ_DB_READY_RETRIES	       20

static int crdma_poll_cq(struct ib_cq *cq, int num_entries,
			struct ib_wc *wc)
{
	struct crdma_cq	*ncq = to_crdma_cq(cq);
	struct crdma_cqe *cqe;
	struct crdma_qp *last_qp = NULL;
	unsigned long	flags;
	int polled = 0;
	int ret = 0;

	spin_lock_irqsave(&ncq->lock, flags);
	while (polled < num_entries) {
		cqe = crdma_cq_head(ncq);
		if (!cqe)
			break;
		/*
		 * If we already have pulled at least one CQE, update
		 * the CQ consumer index so that a false overflow
		 * will not be detected by microcode.
		 */
		if (polled)
			ncq->ci_mbox->ci = cpu_to_le32(ncq->consumer_cnt &
					CRDMA_CQ_MBOX_CONSUMER_NDX_MASK);

		ncq->consumer_cnt++;

#if 1 /* Extra debug only */
		print_hex_dump(KERN_DEBUG, "CQE:", DUMP_PREFIX_OFFSET, 8, 1,
			cqe, 32, 0);
#endif
		ret = crdma_process_cqe(ncq, cqe, &last_qp, &wc[polled]);
		if (ret == 0)
			polled++;
		else if (ret < 0)
			break;
	}

	/* Update the state of the consumer index shared with microcode */
	ncq->ci_mbox->ci = cpu_to_le32(ncq->consumer_cnt &
					CRDMA_CQ_MBOX_CONSUMER_NDX_MASK);
	spin_unlock_irqrestore(&ncq->lock, flags);

	return ret < 0 ? ret : polled;
}

static int crdma_req_notify_cq(struct ib_cq *cq,
			enum ib_cq_notify_flags flags)
{
	struct crdma_ibdev *dev = to_crdma_ibdev(cq->device);
	struct crdma_cq *ncq = to_crdma_cq(cq);
	u32 arm;
	u32 state;
	u32 db[2];
	int cnt = 0;
	u32 fin_state;

	arm = (ncq->arm_seqn << CRDMA_DB_CQ_SEQ_SHIFT) |
		((flags & IB_CQ_SOLICITED_MASK) == IB_CQ_SOLICITED ?
			0 : CRDMA_DB_CQ_ARM_ANY_BIT) |
		(ncq->cqn & CRDMA_DB_CQN_MASK);
	db[0] = cpu_to_le32(arm);
	db[1] = cpu_to_le32(CRDMA_DB_FIN_BIT | (ncq->consumer_cnt &
				CRDMA_DB_CQ_CONS_MASK));

	/* Update state and ensure in memory before ringing CQ doorbell */
	state = (arm & ~CRDMA_DB_CQN_MASK) | (ncq->consumer_cnt &
				CRDMA_DB_CQ_CONS_MASK);
	ncq->ci_mbox->last_db_state = cpu_to_le32(state);
	wmb();

	/*
	 * During integration we are verifying that the doorbell
	 * logic has captured any previous CQ doorbell before writing
	 * a second.
	 */
	while (cnt++ < CRDMA_CQ_DB_READY_RETRIES) {
		fin_state = le32_to_cpu(__raw_readl(
					dev->priv_uar.map +
					CRDMA_DB_CQCI_ADDR_OFFSET));
		if (!(fin_state & CRDMA_DB_FIN_BIT))
			break;
	}

	if (cnt >= CRDMA_CQ_DB_READY_RETRIES)
		crdma_warn(">>>>>> CQ doorbell unresponsive\n");

	if (!mad_cq_event_wa) {
		crdma_debug("CQ Doorbell[0] = 0x%08X\n", db[0]);
		crdma_debug("CQ Doorbell[1] = 0x%08X\n", db[1]);
	}

	/*
		Todo: In hardware doorbell, cq notify only use 32bit, not 64bit.
		This part need to be adapted in latter with development of cq notify.
	*/
	//crdma_write64_db(dev, db, CRDMA_DB_WA_BIT + CRDMA_DB_CQ_ADDR_OFFSET);
	return 0;
}

static struct ib_mr *crdma_get_dma_mr(struct ib_pd *pd, int access_flags)
{
	struct crdma_ibdev *dev = to_crdma_ibdev(pd->device);
	struct crdma_mr *nmr;
	int err;

#if (!(VER_NON_RHEL_GE(5,10) || VER_RHEL_GE(8,0)))
	crdma_info("crdma_get_dma_mr not surpported\n");
	return ERR_PTR(-ENOMEM);
#endif
	crdma_info("crdma_get_dma_mr\n");

	nmr = kmalloc(sizeof(*nmr), GFP_KERNEL);
	if (!nmr) {
		crdma_info("No memory for MR object\n");
		return ERR_PTR(-ENOMEM);
	}

	nmr->mpt_index = crdma_alloc_bitmap_index(&dev->mpt_map);
	if (nmr->mpt_index < 0) {
		err = -ENOMEM;
		goto free_mem;
	}
	crdma_info("DMA MPT Index %d\n", nmr->mpt_index);

	nmr->umem = NULL;
	nmr->pdn = to_crdma_pd(pd)->pd_index;
	nmr->io_vaddr = 0;
	nmr->len = ~0ull;
	nmr->access = access_flags;
	nmr->page_shift = 0;
	nmr->mpt_order = 0;

	nmr->key = nmr->mpt_index;
	nmr->ib_mr.rkey = nmr->ib_mr.lkey = nmr->key;

	if (crdma_init_mpt(dev, nmr, 0, 0)) {
		crdma_info("init_mpt failed\n");
		err = -ENOMEM;
		goto free_mpt;
	}

	return &nmr->ib_mr;

free_mpt:
	crdma_free_bitmap_index(&dev->mpt_map, nmr->mpt_index);
free_mem:
	kfree(nmr);
	return ERR_PTR(err);
}

static struct ib_mr *crdma_reg_user_mr(struct ib_pd *pd, u64 start,
			u64 length, u64 virt_addr, int access_flags,
			struct ib_udata *udata)
{
	struct crdma_ibdev *dev = to_crdma_ibdev(pd->device);
	struct crdma_mr *nmr;
	int count, num_comp, shift, order, log2_page_sz;
	int err;

	crdma_info("crdma_reg_user_mr\n");
	crdma_info("parameter: start=0x%llu, length=0x%llu, virt_addr=0x%llu\n",
		start, length, virt_addr);

	nmr = kmalloc(sizeof(*nmr), GFP_KERNEL);
	if (!nmr) {
		crdma_info("No memory for MR object\n");
		return ERR_PTR(-ENOMEM);
	}

	nmr->mpt_index = crdma_alloc_bitmap_index(&dev->mpt_map);
	if (nmr->mpt_index < 0) {
		err = -ENOMEM;
		goto free_mem;
	}
	crdma_info("MPT Index %d\n", nmr->mpt_index);

#if (VER_NON_RHEL_GE(5,6))
	nmr->umem = ib_umem_get(pd->device, start, length, access_flags);
#elif (VER_NON_RHEL_GE(5,5) || VER_RHEL_GE(8,0))
	nmr->umem = ib_umem_get(udata, start, length, access_flags);
#elif (VER_NON_RHEL_GE(5,1))
	nmr->umem = ib_umem_get(udata, start, length, access_flags, 0);
#else
	nmr->umem = ib_umem_get(pd->uobject->context, start, length,
			access_flags, 0);
#endif
	if (IS_ERR(nmr->umem)) {
		err = PTR_ERR(nmr->umem);
		crdma_info("ib_umem_get() failed %d\n", err);
		goto free_mpt;
	}

#if (VER_NON_RHEL_GE(5,3) || VER_RHEL_GE(8,0))
	log2_page_sz = PAGE_SHIFT;
#else
	log2_page_sz = nmr->umem->page_shift;
#endif
	crdma_info("User Memory Page Size %d\n", log2_page_sz);
#if (VER_NON_RHEL_GE(5,10) || VER_RHEL_GE(8,0))
	crdma_info("User Memory Num Pages %ld\n",
				ib_umem_num_dma_blocks(nmr->umem, PAGE_SIZE));
#else
	crdma_info("User Memory Num Pages %d\n",
				ib_umem_page_count(nmr->umem));
#endif
	/*
	 * Find the largest compound page size that can be used
	 * for the physical page list, limiting to the supported
	 * microcode maximum.
	 */
	crdma_compound_order(nmr->umem, start, &count, &num_comp,
			&shift, &order);
	crdma_info("User Memory Pages %d\n", count);
	crdma_info("User Memory Compound Pages %d\n", num_comp);
	crdma_info("User Memory Compound Page Shift %d\n", shift);
	crdma_info("User Memory Compound Page Order %d\n", order);

	if (order + log2_page_sz > CRDMA_MTT_MAX_PAGESIZE_LOG2) {
		num_comp <<= order  + log2_page_sz -
				CRDMA_MTT_MAX_PAGESIZE_LOG2;
		order -=  order + log2_page_sz -
				CRDMA_MTT_MAX_PAGESIZE_LOG2;
	}
	crdma_info("Adjusted number of compound pages %d\n", num_comp);
	crdma_info("Adjusted compound order %d\n", order);

	nmr->pdn = to_crdma_pd(pd)->pd_index;
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

	if (crdma_init_mpt(dev, nmr, num_comp, order)) {
		crdma_info("init_mpt failed\n");
		err = -ENOMEM;
		goto release_umem;
	}

	return &nmr->ib_mr;

release_umem:
	ib_umem_release(nmr->umem);
free_mpt:
	crdma_free_bitmap_index(&dev->mpt_map, nmr->mpt_index);
free_mem:
	kfree(nmr);
	return ERR_PTR(err);
}

#if (VER_NON_RHEL_GE(5,2) || VER_RHEL_GE(8,0))
static int crdma_dereg_mr(struct ib_mr *mr, struct ib_udata *udata)
#else
static int crdma_dereg_mr(struct ib_mr *mr)
#endif
{
	struct crdma_ibdev *dev = to_crdma_ibdev(mr->device);
	struct crdma_mr *nmr = to_crdma_mr(mr);

	crdma_cleanup_mpt(dev, nmr);
	crdma_free_bitmap_index(&dev->mpt_map, nmr->mpt_index);

	if (nmr->umem)
		ib_umem_release(nmr->umem);

	kfree(nmr);
	return 0;
}

static struct ib_mr *crdma_alloc_mr(struct ib_pd *pd,
			enum ib_mr_type mr_type, u32 max_num_sg)
{
	crdma_warn("crdma_alloc_frmr not implemented\n");
	return ERR_PTR(-ENOMEM);
}


static int crdma_attach_mcast(struct ib_qp *qp, union ib_gid *gid, u16 lid)
{
	crdma_warn("crdma_attach_mcast not implemented\n");
	return 0;
}

static int crdma_detach_mcast(struct ib_qp *qp, union ib_gid *gid, u16 lid)
{
	crdma_warn("crdma_detach_mcast not implemented\n");
	return 0;
}

#if (VER_NON_RHEL_GE(5,3) || VER_RHEL_GE(8,0))
static const struct ib_device_ops crdma_dev_ops = {
    .owner = THIS_MODULE,
    .driver_id = RDMA_DRIVER_CORIGINE,
    .uverbs_abi_ver = CRDMA_UVERBS_ABI_VERSION,

    .query_device = crdma_query_device,
    .query_port = crdma_query_port,
    .get_link_layer = crdma_get_link_layer,
    .query_gid = crdma_query_gid,
    .query_pkey = crdma_query_pkey,
    .get_netdev = crdma_get_netdev,
    .modify_device = crdma_modify_device,
    .modify_port = crdma_modify_port,
    .alloc_ucontext = crdma_alloc_ucontext,
    .dealloc_ucontext = crdma_dealloc_ucontext,
    .mmap = crdma_mmap,
    .alloc_pd = crdma_alloc_pd,
    .dealloc_pd = crdma_dealloc_pd,
    .create_ah = crdma_create_ah,
    .query_ah = crdma_query_ah,
    .destroy_ah = crdma_destroy_ah,
    .create_srq = crdma_create_srq,
    .modify_srq = crdma_modify_srq,
    .query_srq = crdma_query_srq,
    .destroy_srq = crdma_destroy_srq,
    .post_srq_recv = crdma_post_srq_recv,
    .create_qp = crdma_create_qp,
    .modify_qp = crdma_modify_qp,
    .query_qp = crdma_query_qp,
    .destroy_qp = crdma_destroy_qp,
    .post_send = crdma_post_send,
    .post_recv = crdma_post_recv,
    .create_cq = crdma_create_cq,
    .modify_cq = crdma_modify_cq,
    .resize_cq = crdma_resize_cq,
    .destroy_cq = crdma_destroy_cq,
    .poll_cq = crdma_poll_cq,
    .req_notify_cq = crdma_req_notify_cq,
    .get_dma_mr = crdma_get_dma_mr,
    .reg_user_mr = crdma_reg_user_mr,
    .dereg_mr = crdma_dereg_mr,
    .attach_mcast = crdma_attach_mcast,
    .detach_mcast = crdma_detach_mcast,
    .alloc_mr = crdma_alloc_mr,
    .get_port_immutable = crdma_get_port_immutable,
    .get_dev_fw_str = crdma_get_dev_fw_str,

    INIT_RDMA_OBJ_SIZE(ib_pd, crdma_pd, ib_pd),
    INIT_RDMA_OBJ_SIZE(ib_cq, crdma_cq, ib_cq),
    INIT_RDMA_OBJ_SIZE(ib_ucontext, crdma_ucontext, ib_uctxt),
    INIT_RDMA_OBJ_SIZE(ib_ah, crdma_ah, ib_ah),
};
#endif

int crdma_register_verbs(struct crdma_ibdev *dev)
{
	int ret;

	crdma_dev_info(dev, "ib_register_device begin\n");
	dev->ibdev.node_type = RDMA_NODE_IB_CA;
	memcpy(dev->ibdev.node_desc, CRDMA_IB_NODE_DESC,
			sizeof(CRDMA_IB_NODE_DESC));
	crdma_mac_to_guid(dev->nfp_info->def_mac, 0xFFFF,
		(u8 *)&dev->ibdev.node_guid);
	dev->ibdev.phys_port_cnt = dev->cap.n_ports;

	/* If more than one EQ, then EQ 0 is reserved for async events */
	dev->ibdev.num_comp_vectors = dev->eq_table.num_eq > 1 ?
				dev->eq_table.num_eq - 1 : 1;

	/* Currently do not support local DMA key */
	dev->ibdev.local_dma_lkey = 0;

	dev->ibdev.uverbs_cmd_mask =
                (1ull << IB_USER_VERBS_CMD_GET_CONTEXT)         |
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
	dev->ibdev.dev.parent			= &dev->nfp_info->pdev->dev;

#if (VER_NON_RHEL_GE(5,3) || VER_RHEL_GE(8,0))
	ib_set_device_ops(&dev->ibdev, &crdma_dev_ops);
	ret = ib_register_device(&dev->ibdev, "crdma%d", NULL);
#else
	dev->ibdev.owner = THIS_MODULE;
	dev->ibdev.uverbs_abi_ver = CRDMA_UVERBS_ABI_VERSION;
	strlcpy(dev->ibdev.name, "crdma%d", IB_DEVICE_NAME_MAX);

	dev->ibdev.query_device         = crdma_query_device;
	dev->ibdev.query_port           = crdma_query_port;
	dev->ibdev.get_link_layer       = crdma_get_link_layer;
	dev->ibdev.query_gid            = crdma_query_gid;
	dev->ibdev.query_pkey           = crdma_query_pkey;
	dev->ibdev.get_netdev           = crdma_get_netdev;
	dev->ibdev.modify_device        = crdma_modify_device;
	dev->ibdev.modify_port          = crdma_modify_port;
	dev->ibdev.alloc_ucontext       = crdma_alloc_ucontext;
	dev->ibdev.dealloc_ucontext     = crdma_dealloc_ucontext;
	dev->ibdev.mmap                 = crdma_mmap;
	dev->ibdev.alloc_pd             = crdma_alloc_pd;
	dev->ibdev.dealloc_pd           = crdma_dealloc_pd;
	dev->ibdev.create_ah            = crdma_create_ah;
	dev->ibdev.query_ah             = crdma_query_ah;
	dev->ibdev.destroy_ah           = crdma_destroy_ah;
	dev->ibdev.create_srq           = crdma_create_srq;
	dev->ibdev.modify_srq           = crdma_modify_srq;
	dev->ibdev.query_srq            = crdma_query_srq;
	dev->ibdev.destroy_srq          = crdma_destroy_srq;
	dev->ibdev.post_srq_recv        = crdma_post_srq_recv;
	dev->ibdev.create_qp            = crdma_create_qp;
	dev->ibdev.modify_qp            = crdma_modify_qp;
	dev->ibdev.query_qp             = crdma_query_qp;
	dev->ibdev.destroy_qp           = crdma_destroy_qp;
	dev->ibdev.post_send            = crdma_post_send;
	dev->ibdev.post_recv            = crdma_post_recv;
	dev->ibdev.create_cq            = crdma_create_cq;
	dev->ibdev.modify_cq            = crdma_modify_cq;
	dev->ibdev.resize_cq            = crdma_resize_cq;
	dev->ibdev.destroy_cq           = crdma_destroy_cq;
	dev->ibdev.poll_cq              = crdma_poll_cq;
	dev->ibdev.req_notify_cq        = crdma_req_notify_cq;
	dev->ibdev.get_dma_mr           = crdma_get_dma_mr;
	dev->ibdev.reg_user_mr          = crdma_reg_user_mr;
	dev->ibdev.dereg_mr             = crdma_dereg_mr;
	dev->ibdev.attach_mcast         = crdma_attach_mcast;
	dev->ibdev.detach_mcast         = crdma_detach_mcast;
	dev->ibdev.alloc_mr             = crdma_alloc_mr;
	dev->ibdev.get_port_immutable   = crdma_get_port_immutable;
	dev->ibdev.get_dev_fw_str       = crdma_get_dev_fw_str;
	dev->ibdev.driver_id            = RDMA_DRIVER_CORIGINE;
	ret = ib_register_device(&dev->ibdev, NULL);
#endif
	crdma_dev_info(dev, "ib_register_device: status: %d\n", ret);
	return ret;
}

void crdma_unregister_verbs(struct crdma_ibdev *dev)
{
	ib_unregister_device(&dev->ibdev);
	return;
}
