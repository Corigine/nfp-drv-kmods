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
#include <net/addrconf.h>
#include <asm/byteorder.h>

#include <rdma/ib_verbs.h>
#include <rdma/ib_user_verbs.h>
#include <rdma/ib_mad.h>
#include <rdma/ib_addr.h>
#include <rdma/ib_cache.h>
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
	req = kzalloc(sizeof(*req), GFP_KERNEL);
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

#ifdef CRDMA_DETAIL_INFO_DEBUG_FLAG
	crdma_dev_info(dev, "Dump HWQ information: \n");
	crdma_dev_info(dev, "Memory Size              %d\n", mem->tot_len);
	crdma_dev_info(dev, "Number Allocs            %d\n", mem->num_allocs);
	crdma_dev_info(dev, "Min Order                %d\n", mem->min_order);
	crdma_dev_info(dev, "Number of SG             %d\n", mem->num_sg);
	crdma_dev_info(dev, "Number of MTT entries    %d\n", mem->num_mtt);
	crdma_dev_info(dev, "Base_mtt_ndx             %d\n", mem->base_mtt_ndx);
#endif
	err = crdma_mtt_write_sg(dev, mem->alloc, mem->num_sg,
			mem->base_mtt_ndx, mem->num_mtt,
			mem->min_order + PAGE_SHIFT,
			mem->num_sg, 0);
	if (err) {
		crdma_err("crdma_mmt_write_sg failed for HWQ, %d\n", err);
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
#if (VER_NON_RHEL_OR_KYL_GE(5,3) || VER_RHEL_GE(8,0) || VER_KYL_GE(10,3))
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
	pfn_bits = (unsigned long)(start >> page_shift);
	order = __ffs(pfn_bits);
	comp_mask = (1 << order) - 1;

	/*
	 * Go through the memory reducing the alignment to the smallest
	 * order found in the region.
	 */
#if (VER_NON_RHEL_GE(5,15) || RHEL_RELEASE_GE(8,365,0,0))
	for_each_sg(umem->sgt_append.sgt.sgl, sg, umem->sgt_append.sgt.nents,
		    entry) {
#else
	for_each_sg(umem->sg_head.sgl, sg, umem->nmap, entry) {
#endif
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
			} else if (base + comp_pages != pfn) {
				/*
				 * Non compound pages, reset the new
				 * compound mask based on the alignment.
				 */
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
		order = min_t(unsigned long,
				ilog2(roundup_pow_of_two(tot_pages)),
				order);
		if (comp_order)
			*comp_order = order;
		*num_comp = DIV_ROUND_UP(tot_pages, (1 << order));
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
 * @ccq: Pointer to the crdma CQ.
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
static int crdma_process_cqe(struct crdma_cq *ccq, struct crdma_cqe *cqe,
		struct crdma_qp **last_qp, struct ib_wc *wc)
{
	struct crdma_ibdev *dev = to_crdma_ibdev(ccq->ib_cq.device);
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

		/* Advance the SQ head to this work request */
		wq->head = wqe_index;
		wc->wr_id = wq->wrid_map[wq->head & wq->mask];
		wq->head = (wq->head + 1) & wq->mask;
	} else {
		/*
		 * TODO: We will need to handle the case where
		 * the QP is attached to a SRQ here, once SRQ
		 * are implemented.
		 */
		wq = &(*last_qp)->rq;
		wc->wr_id = wq->wrid_map[wq->head & wq->mask];
		wq->head = (wq->head + 1) & wq->mask;
	}

	/*
	 * If the CQE indicates an error completion, process and return
	 * error WC entry.
	 */
	if (cqe->status) {
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
		case CRDMA_WQE_LOCAL_INVAL_OP:
			wc->opcode = IB_WC_LOCAL_INV;
			wc->wc_flags |= IB_WC_WITH_INVALIDATE;
			break;
		case CRDMA_WQE_FAST_REG_MR_OP:
			wc->opcode = IB_WC_REG_MR;
			break;
		case CRDMA_WQE_RDMA_READ_OP:
			wc->opcode = IB_WC_RDMA_READ;
			wc->byte_len = le32_to_cpu(cqe->byte_count);
			break;
		case CRDMA_WQE_SEND_WITH_INVAL_OP:
			wc->opcode = IB_WC_SEND;
			wc->wc_flags |= IB_WC_WITH_INVALIDATE;
			wc->ex.invalidate_rkey = le32_to_cpu(cqe->imm_inval);
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
		case CRDMA_WQE_SEND_WITH_INVAL_OP:
			wc->opcode = IB_WC_RECV;
			wc->wc_flags |= IB_WC_WITH_INVALIDATE;
			wc->ex.invalidate_rkey = le32_to_cpu(cqe->imm_inval);
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
			crdma_mac_swap(wc->smac, cqe->smac);
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

	memcpy(dev_attr, &dev->cap.ib, sizeof(*dev_attr));

	if (uhw->inlen || uhw->outlen)
		return -EINVAL;

	/*
	 * Adjust shared queue size limits exposed to consumer to
	 * account for entries used for driver overhead.
	 */
	dev_attr->max_qp_wr -= CRDMA_WQ_WQE_SPARES;
	if (dev_attr->max_srq_wr)
		dev_attr->max_srq_wr -= CRDMA_WQ_WQE_SPARES;

	return 0;
}

int crdma_modify_port(struct ib_device *ibdev, u8 port, int mask,
		       struct ib_port_modify *props)
{
#ifdef CRDMA_DETAIL_INFO_DEBUG_FLAG
	crdma_info("ibdev=%p,  port=%d, mask=0x%x, set_mask=0x%x\n",
		ibdev, port, mask, props->set_port_cap_mask);
#endif
	return 0;
}

#if (VER_NON_RHEL_GE(5,13) || RHEL_RELEASE_GE(8,365,0,0))
static int crdma_query_port(struct ib_device *ibdev, u32 port_num,
			    struct ib_port_attr *port_attr)
#else
static int crdma_query_port(struct ib_device *ibdev, u8 port_num,
			    struct ib_port_attr *port_attr)
#endif
{
	struct crdma_ibdev *dev = to_crdma_ibdev(ibdev);
	struct net_device *netdev;

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
	port_attr->pkey_tbl_len	= CRDMA_IB_MAX_PKEY_TABLE_SIZE;
	port_attr->bad_pkey_cntr = 0;
	port_attr->qkey_viol_cntr = 0;

	ib_get_eth_speed(ibdev, port_num, &port_attr->active_speed,
			&port_attr->active_width);

	port_attr->max_msg_sz	= CRDMA_MAX_MSG_SIZE;

	/* TODO:  Must really determine value for max virtual lanes */
	port_attr->max_vl_num	= 4;

	return 0;
}
#if !(VER_NON_RHEL_GE(5,1) || VER_RHEL_GE(8,0))
struct net_device *crdma_get_netdev(struct ib_device *ibdev, u8 port_num)
{
	struct crdma_ibdev *crdma_dev = to_crdma_ibdev(ibdev);
	struct net_device *netdev;

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
#endif

#if (VER_NON_RHEL_GE(5,13) || RHEL_RELEASE_GE(8,365,0,0))
int crdma_get_port_immutable(struct ib_device *ibdev, u32 port_num,
			     struct ib_port_immutable *immutable)
#else
int crdma_get_port_immutable(struct ib_device *ibdev, u8 port_num,
			     struct ib_port_immutable *immutable)
#endif
{
	struct ib_port_attr port_attr;

	if (crdma_query_port(ibdev, port_num, &port_attr))
		return -EINVAL;

	immutable->pkey_tbl_len    = port_attr.pkey_tbl_len;
	immutable->gid_tbl_len     = port_attr.gid_tbl_len;
	immutable->core_cap_flags  = RDMA_CORE_PORT_IBA_ROCE_UDP_ENCAP;
	immutable->max_mad_size    = IB_MGMT_MAD_SIZE;

	return 0;
}

void crdma_get_dev_fw_str(struct ib_device *ibdev, char *str)
{
	struct crdma_ibdev *dev = to_crdma_ibdev(ibdev);

	snprintf(str, IB_FW_VERSION_NAME_MAX, "%d.%d",
		 dev->cap.uc_maj_rev, dev->cap.uc_min_rev);

	return;
}

#if (VER_NON_RHEL_GE(5,13) || RHEL_RELEASE_GE(8,365,0,0))
static enum rdma_link_layer crdma_get_link_layer(
			struct ib_device *ibdev, u32 port_num)
{
	return IB_LINK_LAYER_ETHERNET;
}
#else
static enum rdma_link_layer crdma_get_link_layer(
			struct ib_device *ibdev, u8 port_num)
{
	return IB_LINK_LAYER_ETHERNET;
}
#endif

static int crdma_add_gid(const struct ib_gid_attr *attr, void **context)
{
	struct crdma_ibdev *dev = to_crdma_ibdev(attr->device);
	struct crdma_port *port = &dev->port;
	struct crdma_gid_entry *entry;
	int ret = 0;
	unsigned long flags;
	u16 index = attr->index;

	/* CRDMA HCA only support RoCEv2*/
	if (!rdma_protocol_roce_udp_encap(attr->device, attr->port_num)) {
		return -EINVAL;
	}

	if (attr->port_num > 1)
		return -EINVAL;

	if (index >= dev->cap.sgid_table_size)
		return -EINVAL;

	entry = &port->gid_table_entry[index];
	spin_lock_irqsave(&port->table_lock, flags);
	memcpy(&entry->gid, &attr->gid, sizeof(attr->gid));
	entry->type = RDMA_ROCE_V2_GID_TYPE;
	entry->valid = 1;
	spin_unlock_irqrestore(&port->table_lock, flags);

	ret = crdma_write_sgid_table(dev, attr->port_num - 1, port->gid_table_size);
	if (ret) {
		crdma_warn("Write sgid table command failed\n");
		return -EINVAL;
	}

	return 0;
}

static int crdma_del_gid(const struct ib_gid_attr *attr, void **context)
{
	struct crdma_ibdev *dev = to_crdma_ibdev(attr->device);
	struct crdma_port *port = &dev->port;
	struct crdma_gid_entry *entry;
	int ret = 0;
	unsigned long flags;
	u16 index = attr->index;

	/* CRDMA HCA only support RoCEv2*/
	if (!rdma_protocol_roce_udp_encap(attr->device, attr->port_num)) {
		return -EINVAL;
	}

	if (attr->port_num > 1)
		return -EINVAL;

	if (index >= dev->cap.sgid_table_size)
		return -EINVAL;

	entry = &port->gid_table_entry[index];
	spin_lock_irqsave(&port->table_lock, flags);
	memset(&entry->gid, 0, 16);
	entry->valid = 0;
	spin_unlock_irqrestore(&port->table_lock, flags);

	ret = crdma_write_sgid_table(dev, attr->port_num - 1, port->gid_table_size);
	if (ret) {
		crdma_warn("Write sgid table command failed\n");
		return -EINVAL;
	}

	return 0;
}

#if (VER_NON_RHEL_GE(5,13) || RHEL_RELEASE_GE(8,365,0,0))
static int crdma_query_gid(struct ib_device *ibdev, u32 port_num,
			   int index, union ib_gid *gid)
#else
static int crdma_query_gid(struct ib_device *ibdev, u8 port_num,
			   int index, union ib_gid *gid)
#endif
{
	/* CRDMA HCA only support RoCEv2, so do nothing in this function */
	crdma_info("CRDMA HCA only support RoCEv2, it is no-op here.\n");
	return 0;
}

#if (VER_NON_RHEL_GE(5,13) || RHEL_RELEASE_GE(8,365,0,0))
static int crdma_query_pkey(struct ib_device *ibdev, u32 port_num,
			    u16 index, u16 *pkey)
#else
static int crdma_query_pkey(struct ib_device *ibdev, u8 port_num,
			    u16 index, u16 *pkey)
#endif
{

	if (index >= CRDMA_IB_MAX_PKEY_TABLE_SIZE)
		return -EINVAL;

	*pkey = CRDMA_DEFAULT_PKEY;
	return 0;
}

#if (VER_NON_RHEL_OR_KYL_GE(5,1) || VER_RHEL_GE(8,0) || VER_KYL_GE(10,3))
static int crdma_alloc_ucontext(struct ib_ucontext *ib_uctxt,
				struct ib_udata *udata)
{
	struct ib_device *ibdev = ib_uctxt->device;
	struct crdma_ucontext *crdma_uctxt;
	struct crdma_ibdev *dev = to_crdma_ibdev(ibdev);
	struct crdma_ib_alloc_ucontext_resp resp;
	int err;

	/*
	 * Inform the library provider of the chip-set family we
	 * are working with.
	 */
	resp.max_qp = dev->cap.ib.max_qp - dev->cap.rsvd_qp;

	crdma_uctxt = container_of(ib_uctxt, struct crdma_ucontext, ib_uctxt);
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
		return err;

	err = ib_copy_to_udata(udata, &resp, sizeof(resp));
	if (err)
		goto free_uar;

	return 0;

free_uar:
	crdma_free_uar(dev, &crdma_uctxt->uar);
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

	/*
	 * Inform the library provider of the chip-set family we
	 * are working with.
	 */
	resp.max_qp = dev->cap.ib.max_qp - dev->cap.rsvd_qp;

	crdma_uctxt = kzalloc(sizeof(*crdma_uctxt), GFP_KERNEL);
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

#if (VER_NON_RHEL_OR_KYL_GE(5,1) || VER_RHEL_GE(8,0) || VER_KYL_GE(10,3))
static void crdma_dealloc_ucontext(struct ib_ucontext *ib_uctxt)
#else
static int crdma_dealloc_ucontext(struct ib_ucontext *ib_uctxt)
#endif
{
	struct crdma_ibdev *dev = to_crdma_ibdev(ib_uctxt->device);
	struct crdma_ucontext *crdma_uctxt = to_crdma_uctxt(ib_uctxt);
	struct crdma_mmap_req *req, *tmp;

	crdma_free_uar(dev, &crdma_uctxt->uar);

	/* Release any pending mmap definitions */
	mutex_lock(&crdma_uctxt->mmap_pending_lock);
	list_for_each_entry_safe(req, tmp, &crdma_uctxt->mmap_pending, entry) {
		list_del(&req->entry);
		kfree(req);
	}
	mutex_unlock(&crdma_uctxt->mmap_pending_lock);

#if (!(VER_NON_RHEL_OR_KYL_GE(5,1) || VER_RHEL_GE(8,0) || VER_KYL_GE(10,3)))
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

#ifdef CRDMA_DETAIL_INFO_DEBUG_FLAG
	crdma_dev_info(dev, "uctxt           0x%p\n", crdma_uctxt);
	crdma_dev_info(dev, "vma->vm_pgoff   %ld\n", vma->vm_pgoff);
	crdma_dev_info(dev, "offset          0x%016llX\n", offset);
	crdma_dev_info(dev, "length          0x%lld\n", length);
#endif

	if (vma->vm_start & (PAGE_SIZE -1))
		return -EINVAL;

	/* First page offset is for user context UAR used for doorbells */
	if (vma->vm_pgoff == 0) {
#ifdef CRDMA_DETAIL_INFO_DEBUG_FLAG
		crdma_dev_info(dev, "Map user context UAR, index: %d\n",
			crdma_uctxt->uar.index);
#endif
		vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);

		return io_remap_pfn_range(vma, vma->vm_start,
				crdma_uar_pfn(dev, &crdma_uctxt->uar),
				PAGE_SIZE, vma->vm_page_prot);
	}

	/* A request to mmap a kernel allocated QP, SRQ, or CQ queue */
	mutex_lock(&crdma_uctxt->mmap_pending_lock);
	list_for_each_entry_safe(req, tmp, &crdma_uctxt->mmap_pending, entry) {
		if ((req->paddr != offset) || (req->length < length))
			continue;
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

#if (VER_NON_RHEL_OR_KYL_GE(5,2) || VER_RHEL_GE(8,0) || VER_KYL_GE(10,3))
static int crdma_alloc_pd(struct ib_pd *ibpd, struct ib_udata *udata)
{
	struct ib_device *ibdev = ibpd->device;
	struct crdma_pd *pd = container_of(ibpd, struct crdma_pd, ib_pd);
	struct crdma_ibdev *dev = to_crdma_ibdev(ibdev);
	int err;

	if (crdma_alloc_bitmap_index(&dev->pd_map, &pd->pd_index)) {
		return -ENOMEM;
	}

	if(udata) {
		err = ib_copy_to_udata(udata, &pd->pd_index, sizeof(u32));
		if (err)
			goto free_pd;
	}
	return 0;

free_pd:
	crdma_free_bitmap_index(&dev->pd_map, pd->pd_index);
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

	pd = kzalloc(sizeof(*pd), GFP_KERNEL);
	if (!pd)
		return ERR_PTR(-ENOMEM);

	if (crdma_alloc_bitmap_index(&dev->pd_map, &pd->pd_index)) {
		err = -ENOMEM;
		goto free_mem;
	}

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

#if (VER_NON_RHEL_OR_KYL_GE(5,10) || VER_RHEL_GE(8,0) || VER_KYL_GE(10,4))
static int crdma_dealloc_pd(struct ib_pd *pd, struct ib_udata *udata)
{
	struct crdma_ibdev *dev = to_crdma_ibdev(pd->device);
	struct crdma_pd *npd = to_crdma_pd(pd);

	crdma_free_bitmap_index(&dev->pd_map, npd->pd_index);

	return 0;
}
#elif (VER_NON_KYL_GE(5,2) || VER_KYL_GE(10,3))
static void crdma_dealloc_pd(struct ib_pd *pd, struct ib_udata *udata)
{
	struct crdma_ibdev *dev = to_crdma_ibdev(pd->device);
	struct crdma_pd *npd = to_crdma_pd(pd);

	crdma_free_bitmap_index(&dev->pd_map, npd->pd_index);

	return;
}
#else
static int crdma_dealloc_pd(struct ib_pd *pd)
{
	struct crdma_ibdev *dev = to_crdma_ibdev(pd->device);
	struct crdma_pd *npd = to_crdma_pd(pd);

	crdma_free_bitmap_index(&dev->pd_map, npd->pd_index);

	kfree(npd);

	return 0;
}
#endif

#if (VER_NON_RHEL_OR_KYL_GE(5,8) || VER_RHEL_GE(8,0) || VER_KYL_GE(10,4))
static int crdma_create_ah(struct ib_ah *ah, struct rdma_ah_init_attr *init_attr,
			struct ib_udata *udata)
{
	struct crdma_ibdev *dev = to_crdma_ibdev(ah->device);
	struct rdma_ah_attr *ah_attr = init_attr->ah_attr;
	struct crdma_ib_create_ah_resp resp = {};
	struct crdma_ah *cah = to_crdma_ah(ah);
	struct ib_pd *pd = ah->pd;
	int err;


	if (crdma_check_ah_attr(dev, ah_attr)) {
		crdma_warn("CRDMA ah attr check failed\n");
		return -EINVAL;
	}

	if (crdma_set_av(pd, &cah->av, ah_attr)) {
		return -EINVAL;
	}

	if (udata) {
		resp.vlan     = le32_to_cpu(cah->av.vlan);
		resp.v_id     = cah->av.v_id;
		resp.gid_type = cah->av.gid_type;
		memcpy(resp.d_mac, cah->av.d_mac, ETH_ALEN);
		resp.traffic_class = cah->av.traffic_class;

		err = ib_copy_to_udata(udata, &resp, sizeof(resp));
		if (err)
			return -EINVAL;
	}

	return 0;
}
#elif (VER_NON_KYL_GE(5,2) || VER_KYL_GE(10,3))
static int crdma_create_ah(struct ib_ah *ah, struct rdma_ah_attr *ah_attr,
			u32 flags, struct ib_udata *udata)
{
	struct crdma_ibdev *dev = to_crdma_ibdev(ah->device);
	struct crdma_ib_create_ah_resp resp = {};
	struct crdma_ah *cah = to_crdma_ah(ah);
	struct ib_pd *pd = ah->pd;
	int err;


	if (crdma_check_ah_attr(dev, ah_attr)) {
		crdma_warn("CRDMA ah attr check failed\n");
		return -EINVAL;
	}

	if (crdma_set_av(pd, &cah->av, ah_attr)) {
		return -EINVAL;
	}

	if (udata) {
		resp.vlan     = le32_to_cpu(cah->av.vlan);
		resp.v_id     = cah->av.v_id;
		resp.gid_type = cah->av.gid_type;
		memcpy(resp.d_mac, cah->av.d_mac, ETH_ALEN);
		resp.traffic_class = cah->av.traffic_class;

		err = ib_copy_to_udata(udata, &resp, sizeof(resp));
		if (err)
			return -EINVAL;
	}

	return 0;
}
#else
static struct ib_ah *crdma_create_ah(struct ib_pd *pd,
			struct rdma_ah_attr *ah_attr,
			struct ib_udata *udata)
{
	struct crdma_ibdev *dev = to_crdma_ibdev(pd->device);
	struct crdma_ib_create_ah_resp resp = {};
	struct crdma_ah *cah;
	int err;


	if (crdma_check_ah_attr(dev, ah_attr)) {
		crdma_warn("CRDMA ah attr check failed\n");
		return ERR_PTR(-EINVAL);
	}

	cah = kzalloc(sizeof(*cah), GFP_ATOMIC);
	if (!cah)
		return ERR_PTR(-ENOMEM);

	if (crdma_set_av(pd, &cah->av, ah_attr))
		return ERR_PTR(-EINVAL);

	if (udata) {
		resp.vlan     = le32_to_cpu(cah->av.vlan);
		resp.v_id     = cah->av.v_id;
		resp.gid_type = cah->av.gid_type;
		memcpy(resp.d_mac, cah->av.d_mac, ETH_ALEN);
		resp.traffic_class = cah->av.traffic_class;

		err = ib_copy_to_udata(udata, &resp, sizeof(resp));
		if (err)
			return ERR_PTR(-EINVAL);
	}

	return &cah->ib_ah;
}
#endif

static int crdma_query_ah(struct ib_ah *ah, struct rdma_ah_attr *ah_attr)
{
	struct crdma_ah *cah = to_crdma_ah(ah);

	memset(ah_attr, 0, sizeof(*ah_attr));
	ah_attr->type              = ah->type;
	rdma_ah_set_sl(ah_attr, cah->av.service_level);

	/* The reason of swap byte order reference the struct crdma_av */
	ah_attr->roce.dmac[0]      = cah->av.d_mac[3];
	ah_attr->roce.dmac[1]      = cah->av.d_mac[2];
	ah_attr->roce.dmac[2]      = cah->av.d_mac[1];
	ah_attr->roce.dmac[3]      = cah->av.d_mac[0];
	ah_attr->roce.dmac[4]      = cah->av.d_mac[5];
	ah_attr->roce.dmac[5]      = cah->av.d_mac[4];

	rdma_ah_set_port_num(ah_attr, cah->av.port + 1);
	rdma_ah_set_static_rate(ah_attr, 0); /* Do not support*/
	/* Set grh */
	rdma_ah_set_grh(ah_attr, NULL, __swab32(cah->av.flow_label),
			cah->av.s_gid_ndx, cah->av.hop_limit,
			cah->av.traffic_class);
	rdma_ah_set_dgid_raw(ah_attr, cah->av.d_gid);

	return 0;
}

#if (VER_NON_RHEL_OR_KYL_GE(5,0) || VER_RHEL_GE(8,0) || VER_KYL_GE(10,4))
static int crdma_destroy_ah(struct ib_ah *ah, u32 flags)
{
	return 0;
}
#elif (VER_NON_KYL_GE(5,2) || VER_KYL_GE(10,3))
static void crdma_destroy_ah(struct ib_ah *ah, u32 flags)
{
	return;
}
#elif (VER_NON_RHEL_OR_KYL_GE(5,0))
static int crdma_destroy_ah(struct ib_ah *ah, u32 flags)
{
	return 0;
}
#else
static int crdma_destroy_ah(struct ib_ah *ah)
{
	kfree(to_crdma_ah(ah));
	return 0;
}
#endif

static int crdma_qp_val_check(struct crdma_ibdev *dev,
		struct ib_qp_cap *cap, bool use_srq)
{
	/* Note we advertise 1 less than actual hardware maximum */
	if (cap->max_send_wr >= dev->cap.ib.max_qp_wr) {
		crdma_warn("Send WR entries requested > max %d\n",
				dev->cap.ib.max_qp_wr);
		return -EINVAL;
	}

	if (cap->max_send_sge < 1 ||
			cap->max_send_sge > dev->cap.ib.max_send_sge) {
		crdma_warn("Send SG entries requested invalid %d\n",
				cap->max_send_sge);
		return -EINVAL;
	}

	if (!use_srq) {
		/* Note we advertise 1 less than actual hardware maximum */
		if (cap->max_recv_wr >= dev->cap.ib.max_qp_wr) {
			crdma_warn("Recv WR entries requested > max %d\n",
					dev->cap.ib.max_qp_wr);
			return -EINVAL;
		}
		if (cap->max_recv_sge < 1 ||
				cap->max_recv_sge > dev->cap.ib.max_sge_rd) {
			crdma_warn("Receive SG entries requested > max %d\n",
					dev->cap.ib.max_sge_rd);
			return -EINVAL;
		}
	} else {
		if (cap->max_recv_wr) {
			crdma_warn("Recv WR must be 0 when using SRQ\n");
			return -EINVAL;
		}
		crdma_warn("SRQ not yet supported\n");
		return -EINVAL;
	}

	if (cap->max_inline_data > dev->cap.max_inline_data) {
		crdma_warn("Max inline data requested > max %d\n",
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
		crdma_warn("Required SWQE size %d exceeds max %d\n",
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
			crdma_warn("Required RWQE size %d exceeds max %d\n",
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

#ifdef CRDMA_DETAIL_INFO_DEBUG_FLAG
	crdma_dev_info(dev, "Dump WQ information\n");
	crdma_dev_info(dev, "SQ WQE size      %d\n", qp->sq.wqe_size);
	crdma_dev_info(dev, "SQ WQE count     %d\n", qp->sq.wqe_cnt);
	crdma_dev_info(dev, "SQ WQE num SG    %d\n", qp->sq.max_sg);
	crdma_dev_info(dev, "SQ byte length   %d\n", qp->sq.length);
	crdma_dev_info(dev, "RQ WQE size      %d\n", qp->rq.wqe_size);
	crdma_dev_info(dev, "RQ WQE count     %d\n", qp->rq.wqe_cnt);
	crdma_dev_info(dev, "RQ WQE num SG    %d\n", qp->rq.max_sg);
	crdma_dev_info(dev, "RQ byte length   %d\n", qp->rq.length);
#endif
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

#define CRDMA_QP1_INDEX   1

#if (VER_NON_RHEL_GE(5,15) || RHEL_RELEASE_GE(8,394,0,0))
static int crdma_create_qp(struct ib_qp *qp,
			   struct ib_qp_init_attr *qp_init_attr,
			   struct ib_udata *udata)
{
	struct crdma_ibdev *dev = to_crdma_ibdev(qp->device);
	struct crdma_qp *cqp = to_crdma_qp(qp);
	struct ib_pd *pd = qp->pd;
	int err;

	if (qp_init_attr->qp_type != IB_QPT_UD &&
			qp_init_attr->qp_type != IB_QPT_RC &&
			qp_init_attr->qp_type != IB_QPT_GSI) {
		crdma_warn("Unsupported QP type %d\n", qp_init_attr->qp_type);
		return -EINVAL;
	}

	if (udata && qp_init_attr->qp_type == IB_QPT_GSI) {
		crdma_warn("QP1 create restricted to kernel\n");
		return -EINVAL;
	}

	if (crdma_qp_val_check(dev, &qp_init_attr->cap,
				qp_init_attr->srq != NULL)) {
		crdma_warn("QP init attribute validation failed\n");
		return -EINVAL;
	}

	mutex_init(&cqp->mutex);
	spin_lock_init(&cqp->sq.lock);
	spin_lock_init(&cqp->rq.lock);
	cqp->qp_state = IB_QPS_RESET;
	cqp->pdn = pd ? to_crdma_pd(pd)->pd_index : 0;
	cqp->send_cqn = qp_init_attr->send_cq ?
		to_crdma_cq(qp_init_attr->send_cq)->cqn : 0;
	cqp->recv_cqn = qp_init_attr->recv_cq ?
		to_crdma_cq(qp_init_attr->recv_cq)->cqn : 0;
	cqp->srqn = qp_init_attr->srq ?
		to_crdma_srq(qp_init_attr->srq)->srq_index : 0;

	cqp->sq_sig_all = (qp_init_attr->sq_sig_type == IB_SIGNAL_ALL_WR) ? 1 : 0;

	/* Set the actual number and sizes of the QP work requests */
	err = crdma_qp_set_wq_sizes(dev, cqp, qp_init_attr);
	if (err) {
		err = -EINVAL;
		goto free_mem;
	}

	/* Allocate resource index for the QP control object */
	if (qp_init_attr->qp_type == IB_QPT_GSI) {
		cqp->qp_index = CRDMA_QP1_INDEX;
	} else {
		if (crdma_alloc_bitmap_index(&dev->qp_map, &cqp->qp_index)) {
			crdma_warn("No QP index available\n");
			err = -ENOMEM;
			goto free_mem;
		}
	}

	/* Kernel always allocates QP memory, user contexts will mmap it */
	cqp->mem = crdma_alloc_hw_queue(dev, cqp->sq.length + cqp->rq.length);
	if (IS_ERR(cqp->mem)) {
		crdma_dev_err(dev, "Unable to allocate QP HW queue\n");
		err = -ENOMEM;
		goto free_qp_index;
	}

	crdma_init_wq_ownership(cqp->mem, cqp->sq_offset,
				cqp->sq.wqe_cnt, cqp->sq.wqe_size);
	crdma_init_wq_ownership(cqp->mem, cqp->rq_offset,
				cqp->rq.wqe_cnt, cqp->rq.wqe_size);

	/* Add to Radix tree for lookups */
	spin_lock_irq(&dev->qp_lock);
	err = radix_tree_insert(&dev->qp_tree, cqp->qp_index, cqp);
	spin_unlock_irq(&dev->qp_lock);
	if (err) {
		crdma_dev_err(dev, "Unable to insert QP tree\n");
		goto free_dma_memory;
	}

	cqp->ib_qp.qp_num = qp_init_attr->qp_type == IB_QPT_GSI ?
			1 : cqp->qp_index;

	/* return response */
	if (udata) {
		struct crdma_ucontext *crdma_uctxt =
				to_crdma_uctxt(pd->uobject->context);
		struct crdma_ib_create_qp_resp resp;

		resp.wq_base_addr = sg_dma_address(cqp->mem->alloc);
		resp.wq_size = cqp->mem->tot_len;
		if (cqp->sq.length >= cqp->rq.length) {
			resp.sq_offset = 0;
			resp.rq_offset = cqp->sq.length;
		} else {
			resp.rq_offset = 0;
			resp.sq_offset = cqp->rq.length;
		}
		resp.swqe_size = cqp->sq.wqe_size;
		resp.num_swqe = cqp->sq.wqe_cnt;
		resp.rwqe_size = cqp->rq.wqe_size;
		resp.num_rwqe = cqp->rq.wqe_cnt;
		resp.spares = CRDMA_WQ_WQE_SPARES;

		err = ib_copy_to_udata(udata, &resp, sizeof(resp));
		if (err) {
			crdma_warn("Copy of UDATA failed, %d\n", err);
			goto delete_qp;
		}

		err = crdma_add_mmap_req(crdma_uctxt, resp.wq_base_addr,
				cqp->mem->tot_len);
		if (err) {
			crdma_warn("Failed to add pending mmap, %d\n", err);
			goto delete_qp;
		}
	} else {
		cqp->sq.buf = sg_virt(cqp->mem->alloc) + cqp->sq_offset;
		cqp->sq.mask = cqp->sq.wqe_cnt - 1;
		cqp->sq.wqe_size_log2 = ilog2(cqp->sq.wqe_size);

		cqp->sq.wrid_map = kcalloc(cqp->sq.wqe_cnt, sizeof(u64),
						GFP_KERNEL);
		if (!cqp->sq.wrid_map) {
			crdma_warn("Could not allocate SQ WRID map\n");
			err = -ENOMEM;
			goto delete_qp;
		}

		cqp->rq.buf = sg_virt(cqp->mem->alloc) + cqp->rq_offset;
		cqp->rq.mask = cqp->rq.wqe_cnt - 1;
		cqp->rq.wqe_size_log2 = ilog2(cqp->rq.wqe_size);

		cqp->rq.wrid_map = kcalloc(cqp->rq.wqe_cnt, sizeof(u64),
						GFP_KERNEL);
		if (!cqp->rq.wrid_map) {
			crdma_warn("Could not allocate RQ WRID map\n");
			err = -ENOMEM;
			kfree(cqp->sq.wrid_map);
			goto delete_qp;
		}
	}
	atomic_set(&cqp->ref_cnt, 1);
	init_completion(&cqp->free);
	return 0;

delete_qp:
	spin_lock_irq(&dev->qp_lock);
	radix_tree_delete(&dev->qp_tree, cqp->qp_index);
	spin_unlock_irq(&dev->qp_lock);
free_dma_memory:
	crdma_free_hw_queue(dev, cqp->mem);
free_qp_index:
	if (qp_init_attr->qp_type != IB_QPT_GSI)
		crdma_free_bitmap_index(&dev->qp_map, cqp->qp_index);
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
static struct ib_qp *crdma_create_qp(struct ib_pd *pd,
			struct ib_qp_init_attr *qp_init_attr,
			struct ib_udata *udata)
{
	struct crdma_ibdev *dev = to_crdma_ibdev(pd->device);
	struct crdma_qp *cqp;
	int err;

	if (qp_init_attr->qp_type != IB_QPT_UD &&
			qp_init_attr->qp_type != IB_QPT_RC &&
			qp_init_attr->qp_type != IB_QPT_GSI) {
		crdma_warn("Unsupported QP type %d\n", qp_init_attr->qp_type);
		return ERR_PTR(-EINVAL);
	}

	if (udata && qp_init_attr->qp_type == IB_QPT_GSI) {
		crdma_warn("QP1 create restricted to kernel\n");
		return ERR_PTR(-EINVAL);
	}

	if (crdma_qp_val_check(dev, &qp_init_attr->cap,
				qp_init_attr->srq != NULL)) {
		crdma_warn("QP init attribute validation failed\n");
		return ERR_PTR(-EINVAL);
	}

	cqp = kzalloc(sizeof(*cqp), GFP_KERNEL);
	if (!cqp)
		return ERR_PTR(-ENOMEM);

	mutex_init(&cqp->mutex);
	spin_lock_init(&cqp->sq.lock);
	spin_lock_init(&cqp->rq.lock);
	cqp->qp_state = IB_QPS_RESET;
	cqp->pdn = pd ? to_crdma_pd(pd)->pd_index : 0;
	cqp->send_cqn = qp_init_attr->send_cq ?
		to_crdma_cq(qp_init_attr->send_cq)->cqn : 0;
	cqp->recv_cqn = qp_init_attr->recv_cq ?
		to_crdma_cq(qp_init_attr->recv_cq)->cqn : 0;
	cqp->srqn = qp_init_attr->srq ?
		to_crdma_srq(qp_init_attr->srq)->srq_index : 0;

	cqp->sq_sig_all = (qp_init_attr->sq_sig_type == IB_SIGNAL_ALL_WR) ? 1 : 0;

	/* Set the actual number and sizes of the QP work requests */
	err = crdma_qp_set_wq_sizes(dev, cqp, qp_init_attr);
	if (err) {
		err = -EINVAL;
		goto free_mem;
	}

	/* Allocate resource index for the QP control object */
	if (qp_init_attr->qp_type == IB_QPT_GSI) {
		cqp->qp_index = CRDMA_QP1_INDEX;
	} else {
		if (crdma_alloc_bitmap_index(&dev->qp_map, &cqp->qp_index)) {
			crdma_warn("No QP index available\n");
			err = -ENOMEM;
			goto free_mem;
		}
	}

	/* Kernel always allocates QP memory, user contexts will mmap it */
	cqp->mem = crdma_alloc_hw_queue(dev, cqp->sq.length + cqp->rq.length);
	if (IS_ERR(cqp->mem)) {
		crdma_dev_err(dev, "Unable to allocate QP HW queue\n");
		err = -ENOMEM;
		goto free_qp_index;
	}

	crdma_init_wq_ownership(cqp->mem, cqp->sq_offset,
				cqp->sq.wqe_cnt, cqp->sq.wqe_size);
	crdma_init_wq_ownership(cqp->mem, cqp->rq_offset,
				cqp->rq.wqe_cnt, cqp->rq.wqe_size);

	/* Add to Radix tree for lookups */
	spin_lock_irq(&dev->qp_lock);
	err = radix_tree_insert(&dev->qp_tree, cqp->qp_index, cqp);
	spin_unlock_irq(&dev->qp_lock);
	if (err) {
		crdma_dev_err(dev, "Unable to insert QP tree\n");
		goto free_dma_memory;
	}

	cqp->ib_qp.qp_num = qp_init_attr->qp_type == IB_QPT_GSI ?
			1 : cqp->qp_index;

	/* return response */
	if (udata) {
		struct crdma_ucontext *crdma_uctxt =
				to_crdma_uctxt(pd->uobject->context);
		struct crdma_ib_create_qp_resp resp;

		resp.wq_base_addr = sg_dma_address(cqp->mem->alloc);
		resp.wq_size = cqp->mem->tot_len;
		if (cqp->sq.length >= cqp->rq.length) {
			resp.sq_offset = 0;
			resp.rq_offset = cqp->sq.length;
		} else {
			resp.rq_offset = 0;
			resp.sq_offset = cqp->rq.length;
		}
		resp.swqe_size = cqp->sq.wqe_size;
		resp.num_swqe = cqp->sq.wqe_cnt;
		resp.rwqe_size = cqp->rq.wqe_size;
		resp.num_rwqe = cqp->rq.wqe_cnt;
		resp.spares = CRDMA_WQ_WQE_SPARES;

		err = ib_copy_to_udata(udata, &resp, sizeof(resp));
		if (err) {
			crdma_warn("Copy of UDATA failed, %d\n", err);
			goto delete_qp;
		}

		err = crdma_add_mmap_req(crdma_uctxt, resp.wq_base_addr,
				cqp->mem->tot_len);
		if (err) {
			crdma_warn("Failed to add pending mmap, %d\n", err);
			goto delete_qp;
		}
	} else {
		cqp->sq.buf = sg_virt(cqp->mem->alloc) + cqp->sq_offset;
		cqp->sq.mask = cqp->sq.wqe_cnt - 1;
		cqp->sq.wqe_size_log2 = ilog2(cqp->sq.wqe_size);

		cqp->sq.wrid_map = kcalloc(cqp->sq.wqe_cnt, sizeof(u64),
						GFP_KERNEL);
		if (!cqp->sq.wrid_map) {
			crdma_warn("Could not allocate SQ WRID map\n");
			err = -ENOMEM;
			goto delete_qp;
		}

		cqp->rq.buf = sg_virt(cqp->mem->alloc) + cqp->rq_offset;
		cqp->rq.mask = cqp->rq.wqe_cnt - 1;
		cqp->rq.wqe_size_log2 = ilog2(cqp->rq.wqe_size);

		cqp->rq.wrid_map = kcalloc(cqp->rq.wqe_cnt, sizeof(u64),
						GFP_KERNEL);
		if (!cqp->rq.wrid_map) {
			crdma_warn("Could not allocate RQ WRID map\n");
			err = -ENOMEM;
			kfree(cqp->sq.wrid_map);
			goto delete_qp;
		}
	}
	atomic_set(&cqp->ref_cnt, 1);
	init_completion(&cqp->free);
	return &cqp->ib_qp;

delete_qp:
	spin_lock_irq(&dev->qp_lock);
	radix_tree_delete(&dev->qp_tree, cqp->qp_index);
	spin_unlock_irq(&dev->qp_lock);
free_dma_memory:
	crdma_free_hw_queue(dev, cqp->mem);
free_qp_index:
	if (qp_init_attr->qp_type != IB_QPT_GSI)
		crdma_free_bitmap_index(&dev->qp_map, cqp->qp_index);
free_mem:
	kfree(cqp);

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

static int crdma_modify_qp(struct ib_qp *qp, struct ib_qp_attr *qp_attr,
			int qp_attr_mask, struct ib_udata *udata)
{
	struct crdma_ibdev *dev = to_crdma_ibdev(qp->device);
	struct crdma_ucontext *crdma_uctxt;
	struct crdma_qp *cqp = to_crdma_qp(qp);
	enum ib_qp_state cur_state;
	enum ib_qp_state new_state;
	int ret;


	mutex_lock(&cqp->mutex);
	/*
	 * TODO: Our microcode does not support Queue Pair state transitions.
	 * This part needs to be adapted latter.
	 */
	if (qp_attr_mask & IB_QP_CUR_STATE &&
	    qp_attr->cur_qp_state != cqp->qp_state) {
		crdma_warn("IB_QP_CUR_STATE is set, but qp_attr->cur_qp_state "
			   "%d, cqp->qp_state %d\n",
			   qp_attr->cur_qp_state, cqp->qp_state);
		ret = -EINVAL;
		goto out;
	}

	cur_state = cqp->qp_state;
	new_state = qp_attr_mask & IB_QP_STATE ? qp_attr->qp_state : cur_state;

	/* State transition attribute/transport type validation */
	ret = -EINVAL;
#if (VER_NON_RHEL_OR_KYL_GE(4,20) || VER_RHEL_GE(8,0) || VER_KYL_GE(10,3))
	if (!ib_modify_qp_is_ok(cur_state, new_state,
			qp->qp_type, qp_attr_mask)) {
#else
	if (!ib_modify_qp_is_ok(cur_state, new_state,
			qp->qp_type, qp_attr_mask, IB_LINK_LAYER_ETHERNET)) {
#endif
		crdma_warn("QPN %d, invalid attribute mask specified "
				"for transition %d to %d. qp_type %d, "
				"attr_mask 0x%08X\n",
				qp->qp_num, cur_state, new_state,
				qp->qp_type, qp_attr_mask);
		goto out;
	}

	/* Requester resources can't be larger than device allows for QP */
	if (qp_attr_mask & IB_QP_MAX_QP_RD_ATOMIC && (qp_attr->max_rd_atomic >
							dev->cap.ib.max_qp_init_rd_atom)) {
		crdma_warn("QPN %d, max_rd_atomic %d too large\n",
						qp->qp_num, qp_attr->max_rd_atomic);
		goto out;
	}

	/* Perform validation of the requested attributes */
	if ((qp_attr_mask & IB_QP_PORT) && (qp_attr->port_num == 0 ||
							qp_attr->port_num > dev->cap.n_ports)) {
		crdma_warn("Invalid port number %d\n", qp_attr->port_num);
		goto out;
	}

	if ((qp_attr_mask & IB_QP_PKEY_INDEX) && (qp_attr->pkey_index > 0)) {
		crdma_warn("Invalid PKEY index %d\n", qp_attr->pkey_index);
		goto out;
	}

	/* Requester resources can't be larger than device allows for QP */
	if (qp_attr_mask & IB_QP_MAX_QP_RD_ATOMIC && (qp_attr->max_rd_atomic >
							dev->cap.ib.max_qp_init_rd_atom)) {
		crdma_warn("QPN %d, max_rd_atomic %d too large\n",
						qp->qp_num, qp_attr->max_rd_atomic);
		goto out;
	}

	/* Responder resources can't be larger than device allows for QP */
	if (qp_attr_mask & IB_QP_MAX_DEST_RD_ATOMIC &&
					(qp_attr->max_dest_rd_atomic >
					dev->cap.ib.max_qp_rd_atom)) {
		crdma_warn("QPN %d, max_dest_rd_atomic %d too large\n",
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
	crdma_uctxt = rdma_udata_to_drv_context(udata,
				struct crdma_ucontext, ib_uctxt);
#else
	if (udata)
		crdma_uctxt = to_crdma_uctxt(qp->uobject->context);
#endif
	ret = crdma_qp_modify_cmd(dev, cqp, udata ?
			&crdma_uctxt->uar : &dev->priv_uar,
			qp_attr, qp_attr_mask, cur_state, new_state);

	if (ret) {
		crdma_err("Microcode QP_MODIFY error, %d\n", ret);
		ret = -EINVAL;
	}

out:
	mutex_unlock(&cqp->mutex);
	return ret;
}

static int crdma_query_qp(struct ib_qp *qp, struct ib_qp_attr *qp_attr,
			int qp_attr_mask, struct ib_qp_init_attr *qp_init_attr)
{
	struct crdma_ibdev *dev = to_crdma_ibdev(qp->device);
	struct crdma_qp *cqp = to_crdma_qp(qp);
	int ret = 0;

	mutex_lock(&cqp->mutex);

	/* If we are in RESET state then no attributes are assigned */
	if (cqp->qp_state == IB_QPS_RESET) {
		qp_attr->qp_state = IB_QPS_RESET;
		goto out;
	}

	ret = crdma_qp_query_cmd(dev, cqp, qp_attr, qp_attr_mask);
	if (ret) {
		crdma_err("Microcode QP_QUERY error, %d\n", ret);
		ret = -EINVAL;
		goto out;
	}

	qp_attr->cur_qp_state = qp_attr->qp_state;
	qp_attr->cap.max_recv_wr = cqp->rq.wqe_cnt;
	qp_attr->cap.max_recv_sge = cqp->rq.max_sg;
	qp_attr->cap.max_send_wr = cqp->sq.wqe_cnt;
	qp_attr->cap.max_send_sge = cqp->sq.max_sg;
	qp_attr->cap.max_inline_data = cqp->max_inline;
	qp_init_attr->sq_sig_type = cqp->sq_sig_all ? IB_SIGNAL_ALL_WR : 0;
	qp_init_attr->qp_type = cqp->ib_qp.qp_type;
	qp_init_attr->cap = qp_attr->cap;
out:
	mutex_unlock(&cqp->mutex);
	return ret;
}

#if (VER_NON_RHEL_OR_KYL_GE(5,2) || VER_RHEL_GE(8,0) || VER_KYL_GE(10,3))
static int crdma_destroy_qp(struct ib_qp *qp, struct ib_udata *udata)
#else
static int crdma_destroy_qp(struct ib_qp *qp)
#endif
{
	struct crdma_ibdev *dev = to_crdma_ibdev(qp->device);
	struct crdma_qp *cqp = to_crdma_qp(qp);
	int err;


	if (cqp->qp_state != IB_QPS_RESET) {
		err = crdma_qp_destroy_cmd(dev, cqp);
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
	radix_tree_delete(&dev->qp_tree, cqp->qp_index);
	spin_unlock_irq(&dev->qp_lock);

	/* Free resources specific to kernel based QP */
#if (VER_NON_RHEL_GE(5,2) || VER_RHEL_GE(8,0))
	if (!udata) {
#else
	if (!qp->uobject) {
#endif
		if (!cqp->rq.wrid_map)
			crdma_warn("RQ WRID map memory NULL\n");
		else
			kfree(cqp->rq.wrid_map);
		if (!cqp->sq.wrid_map)
			crdma_warn("SQ WRID map memory NULL\n");
		else
			kfree(cqp->sq.wrid_map);
	}

	crdma_free_hw_queue(dev, cqp->mem);
	if (cqp->ib_qp.qp_type != IB_QPT_GSI)
		crdma_free_bitmap_index(&dev->qp_map, cqp->qp_index);
	kfree(cqp);
	return 0;
}

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
	*ownership = 0xFFFFFFFF;
	return;
}

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
                                    const struct ib_send_wr *wr, int max)
{
	struct ib_sge *sg;
	int i;
	int length = 0;

	for (i = 0, sg = wr->sg_list; i < wr->num_sge; i++, sg++) {
		if (length + sg->length > max)
				return ENOMEM;
		memcpy(&data->data[length], (void *)(uintptr_t)sg->addr,
						sg->length);
		length += sg->length;
	}
	data->byte_count = cpu_to_le16((uint16_t)length);
	return 0;
}

static void set_reg_seg(struct crdma_swqe_frmr *fseg,
			const struct ib_reg_wr *wr)
{
	struct crdma_mr *cmr = to_crdma_mr(wr->mr);

	fseg->flags		= cpu_to_le32((wr->access & IB_ACCESS_REMOTE_ATOMIC ?
		CRDMA_MR_ACCESS_FLAGS_ATOMIC_EN       : 0) |
	       (wr->access & IB_ACCESS_REMOTE_WRITE  ?
		CRDMA_MR_ACCESS_FLAGS_R_WRITE_EN : 0) |
	       (wr->access & IB_ACCESS_REMOTE_READ   ?
		CRDMA_MR_ACCESS_FLAGS_R_READ_EN  : 0) |
	       (wr->access & IB_ACCESS_LOCAL_WRITE   ?
	       CRDMA_MR_ACCESS_FLAGS_L_WRITE_EN  : 0) |
		CRDMA_MR_ACCESS_FLAGS_L_READ_EN | CRDMA_MR_ACCESS_FLAGS_INVAL_EN);
	fseg->key		= cpu_to_le32(wr->key);
/* TO DO: by now, they are not used by firmware */
	fseg->page_list_paddr_h	= 0;
	fseg->page_list_paddr_l = 0;
	fseg->io_addr_h		= cpu_to_le32(cmr->io_vaddr >> 32);
	fseg->io_addr_l 	= cpu_to_le32(cmr->io_vaddr & 0x0FFFFFFFFull);
	fseg->length 		= cpu_to_le32(cmr->len & 0x0FFFFFFFFull);
	fseg->offset		= 0;
	fseg->page_size		= cpu_to_le32(ilog2(cmr->ib_mr.page_size));
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

	for (i = 0; i < num_sge; i++, sge_list++, wqe_sg++) {
		wqe_sg->io_addr_h = cpu_to_le32(sge_list->addr >> 32);
		wqe_sg->io_addr_l = cpu_to_le32(sge_list->addr &
						0x0FFFFFFFFull);
		wqe_sg->l_key = cpu_to_le32(sge_list->lkey);
		wqe_sg->byte_count = cpu_to_le32(sge_list->length);
	}

	return;
}


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
static struct crdma_swqe *get_sq_tail(struct crdma_qp *cqp)
{
	uint32_t next = (cqp->sq.tail + CRDMA_WQ_WQE_SPARES) & cqp->sq.mask;
	unsigned long flags;

	/*
		* If it looks like an overflow allow for any active CQ
		* processing to complete and look again.
		*/
	if (next == cqp->sq.head) {
		struct crdma_cq *ccq = to_crdma_cq(cqp->ib_qp.send_cq);

		spin_lock_irqsave(&ccq->lock, flags);
		next = (cqp->sq.tail + CRDMA_WQ_WQE_SPARES) & cqp->sq.mask;
		spin_unlock_irqrestore(&ccq->lock, flags);
		if (next == cqp->sq.head)
				return NULL;
	}

	/* Post SWQE at the software producer tail */
	return cqp->sq.buf + (cqp->sq.tail << cqp->sq.wqe_size_log2);
}

#define CRDMA_SQ_DB_READY_RETRIES              20

static int crdma_post_send(struct ib_qp *qp, const struct ib_send_wr *wr,
			   const struct ib_send_wr **bad_wr)
{
	struct crdma_ibdev *dev = to_crdma_ibdev(qp->device);
	struct crdma_qp *cqp = to_crdma_qp(qp);
	struct crdma_swqe *swqe;
	struct crdma_swqe_inline *inline_data;
	struct crdma_wqe_sge *sg;
	struct crdma_swqe_owner owner;
	int wr_cnt = 0;
	int ret = 0;
	u8 flags;
	u32 qpn = cqp->qp_index;
	unsigned long irq_flags;

	spin_lock_irqsave(&cqp->sq.lock, irq_flags);
	while (wr) {
		if (wr->num_sge > cqp->sq.max_sg) {
			crdma_warn("WR num_sge too large %d\n", wr->num_sge);
			*bad_wr = wr;
			ret = -EINVAL;
			goto out;
		}

		/* Post new SWQE's at the software tail, NULL if SQ full */
		swqe = get_sq_tail(cqp);
		if (!swqe) {
			crdma_warn("SQ Overflow\n");
			*bad_wr = wr;
			ret = -ENOMEM;
			goto out;
		}

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
				crdma_warn("Only UD SEND, SEND w/IMM "
					   "supported %d\n", wr->opcode);
				*bad_wr = wr;
				ret = -EINVAL;
				goto out;
			}

			/* Set the UD address vector */
			memcpy(&swqe->ud.addr.av,
			       &to_crdma_ah(ud_wr(wr)->ah)->av,
			       sizeof(struct crdma_av));
			swqe->ud.addr.dest_qpn =
				cpu_to_le32(ud_wr(wr)->remote_qpn);
			swqe->ud.addr.qkey =
				cpu_to_le32(ud_wr(wr)->remote_qkey);
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
					cpu_to_le32(rdma_wr(wr)->remote_addr >>
						    32);
				swqe->rc.rem_addr.rem_io_addr_l =
					cpu_to_le32(rdma_wr(wr)->remote_addr &
						    0x0FFFFFFFFLL);
				swqe->rc.rem_addr.r_key =
					cpu_to_le32(rdma_wr(wr)->rkey);
				swqe->rc.rem_addr.rsvd = 0;
				break;
			case IB_WR_REG_MR:
				set_reg_seg(&swqe->rc.frmr, reg_wr(wr));
				break;
			case IB_WR_LOCAL_INV:
			case IB_WR_SEND_WITH_INV:
				swqe->ctrl.imm_inval = cpu_to_le32(wr->ex.invalidate_rkey);
				break;
			default:
				break;
			}
			inline_data = &swqe->rc.inline_data;
			sg = &swqe->rc.sg[0];
			break;

		default:
			crdma_warn("Only UD and RC QP supported %d\n",
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
						cqp->max_inline);
			if (ret) {
				*bad_wr = wr;
				goto out;
			}
		} else {
			owner.num_sg = wr->num_sge;
			crdma_set_wqe_sge(sg, wr->num_sge, wr->sg_list);
		}
		cqp->sq.wrid_map[cqp->sq.tail] = wr->wr_id;

		/* Write ownership control word last */
		owner.opcode = wr->opcode;
		owner.flags  = flags |
				(wr->send_flags & IB_SEND_FENCE ?
				 CRDMA_WQE_CTRL_FENCE_BIT : 0) |
				(wr->send_flags & IB_SEND_SIGNALED || cqp->sq_sig_all ?
				 CRDMA_WQE_CTRL_SIGNAL_BIT : 0) |
				(wr->send_flags & IB_SEND_SOLICITED ?
				 CRDMA_WQE_CTRL_SOLICITED_BIT : 0) |
				(qp->qp_type == IB_QPT_GSI ?
				 CRDMA_WQE_CTRL_GSI_BIT : 0);
		wmb();
		swqe->ctrl.owner.word = owner.word;

#ifdef CRDMA_DETAIL_INFO_DEBUG_FLAG /* Extra debug only */
		print_hex_dump(KERN_DEBUG, "SWQE:", DUMP_PREFIX_OFFSET, 8, 1,
			       swqe, 128, 0);
#endif

		/* Advance to the next SWQE to consume */
		wr_cnt++;
		cqp->sq.tail = (cqp->sq.tail + 1) & cqp->sq.mask;
		wr = wr->next;

		/*
		 * If there are more WQE to post, update the WQE
		 * ownership stamp of the last spare.  If this is the
		 * last work request or there was only one work request,
		 * wait until after ringing the doorbell to update the
		 * ownership.
		 */
		if (wr)
			set_wqe_sw_ownership(&cqp->sq, cqp->sq.tail +
					     CRDMA_WQ_WQE_SPARES);
	}

out:
	if (wr_cnt) {

		/*
		 * Make sure last control word has been written, and we have
		 * and the read check has completed  before the doorbell
		 * is written
		 */
		mb();
		crdma_sq_ring_db32(dev, qpn);

		/*
		 * Make sure the last spare request is set to software
		 * ownership.
		 */
		set_wqe_sw_ownership(&cqp->sq, cqp->sq.tail +
				     CRDMA_WQ_WQE_SPARES);
	}
	spin_unlock_irqrestore(&cqp->sq.lock, irq_flags);

	return 0;
}

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
static struct crdma_rwqe *get_rq_tail(struct crdma_qp *cqp)
{
	u32 next = (cqp->rq.tail + CRDMA_WQ_WQE_SPARES) & cqp->rq.mask;
	unsigned long flags;

	/*
	 * If it looks like an overflow allow for any active CQ
	 * processing to complete and look again.
	 */
	if (next == cqp->rq.head) {
		struct crdma_cq *ccq = to_crdma_cq(cqp->ib_qp.recv_cq);

		spin_lock_irqsave(&ccq->lock, flags);
		next = (cqp->rq.tail + CRDMA_WQ_WQE_SPARES) & cqp->rq.mask;
		spin_unlock_irqrestore(&ccq->lock, flags);
		if (next == cqp->rq.head)
			return NULL;
	}

	/* Post RWQE at the software producer tail */
	return cqp->rq.buf + (cqp->rq.tail << cqp->rq.wqe_size_log2);
}

static int crdma_post_recv(struct ib_qp *qp, const struct ib_recv_wr *wr,
			   const struct ib_recv_wr **bad_wr)
{
	struct crdma_qp *cqp = to_crdma_qp(qp);
	struct crdma_rwqe *rwqe;
	int ret = 0;
	unsigned long irq_flags;

	spin_lock_irqsave(&cqp->rq.lock, irq_flags);
	while(wr) {
		if (wr->num_sge > cqp->rq.max_sg) {
			crdma_warn("RQ work request SG entries too large %d\n",
				   wr->num_sge);
			*bad_wr = wr;
			ret = -EINVAL;
			break;
		}

		rwqe = get_rq_tail(cqp);
		if (!rwqe) {
			crdma_warn("RQ overflow\n");
			*bad_wr = wr;
			ret = -ENOMEM;
			break;
		}

		/*
		 * Build the RWQE making sure not to clear the software
		 * ownership word prior to all of the rest of the WQE
		 * being written.
		 */
		crdma_set_wqe_sge(&rwqe->sg[0], wr->num_sge, wr->sg_list);
		rwqe->ctrl.num_sge = wr->num_sge;
		rwqe->ctrl.next_srq_wqe_ndx = 0;
		cqp->rq.wrid_map[cqp->rq.tail] = wr->wr_id;
		wmb();

		rwqe->ctrl.ownership = 0;

		/*
		 * We maintain a sliding block of spare RWQE so that there
		 * is always more than one RWQE in software ownership, allowing
		 * the new RWQE to be added prior to updating the last
		 * RWQE in the sliding block to indicate software ownership.
		 */
		set_wqe_sw_ownership(&cqp->rq, cqp->rq.tail +
				     CRDMA_WQ_WQE_SPARES);
		cqp->rq.tail = (cqp->rq.tail + 1) & cqp->rq.mask;
		wr = wr->next;
	}
	spin_unlock_irqrestore(&cqp->rq.lock, irq_flags);

	return ret;

}

static void crdma_drain_rq(struct ib_qp *qp)
{
#ifdef CRDMA_DEBUG_FLAG
	crdma_info("crdma_drain_rq \n");
#endif
	return;
}

#if (VER_NON_RHEL_OR_KYL_GE(5,3) || VER_RHEL_GE(8,0) || VER_KYL_GE(10,3))
static int crdma_create_cq(struct ib_cq *cq, const struct ib_cq_init_attr *attr,
				  struct ib_udata *udata)
{
	struct crdma_ibdev *dev = to_crdma_ibdev(cq->device);
	struct crdma_cq *ccq = container_of(cq, struct crdma_cq, ib_cq);
	struct crdma_cqe *cqe;
	unsigned int num_cqe = attr->cqe;
	int comp_vector = attr->comp_vector;
	int err;
	int i;

	if (num_cqe < 1 || num_cqe > dev->cap.ib.max_cqe - 1) {
		crdma_warn("Too many CQE requested %d\n", num_cqe);
		return -EINVAL;
	}

	spin_lock_init(&ccq->lock);
	ccq->num_cqe = roundup_pow_of_two(num_cqe + 1);
	ccq->ib_cq.cqe = ccq->num_cqe - 1;

#ifdef CRDMA_DEBUG_FLAG
	crdma_info("Rounded up CQE count %d\n", ccq->num_cqe);
#endif

	/* Allocate resource index for the CQ control object */
	if (crdma_alloc_bitmap_index(&dev->cq_map, &ccq->cqn)) {
		crdma_warn("No CQ index available\n");
		err = -ENOMEM;
		goto free_mem;
	}

	/* Kernel allocates CQ memory, user contexts will mmap it */
	ccq->mem = crdma_alloc_hw_queue(dev,
				ccq->num_cqe * dev->cap.cqe_size);
	if (IS_ERR(ccq->mem)) {
		crdma_dev_err(dev, "Unable to allocate CQ HW queue\n");
		err = -ENOMEM;
		goto free_cq;
	}

	/*
	 * Hardware CQE ownership is initially indicated by 0, and alternates
	 * between 1 and 0 for each reuse of the CQE. Set kernel virtual
	 * address and initialize to indicate invalid CQE.
	 */
	ccq->cqe_buf = sg_virt(ccq->mem->alloc);
	for (i = 0, cqe = ccq->cqe_buf; i < ccq->num_cqe; i++, cqe++)
		cqe->owner = 0;

	/*
	 * We are currently just allocating a page for each CQ
	 * for the consumer state mailbox. We should modify this later to
	 * have multiple CQ mailboxes for the same context share pages
	 * to reduce overhead.
	 */
	ccq->ci_mbox = dma_alloc_coherent(&dev->nfp_info->pdev->dev,
			PAGE_SIZE, &ccq->ci_mbox_paddr, GFP_KERNEL);
	if (!ccq->ci_mbox) {
		crdma_warn("ci_mbox allocation failed\n");
		err = -ENOMEM;
		goto free_queue_mem;
	}
	ccq->ci_mbox->ci = 0;
	ccq->ci_mbox->last_db_state = 0;
	wmb();

	/* Assign CQ to MSI-X EQ based on completion vector */
	ccq->eq_num = dev->eq_table.num_eq > 1 ? 1 + comp_vector %
			(dev->eq_table.num_eq - 1) : 0;
	dev->cq_table[ccq->cqn] = ccq;

	if (udata) {
		struct crdma_ucontext *crdma_uctxt = rdma_udata_to_drv_context(
				udata, struct crdma_ucontext, ib_uctxt);
		struct crdma_ib_create_cq_resp resp;

		err = crdma_cq_create_cmd(dev, ccq, &crdma_uctxt->uar);
		if (err) {
			crdma_err("Microcode error creating CQ, %d\n", err);
			goto cmd_fail;
		}
		resp.cq_base_addr = sg_dma_address(ccq->mem->alloc);
		resp.cq_size = ccq->mem->tot_len;
		resp.ci_mbox_base_addr = ccq->ci_mbox_paddr;
		resp.ci_mbox_size = PAGE_SIZE;
		resp.cqn = ccq->cqn;
		resp.num_cqe = ccq->num_cqe;

		err = ib_copy_to_udata(udata, &resp, sizeof(resp));
		if (err) {
			crdma_warn("Copy of UDATA failed, %d\n", err);
			goto cq_destroy;
		}

		err = crdma_add_mmap_req(crdma_uctxt, resp.cq_base_addr,
				ccq->mem->tot_len);
		if (err) {
			crdma_warn("Failed to add pending mmap, %d\n", err);
			goto cq_destroy;
		}
		err = crdma_add_mmap_req(crdma_uctxt, resp.ci_mbox_base_addr,
				PAGE_SIZE);
		if (err) {
			crdma_warn("Failed to add mbox pending mmap, %d\n",
					err);
			crdma_remove_mmap_req(crdma_uctxt, resp.cq_base_addr,
					ccq->mem->tot_len);
			goto cq_destroy;
		}
	} else {
		err = crdma_cq_create_cmd(dev, ccq, &dev->priv_uar);
		if (err) {
			crdma_err("Microcode error creating CQ, %d\n", err);
			goto cmd_fail;
		}
		ccq->mask = ccq->num_cqe - 1;
		ccq->arm_seqn = 1;
		while ((1 << ccq->num_cqe_log2) < ccq->num_cqe)
			ccq->num_cqe_log2++;
	}

	atomic_set(&ccq->ref_cnt, 1);
	init_completion(&ccq->free);

	return 0;

cq_destroy:
	crdma_cq_destroy_cmd(dev, ccq);
cmd_fail:
	dev->cq_table[ccq->cqn] = NULL;
	dma_free_coherent(&dev->nfp_info->pdev->dev, PAGE_SIZE,
			ccq->ci_mbox, ccq->ci_mbox_paddr);
free_queue_mem:
	crdma_free_hw_queue(dev, ccq->mem);
free_cq:
	crdma_free_bitmap_index(&dev->cq_map, ccq->cqn);
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
	struct crdma_cq *ccq;
	struct crdma_cqe *cqe;
	unsigned int num_cqe = attr->cqe;
	int comp_vector = attr->comp_vector;
	int err;
	int i;

	if (num_cqe < 1 || num_cqe > dev->cap.ib.max_cqe - 1) {
		crdma_info("Too many CQE requested %d\n", num_cqe);
		return ERR_PTR(-EINVAL);
	}

	ccq = kzalloc(sizeof(*ccq), GFP_KERNEL);
	if (!ccq)
		return ERR_PTR(-ENOMEM);

	spin_lock_init(&ccq->lock);
	ccq->num_cqe = roundup_pow_of_two(num_cqe + 1);
	ccq->ib_cq.cqe = ccq->num_cqe - 1;

#ifdef CRDMA_DEBUG_FLAG
	crdma_info("Rounded up CQE count %d\n", ccq->num_cqe);
#endif

	/* Allocate resource index for the CQ control object */
	if (crdma_alloc_bitmap_index(&dev->cq_map, &ccq->cqn)) {
		crdma_warn("No CQ index available\n");
		err = -ENOMEM;
		goto free_mem;
	}

	/* Kernel allocates CQ memory, user contexts will mmap it */
	ccq->mem = crdma_alloc_hw_queue(dev,
				ccq->num_cqe * dev->cap.cqe_size);
	if (IS_ERR(ccq->mem)) {
		crdma_dev_err(dev, "Unable to allocate CQ HW queue\n");
		err = -ENOMEM;
		goto free_cq;
	}

	/*
	 * Hardware CQE ownership is initially indicated by 0, and alternates
	 * between 1 and 0 for each reuse of the CQE. Set kernel virtual
	 * address and initialize to indicate invalid CQE.
	 */
	ccq->cqe_buf = sg_virt(ccq->mem->alloc);
	for (i = 0, cqe = ccq->cqe_buf; i < ccq->num_cqe; i++, cqe++)
		cqe->owner = 0;

	/*
	 * We are currently just allocating a page for each CQ
	 * for the consumer state mailbox. We should modify this later to
	 * have multiple CQ mailboxes for the same context share pages
	 * to reduce overhead.
	 */
	ccq->ci_mbox = dma_alloc_coherent(&dev->nfp_info->pdev->dev,
			PAGE_SIZE, &ccq->ci_mbox_paddr, GFP_KERNEL);
	if (!ccq->ci_mbox) {
		crdma_warn("ci_mbox allocation failed\n");
		err = -ENOMEM;
		goto free_queue_mem;
	}
	ccq->ci_mbox->ci = 0;
	ccq->ci_mbox->last_db_state = 0;
	wmb();

	/* Assign CQ to MSI-X EQ based on completion vector */
	ccq->eq_num = dev->eq_table.num_eq > 1 ? 1 + comp_vector %
			(dev->eq_table.num_eq - 1) : 0;
	dev->cq_table[ccq->cqn] = ccq;

	if (ib_uctxt) {
		struct crdma_ucontext *crdma_uctxt = to_crdma_uctxt(ib_uctxt);
		struct crdma_ib_create_cq_resp resp;

		err = crdma_cq_create_cmd(dev, ccq, &crdma_uctxt->uar);
		if (err) {
			crdma_err("Microcode error creating CQ, %d\n", err);
			goto cmd_fail;
		}
		resp.cq_base_addr = sg_dma_address(ccq->mem->alloc);
		resp.cq_size = ccq->mem->tot_len;
		resp.ci_mbox_base_addr = ccq->ci_mbox_paddr;
		resp.ci_mbox_size = PAGE_SIZE;
		resp.cqn = ccq->cqn;
		resp.num_cqe = ccq->num_cqe;

		err = ib_copy_to_udata(udata, &resp, sizeof(resp));
		if (err) {
			crdma_warn("Copy of UDATA failed, %d\n", err);
			goto cq_destroy;
		}

		err = crdma_add_mmap_req(crdma_uctxt, resp.cq_base_addr,
				ccq->mem->tot_len);
		if (err) {
			crdma_warn("Failed to add pending mmap, %d\n", err);
			goto cq_destroy;
		}
		err = crdma_add_mmap_req(crdma_uctxt, resp.ci_mbox_base_addr,
				PAGE_SIZE);
		if (err) {
			crdma_warn("Failed to add mbox pending mmap, %d\n",
					err);
			crdma_remove_mmap_req(crdma_uctxt, resp.cq_base_addr,
					ccq->mem->tot_len);
			goto cq_destroy;
		}
	} else {
		err = crdma_cq_create_cmd(dev, ccq, &dev->priv_uar);
		if (err) {
			crdma_warn("Microcode error creating CQ, %d\n", err);
			goto cmd_fail;
		}
		ccq->mask = ccq->num_cqe - 1;
		ccq->arm_seqn = 1;
		while ((1 << ccq->num_cqe_log2) < ccq->num_cqe)
			ccq->num_cqe_log2++;
	}

	atomic_set(&ccq->ref_cnt, 1);
	init_completion(&ccq->free);

	return &ccq->ib_cq;

cq_destroy:
	crdma_cq_destroy_cmd(dev, ccq);
cmd_fail:
	dev->cq_table[ccq->cqn] = NULL;
	dma_free_coherent(&dev->nfp_info->pdev->dev, PAGE_SIZE,
			ccq->ci_mbox, ccq->ci_mbox_paddr);
free_queue_mem:
	crdma_free_hw_queue(dev, ccq->mem);
free_cq:
	crdma_free_bitmap_index(&dev->cq_map, ccq->cqn);
free_mem:
	kfree(ccq);

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

#if (VER_NON_RHEL_OR_KYL_GE(5,8) || VER_RHEL_GE(8,0) || VER_KYL_GE(10,4))
static int crdma_destroy_cq(struct ib_cq *cq, struct ib_udata *udata)
{
        struct crdma_ibdev *dev = to_crdma_ibdev(cq->device);
        struct crdma_cq *ccq = to_crdma_cq(cq);
	int err;

        err = crdma_cq_destroy_cmd(dev, ccq);
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
                synchronize_irq(dev->eq_table.eq[ccq->eq_num].vector);

        dev->cq_table[ccq->cqn] = NULL;

        if (atomic_dec_and_test(&ccq->ref_cnt))
                complete(&ccq->free);
        wait_for_completion(&ccq->free);

        dma_free_coherent(&dev->nfp_info->pdev->dev, PAGE_SIZE,
                        ccq->ci_mbox, ccq->ci_mbox_paddr);
        crdma_free_hw_queue(dev, ccq->mem);
        crdma_free_bitmap_index(&dev->cq_map, ccq->cqn);

        return 0;
}
#elif (VER_NON_KYL_GE(5,3) || VER_KYL_GE(10,3))
static void crdma_destroy_cq(struct ib_cq *cq, struct ib_udata *udata)
{
        struct crdma_ibdev *dev = to_crdma_ibdev(cq->device);
        struct crdma_cq *ccq = to_crdma_cq(cq);
	int err;

        err = crdma_cq_destroy_cmd(dev, ccq);
        if (err) {
                /*
                 * TODO: Determine best course of action here, if we
                 * ignore and continue we can not free the resource
                 * because microcode will believe it is still in use.
                 */
                crdma_warn("Microcode destroy CQ command failed\n");
                return;
        }

        if (dev->have_interrupts)
                synchronize_irq(dev->eq_table.eq[ccq->eq_num].vector);

        dev->cq_table[ccq->cqn] = NULL;

        if (atomic_dec_and_test(&ccq->ref_cnt))
                complete(&ccq->free);
        wait_for_completion(&ccq->free);

        dma_free_coherent(&dev->nfp_info->pdev->dev, PAGE_SIZE,
                        ccq->ci_mbox, ccq->ci_mbox_paddr);
        crdma_free_hw_queue(dev, ccq->mem);
        crdma_free_bitmap_index(&dev->cq_map, ccq->cqn);

	return;
}
#elif VER_KERN_GE(5,2)
static int crdma_destroy_cq(struct ib_cq *cq, struct ib_udata *udata)
{
        struct crdma_ibdev *dev = to_crdma_ibdev(cq->device);
        struct crdma_cq *ccq = to_crdma_cq(cq);
	int err;

        err = crdma_cq_destroy_cmd(dev, ccq);
        if (err) {
                /*
                 * TODO: Determine best course of action here, if we
                 * ignore and continue we can not free the resource
                 * because microcode will believe it is still in use.
                 */
                crdma_warn("Microcode destroy CQ command failed\n");
                kfree(ccq);
                return -EINVAL;
        }

        if (dev->have_interrupts)
                synchronize_irq(dev->eq_table.eq[ccq->eq_num].vector);

        dev->cq_table[ccq->cqn] = NULL;

        if (atomic_dec_and_test(&ccq->ref_cnt))
                complete(&ccq->free);
        wait_for_completion(&ccq->free);

        dma_free_coherent(&dev->nfp_info->pdev->dev, PAGE_SIZE,
                        ccq->ci_mbox, ccq->ci_mbox_paddr);
        crdma_free_hw_queue(dev, ccq->mem);
        crdma_free_bitmap_index(&dev->cq_map, ccq->cqn);

        kfree(ccq);

        return 0;
}
#else
static int crdma_destroy_cq(struct ib_cq *cq)
{
	struct crdma_ibdev *dev = to_crdma_ibdev(cq->device);
	struct crdma_cq *ccq = to_crdma_cq(cq);
	int err;

	err = crdma_cq_destroy_cmd(dev, ccq);
	if (err) {
		/*
		 * TODO: Determine best course of action here, if we
		 * ignore and continue we can not free the resource
		 * because microcode will believe it is still in use.
		 */
		crdma_warn("Microcode destroy CQ command failed\n");
		kfree(ccq);
		return -EINVAL;
	}

	if (dev->have_interrupts)
		synchronize_irq(dev->eq_table.eq[ccq->eq_num].vector);

	dev->cq_table[ccq->cqn] = NULL;

	if (atomic_dec_and_test(&ccq->ref_cnt))
		complete(&ccq->free);
	wait_for_completion(&ccq->free);

	dma_free_coherent(&dev->nfp_info->pdev->dev, PAGE_SIZE,
			ccq->ci_mbox, ccq->ci_mbox_paddr);
	crdma_free_hw_queue(dev, ccq->mem);
	crdma_free_bitmap_index(&dev->cq_map, ccq->cqn);

	kfree(ccq);

	return 0;
}
#endif

static int crdma_resize_cq(struct ib_cq *ibcq, int num_cqe,
			struct ib_udata *udata)
{
	struct crdma_cq *ccq = to_crdma_cq(ibcq);
	struct crdma_ibdev *dev = to_crdma_ibdev(ibcq->device);
	struct crdma_mem *newmem;
	struct crdma_cqe *newcqe;
	struct crdma_cqe *tmpcqe;
	int oldnum,i;
	int ret = 0;

	/* We don't downsize... */
	if (num_cqe <= ibcq->cqe)
		return 0;

	if (num_cqe < 1 || num_cqe > dev->cap.ib.max_cqe - 1) {
		crdma_warn("Too many CQE requested %d\n", num_cqe);
		return -EINVAL;
	}

	num_cqe = roundup_pow_of_two(num_cqe + 1);
	oldnum = ccq->num_cqe;
	ccq->num_cqe = num_cqe - 1;
	if (num_cqe == ibcq->cqe + 1)
		return 0;
	spin_lock_irq(&ccq->lock);

	newmem = crdma_alloc_hw_queue(dev,
                                num_cqe * dev->cap.cqe_size);
        if (IS_ERR(newmem)) {
                crdma_dev_err(dev, "Unable to allocate CQ HW queue\n");
                ret = -ENOMEM;
                goto out;
        }

	newcqe = sg_virt(newmem->alloc);
	for (i = 0, tmpcqe = newcqe; i < ccq->num_cqe; i++, tmpcqe++)
                tmpcqe->owner = 0;
	memcpy(newcqe, ccq->cqe_buf,oldnum * sizeof(struct crdma_cqe));
	crdma_free_hw_queue(dev, ccq->mem);
	ccq->mem = newmem;
	ccq->cqe_buf = newcqe;
	ccq->num_cqe_log2 = ilog2(num_cqe);
	ibcq->cqe = num_cqe -1;

	ret = crdma_cq_resize_cmd(dev, ccq);
	if (ret) {

		crdma_warn("Microcode resize CQ command failed\n");
		dma_free_coherent(&dev->nfp_info->pdev->dev, PAGE_SIZE,
			ccq->ci_mbox, ccq->ci_mbox_paddr);
		ret = -EINVAL;
		goto out;
	}
out:
	spin_unlock_irq(&ccq->lock);
	return ret;
}

static inline struct crdma_cqe *crdma_cq_head(struct crdma_cq *ccq)
{
	struct crdma_cqe *cqe = NULL;

	cqe = &ccq->cqe_buf[ccq->consumer_cnt & ccq->mask];

	/*
	 * Microcode alternates writing 1 or 0 in the CQE ownership
	 * bit every pass through the CQ memory, starting with writing
	 * a 1 on the first pass.
	 */
	if (!!(cqe->owner & CRDMA_CQE_OWNERSHIP_BIT) ==
			!!(ccq->consumer_cnt & (1 << ccq->num_cqe_log2)))
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
	struct crdma_cq	*ccq = to_crdma_cq(cq);
	struct crdma_cqe *cqe;
	struct crdma_qp *last_qp = NULL;
	unsigned long	flags;
	int polled = 0;
	int ret = 0;

	spin_lock_irqsave(&ccq->lock, flags);
	while (polled < num_entries) {
		cqe = crdma_cq_head(ccq);
		if (!cqe)
			break;
		/*
		 * If we already have pulled at least one CQE, update
		 * the CQ consumer index so that a false overflow
		 * will not be detected by microcode.
		 */
		if (polled)
			ccq->ci_mbox->ci = cpu_to_le32(ccq->consumer_cnt &
					CRDMA_CQ_MBOX_CONSUMER_NDX_MASK);

		ccq->consumer_cnt++;

#ifdef CRDMA_DETAIL_INFO_DEBUG_FLAG
		print_hex_dump(KERN_DEBUG, "CQE:", DUMP_PREFIX_OFFSET, 8, 1,
			cqe, 32, 0);
#endif
		ret = crdma_process_cqe(ccq, cqe, &last_qp, &wc[polled]);
		if (ret == 0)
			polled++;
		else if (ret < 0)
			break;
	}

	/* Update the state of the consumer index shared with microcode */
	ccq->ci_mbox->ci = cpu_to_le32(ccq->consumer_cnt &
					CRDMA_CQ_MBOX_CONSUMER_NDX_MASK);
	spin_unlock_irqrestore(&ccq->lock, flags);

	return ret < 0 ? ret : polled;
}

static int crdma_req_notify_cq(struct ib_cq *cq, enum ib_cq_notify_flags flags)
{
	struct crdma_ibdev *dev = to_crdma_ibdev(cq->device);
	struct crdma_cq *ccq = to_crdma_cq(cq);
	u32 arm;
	u32 db;

	arm = (ccq->arm_seqn << CRDMA_DB_CQ_SEQ_SHIFT) |
		((flags & IB_CQ_SOLICITED_MASK) == IB_CQ_SOLICITED ?
			0 : CRDMA_DB_CQ_ARM_ANY_BIT) |
		(ccq->cqn & CRDMA_DB_CQN_MASK);
	db = cpu_to_le32(arm);
	ccq->ci_mbox->last_db_state = 0;
	wmb();
	crdma_cq_ring_db32(dev, db);
	return 0;
}

static struct ib_mr *crdma_get_dma_mr(struct ib_pd *pd, int access_flags)
{
	struct crdma_ibdev *dev = to_crdma_ibdev(pd->device);
	struct crdma_mr *cmr;
	int err;

	cmr = kzalloc(sizeof(*cmr), GFP_KERNEL);
	if (!cmr) {
		crdma_info("No memory for MR object\n");
		return ERR_PTR(-ENOMEM);
	}

	if (crdma_alloc_bitmap_index(&dev->mpt_map, &cmr->mpt_index)) {
		err = -ENOMEM;
		goto free_mem;
	}

	cmr->umem = NULL;
	cmr->pdn = to_crdma_pd(pd)->pd_index;
	cmr->io_vaddr = 0;
	cmr->len = ~0ull;
	cmr->access = access_flags;
	cmr->page_shift = 0;
	cmr->mpt_order = 0;

	cmr->key = cmr->mpt_index << 8;
	cmr->ib_mr.rkey = cmr->ib_mr.lkey = cmr->key;

	cmr->type = CRDMA_MR_TYPE_DMA;

	if (crdma_init_mpt(dev, cmr, 0, 0)) {
		crdma_err("init_mpt failed\n");
		err = -ENOMEM;
		goto free_mpt;
	}

	return &cmr->ib_mr;

free_mpt:
	crdma_free_bitmap_index(&dev->mpt_map, cmr->mpt_index);
free_mem:
	kfree(cmr);
	return ERR_PTR(err);
}

static struct ib_mr *crdma_reg_user_mr(struct ib_pd *pd, u64 start,
			u64 length, u64 virt_addr, int access_flags,
			struct ib_udata *udata)
{
	struct crdma_ibdev *dev = to_crdma_ibdev(pd->device);
	struct crdma_mr *cmr;
	int count, num_comp, shift, order, log2_page_sz;
	int err;

	cmr = kzalloc(sizeof(*cmr), GFP_KERNEL);
	if (!cmr) {
		crdma_warn("No memory for MR object\n");
		return ERR_PTR(-ENOMEM);
	}

	if (crdma_alloc_bitmap_index(&dev->mpt_map, &cmr->mpt_index)) {
		err = -ENOMEM;
		goto free_mem;
	}

#if (VER_NON_RHEL_GE(5,6))
	cmr->umem = ib_umem_get(pd->device, start, length, access_flags);
#elif (VER_NON_RHEL_OR_KYL_GE(5,5) || VER_RHEL_GE(8,0) || VER_KYL_GE(10,4))
	cmr->umem = ib_umem_get(udata, start, length, access_flags);
#elif (VER_NON_RHEL_OR_KYL_GE(5,1) || VER_KYL_GE(10,3))
	cmr->umem = ib_umem_get(udata, start, length, access_flags, 0);
#else
	cmr->umem = ib_umem_get(pd->uobject->context, start, length,
			access_flags, 0);
#endif
	if (IS_ERR(cmr->umem)) {
		err = PTR_ERR(cmr->umem);
		crdma_warn("ib_umem_get() failed %d\n", err);
		goto free_mpt;
	}

#if (VER_NON_RHEL_OR_KYL_GE(5,3) || VER_RHEL_GE(8,0) || VER_KYL_GE(10,3))
	log2_page_sz = PAGE_SHIFT;
#else
	log2_page_sz = cmr->umem->page_shift;
#endif
#ifdef CRDMA_DETAIL_INFO_DEBUG_FLAG
	crdma_dev_info(dev, "User Memory Page Size %d\n", log2_page_sz);
#endif
	/*
	 * Find the largest compound page size that can be used
	 * for the physical page list, limiting to the supported
	 * microcode maximum.
	 */
	crdma_compound_order(cmr->umem, start, &count, &num_comp,
			&shift, &order);
#ifdef CRDMA_DETAIL_INFO_DEBUG_FLAG
	crdma_dev_info(dev, "User Memory Pages                 %d\n", count);
	crdma_dev_info(dev, "User Memory Compound Pages        %d\n", num_comp);
	crdma_dev_info(dev, "User Memory Compound Page Shift   %d\n", shift);
	crdma_dev_info(dev, "User Memory Compound Page Order   %d\n", order);
#endif
	if (order + log2_page_sz > CRDMA_MTT_MAX_PAGESIZE_LOG2) {
		num_comp <<= order  + log2_page_sz -
				CRDMA_MTT_MAX_PAGESIZE_LOG2;
		order -=  order + log2_page_sz -
				CRDMA_MTT_MAX_PAGESIZE_LOG2;
	}
#ifdef CRDMA_DETAIL_INFO_DEBUG_FLAG
	crdma_dev_info(dev, "Adjusted number of compound pages %d\n", num_comp);
	crdma_dev_info(dev, "Adjusted compound order           %d\n", order);
#endif
	cmr->pdn = to_crdma_pd(pd)->pd_index;
	cmr->io_vaddr = virt_addr;
	cmr->len = length;
	cmr->access = access_flags;
#if (VER_NON_RHEL_OR_KYL_GE(5,3) || VER_RHEL_GE(8,0) || VER_KYL_GE(10,3))
	cmr->page_shift = PAGE_SHIFT;
#else
	cmr->page_shift = cmr->umem->page_shift;
#endif
	cmr->mpt_order = order;

	cmr->key = cmr->mpt_index << 8;
	cmr->ib_mr.rkey = cmr->ib_mr.lkey = cmr->key;
	cmr->type = CRDMA_MR_TYPE_DEFAULT;

	if (crdma_init_mpt(dev, cmr, num_comp, order)) {
		crdma_err("init_mpt failed\n");
		err = -ENOMEM;
		goto release_umem;
	}

	return &cmr->ib_mr;

release_umem:
	ib_umem_release(cmr->umem);
free_mpt:
	crdma_free_bitmap_index(&dev->mpt_map, cmr->mpt_index);
free_mem:
	kfree(cmr);
	return ERR_PTR(err);
}

#if (VER_NON_RHEL_OR_KYL_GE(5,2) || VER_RHEL_GE(8,0) || VER_KYL_GE(10,3))
static int crdma_dereg_mr(struct ib_mr *mr, struct ib_udata *udata)
#else
static int crdma_dereg_mr(struct ib_mr *mr)
#endif
{
	struct crdma_ibdev *dev = to_crdma_ibdev(mr->device);
	struct crdma_mr *cmr = to_crdma_mr(mr);

	crdma_cleanup_mpt(dev, cmr);
	crdma_free_bitmap_index(&dev->mpt_map, cmr->mpt_index);

	if (cmr->umem)
		ib_umem_release(cmr->umem);

	kfree(cmr);
	return 0;
}

#if ((VER_NON_KYL_GE(5,2) && VER_NON_KYL_LT(5,9)) || VER_KYL_GE(10,3))
static struct ib_mr *crdma_alloc_mr(struct ib_pd *pd, enum ib_mr_type type,
		     u32 max_num_sg, struct ib_udata *udata)
{
	struct crdma_ibdev *cdev = to_crdma_ibdev(pd->device);
	struct crdma_mr *cmr;
	int err;

	if (type != IB_MR_TYPE_MEM_REG) {
		crdma_info("MR type 0x%x not supported", type);
		return ERR_PTR(-EINVAL);
	}

	if (max_num_sg > cdev->cap.ib.max_fast_reg_page_list_len) {
		crdma_err("max num sg (0x%x) exceeded dev cap (0x%x)\n",
		    max_num_sg, cdev->cap.ib.max_fast_reg_page_list_len);
		return ERR_PTR(-EINVAL);
	}

	cmr = kzalloc(sizeof(*cmr), GFP_KERNEL);
	if (!cmr) {
		crdma_err("No memory for MR object\n");
		return ERR_PTR(-ENOMEM);
	}

	cmr->num_mtt = max_num_sg;
	if (cmr->num_mtt) {
		cmr->base_mtt = crdma_alloc_bitmap_area(&cdev->mtt_map,
						cmr->num_mtt);
		if (cmr->base_mtt < 0) {
			err = -ENOMEM;
			goto free_mem;
		}
	}

	if (crdma_alloc_bitmap_index(&cdev->mpt_map, &cmr->mpt_index)) {
		err = -ENOMEM;
		goto free_mtt;
	}

	cmr->pdn = to_crdma_pd(pd)->pd_index;
	cmr->access = 0;
	cmr->io_vaddr = 0;
	cmr->len = 0;
	cmr->mpt_order = 0;
	cmr->page_shift = PAGE_SHIFT;
	cmr->key = cmr->mpt_index << 8;
	cmr->ib_mr.rkey = cmr->key;
	cmr->ib_mr.lkey = cmr->key;
	cmr->umem = NULL;
	cmr->type = CRDMA_MR_TYPE_FRMR;

	return &cmr->ib_mr;

free_mtt:
	if (cmr->num_mtt)
		crdma_free_bitmap_area(&cdev->mtt_map, cmr->base_mtt,
						cmr->num_mtt);
free_mem:
	kfree(cmr);
	return ERR_PTR(err);
}
#else
static struct ib_mr *crdma_alloc_mr(struct ib_pd *pd,
			enum ib_mr_type type, u32 max_num_sg)
{
	struct crdma_ibdev *cdev = to_crdma_ibdev(pd->device);
	struct crdma_mr *cmr;
	int err;

	if (type != IB_MR_TYPE_MEM_REG) {
		crdma_info("MR type 0x%x not supported", type);
		return ERR_PTR(-EINVAL);
	}

	if (max_num_sg > cdev->cap.ib.max_fast_reg_page_list_len) {
		crdma_err("max num sg (0x%x) exceeded dev cap (0x%x)\n",
		    max_num_sg, cdev->cap.ib.max_fast_reg_page_list_len);
		return ERR_PTR(-EINVAL);
	}

	cmr = kzalloc(sizeof(*cmr), GFP_KERNEL);
	if (!cmr) {
		crdma_err("No memory for MR object\n");
		return ERR_PTR(-ENOMEM);
	}

	cmr->num_mtt = max_num_sg;
	if (cmr->num_mtt) {
		cmr->base_mtt = crdma_alloc_bitmap_area(&cdev->mtt_map,
						cmr->num_mtt);
		if (cmr->base_mtt < 0) {
			err = -ENOMEM;
			goto free_mem;
		}
	}

	if (crdma_alloc_bitmap_index(&cdev->mpt_map, &cmr->mpt_index)) {
		err = -ENOMEM;
		goto free_mtt;
	}

	cmr->pdn = to_crdma_pd(pd)->pd_index;
	cmr->access = 0;
	cmr->io_vaddr = 0;
	cmr->len = 0;
	cmr->mpt_order = 0;
	cmr->page_shift = PAGE_SHIFT;
	cmr->key = cmr->mpt_index << 8;
	cmr->ib_mr.rkey = cmr->key;
	cmr->ib_mr.lkey = cmr->key;
	cmr->umem = NULL;
	cmr->type = CRDMA_MR_TYPE_FRMR;

	return &cmr->ib_mr;

free_mtt:
	if (cmr->num_mtt)
		crdma_free_bitmap_area(&cdev->mtt_map, cmr->base_mtt,
						cmr->num_mtt);
free_mem:
	kfree(cmr);
	return ERR_PTR(err);
}
#endif

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

static int crdma_set_page(struct ib_mr *mr, u64 addr)
{
	struct crdma_mr *cmr = to_crdma_mr(mr);
	unsigned long mask = (1 << (cmr->mpt_order + PAGE_SHIFT)) - 1;
	struct crdma_mtt_write_param *mtt_param;

	if (unlikely(cmr->npages == cmr->num_mtt))
		return -ENOMEM;

	mtt_param = cmr->buf;
	mtt_param->entry[cmr->npages].paddr_h = cpu_to_le32(addr >> 32);
	mtt_param->entry[cmr->npages].paddr_l =	cpu_to_le32(addr & ~mask);

	cmr->npages++;
	return 0;
}

static int crdma_map_mr_sg(struct ib_mr *mr, struct scatterlist *sg,
			   int sg_nents, unsigned int *sg_offset)
{
	struct crdma_mr *cmr = to_crdma_mr(mr);
	struct crdma_ibdev *cdev = to_crdma_ibdev(mr->device);
	unsigned int page_size = mr->page_size;
	long order = get_order(page_size);
	struct crdma_cmd_mbox in_mbox;
	int nents;
	int ret;

	if (crdma_init_mailbox(cdev, &in_mbox))
		return -ENOMEM;

	cmr->buf = in_mbox.buf;
	cmr->mpt_order = order;
	cmr->npages = 0;
	nents = ib_sg_to_pages(mr, sg, sg_nents, sg_offset, crdma_set_page);

	ret = __crdma_mtt_write(cdev, cmr->base_mtt, cmr->npages, &in_mbox);
	if (ret) {
		crdma_warn("MTT_WRITE failed %d\n", ret);
		goto free_mbox;
	}

	cmr->access = IB_ACCESS_LOCAL_WRITE|IB_ACCESS_REMOTE_WRITE
		|IB_ACCESS_REMOTE_READ|IB_ACCESS_REMOTE_ATOMIC;
	cmr->io_vaddr = mr->iova & ~((u64)page_size - 1);
	cmr->len = cmr->npages * page_size;
	cmr->page_shift = PAGE_SHIFT + order;

	if(crdma_mpt_create_cmd(cdev, cmr)) {
		crdma_warn("crdma_mpt_create_cmd failed\n");
		ret = -ENOMEM;
		goto free_mbox;
	}
	ret = nents;

free_mbox:
	cmr->buf = NULL;
	crdma_cleanup_mailbox(cdev, &in_mbox);

	return ret;
}

#if (VER_NON_RHEL_GE(5,13) || RHEL_RELEASE_GE(8,365,0,0))
int crdma_process_mad(struct ib_device *ibdev, int mad_flags, u32 port,
                      const struct ib_wc *in_wc, const struct ib_grh *in_grh,
                      const struct ib_mad *in_mad, struct ib_mad *out_mad,
                      size_t *out_mad_size, u16 *out_mad_pkey_index)
{
#ifdef CRDMA_DETAIL_INFO_DEBUG_FLAG
	const struct ib_mad_hdr *in_mad_hdr = &in_mad->mad_hdr;

	crdma_info("Dump MAD information\n");
	crdma_info("base_version=0x%x mgmt_class=0x%x\n",
		in_mad_hdr->base_version, in_mad_hdr->mgmt_class);
	crdma_info("class_version=0x%x method=0x%x\n",
		in_mad_hdr->class_version, in_mad_hdr->method);
	crdma_info("status=0x%x class_specific=0x%x\n",
		in_mad_hdr->status, in_mad_hdr->class_specific);
	crdma_info("tid=0x%llx attr_id=0x%x\n",
		in_mad_hdr->tid, in_mad_hdr->attr_id);
	crdma_info("attr_mod=0x%x\n", in_mad_hdr->attr_mod);
#endif

       return IB_MAD_RESULT_SUCCESS;
}
#elif (VER_NON_RHEL_OR_KYL_GE(5,3) || VER_RHEL_GE(8,0) || VER_KYL_GE(10,3))
int crdma_process_mad(struct ib_device *ibdev, int mad_flags, u8 port,
                      const struct ib_wc *in_wc, const struct ib_grh *in_grh,
                      const struct ib_mad *in_mad, struct ib_mad *out_mad,
		      size_t *out_mad_size, u16 *out_mad_pkey_index)
{
#ifdef CRDMA_DETAIL_INFO_DEBUG_FLAG
	const struct ib_mad_hdr *in_mad_hdr = &in_mad->mad_hdr;

	crdma_info("Dump MAD information\n");
	crdma_info("base_version=0x%x mgmt_class=0x%x\n",
		in_mad_hdr->base_version, in_mad_hdr->mgmt_class);
	crdma_info("class_version=0x%x method=0x%x\n",
		in_mad_hdr->class_version, in_mad_hdr->method);
	crdma_info("status=0x%x class_specific=0x%x\n",
		in_mad_hdr->status, in_mad_hdr->class_specific);
	crdma_info("tid=0x%llx attr_id=0x%x\n",
		in_mad_hdr->tid, in_mad_hdr->attr_id);
	crdma_info("attr_mod=0x%x\n", in_mad_hdr->attr_mod);
#endif

       return IB_MAD_RESULT_SUCCESS;
}

#else
int crdma_process_mad(struct ib_device *ibdev, int mad_flags, u8 port,
                    const struct ib_wc *in_wc, const struct ib_grh *in_grh,
                    const struct ib_mad_hdr *in_mad_hdr, size_t in_mad_size,
                    struct ib_mad_hdr *out_mad_hdr, size_t *out_mad_size,
                    u16 *out_mad_pkey_index)
{
#ifdef CRDMA_DETAIL_INFO_DEBUG_FLAG
	crdma_info("Dump MAD information\n");
	crdma_info("base_version=0x%x mgmt_class=0x%x\n",
		in_mad_hdr->base_version, in_mad_hdr->mgmt_class);
	crdma_info("class_version=0x%x method=0x%x\n",
		in_mad_hdr->class_version, in_mad_hdr->method);
	crdma_info("status=0x%x class_specific=0x%x\n",
		in_mad_hdr->status, in_mad_hdr->class_specific);
	crdma_info("tid=0x%llx attr_id=0x%x\n",
		in_mad_hdr->tid, in_mad_hdr->attr_id);
	crdma_info("attr_mod=0x%x\n", in_mad_hdr->attr_mod);
#endif

       return IB_MAD_RESULT_SUCCESS;
}
#endif

#if (VER_NON_RHEL_OR_KYL_GE(5,3) || VER_RHEL_GE(8,0) || VER_KYL_GE(10,3))
static const struct ib_device_ops crdma_dev_ops = {
    .owner              = THIS_MODULE,
    .driver_id          = RDMA_DRIVER_CRDMA,
    .uverbs_abi_ver     = CRDMA_UVERBS_ABI_VERSION,

    .add_gid            = crdma_add_gid,
    .alloc_mr           = crdma_alloc_mr,
    .alloc_pd           = crdma_alloc_pd,
    .alloc_ucontext     = crdma_alloc_ucontext,
    .attach_mcast       = crdma_attach_mcast,
    .create_ah          = crdma_create_ah,
    .create_cq          = crdma_create_cq,
    .create_qp          = crdma_create_qp,
#if (VER_NON_RHEL_GE(5,11) || VER_RHEL_GE(8,0))
    .create_user_ah     = crdma_create_ah,
#endif
    .dealloc_pd         = crdma_dealloc_pd,
    .dealloc_ucontext   = crdma_dealloc_ucontext,
    .del_gid            = crdma_del_gid,
    .dereg_mr           = crdma_dereg_mr,
    .destroy_ah         = crdma_destroy_ah,
    .destroy_cq         = crdma_destroy_cq,
    .destroy_qp         = crdma_destroy_qp,
    .detach_mcast       = crdma_detach_mcast,
    .get_dev_fw_str     = crdma_get_dev_fw_str,
    .get_dma_mr         = crdma_get_dma_mr,
    .get_link_layer     = crdma_get_link_layer,
    .get_port_immutable = crdma_get_port_immutable,
    .map_mr_sg          = crdma_map_mr_sg,
    .mmap               = crdma_mmap,
    .modify_cq          = crdma_modify_cq,
    .modify_qp          = crdma_modify_qp,
    .poll_cq            = crdma_poll_cq,
    .post_recv          = crdma_post_recv,
    .post_send          = crdma_post_send,
    .query_ah           = crdma_query_ah,
    .query_device       = crdma_query_device,
    .query_gid          = crdma_query_gid,
    .query_pkey         = crdma_query_pkey,
    .query_port         = crdma_query_port,
    .query_qp           = crdma_query_qp,
    .reg_user_mr        = crdma_reg_user_mr,
    .req_notify_cq      = crdma_req_notify_cq,
    .resize_cq          = crdma_resize_cq,
    .process_mad        = crdma_process_mad,
    .drain_rq		 = crdma_drain_rq,

    INIT_RDMA_OBJ_SIZE(ib_pd, crdma_pd, ib_pd),
    INIT_RDMA_OBJ_SIZE(ib_cq, crdma_cq, ib_cq),
    INIT_RDMA_OBJ_SIZE(ib_ucontext, crdma_ucontext, ib_uctxt),
    INIT_RDMA_OBJ_SIZE(ib_ah, crdma_ah, ib_ah),
#if (VER_NON_RHEL_GE(5,15) || RHEL_RELEASE_GE(8,394,0,0))
    INIT_RDMA_OBJ_SIZE(ib_qp, crdma_qp, ib_qp),
#endif
};
#endif

int crdma_register_verbs(struct crdma_ibdev *dev)
{
	int ret;

	dev->ibdev.node_type = RDMA_NODE_IB_CA;
	memcpy(dev->ibdev.node_desc, CRDMA_IB_NODE_DESC,
			sizeof(CRDMA_IB_NODE_DESC));
	addrconf_addr_eui48((u8 *)&dev->ibdev.node_guid,
				dev->nfp_info->netdev->dev_addr);
	dev->ibdev.phys_port_cnt = dev->cap.n_ports;

	/* If more than one EQ, then EQ 0 is reserved for async events */
	dev->ibdev.num_comp_vectors = dev->eq_table.num_eq > 1 ?
				dev->eq_table.num_eq - 1 : 1;

	/* Currently do not support local DMA key */
	dev->ibdev.local_dma_lkey = 0;

#if !(VER_NON_RHEL_GE(5,11) || VER_RHEL_GE(8,5))
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
#endif
	dev->ibdev.dev.parent			= &dev->nfp_info->pdev->dev;

#if (VER_NON_RHEL_OR_KYL_GE(5,0) || VER_RHEL_GE(8,0) || VER_KYL_GE(10,3))
	ib_set_device_ops(&dev->ibdev, &crdma_dev_ops);
#else
	dev->ibdev.owner                = THIS_MODULE;
	dev->ibdev.driver_id            = RDMA_DRIVER_CRDMA;
	dev->ibdev.uverbs_abi_ver       = CRDMA_UVERBS_ABI_VERSION;
	strlcpy(dev->ibdev.name, "crdma%d", IB_DEVICE_NAME_MAX);

	dev->ibdev.add_gid		= crdma_add_gid;
	dev->ibdev.alloc_mr             = crdma_alloc_mr;
	dev->ibdev.alloc_pd             = crdma_alloc_pd;
	dev->ibdev.alloc_ucontext       = crdma_alloc_ucontext;
	dev->ibdev.attach_mcast         = crdma_attach_mcast;
	dev->ibdev.create_ah            = crdma_create_ah;
	dev->ibdev.create_cq            = crdma_create_cq;
	dev->ibdev.create_qp            = crdma_create_qp;
	dev->ibdev.dealloc_pd           = crdma_dealloc_pd;
	dev->ibdev.dealloc_ucontext     = crdma_dealloc_ucontext;
	dev->ibdev.del_gid		= crdma_del_gid;
	dev->ibdev.dereg_mr             = crdma_dereg_mr;
	dev->ibdev.destroy_ah           = crdma_destroy_ah;
	dev->ibdev.destroy_cq           = crdma_destroy_cq;
	dev->ibdev.destroy_qp           = crdma_destroy_qp;
	dev->ibdev.detach_mcast         = crdma_detach_mcast;
	dev->ibdev.get_dev_fw_str       = crdma_get_dev_fw_str;
	dev->ibdev.get_dma_mr           = crdma_get_dma_mr;
	dev->ibdev.get_link_layer       = crdma_get_link_layer;
#if !(VER_NON_RHEL_GE(5,1) || VER_RHEL_GE(8,0))
	dev->ibdev.get_netdev           = crdma_get_netdev;
#endif
	dev->ibdev.get_port_immutable   = crdma_get_port_immutable;
	dev->ibdev.map_mr_sg            = crdma_map_mr_sg;
	dev->ibdev.mmap                 = crdma_mmap;
	dev->ibdev.modify_cq            = crdma_modify_cq;
	dev->ibdev.modify_qp            = crdma_modify_qp;
	dev->ibdev.poll_cq              = crdma_poll_cq;
	dev->ibdev.post_recv            = crdma_post_recv;
	dev->ibdev.post_send            = crdma_post_send;
	dev->ibdev.query_ah             = crdma_query_ah;
	dev->ibdev.query_device         = crdma_query_device;
	dev->ibdev.query_gid            = crdma_query_gid;
	dev->ibdev.query_pkey           = crdma_query_pkey;
	dev->ibdev.query_port           = crdma_query_port;
	dev->ibdev.modify_port          = crdma_modify_port;
	dev->ibdev.query_qp             = crdma_query_qp;
	dev->ibdev.reg_user_mr          = crdma_reg_user_mr;
	dev->ibdev.req_notify_cq        = crdma_req_notify_cq;
	dev->ibdev.resize_cq            = crdma_resize_cq;
	dev->ibdev.process_mad          = crdma_process_mad;
	dev->ibdev.drain_rq		= crdma_drain_rq;
#endif

#if (VER_NON_RHEL_OR_KYL_GE(5,10) || VER_RHEL_GE(8,0) || VER_KYL_GE(10,4))
        ret = ib_register_device(&dev->ibdev, "crdma%d",
		&dev->nfp_info->pdev->dev);
#elif (VER_NON_RHEL_OR_KYL_GE(5,1) || VER_KYL_GE(10,3))
        ret = ib_register_device(&dev->ibdev, "crdma%d");
#elif (VER_NON_KYL_GE(4,20) || VER_KYL_GE(10,2))
	ret = ib_register_device(&dev->ibdev, "crdma%d", NULL);
#else
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
