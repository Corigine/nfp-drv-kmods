/*
 * Copyright (c) 2015, Netronome, Inc.  All rights reserved.
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

/*
 * crdma_ib.h - Provides Corigine RoCEv2 InfiniBand specific details.
 */
#ifndef CRDMA_IB_H
#define CRDMA_IB_H

#include <linux/compiler.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/idr.h>
#include <linux/radix-tree.h>

#include <rdma/ib_verbs.h>
#include <rdma/ib_umem.h>

#include "nfp_roce.h"
#include "crdma_abi.h"
#include "crdma_ucif.h"
#include "crdma_util.h"

#define CRDMA_IB_HCA_DRV_NAME		"crdma"
#define CRDMA_IB_NODE_DESC		"Corigine NFP RoCEv2 HCA"

/* Internal crdma provider ABI between user library and kernel driver */
#define CRDMA_UVERBS_ABI_VERSION	1

/*
   All debug flags are off by default,
   open these as you want in debugging mode.
   All debug codes will be removed when upstreamed into community.
*/
//#define CRDMA_DEBUG_FLAG
//#define CRDMA_DETAIL_INFO_DEBUG_FLAG

/*
 * Maximum limits placed on IB resources by the driver.
 */
enum {
	CRDMA_IB_MAX_PD			= 1 << 16,
	CRDMA_IB_MAX_AH			= 1 << 20,
	CRDMA_IB_MAX_PKEY_TABLE_SIZE	= 1,
	CRDMA_IB_MAX_GID_TABLE_SIZE	= 4,
	CRDMA_IB_MAX_MAC_TABLE_SIZE	= 8,
	CRDMA_IB_MAX_FAST_REG_PAGES     = 64
};

/*
 * Expect that something like these will be defined in ib_addr.h eventually.
 */
enum {
       RDMA_ROCE_V1_GID_TYPE           = 0,
       RDMA_ROCE_V2_GID_TYPE           = 1
};

/*
 * We further define GIDs as IPv4 encoded or v6 to tell microcode. Note
 * that both types indicate RoCEv2.
 */
enum {
       CRDMA_ROCE_V2_IPV4_GID_TYPE     = 1,
       CRDMA_ROCE_V2_IPV6_GID_TYPE     = 2
};

/*
 * Microcode supports a varying number of IB resources and parameters
 * for the HCA that are passed to the driver as part of the HCA initialization
 * sequence.
 */
struct crdma_hca_cap {
	/* Keep common IB core attributes directly in common struct */
	struct ib_device_attr	ib;

	/* Corigine specific limits and attributes */
	u64		build_id;
	u32		board_id;
	u16		uc_maj_rev;
	u16		uc_min_rev;
	u16		cmdif_abi_rev;
	u16		max_cmds_out;
	u32		uc_mhz_clock;
	int		n_ports;
	u8		opt_flags;
	int		bs_size_mb;
	u32		max_mpt;
	u32		max_mtt;
	int		vlan_table_size;
	int		smac_table_size;
	int		sgid_table_size;
	int		max_uar_pages;
	int		min_page_size;
	int		max_swqe_size;
	int		max_rwqe_size;
	int		max_srq_rwqe_size;
	int		rsvd_qp;
	int		cqe_size;
	int		max_eq;
	int		max_eqe;
	int		eqe_size;
	u16		max_inline_data;
};

enum {
	CRDMA_MAX_MSG_SIZE		= 0x80000000,
	CRDMA_EQ_ENTRIES_LOG2		= 11,

	/* MTT page sizes range expressed log2 values 4K to 16MB. */
	CRDMA_MTT_MIN_PAGESIZE_LOG2	= 12,
	CRDMA_MTT_MAX_PAGESIZE_LOG2	= 24,
	CRDMA_MTT_MAX_PAGESIZE          = 1 << CRDMA_MTT_MAX_PAGESIZE_LOG2
};

struct crdma_mem;

struct crdma_uar {
	int	index;
	void __iomem *map;
};

/*
 * The following provide the crdma specific data associated with
 * the verb allocated objects.
 */
struct crdma_ucontext {
	struct ib_ucontext	ib_uctxt;
	struct crdma_uar	uar;		/* User Access Region */

	/* Memory pending mmap into the user contexts address space */
	struct list_head	mmap_pending;
	struct mutex		mmap_pending_lock;
};

struct crdma_pd {
	struct ib_pd		ib_pd;
	u32			pd_index;	/* Unique identifier */
};

struct crdma_ah {
	struct ib_ah            ib_ah;
	struct crdma_av         av;
	u8                      smac[6];
};

struct crdma_cq {
	struct ib_cq             ib_cq;
	spinlock_t               lock;

	u32                      cqn;            /* Control object index */
	atomic_t                 ref_cnt;
	u32                      eq_num;         /* EQ used for notifications */
	struct completion        free;

	struct crdma_mem        *mem;            /* CQ memory */
	struct crdma_cqe        *cqe_buf;        /* vaddr for kernel of above */

	int                      arm_seqn;       /* Rolling sequence number */
	u32                      num_cqe;        /* Power of 2 */
	u32                      num_cqe_log2;   /* Above as a log2 value */
	u32                      consumer_cnt;   /* S/W consumer counter */
	u32                      mask;           /* CQE count -> CQE index */

	/* Event and time interrupt moderation values */
	u16                      event_mod;
	u16                      time_mod;

	/*
	 * Software maintains the state of the CQ at the time of the
	 * last doorbell, providing the physical addresses of these
	 * values to microcode.
	 */
	struct crdma_ci_mbox	*ci_mbox;
	dma_addr_t               ci_mbox_paddr;
};

struct crdma_srq {
	struct ib_srq		ib_srq;
	u32			srq_index;	/* Assigned control object */
};

struct crdma_hw_workq {
	spinlock_t              lock;
	void                    *buf;
	u64                     *wrid_map;      /* WQE index to WRID map */
	u32                     wqe_cnt;        /* Rounded up to power of 2 */
	u32                     wqe_size;       /* Rounded up to power of 2 */
	u32                     wqe_size_log2;  /* Above log 2 value */
	u32                     max_sg;         /* Maximum SG entries */
	u32                     head;           /* SW Consumer */
	u32                     tail;           /* SW Producer */
	u32                     length;         /* Queue size in bytes */
	u32                     mask;           /* Num WQE - 1 */
};

struct crdma_qp {
	struct ib_qp		ib_qp;		/* IB QPN stored here */
	struct mutex		mutex;

	u32			        qp_index;  /* Microcode control object */

	/*
	* If this QP is a GSI QP (i.e. QP1), then qp1_port indicates
	* the physical port the QP is associated with. Microcode reserves QP
	* control objects starting at 0 to be used to maintain QP1 object
	* state. The QP1 port number determines the control object
	* index used to manage that QP1. NOTE: for special QP the
	* above "qp_index" is not used.
	*/
	int                     qp1_port;

	enum ib_qp_state	qp_state;
	enum ib_sig_type	sq_sig_type;
	u32                     max_inline;
	u32			pdn;
	u32			send_cqn;
	u32			recv_cqn;
	u32			srqn;

	atomic_t		ref_cnt;
	struct completion	free;

	/* Hardware work queue DMA memory (for SQ and RQ) */
	struct crdma_mem	*mem;
	u32			sq_offset;
	u32			rq_offset;

	/* Work queues, RQ only valid if QP is not attached to SRQ */
	struct crdma_hw_workq   sq;
	struct crdma_hw_workq   rq;
};

struct crdma_mr {
	struct ib_mr		ib_mr;

	 /* User page information, or NULL if DMA memory region */
	struct ib_umem		*umem;

	/*
	 * Associated memory protection table entry and the block of
	 * contiguous memory translation table entries it uses.
	 */
	u32			mpt_index;
	u32			base_mtt;
	u32			num_mtt;

	/*
	 * The log2 page shift for the mapping can be any supported page
	 * size and represents the host mapping size; the order determines
	 * how many page size pages will be addressed by each MTT entry
	 * and represents the compound page size used by the device.
	 */
	unsigned long		page_shift;
	unsigned long		mpt_order;

	/*
	 * IB virtual I/O addressing, protection, and allowed
	 * access types.
	 */
	u64			io_vaddr;
	u64			len;
	u32			key;		/* Both Lkey and Rkey */
	u32			pdn;		/* Protection Domain */
	u32			access;		/* IB enable flags */

	u32			npages;
	void			*buf;
};

/* Software formatted copy of microcode GID table entries */
struct crdma_gid_entry {
       u8              type;
       u8              valid;
       u8              rsvd[2];
       union ib_gid    gid;
};

/* Software formatted copy of microcode SMAC table entries */
struct crdma_mac_entry {
       int             ref_cnt;
       u8              mac[ETH_ALEN];
};

struct crdma_port {
	struct net_device       *netdev;
	u8                      mac[ETH_ALEN];

	/*
		* General Services Interface QP specific information indicating
		* if the special QP has been created. If so, the microcode
		* QP control object will be the number of this port zero based.
		*/
	spinlock_t              qp1_lock;
	bool                    qp1_created;

	/*
		* XXX: For test purposes only, while event notification is not
		* available in microcode we periodically initiate a notification
		* to keep event driven MAD driver code from hanging. This work
		* around is controlled by the "mad_cq_event_wa" module parameter.
		* NOTE that while the qp1_created is true, the associated CQ must
		* exist.
		*/
	struct delayed_work     qp1_cq_dwork;
	struct crdma_cq         *qp1_send_ccq;
	struct crdma_cq         *qp1_recv_ccq;

	/*
		* Ports in host memory Ethernet source addressing information.
		* Much of this function is common across RoCE providers with
		* respect to the management of the GIDs and MAC addresses.
		* It is expected that the API to these interfaces will change,
		* but ultimately the provider will need the ability to push
		* SGID and SMAC tables to microcode.
		*/
	spinlock_t              table_lock;
	int                     gid_table_size;
	struct crdma_gid_entry  gid_table_entry[CRDMA_IB_MAX_GID_TABLE_SIZE];
	int                     mac_table_size;
	struct crdma_mac_entry  mac_table_entry[CRDMA_IB_MAX_MAC_TABLE_SIZE];
};

struct crdma_ibdev {
	struct ib_device	ibdev;

	/*
	 * XXX Used during integration to indicate to code that the NFP
	 * driver has allocated interrupts and we can register handlers.
	 * This is not needed once NFP registration is supported.
	 */
	bool			have_interrupts;

	/* Device IDR ID */
	int			id;

	/* RDMA Verbs consumer contexts */
	struct list_head	ctxt_list;
	spinlock_t		ctxt_lock;

	/* Driver resource allocation maps/tables */
	struct crdma_eq_table	eq_table;
	struct crdma_bitmap	mpt_map;
	struct crdma_bitmap	mtt_map;
	struct crdma_bitmap	uar_map;
	struct crdma_bitmap	pd_map;
	struct crdma_bitmap	qp_map;
	spinlock_t		qp_lock;
	struct radix_tree_root	qp_tree;

	/* 
	 * CQ allocation bitmap and table. For now we are being wasteful
	 * and allocating a table for CQN to CQ map; we will change this
	 * to be a Radix Tree or something with a smaller footprint later.
	 */
	struct crdma_bitmap	cq_map;
	struct crdma_cq		**cq_table;

	/* NFP allocated resources and microcode capabilities/attributes */
	struct nfp_roce_info	*nfp_info;
	struct crdma_hca_cap	cap;

	/*
	 * Microcode command/status interface register located in NFP
	 * PCI BAR I/O memory.
	 */
	struct mutex		cmdif_mutex;	/* Interface register access */
	void __iomem		*cmdif;

	struct dma_pool		*mbox_pool;	/* Input/output DMA buffers */
	struct semaphore	poll_sem;	/* One poller at a time */
	u8			toggle;		/* Next not busy */

	/*
	 * Once microcode event delivery and interrupts have been
	 * validated in startup; the driver switches into event driven
	 * command mode. Up to max_cmds_out can be in progress by microcode.
	 * The state associated with each event driven command in progress
	 * is saved in the cmd_q. The (max_cmds_log2 - 1) low order bits of
	 * the command's assigned token value maps back to the cmd_q slot
	 * associated with the command.
	 */
	bool			use_event_cmds;
	u16			max_cmds_out;
	u16			max_cmds_log2;
	struct semaphore	event_sem;	/* Limits max outstanding */

	spinlock_t		cmd_q_lock;
	u16			token;
	struct crdma_event_cmd	*cmd_q;
	int			cmd_q_free;

	/*
	 * Microcode device doorbell pages (UAR pages) located in NFP
	 * PCI BAR I/O memory.
	 */
	phys_addr_t		db_paddr;
	u32			db_len;

	/*
	 * Note we have separate kernel UAR pointers for EQ and QP/CQ.
	 * This is because some implementations require unique pages;
	 * but it is entirely possible they both point to the same page.
	 */
	struct crdma_uar	priv_eq_uar;	/* Kernel EQ doorbells */
	struct crdma_uar	priv_uar;	/* Kernel SQ/CQ UAR */
	spinlock_t              priv_uar_lock;  /* For CQ on 32-bit systems */

	int			numa_node;

	/* Linkage back to net_device notification chain */
	struct notifier_block   nb_netdev;

	struct crdma_port       port;
};

/**
 * Return CRDMA RoCE device from IB device.
 *
 * @ibdev: The IB device returned from ib_alloc_device().
 *
 * Returns the address of the CRDMA RoCE device.
 */
static inline struct crdma_ibdev *to_crdma_ibdev(struct ib_device *ibdev)
{
	return container_of(ibdev, struct crdma_ibdev, ibdev);
}

/**
 * Return CRDMA RoCE user context from IB verbs user context.
 *
 * @ib_uctxt: The IB user context.
 *
 * Returns the address of the CRDMA user context.
 */
static inline struct crdma_ucontext *to_crdma_uctxt(
			struct ib_ucontext *ib_uctxt)
{
	return container_of(ib_uctxt, struct crdma_ucontext, ib_uctxt);
}

/**
 * Return CRDMA RoCE protection domain from IB verbs protection domain.
 *
 * @ib_pd: The IB protection domain.
 *
 * Returns the address of the CRDMA private protection domain.
 */
static inline struct crdma_pd *to_crdma_pd(struct ib_pd *ib_pd)
{
	return container_of(ib_pd, struct crdma_pd, ib_pd);
}

/**
 * Return CRDMA RoCE CQ from IB verbs completion queue.
 *
 * @ib_cq: The IB completion queue.
 *
 * Returns the address of the CRDMA private completion queue.
 */
static inline struct crdma_cq *to_crdma_cq(struct ib_cq *ib_cq)
{
	return container_of(ib_cq, struct crdma_cq, ib_cq);
}

/**
 * Return CRDMA RoCE SRQ from IB verbs shared receive queue.
 *
 * @ib_srq: The IB shared receive queue.
 *
 * Returns the address of the CRDMA private shared receive queue.
 */
static inline struct crdma_srq *to_crdma_srq(struct ib_srq *ib_srq)
{
	return container_of(ib_srq, struct crdma_srq, ib_srq);
}

/**
 * Return CRDMA RoCE QP from IB verbs queue pair.
 *
 * @ib_qp: The IB queue pair.
 *
 * Returns the address of the CRDMA private queue pair.
 */
static inline struct crdma_qp *to_crdma_qp(struct ib_qp *ib_qp)
{
	return container_of(ib_qp, struct crdma_qp, ib_qp);
}

/**
 * Return CRDMA RoCE memory region from IB verbs memory region.
 *
 * @ib_mr: The IB memory region.
 *
 * Returns the address of the CRDMA private memory region.
 */
static inline struct crdma_mr *to_crdma_mr(struct ib_mr *ib_mr)
{
	return container_of(ib_mr, struct crdma_mr, ib_mr);
}

 /**
 * Return CRDMA RoCE address handle from IB address handle.
 *
 * @ib_ah: The IB address handle.
 *
 * Returns the address of the CRDMA private address handle structure.
 */
static inline struct crdma_ah *to_crdma_ah(struct ib_ah *ib_ah)
{
	return container_of(ib_ah, struct crdma_ah, ib_ah);
}

/* Add minimal extra detail to pr_xxx() and dev_xxx() type calls */
#define crdma_err(format, ...)				\
	pr_err("%s:%d:(pid %d): " format,			\
		__func__, __LINE__, current->pid, ##__VA_ARGS__)

#define crdma_warn(format, ...)				\
	pr_warn("%s:%d:(pid %d): " format,			\
		__func__, __LINE__, current->pid, ##__VA_ARGS__)

#define crdma_info(format, ...)				\
	pr_info("%s:%d:(pid %d): " format,			\
		__func__, __LINE__, current->pid, ##__VA_ARGS__)

#define crdma_debug(format, ...)				\
	pr_debug("%s:%d:(pid %d): " format,			\
		__func__, __LINE__, current->pid, ##__VA_ARGS__)

#define crdma_dev_err(crdma_dev, format, ...)				\
	dev_err(&(crdma_dev)->nfp_info->pdev->dev, "%s:%d:(pid %d): " format, \
		__func__, __LINE__, current->pid, ##__VA_ARGS__)

#define crdma_dev_warn(crdma_dev, format, ...)				\
	dev_warn(&(crdma_dev)->nfp_info->pdev->dev, "%s:%d:(pid %d): " format, \
		__func__, __LINE__, current->pid, ##__VA_ARGS__)

#define crdma_dev_info(crdma_dev, format, ...)				\
	dev_info(&(crdma_dev)->nfp_info->pdev->dev, "%s:%d:(pid %d): " format, \
		__func__, __LINE__, current->pid, ##__VA_ARGS__)
#endif /* CRDMA_IB_H */
