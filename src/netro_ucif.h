/*
 * Copyright (c) 2015, Netronome, Inc.  All rights reserved.
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

#ifndef NETRO_UCIF_H
#define NETRO_UCIF_H

#include <linux/compiler.h>
#include "netro_ib.h"
#include "netro_hw.h"

/*
 * netro_ucif - Provides the driver/NFP micro-code interface.
 */

/*
 * The kernel driver configures/commands microcode using a set
 * of commands that are posted to microcode via the HCA
 * command/status interface register.
 */
#define NETRO_CMDIF_ABI_VERSION		0

/* Microcode command interface opcodes */
enum {
	NETRO_CMD_NO_OP			= 1,
	NETRO_CMD_QUERY_DEV_CAP		= 2,
	NETRO_CMD_QUERY_UCODE		= 3,
	NETRO_CMD_QUERY_NIC		= 4,
	NETRO_CMD_QUERY_HCA		= 5,
	NETRO_CMD_QUERY_PORT		= 6,
	NETRO_CMD_HCA_ENABLE		= 7,
	NETRO_CMD_HCA_DISABLE		= 8,
	NETRO_CMD_ROCE_PORT_ENABLE	= 9,
	NETRO_CMD_ROCE_PORT_DISABLE	= 10,
	NETRO_CMD_SET_BS_HOST_MEM_SIZE	= 11,
	NETRO_CMD_MAP_BS_HOST_MEM	= 12,
	NETRO_CMD_UNMAP_BS_HOST_MEM	= 13,
	NETRO_CMD_MPT_CREATE		= 14,
	NETRO_CMD_MPT_DESTROY		= 15,
	NETRO_CMD_MPT_QUERY		= 16,
	NETRO_CMD_MTT_WRITE		= 17,
	NETRO_CMD_MTT_READ		= 18,
	NETRO_CMD_MAPT_SYNC		= 19,
	NETRO_CMD_SET_PORT_GID_TABLE	= 20,
	NETRO_CMD_GET_PORT_GID_TABLE	= 21,
	NETRO_CMD_SET_PORT_MAC_TABLE	= 22,
	NETRO_CMD_GET_PORT_MAC_TABLE	= 23,
	NETRO_CMD_SET_PORT_VLAN_TABLE	= 24,
	NETRO_CMD_GET_PORT_VLAN_TABLE	= 25,
	NETRO_CMD_EQ_CREATE		= 26,
	NETRO_CMD_EQ_DESTROY		= 27,
	NETRO_CMD_EQ_MAP		= 28,
	NETRO_CMD_QP_MODIFY		= 29,
	NETRO_CMD_QP_QUERY		= 30,
	NETRO_CMD_QP_SUSPEND		= 31,
	NETRO_CMD_QP_RESUME		= 32,
	NETRO_CMD_CQ_CREATE		= 33,
	NETRO_CMD_CQ_DESTROY		= 34,
	NETRO_CMD_CQ_MODIFY		= 35,
	NETRO_CMD_CQ_RESIZE		= 36,
	NETRO_CMD_SRQ_CREATE		= 37,
	NETRO_CMD_SRQ_DESTROY		= 38,
	NETRO_CMD_SRQ_SET_ARM_LIMIT	= 39,
	NETRO_CMD_MCG_CREATE		= 40,
	NETRO_CMD_MCG_DESTROY		= 41,
	NETRO_CMD_MCG_ATTACH		= 42,
	NETRO_CMD_MCG_DETACH		= 43
};

/* Microcode QP Modify opcode modifiers */
enum {
	NETRO_QP_MODIFY_RST2INIT	= 1,
	NETRO_QP_MODIFY_INIT2RTR	= 2,
	NETRO_QP_MODIFY_INIT2INIT	= 3,
	NETRO_QP_MODIFY_RTR2RTS		= 4,
	NETRO_QP_MODIFY_RTS2RTS		= 5,
	NETRO_QP_MODIFY_SQER2RTS	= 6,
	NETRO_QP_MODIFY_RTS2SQD		= 7,
	NETRO_QP_MODIFY_SQD2SQD		= 8,
	NETRO_QP_MODIFY_SQD2RTS		= 9,
	NETRO_QP_MODIFY_2ERR		= 10,
	NETRO_QP_MODIFY_2RST		= 11
};

/* Microcode command interface status values returned by microcode */
enum {
	NETRO_STS_OK			= 0,
	NETRO_STS_UCODE_CORRUPTED	= 1,
	NETRO_STS_UCODE_INTERNAL_ERR	= 2,
	NETRO_STS_UNSUPPORTED_OPCODE	= 3,
	NETRO_STS_BAD_PARAMETER		= 4,
	NETRO_STS_BAD_SYSTEM_STATE	= 5,
	NETRO_STS_BAD_CNTRL_OBJ_REF	= 6,
	NETRO_STS_CNTRL_OBJ_BUSY	= 7,
	NETRO_STS_EXCEEDS_HCA_LIMITS	= 8,
	NETRO_STS_BAD_CNTRL_OBJ_STATE	= 9,
	NETRO_STS_INVALID_INDEX		= 10,
	NETRO_STS_BAD_QP_STATE		= 11,
	NETRO_STS_BAD_SIZE		= 12,
	NETRO_STS_INVALID_PORT		= 13,
};

enum {
	NETRO_CMDIF_DRIVER_MAX_CMDS	= 16,	/* Driver limit, not ucode */
	NETRO_CMDIF_GEN_TIMEOUT_MS	= 2000,
	NETRO_CMDIF_GO_TIMEOUT_MS	= 2000,
	NETRO_CMDIF_MBOX_SIZE		= 4096,
	NETRO_CMDIF_POLL_TOKEN		= 0xA5A5
};

/* DMA mailbox buffer for both command input and output */
struct netro_cmd_mbox {
	void		*buf;
	dma_addr_t	dma_addr;
};

struct netro_cmd {
	u64		input_param;
	u64		output_param;
	u64		timeout;
	u32		input_mod;
	bool		output_imm;
	u8		opcode;
	u8		opcode_mod;
	u8		status;
};

/* Used to save command state in event driven command mode */
struct netro_event_cmd {
	struct	completion comp;
	int		next;
	u64		output_param;
	u16		token;
	u8		status;
};

/* Microcode hardware specific work request for Send Queue WQE */
enum {
	NETRO_WQE_RDMA_WRITE_OP			= 0,
	NETRO_WQE_RDMA_WRITE_WITH_IMM_OP	= 1,
	NETRO_WQE_SEND_OP			= 2,
	NETRO_WQE_SEND_WITH_IMM_OP		= 3,
	NETRO_WQE_RDMA_READ_OP			= 4
#if 0 /* The following are required, but not yet used */
	NETRO_WQE_SEND_WITH_INVAL_OP		= 8,
	NETRO_WQE_LOCAL_INVAL_OP		= 10,
	NETRO_WQE_FAST_REG_MR_OP		= 11
#endif
};

enum {
	NETRO_WQE_CTRL_FENCE_BIT		= 1 << 0,
	NETRO_WQE_CTRL_SOLICITED_BIT		= 1 << 1,
	NETRO_WQE_CTRL_SIGNAL_BIT		= 1 << 2,
	NETRO_WQE_CTRL_LOOPBACK_BIT		= 1 << 3,
	NETRO_WQE_CTRL_INLINE_DATA_BIT		= 1 << 4,
#if 0 /* The following is required, but not yet used */
	NETRO_WQE_CTRL_STRONG_ORDER_BIT		= 1 << 5,
#endif
	NETRO_WQE_CTRL_GSI_BIT			= 1 << 6
};

struct netro_swqe_owner {
	union {
		__le32	word;
		struct {
			u8	opcode;
			u8	flags;
			u8	num_sg;
			u8	rsvd;
		};
	};
} __packed;

struct netro_swqe_ctrl {
	struct netro_swqe_owner	owner;

	/*
	 * Immediate data or Invalidate information, always swapped by
	 * driver to undo byte swap done by hardware DMA of SWQE, leaving
	 * in user defined endian byte order.
	 */
	u32	imm_inval;
} __packed;

/* SWQE UD address vector information */
struct netro_swqe_ud_addr {
	struct netro_av	av;
	__le32		dest_qpn;
	__le32		qkey;
} __packed;

/* Send WQE Remote Address Entry */
struct netro_swqe_rem_addr {
	__le32		rem_io_addr_h;
	__le32		rem_io_addr_l;
	__le32		r_key;
	__le32		rsvd;
} __packed;

/* Send and Receive WQE Scatter Gather Entry */
struct netro_wqe_sge {
	__le32		io_addr_h;
	__le32		io_addr_l;
	__le32		l_key;
	__le32		byte_count;
} __packed;

/* Send WQE In-line data header, byte_count inline data follows header */
struct netro_swqe_inline {
	__le16		byte_count;
	__le16		rsvd;
	u8		data[0];
};

/* Send WQE Fast Register Memory Region */
#if 0 /* The following are required, but not yet used */
enum {
	NETRO_SWQE_FRMR_FLAGS_L_WRITE_EN	= 0,
	NETRO_SWQE_FRMR_FLAGS_R_READ_EN		= 1,
	NETRO_SWQE_FRMR_FLAGS_R_WRITE_EN	= 2,
	NETRO_SWQE_FRMR_FLAGS_ATOMIC_EN		= 3,
	NETRO_SWQE_FRMR_FLAGS_INVAL_EN		= 5
};
#endif

struct netro_swqe_frmr {
	u8		flags;
	u8		rsvd[3];
	__le32		key;
	__le32		page_list_paddr_h;
	__le32		page_list_paddr_l;
	__le32		io_addr_h;
	__le32		io_addr_l;
	__le32		rsvd2;
	__le32		length;
	__le32		offset;
	__le32		page_size;
} __packed;

struct netro_ud_swqe {
	struct netro_swqe_ud_addr	addr;
	union {
		struct netro_swqe_inline inline_data;
		struct netro_wqe_sge	sg[0];
	};
} __packed;

struct netro_rc_swqe {
	struct netro_swqe_rem_addr	rem_addr;
	union {
		struct netro_swqe_inline inline_data;
		struct netro_swqe_frmr	frmr;
		struct netro_wqe_sge	sg[0];
	};
} __packed;

struct netro_swqe {
	struct netro_swqe_ctrl		ctrl;
	union {
		struct netro_ud_swqe	ud;
		struct netro_rc_swqe	rc;
	};
} __packed;

/*
 * Hardware receive work queue entry (WQE) formats.
 */
struct netro_rwqe_ctrl {
	__le32			ownership;
	uint8_t			num_sge;
	uint8_t			rsvd;
	__le16			next_srq_wqe_ndx;
} __packed;

struct netro_rwqe {
	struct netro_rwqe_ctrl	ctrl;
	struct netro_wqe_sge	sg[0];
} __packed;

/*
 * Microcode event queues are used to deliver interrupt event data
 * to the provider driver.
 */
enum {
	NETRO_EQ_COMPLETION_EVENTS	= 1 << 0,
	NETRO_EQ_ASYNC_EVENTS		= 1 << 1,
	NETRO_EQ_EVENT_MASK		= NETRO_EQ_COMPLETION_EVENTS |
						NETRO_EQ_ASYNC_EVENTS,
	NETRO_EQ_OWNER_BIT		= 1 << 0
};

struct netro_eq {
	struct netro_ibdev	*ndev;
	struct netro_mem	*mem;
	struct netro_eqe	*eqe;
	u32			consumer_cnt;
	int			eq_num;
	int			num_eqe_log2;
	u32			consumer_mask;
	char			irq_name[32];
	u16			intr;
	u32			vector;

	/*
	 * An EQ can receive asynchronous events (affiliated and non-
	 * affiliated) and/or completion events. Keep track of how
	 * many CQ are reporting completions through this EQ.
	 */
	u32			event_map;
	int			cq_cnt;

	/*
	 * Interrupt moderation values to reduce interrupts for this
	 * EQ based on events and time. Defaults of 0 mean no moderation.
	 */
	u16			time_mod;
	u16			event_mod;
};

struct netro_eq_table {
	u32			num_eq;
	struct netro_eq		*eq;
};

/*
 * Event queue entry format is defined by the event type. Three classes
 * of events provide additional information: affiliated, command status,
 * and port change events.
 */
enum {
	NETRO_EQ_CQ_COMPLETION_NOTIFY	= 1,
	NETRO_EQ_CQ_ERROR		= 2,
	NETRO_EQ_QP_COMM_ESTABLISHED	= 5,
	NETRO_EQ_QP_SQ_DRAINED		= 6,
	NETRO_EQ_QP_SQ_LAST_WQE		= 7,
	NETRO_EQ_QP_CATASTROPHIC_ERROR	= 8,
	NETRO_EQ_QP_INVALID_REQUEST	= 9,
	NETRO_EQ_QP_ACCESS_ERROR	= 10,
	NETRO_EQ_SRQ_LIMIT_REACHED	= 11,
	NETRO_EQ_SRQ_CATASTROPHIC_ERROR	= 12,
	NETRO_EQ_EQ_OVERRUN_ERROR	= 13,
	NETRO_EQ_CMDIF_COMPLETE		= 14,
	NETRO_EQ_LOCAL_CATASTROPHIC_ERROR = 15,
	NETRO_EQ_PORT_CHANGE		= 16,
	NETRO_EQ_MGMT_PORT_CHANGE	= 17,
	NETRO_EQ_MICROCODE_WARNING	= 18
};

/* Format of EQE written by microcode */
struct netro_eqe {
	union {
		__le32	words[3];
		struct {
			__le32	obj_num;
			__le32	rsvd[2];
		} affiliated __packed;
		struct {
			__le32	output_param_h;
			__le32	output_param_l;
			__le16	token;
			u8	status;
			u8	rsvd2;
		} cmdif __packed;
		struct {
			u8	number;
			u8	rsvd3[3];
			__le32	rsvd4[2];
		} port __packed;
	} __packed;
	__le16	rsvd_owner;
	u8	sub_type;
	u8	type;
} __packed;

/**
 * Initialize a microcode event queue.
 *
 * @ndev: RoCE IB device.
 * @index: The EQN relative to this device.
 * @entries_log2: The number of EQE requested expressed as a log2 value.
 * @intr: The device interrupt to use (message table index).
 * @vector: The MSI/MSI-X interrupt vector/IRQ assigned to the EQ.
 * @events: The events that should be delivered to this EQ.
 *
 * Returns 0 on success, otherwise an error.
 */
int netro_init_eq(struct netro_ibdev *ndev, int index, int entries_log2,
		u16 intr, u32 vector, u32 events);

/**
 * Disable EQ interrupts and release microcode event queue resources.
 *
 * @ndev: The RoCE IB device.
 * @eqn: The EQ number.
 */
void netro_cleanup_eq(struct netro_ibdev *ndev, int eqn);

/**
 * Verify microcode command interface is operational by
 * requesting execution of a microcode no-op command.
 *
 * @ndev: RoCE IB device.
 *
 * Returns 0 on success, otherwise an error.
 */
int netro_noop(struct netro_ibdev *ndev);

/*
 * Query Device Capabilities output mailbox format.
 */
enum {
	NETRO_DEV_CAP_FLAG_RC		= 1 << 0,
	NETRO_DEV_CAP_FLAG_UD		= 1 << 1,
	NETRO_DEV_CAP_FLAG_UC		= 1 << 2,
	NETRO_DEV_CAP_FLAG_XRC		= 1 << 3,
	NETRO_DEV_CAP_FLAG_PHYS		= 1 << 4,
	NETRO_DEV_CAP_FLAG_FRMR		= 1 << 5,
	NETRO_DEV_CAP_FLAG_MW		= 1 << 6,
	NETRO_DEV_CAP_FLAG_SRQ		= 1 << 7,

	NETRO_DEV_CAP_PORT_SHIFT	= 3,
	NETRO_DEV_CAP_PORT_MASK		= 0x1F,
};

struct netro_dev_cap_param {
	__le16	req_bs_size_mb;
	u8	ports_rsvd;
	u8	flags;

	u8	max_rq_sge;
	u8	max_sq_sge;
	u8	max_qp_wr_log2;
	u8	max_qp_log2;

	u8	max_rdma_res_log2;
	u8	rsvd_qp;
	u8	max_rwqe_size_log2;
	u8	max_swqe_size_log2;

	u8	max_cqe_log2;
	u8	max_cq_log2;
	u8	max_qp_req_res_log2;
	u8	max_qp_rsp_res_log2;

	u8	eqe_size_log2;
	u8	max_eqe_log2;
	u8	max_eq_log2;
	u8	cqe_size_log2;

	u8	max_mcg_log2;
	u8	max_srq_rwqe_size_log2;
	u8	max_srq_wr_log2;
	u8	max_srq_log2;

	__le16  rsvd;
	u8	max_mr_size_log2;
	u8	max_mcg_qp_log2;

	u8	max_uar_pages_log2;
	u8	sgid_table_size;
	u8	smac_table_size;
	u8	vlan_table_size_log2;

	__le16	max_inline_data;
	u8	reserved;
	u8	min_page_size_log2;

	__le32	max_mpt;
	__le32	max_mtt;
} __packed;

/**
 * Return microcode capabilities for device.
 *
 * @ndev: RoCE IB device.
 * @caps: Location to return device capabilities.
 *
 * Returns 0 on success, otherwise an error code.
 */
int netro_query_dev_cap(struct netro_ibdev *ndev,
		struct netro_dev_cap_param *cap);

/*
 * Query HCA microcode attributes output mailbox format
 */
struct netro_query_ucode_attr {
	__le16		min_rev;
	__le16		maj_rev;
	__le16		max_cmds_out;
	__le16		cmd_abi_rev;
	__le32		build_id_high;
	__le32		build_id_low;
	__le32		deprecated_1;
	__le32		deprecated_2;
	__le32		mhz_clock;
} __packed;

/**
 * Query microcode attributes
 *
 * @ndev: RoCE IB device.
 * @attr: Structure to be initialized with microcode attributes.
 *
 * Returns 0 on success, otherwise an error.
 */
int netro_query_ucode(struct netro_ibdev *ndev,
		struct netro_query_ucode_attr *attr);

/**
 * Query NIC attributes
 *
 * @ndev: RoCE IB device.
 * @boardid: Returns hardware board ID in host order.
 *
 * Returns 0 on success, otherwise an error.
 */
int netro_query_nic(struct netro_ibdev *ndev, uint32_t *boardid);

/*
 * Set HCA backing store input parameters
 */
enum {
	NETRO_SET_BS_PAGE_SHIFT		= 27,
	NETRO_SET_BS_PAGE_MASK		= 0xF8000000ul,
	NETRO_SET_BS_NUM_MTT_MASK	= 0x07FFFFFFul,
	NETRO_SET_BS_SIZE_MASK		= 0x0000FFFFul,
};

/**
 * Set the HCA backing store memory size parameter requirements.
 *
 * @ndev: RoCE IB device.
 * @num_mtt: The number of entries (starting at index 0).
 * @order: The log2 multiple of page size for the mapping.
 * @size_mb: The size of the backing store expressed as megabytes.
 *
 * Returns 0 on success, otherwise an error.
 */
int netro_set_bs_mem_size(struct netro_ibdev *ndev,
		int num_mtt, int order, int size_mb);

/*
 *Map HCA backing store input mailbox parameters
 */
struct netro_bs_map_mem {
	__le32		vaddr_h;
	__le32		vaddr_l;
	__le16		bs_mb_size;
	__le16		rsvd;
	__le32		pg_sz_mtts;
} __packed;

/**
 * Notify microcode that HCA backing store memory is ready for use and
 * pass memory access parameters.
 *
 * @ndev: RoCE IB device.
 * @vaddr: The 64 bit virtual I/O address to assign.
 * @size_mb: The size of the backing store expressed as megabytes.
 * @num_mtt: The total number of MTT entries in the mapping.
 * @order: The log2 multiple of page size for the mapping.
 *
 * Returns 0 on success, otherwise an error.
 */
int netro_bs_map_mem(struct netro_ibdev *ndev, u64 vaddr, int size_mb,
		int num_mtt, int order);

/**
 * Notify microcode that HCA backing store memory is being removed and
 * no further accesses by microcode should occur.
 *
 * @ndev: RoCE IB device.
 *
 * Returns 0 on success, otherwise an error.
 */
int netro_bs_unmap_mem(struct netro_ibdev *ndev);

/*
 * HCA enable parameters - not yet defined.
 */
struct netro_hca_enable {
	__le32	undefined_1;
	__le32	undefined_2;
} __packed;

/**
 * Enable HCA, passing any tunable parameters. Microcode
 * should acquire any microcode RoCEv2 specific HCA resources.
 *
 * @ndev: RoCE IB device.
 *
 * Returns 0 on success, otherwise an error.
 */
int netro_hca_enable(struct netro_ibdev *ndev);

/**
 * Disable HCA in preparation for shutdown. The HCA should
 * should release any microcode RoCEv2 specific HCA resources.
 *
 * @ndev: RoCE IB device.
 *
 * Returns 0 on success, otherwise an error.
 */
int netro_hca_disable(struct netro_ibdev *ndev);

/*
 * Write MTT entry input mailbox parameter format
 */
struct netro_mtt_write_entry {
	__le32		paddr_h;
	__le32		paddr_l;
} __packed;

struct netro_mtt_write_param {
	__le32		rsvd;
	__le32		base_mtt_ndx;
	struct netro_mtt_write_entry entry[];
} __packed;

#define NETRO_MTT_PER_WRITE_CMD	((NETRO_CMDIF_MBOX_SIZE - sizeof(u64))	\
				/ sizeof(struct netro_mtt_write_entry))

/**
 * Write a consecutive block of MTT entries for translation of I/O
 * virtual addresses to DMA bus addresses.
 *
 * @ndev: The RoCE IB device.
 * @sg_list: A chain of scatter/gather entries backing the memory.
 * @num_sg: The number of SG entries in the chain.
 * @base_mtt: The starting MTT index to write to.
 * @num_mtt: The number of MTT entries to write.
 * @page_size: The page size for the MTT translation entries.
 * @comp_page: The number of compound pages.
 * @comp_order: The order for compound pages based on page_size specified.
 *
 * Returns 0 on success, otherwise and error.
 */
int netro_mtt_write_sg(struct netro_ibdev *ndev, struct scatterlist *sg_list,
			int num_sg, u32 base_mtt, u32 num_mtt,
			unsigned long page_size, int comp_page, int comp_order);

/*
 * Create a microcode event queue.
 */
enum {
	NETRO_EQ_CREATE_EQN_MASK		= 0x01F,

	NETRO_EQ_CREATE_LOG2_PAGE_SZ_SHIFT	= 27,
	NETRO_EQ_CREATE_PHYS_BIT_SHIFT		= 24,
	NETRO_EQ_CREATE_EQ_PAGE_OFF_MASK	= 0x00FFFFFF
};

struct netro_eq_params {
	u8		eqn;
	u8		eqe_log2;
	__le16		intr;
	__le32		page_info;
	__le32		mtt_index;
	__le16		time_mod;
	__le16		event_mod;
} __packed;

struct netro_eq;

/**
 * Create a microcode event queue control object.
 *
 * @ndev: RoCE IB device.
 * @eq: The driver EQ object.
 *
 * Returns 0 on success, otherwise an error.
 */
int netro_eq_create_cmd(struct netro_ibdev *ndev, struct netro_eq *eq);

/**
 * Destroy a microcode event queue control object.
 *
 * @ndev: RoCE IB device.
 * @eq: The driver EQ object.
 *
 * Returns 0 on success, otherwise an error.
 */
int netro_eq_destroy_cmd(struct netro_ibdev *ndev, struct netro_eq *eq);

/**
 * Map event types to an existing EQ.
 *
 * @ndev: RoCE IB device.
 * @eqn: The EQ number.
 * @events: The new event mask to map.
 *
 * Returns 0 on success, otherwise an error.
 */
int netro_eq_map_cmd(struct netro_ibdev *ndev, u32 eqn, u32 events);

/**
 * Initialize the microcode event driven command interface
 *
 * @ndev: RoCE IB device.
 *
 * Returns 0 on success, otherwise an error code.
 */
int netro_init_event_cmdif(struct netro_ibdev *ndev);

/**
 * Release microcode event driven command interface resources.
 *
 * @ndev: RoCE IB device.
 */
void netro_cleanup_event_cmdif(struct netro_ibdev *ndev);

/*
 * Completion Queue Entry (CQE) format and accessors.
 */
enum {
	NETRO_CQE_QPN_MASK		= 0x00FFFFFF,
	NETRO_CQE_REM_QPN_MASK		= 0x00FFFFFF,
	NETRO_CQE_SENDQ_FLAG_BIT	= 1 << 5,
	NETRO_CQE_GRH_FLAG_BIT		= 1 << 6,
	NETRO_CQE_OWNERSHIP_BIT		= 1
};

enum {
	NETRO_CQE_NO_ERR		= 0,
	NETRO_CQE_BAD_RESPONSE_ERR	= 1,
	NETRO_CQE_LOCAL_LENGTH_ERR	= 2,
	NETRO_CQE_LOCAL_ACCESS_ERR	= 3,
	NETRO_CQE_LOCAL_QP_PROT_ERR	= 4,
	NETRO_CQE_LOCAL_QP_OP_ERR	= 5,
	NETRO_CQE_MEMORY_MGMT_OP_ERR	= 6,
	NETRO_CQE_REMOTE_ACCESS_ERR	= 7,
	NETRO_CQE_REMOTE_INV_REQ_ERR	= 8,
	NETRO_CQE_REMOTE_OP_ERR		= 9,
	NETRO_CQE_RNR_RETRY_ERR		= 10,
	NETRO_CQE_TRANSPORT_RETRY_ERR	= 11,
	NETRO_CQE_ABORTED_ERR		= 12,
	NETRO_CQE_FLUSHED_ERR		= 13
};

struct netro_cqe {
	union {
		__le32	words[8];
		struct {
			__le32		qpn;
			__le32		rem_qpn;
			__le32		imm_inval;
			__le32		byte_count;
			u8		smac[6];
			__le16		sl_vid;
			__le16		wqe_index;
			u8		flags;
			u8		rsvd;
			u8		status;
			u8		pkey_index;
			u8		opcode;
			u8		owner;
		} __packed;
	} __packed;
} __packed;

/*
 * Create a microcode completion queue.
 */
enum {
	NETRO_CQ_CREATE_CQN_MASK		= 0x00FFFFFF,
	NETRO_CQ_CREATE_LOG2_PAGE_SZ_SHIFT	= 27,
	NETRO_CQ_CREATE_PHYS_BIT_SHIFT		= 24,
};

struct netro_cq_params {
	__le32		rsvd_cqn;
	u8		eqn;
	u8		rsvd[2];
	u8		cqe_log2;
	__le32		page_info;
	__le32		mtt_index;
	__le16		time_mod;
	__le16		event_mod;
	__le32		ci_addr_high;
	__le32		ci_addr_low;
	__le32		uar_pfn_high;
	__le32		uar_pfn_low;
} __packed;

enum {
	NETRO_CQ_MBOX_CONSUMER_NDX_MASK		= 0x00FFFFFF,
};

struct netro_ci_mbox {
	__le32		ci;		/* Consumer Index */
	__le32		last_db_state;
};

struct netro_cq;
struct netro_uar;

/**
 * Create a completion queue control object.
 *
 * @ndev: RoCE IB device.
 * @cq: The driver CQ object.
 * @uar: The UAR that may be used to ring the CQ's doorbell.
 *
 * Returns 0 on success, otherwise an error.
 */
int netro_cq_create_cmd(struct netro_ibdev *ndev, struct netro_cq *cq,
		struct netro_uar *uar);

/**
 * Destroy a microcode completion queue control object.
 *
 * @ndev: RoCE IB device.
 * @cq: The driver CQ object.
 *
 * Returns 0 on success, otherwise an error.
 */
int netro_cq_destroy_cmd(struct netro_ibdev *ndev, struct netro_cq *cq);

/* Queue Pair attributes that can be set and modified. */
/* QP control object parameters set on QP RESET to INIT transition */
enum {
	NETRO_QP_ATTR_QPN_MASK			= 0x00FFFFFF,
	NETRO_QP_ATTR_ACCESS_MASK		= 0x0F,
	NETRO_QP_ATTR_MTU_SHIFT			= 4
};

struct netro_qp_attr_params {
	u8		rsvd;
	u8		phys_port_num;
	u8		mtu_access;
	u8		qp_state;
	u8		min_rnr_timer;
	u8		rnr_retry;
	u8		retry_count;
	u8		timeout;
	__le32		dest_qpn;
	__le16		pkey_index;
	u8		rdma_init_depth;
	u8		rdma_rsp_res;
	__le32		qkey;
	__le32		rq_psn;
	__le32		sq_psn;
	struct netro_av	av;
} __packed;

/* QP control object parameters set on QP RESET to INIT transition */
enum {
	NETRO_QP_CTRL_QPN_MASK			= 0x00FFFFFF,
	NETRO_QP_CTRL_GSI_BIT_SHIFT		= 26,
	NETRO_QP_CTRL_PHYS_BIT_SHIFT		= 27,
	NETRO_QP_CTRL_SIGALL_BIT_SHIFT		= 28,
	NETRO_QP_CTRL_SRQ_BIT_SHIFT		= 29,
	NETRO_QP_CTRL_FRMR_BIT_SHIFT		= 30,
	NETRO_QP_CTRL_R_LKEY_BIT_SHIFT		= 31,

	NETRO_QP_CTRL_PD_MASK			= 0x00FFFFFF,
	NETRO_QP_CTRL_SWQE_LOG2_MASK		= 0x0F,
	NETRO_QP_CTRL_SWQE_LOG2_SHIFT		= 28,
	NETRO_QP_CTRL_RWQE_LOG2_MASK		= 0x0F,
	NETRO_QP_CTRL_RWQE_LOG2_SHIFT		= 24,

	NETRO_QP_CTRL_SCQN_MASK			= 0x00FFFFFF,
	NETRO_QP_CTRL_QPTYPE_SHIFT		= 28,
	NETRO_QP_CTRL_RCQN_MASK			= 0x00FFFFFF,
	NETRO_QP_CTRL_LOG2_PAGE_SZ_SHIFT	= 27,
	NETRO_QP_CTRL_SRQN_MASK			= 0x00FFFFFF,
};

struct netro_qp_ctrl_params {
	__le32		flags_qpn;
	__le32		wqe_pd;
	__le32		type_send_cqn;
	__le32		recv_cqn;
	__le16		max_recv_wr;
	__le16		max_send_wr;
	__le16		max_inline_data;
	u8		max_recv_sge;
	u8		max_send_sge;
	__le32		page_info;
	__le32		mtt_index;
	__le32		sq_base_off;
	__le32		rq_base_off;
	__le32		srqn;
	__le32		uar_pfn_high;
	__le32		uar_pfn_low;
	__le32		rsvd;
} __packed;

struct netro_qp_params {
	/* Attribute mask bits are the same as "ib_qp_attr_mask" values */
	__le32				attr_mask;
	struct netro_qp_attr_params	attr;
	struct netro_qp_ctrl_params	ctrl;
} __packed;

struct netro_qp;

/**
 * Modify a queue pair control object.
 *
 * @ndev: RoCE IB device.
 * @qp: The driver QP object.
 * @uar: The UAR that may be used to ring the QP's doorbell.
 * @qp_attr: IB attributes to modify.
 * @qp_attr_mask: Mask of IB attributes to modify/set.
 * @cur_state: The current state of the QP.
 * @new_state: The new state of the QP.
 *
 * Returns 0 on success, otherwise an error.
 */
int netro_qp_modify_cmd(struct netro_ibdev *ndev, struct netro_qp *qp,
		struct netro_uar *uar, struct ib_qp_attr *qp_attr,
		int qp_attr_mask, enum ib_qp_state cur_state,
		enum ib_qp_state new_state);

/**
 * Query a queue pair control object for attributes.
 *
 * @ndev: RoCE IB device.
 * @qp: The driver QP object.
 * @qp_attr: Returns IB attributes requested.
 * @qp_attr_mask: Mask of IB attributes requested.
 *
 * Returns 0 on success, otherwise an error.
 */
int netro_qp_query_cmd(struct netro_ibdev *ndev, struct netro_qp *qp,
		struct ib_qp_attr *qp_attr, int qp_attr_mask);

/**
 * Destroy a microcode queue pair control object.
 *
 * @ndev: RoCE IB device.
 * @qp: The driver QP object.
 *
 * Returns 0 on success, otherwise an error.
 */
int netro_qp_destroy_cmd(struct netro_ibdev *ndev, struct netro_qp *qp);

/**
 * Notify microcode to enable RoCEv2 capability on a port.
 *
 * @ndev: RoCE IB device.
 * @port: The port number to enable RoCEv2.
 *
 * Returns 0 on success, otherwise an error.
 */
int netro_port_enable_cmd(struct netro_ibdev *ndev, u8 port);

/**
 * Notify microcode to disable RoCEv2 capability on a port.
 *
 * @ndev: RoCE IB device.
 * @port: The port number to enable RoCEv2.
 *
 * Returns 0 on success, otherwise an error.
 */
int netro_port_disable_cmd(struct netro_ibdev *ndev, u8 port);

/*
 * Create a Memory Access and Protection Table entry.
 */
enum {
	NETRO_MPT_CREATE_PD_MASK		= 0x00FFFFFF,

	NETRO_MPT_LOCAL_WRITE_ENABLE		= 1 << 24,
	NETRO_MPT_REMOTE_READ_ENABLE		= 1 << 25,
	NETRO_MPT_REMOTE_WRITE_ENABLE		= 1 << 26,
#if 0 /* The following is required, but not yet used */
	NETRO_MPT_ATOMIC_ENABLE			= 1 << 27,
#endif
	NETRO_MPT_DMA				= 1 << 28,
#if 0 /* The following is required, but not yet used */
	NETRO_MPT_INVALIDATE_ENABLE		= 1 << 29,
#endif
	NETRO_MPT_PHYS				= 1 << 30,
#if 0 /* The following is required, but not yet used */
	NETRO_MPT_FRMR_ENABLE			= 1 << 31,
#endif
	NETRO_MPT_LOG2_PAGE_SZ_SHIFT		= 27,
};

struct netro_mpt_params {
	__le32		key;
	__le32		flags_pd;
	__le32		io_addr_h;
	__le32		io_addr_l;
	__le32		length;
	__le32		page_info;
	__le32		mtt_index;
	__le32		frmr_entries;
} __packed;

/*
 * Memory and Protection Table command formats.
 */
struct netro_mr;

/**
 * Issue a microcode MPT query command.
 *
 * @ndev: The IB RoCE device.
 * @mpt_index: The MPT control object identifier to query.
 * @param: The MPT param returned from microcode in LE format.
 *
 * Returns 0 on success, otherwise an error.
 */
int netro_mpt_query_cmd(struct netro_ibdev *ndev, u32 mpt_index,
			struct netro_mpt_params *param);

/**
 * Initialize a microcode MPT and any associated MTT entries.
 *
 * @ndev: The IB RoCE device.
 * @mr: The user memory registration request.
 * @comp_page: The number of compound pages. Zero for DMA
 * memory region.
 * @comp_order: The order of the compound pages. Zero for DMA
 * memory region.
 *
 * Returns 0 on success; otherwise an error.
 */
int netro_init_mpt(struct netro_ibdev *ndev, struct netro_mr *mr,
			int comp_pages, int comp_order);

/**
 * Release MPT resources associated with a memory registration.
 *
 * @ndev: The IB RoCE device.
 * @mr: The memory registration.
 *
 * Returns 0 on success; otherwise an error.
 */
void netro_cleanup_mpt(struct netro_ibdev *ndev, struct netro_mr *mr);

/*
 * We are using a separate structure from the software entry in anticipation
 * that it will be required when table is managed by core software.
 */
enum {
	NETRO_SGID_PARAM_COUNT_SHIFT		= 16,
	NETRO_SGID_PARAM_COUNT_MASK		= 0x0FF,
	NETRO_SGID_PARAM_PORT_NUM_SHIFT		= 24
};

struct netro_gid_entry_param {
	u8		gid_type;
	u8		valid;
	u8		rsvd[2];
	union {
		u32	gid_word[4];
		u8	gid[16];
	};
};

/**
 * Write a ports GID table.
 *
 * @ndev: The IB RoCE device.
 * @port_num: The port number to update the GID table [0 based].
 * @num_entries: The size of the GID table.
 *
 * Returns 0 on success; otherwise an error.
 */
int netro_write_sgid_table(struct netro_ibdev *ndev, int port_num,
			int num_entries);

struct netro_gid_entry;
/**
 * Read a ports GID table.
 *
 * @ndev: The IB RoCE device.
 * @port_num: The port number the desired ports GID table [0 based].
 * @entries: The location to be initialized to the GID table entries read.
 * @num_entries: The size of the GID table to read.
 *
 * Returns 0 on success; otherwise an error.
 */
int netro_read_sgid_table(struct netro_ibdev *ndev, int port_num,
		struct netro_gid_entry *entries, int num_entries);

/*
 * We are using a separate structure from the software entry in anticipation
 * that it will be required when table is managed by core software.
 */
enum {
	NETRO_SMAC_PARAM_COUNT_SHIFT		= 16,
	NETRO_SMAC_PARAM_COUNT_MASK		= 0x0FF,
	NETRO_SMAC_PARAM_PORT_NUM_SHIFT		= 24
};

/*
 * Note that MAC byte offsets should be stored as mac: 1, 0, and
 * mac_l: 5, 4, 3, 1.
 */
struct netro_mac_entry_param {
	u8		mac[2];
	u8		valid;
	u8		rsvd;
	u8		mac_l[4];
};

/**
 * Write a ports source MAC table.
 *
 * @ndev: The IB RoCE device.
 * @port_num: The port number to update the source MAC table [0 based].
 * @num_entries: The size of the source MAC table.
 *
 * Returns 0 on success; otherwise an error.
 */
int netro_write_smac_table(struct netro_ibdev *ndev,
			int port_num, int num_entries);

/**
 * Simple development test to force microcode to generate EQE and
 * validate.
 *
 * @ndev: RoCEe IB device.
 * @eqn: The EQN number.
 * @cnt: Then number of EQE to generate.
 *
 * Returns 0 on success, otherwise and error.
 */
int netro_test_eq_enqueue(struct netro_ibdev *ndev, int eqn, int cnt);

/**
 * Initialize the microcode command/status interface resources and state.
 *
 * @ndev: RoCE IB device.
 *
 * Returns 0 on success, otherwise an error code.
 */
int netro_init_cmdif(struct netro_ibdev *ndev);

/**
 * Release microcode command/status interface resources.
 *
 * @ndev: RoCE IB device.
 */
void netro_cleanup_cmdif(struct netro_ibdev *ndev);

/**
 * Return the string representation of a command opcode.
 *
 * @opcode: The opcode desired.
 *
 * Returns the associated string, or the undefined string.
 */
const char *netro_opcode_to_str(u8 opcode);

/**
 * Return the string representation of a command status.
 *
 * @status: The status for which the string is desired.
 *
 * Returns the associated string, or the undefined string.
 */
const char *netro_status_to_str(u8 status);

/**
 * Return the string representation of an interrupt event
 *
 * @event_type: The event type for which the string is desired.
 *
 * Returns the associated string, or the undefined string.
 */
const char *netro_event_to_str(u8 event_type);

#endif /* NETRO_UCIF_H */
