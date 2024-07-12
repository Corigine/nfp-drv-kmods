/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright (C) 2023 Corigine, Inc. */

#ifndef CRDMA_UCIF_H
#define CRDMA_UCIF_H

#include <linux/compiler.h>
#include "crdma_ib.h"
#include "crdma_hw.h"

/*
 * crdma_ucif - Provides the driver/NFP micro-code interface.
 */

/*
 * The kernel driver configures/commands microcode using a set
 * of commands that are posted to microcode via the HCA
 * command/status interface register.
 */
#define CRDMA_CMDIF_ABI_VERSION		0

/* Microcode command interface opcodes */
enum {
	CRDMA_CMD_NO_OP			= 1,
	CRDMA_CMD_QUERY_DEV_CAP		= 2,
	CRDMA_CMD_QUERY_UCODE		= 3,
	CRDMA_CMD_QUERY_NIC		= 4,
	CRDMA_CMD_QUERY_HCA		= 5,
	CRDMA_CMD_QUERY_PORT		= 6,
	CRDMA_CMD_HCA_ENABLE		= 7,
	CRDMA_CMD_HCA_DISABLE		= 8,
	CRDMA_CMD_ROCE_PORT_ENABLE	= 9,
	CRDMA_CMD_ROCE_PORT_DISABLE	= 10,
	CRDMA_CMD_SET_BS_HOST_MEM_SIZE	= 11, //Deprecated
	CRDMA_CMD_MAP_BS_HOST_MEM	= 12, //Deprecated
	CRDMA_CMD_UNMAP_BS_HOST_MEM	= 13, //Deprecated
	CRDMA_CMD_MPT_CREATE		= 14,
	CRDMA_CMD_MPT_DESTROY		= 15,
	CRDMA_CMD_MPT_QUERY		= 16,
	CRDMA_CMD_MTT_WRITE		= 17,
	CRDMA_CMD_MTT_READ		= 18,
	CRDMA_CMD_MAPT_SYNC		= 19,
	CRDMA_CMD_SET_PORT_GID_TABLE	= 20,
	CRDMA_CMD_GET_PORT_GID_TABLE	= 21,
	CRDMA_CMD_SET_PORT_MAC_TABLE	= 22,
	CRDMA_CMD_GET_PORT_MAC_TABLE	= 23,
	CRDMA_CMD_SET_PORT_VLAN_TABLE	= 24,
	CRDMA_CMD_GET_PORT_VLAN_TABLE	= 25,
	CRDMA_CMD_EQ_CREATE		= 26,
	CRDMA_CMD_EQ_DESTROY		= 27,
	CRDMA_CMD_EQ_MAP		= 28,
	CRDMA_CMD_QP_MODIFY		= 29,
	CRDMA_CMD_QP_QUERY		= 30,
	CRDMA_CMD_QP_SUSPEND		= 31,
	CRDMA_CMD_QP_RESUME		= 32,
	CRDMA_CMD_CQ_CREATE		= 33,
	CRDMA_CMD_CQ_DESTROY		= 34,
	CRDMA_CMD_CQ_MODIFY		= 35,
	CRDMA_CMD_CQ_RESIZE		= 36,
	CRDMA_CMD_SRQ_CREATE		= 37,
	CRDMA_CMD_SRQ_DESTROY		= 38,
	CRDMA_CMD_SRQ_SET_ARM_LIMIT	= 39,
	CRDMA_CMD_MCG_CREATE		= 40,
	CRDMA_CMD_MCG_DESTROY		= 41,
	CRDMA_CMD_MCG_ATTACH		= 42,
	CRDMA_CMD_MCG_DETACH		= 43,
	CRDMA_CMD_SET_PORT_MTU		= 49,
	CRDMA_CMD_DCQCN_ENABLE		= 50,
	CRDMA_CMD_RETRANS_ENABLE	= 51,
	CRDMA_CMD_BOND_CONFIG		= 52,
	CRDMA_CMD_HIGH_PERF_READ_ENABLE	= 53
};

/* Microcode QP Modify opcode modifiers */
enum {
	CRDMA_QP_MODIFY_RST2INIT	= 1,
	CRDMA_QP_MODIFY_INIT2RTR	= 2,
	CRDMA_QP_MODIFY_INIT2INIT	= 3,
	CRDMA_QP_MODIFY_RTR2RTS		= 4,
	CRDMA_QP_MODIFY_RTS2RTS		= 5,
	CRDMA_QP_MODIFY_SQER2RTS	= 6,
	CRDMA_QP_MODIFY_RTS2SQD		= 7,
	CRDMA_QP_MODIFY_SQD2SQD		= 8,
	CRDMA_QP_MODIFY_SQD2RTS		= 9,
	CRDMA_QP_MODIFY_2ERR		= 10,
	CRDMA_QP_MODIFY_2RST		= 11
};

enum {
	CRDMA_BOND_MOD_CREATE	= 0,
	CRDMA_BOND_MOD_UPDATE,
	CRDMA_BOND_MOD_DESTROY
};

/* Microcode command interface status values returned by microcode */
enum {
	CRDMA_STS_OK			= 0,
	CRDMA_STS_UCODE_CORRUPTED	= 1,
	CRDMA_STS_UCODE_INTERNAL_ERR	= 2,
	CRDMA_STS_UNSUPPORTED_OPCODE	= 3,
	CRDMA_STS_BAD_PARAMETER		= 4,
	CRDMA_STS_BAD_SYSTEM_STATE	= 5,
	CRDMA_STS_BAD_CNTRL_OBJ_REF	= 6,
	CRDMA_STS_CNTRL_OBJ_BUSY	= 7,
	CRDMA_STS_EXCEEDS_HCA_LIMITS	= 8,
	CRDMA_STS_BAD_CNTRL_OBJ_STATE	= 9,
	CRDMA_STS_INVALID_INDEX		= 10,
	CRDMA_STS_BAD_QP_STATE		= 11,
	CRDMA_STS_BAD_SIZE		= 12,
	CRDMA_STS_INVALID_PORT		= 13,
};

enum {
	CRDMA_CMDIF_DRIVER_MAX_CMDS	= 16,	/* Driver limit, not ucode */
	CRDMA_CMDIF_GEN_TIMEOUT_MS	= 2000,
	CRDMA_CMDIF_GO_TIMEOUT_MS	= 2000,
	CRDMA_CMDIF_MBOX_SIZE		= 4096,
	CRDMA_CMDIF_POLL_TOKEN		= 0xA5A5
};

/* DMA mailbox buffer for both command input and output */
struct crdma_cmd_mbox {
	void		*buf;
	dma_addr_t	dma_addr;
};

struct crdma_cmd {
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
struct crdma_event_cmd {
	struct	completion comp;
	int		next;
	u64		output_param;
	u16		token;
	u8		status;
};

enum {
	CRDMA_WQ_WQE_SPARES	= 8
};

struct crdma_av {
	/*
	 * Destination MAC is stored in 32-bit word byte swapped
	 * form so that this transformation is not done on each
	 * SWQE post.  MAC offsets are stored in the following
	 * order: 3, 2, 1, 0, 5, 4. The DMA of the SWQE will undo
	 * this swap.
	 */
	__u8	d_mac[6];
	__le16	vlan;
	__u8	port;			/* Physical port, 0 based */

	/* We classify GID type as RoCEv2 and indicate IPv4 or IPv6 */
	__u8	gid_type;
	__u8	s_mac_ndx;		/* Deprecated, set to zero */
	__u8	v_id;			/* If vlan is valid, set to 1 */
	__u8	traffic_class;		/* Used for Traffic class */
	__u8	hop_limit;
	__u8	s_gid_ndx;		/* Source GID table entry to use */
	__u8	service_level;		/* Used for PCP if vlan tag exist */
	__le32	flow_label;		/* Always byte swapped */
	/*
	 * Destination GID is stored in 32-bit byte swapped form so that
	 * this transformation is not done on each SWQE post.  GID byte
	 * offsets are stored in the following order: 3, 2, 1 0, 7, 6, 5, 4,
	 * 11, 10, 9, 8, 15, 14, 13, 12. The DMA of the SWQE will undo this
	 * swap.
	 */
	union {
		__u32	d_gid_word[4];
		__u8	d_gid[16];
	};
	__le32	ib_sr_ipd;
};

enum {
	CRDMA_AV_IBSR_IPD_SHIFT		= 24,
	CRDMA_AV_PD_MASK		= 0x00FFFFFF,
	CRDMA_AV_ROCE_V2_IPV4_GID_TYPE	= 1,
	CRDMA_AV_ROCE_V2_IPV6_GID_TYPE	= 2
};

/* Microcode hardware specific work request for Send Queue WQE */
enum {
	CRDMA_WQE_RDMA_WRITE_OP			= 0,
	CRDMA_WQE_RDMA_WRITE_WITH_IMM_OP	= 1,
	CRDMA_WQE_SEND_OP			= 2,
	CRDMA_WQE_SEND_WITH_IMM_OP		= 3,
	CRDMA_WQE_RDMA_READ_OP			= 4,
	CRDMA_WQE_LOCAL_INVAL_OP		= 7,
	CRDMA_WQE_SEND_WITH_INVAL_OP		= 9,
/* The value comes from ib_wr_opcode */
	CRDMA_WQE_FAST_REG_MR_OP		= 32
};

enum {
	CRDMA_WQE_CTRL_FENCE_BIT		= 1 << 0,
	CRDMA_WQE_CTRL_SOLICITED_BIT		= 1 << 1,
	CRDMA_WQE_CTRL_SIGNAL_BIT		= 1 << 2,
	CRDMA_WQE_CTRL_LOOPBACK_BIT		= 1 << 3,
	CRDMA_WQE_CTRL_INLINE_DATA_BIT		= 1 << 4,
#if 0 /* The following is required, but not yet used */
	CRDMA_WQE_CTRL_STRONG_ORDER_BIT		= 1 << 5,
#endif
	CRDMA_WQE_CTRL_GSI_BIT			= 1 << 6
};

struct crdma_swqe_owner {
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

struct crdma_swqe_ctrl {
	struct crdma_swqe_owner	owner;

	/*
	 * Immediate data or Invalidate information, always swapped by
	 * driver to undo byte swap done by hardware DMA of SWQE, leaving
	 * in user defined endian byte order.
	 */
	u32	imm_inval;
} __packed;

/* SWQE UD address vector information */
struct crdma_swqe_ud_addr {
	struct crdma_av	av;
	__le32		dest_qpn;
	__le32		qkey;
} __packed;

/* Send WQE Remote Address Entry */
struct crdma_swqe_rem_addr {
	__le32		rem_io_addr_h;
	__le32		rem_io_addr_l;
	__le32		r_key;
	__le32		rsvd;
} __packed;

/* Send and Receive WQE Scatter Gather Entry */
struct crdma_wqe_sge {
	__le32		io_addr_h;
	__le32		io_addr_l;
	__le32		l_key;
	__le32		byte_count;
} __packed;

/* Send WQE In-line data header, byte_count inline data follows header */
struct crdma_swqe_inline {
	__le16		byte_count;
	__le16		rsvd;
	u8		data[0];
};

/* Send WQE Fast Register Memory Region */
enum {
	CRDMA_MR_ACCESS_FLAGS_L_WRITE_EN	= 1 << 0,
	CRDMA_MR_ACCESS_FLAGS_R_READ_EN		= 1 << 1,
	CRDMA_MR_ACCESS_FLAGS_R_WRITE_EN	= 1 << 2,
	CRDMA_MR_ACCESS_FLAGS_ATOMIC_EN		= 1 << 3,
	CRDMA_MR_ACCESS_FLAGS_L_READ_EN		= 1 << 4,
	CRDMA_MR_ACCESS_FLAGS_INVAL_EN		= 1 << 5
};

enum{
	CRDMA_MR_TYPE_DEFAULT	= 0,
	CRDMA_MR_TYPE_FRMR	= 1,
	CRDMA_MR_TYPE_DMA	= 2
};

struct crdma_swqe_frmr {
	__le32		flags;
	__le32		key;
	__le32		page_list_paddr_h;
	__le32		page_list_paddr_l;
	__le32		io_addr_h;
	__le32		io_addr_l;
	__le32		rsvd;
	__le32		length;
	__le32		offset;
	__le32		page_size;
} __packed;

struct crdma_ud_swqe {
	struct crdma_swqe_ud_addr	addr;
	union {
		struct crdma_swqe_inline inline_data;
		struct crdma_wqe_sge	 sg[0];
	};
} __packed;

struct crdma_rc_swqe {
	struct crdma_swqe_rem_addr	rem_addr;
	union {
		struct crdma_swqe_inline inline_data;
		struct crdma_swqe_frmr	 frmr;
		struct crdma_wqe_sge	 sg[0];
	};
} __packed;

struct crdma_swqe {
	struct crdma_swqe_ctrl		ctrl;
	union {
		struct crdma_ud_swqe	ud;
		struct crdma_rc_swqe	rc;
	};
} __packed;

/*
 * Hardware receive work queue entry (WQE) formats.
 */
struct crdma_rwqe_ctrl {
	__le32			ownership;
	uint8_t			num_sge;
	uint8_t			rsvd;
	__le16			next_srq_wqe_ndx;
} __packed;

struct crdma_rwqe {
	struct crdma_rwqe_ctrl	ctrl;
	struct crdma_wqe_sge	sg[0];
} __packed;

/*
 * Microcode event queues are used to deliver interrupt event data
 * to the provider driver.
 */
enum {
	CRDMA_EQ_COMPLETION_EVENTS	= 1 << 0,
	CRDMA_EQ_ASYNC_EVENTS		= 1 << 1,
	CRDMA_EQ_EVENT_MASK		= CRDMA_EQ_COMPLETION_EVENTS |
					  CRDMA_EQ_ASYNC_EVENTS,
	CRDMA_EQ_OWNER_BIT		= 1 << 0
};

struct crdma_eq {
	struct crdma_ibdev	*dev;
	struct crdma_mem	*mem;
	struct crdma_eqe	*eqe;
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
	struct tasklet_struct 	tasklet;
};

struct crdma_eq_table {
	u32			num_eq;
	struct crdma_eq		*eq;
};

/*
 * Event queue entry format is defined by the event type. Three classes
 * of events provide additional information: affiliated, command status,
 * and port change events.
 */
enum {
	CRDMA_EQ_CQ_COMPLETION_NOTIFY		= 1,
	CRDMA_EQ_CQ_ERROR			= 2,
	CRDMA_EQ_QP_COMM_ESTABLISHED		= 5,
	CRDMA_EQ_QP_SQ_DRAINED			= 6,
	CRDMA_EQ_QP_SQ_LAST_WQE			= 7,
	CRDMA_EQ_QP_CATASTROPHIC_ERROR		= 8,
	CRDMA_EQ_QP_INVALID_REQUEST		= 9,
	CRDMA_EQ_QP_ACCESS_ERROR		= 10,
	CRDMA_EQ_SRQ_LIMIT_REACHED		= 11,
	CRDMA_EQ_SRQ_CATASTROPHIC_ERROR		= 12,
	CRDMA_EQ_EQ_OVERRUN_ERROR		= 13,
	CRDMA_EQ_CMDIF_COMPLETE			= 14,
	CRDMA_EQ_LOCAL_CATASTROPHIC_ERROR	= 15,
	CRDMA_EQ_PORT_CHANGE			= 16,
	CRDMA_EQ_MGMT_PORT_CHANGE		= 17,
	CRDMA_EQ_MICROCODE_WARNING		= 18
};

/* Format of EQE written by microcode */
struct crdma_eqe {
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
 * @dev: RoCE IB device.
 * @index: The EQN relative to this device.
 * @entries_log2: The number of EQE requested expressed as a log2 value.
 * @intr: The device interrupt to use (message table index).
 * @vector: The MSI/MSI-X interrupt vector/IRQ assigned to the EQ.
 * @events: The events that should be delivered to this EQ.
 *
 * Returns 0 on success, otherwise an error.
 */
int crdma_init_eq(struct crdma_ibdev *dev, int index, int entries_log2,
		u16 intr, u32 vector, u32 events);

/**
 * Disable EQ interrupts and release microcode event queue resources.
 *
 * @dev: The RoCE IB device.
 * @eqn: The EQ number.
 */
void crdma_cleanup_eq(struct crdma_ibdev *dev, int eqn);

/**
 * Verify microcode command interface is operational by
 * requesting execution of a microcode no-op command.
 *
 * @dev: RoCE IB device.
 *
 * Returns 0 on success, otherwise an error.
 */
int crdma_noop(struct crdma_ibdev *dev);

/*
 * Query Device Capabilities output mailbox format.
 */
enum {
	CRDMA_DEV_CAP_FLAG_RC		= 1 << 0,
	CRDMA_DEV_CAP_FLAG_UD		= 1 << 1,
	CRDMA_DEV_CAP_FLAG_UC		= 1 << 2,
	CRDMA_DEV_CAP_FLAG_XRC		= 1 << 3,
	CRDMA_DEV_CAP_FLAG_PHYS		= 1 << 4,
	CRDMA_DEV_CAP_FLAG_FRMR		= 1 << 5,
	CRDMA_DEV_CAP_FLAG_MW		= 1 << 6,
	CRDMA_DEV_CAP_FLAG_SRQ		= 1 << 7,

	CRDMA_DEV_CAP_PORT_SHIFT	= 3,
	CRDMA_DEV_CAP_PORT_MASK		= 0x1F,
};

struct crdma_dev_cap_param {
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
 * @dev: RoCE IB device.
 * @caps: Location to return device capabilities.
 *
 * Returns 0 on success, otherwise an error code.
 */
int crdma_query_dev_cap(struct crdma_ibdev *dev,
		struct crdma_dev_cap_param *cap);

/*
 * Query HCA microcode attributes output mailbox format
 */
struct crdma_query_ucode_attr {
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
 * @dev: RoCE IB device.
 * @attr: Structure to be initialized with microcode attributes.
 *
 * Returns 0 on success, otherwise an error.
 */
int crdma_query_ucode(struct crdma_ibdev *dev,
		struct crdma_query_ucode_attr *attr);

/**
 * Query NIC attributes
 *
 * @dev: RoCE IB device.
 * @boardid: Returns hardware board ID in host order.
 *
 * Returns 0 on success, otherwise an error.
 */
int crdma_query_nic(struct crdma_ibdev *dev, uint32_t *boardid);

/*
 * HCA enable parameters - not yet defined.
 */
struct crdma_hca_enable {
	__le32	undefined_1;
	__le32	undefined_2;
} __packed;

/**
 * Enable HCA, passing any tunable parameters. Microcode
 * should acquire any microcode RoCEv2 specific HCA resources.
 *
 * @dev: RoCE IB device.
 *
 * Returns 0 on success, otherwise an error.
 */
int crdma_hca_enable(struct crdma_ibdev *dev);

/**
 * Disable HCA in preparation for shutdown. The HCA should
 * should release any microcode RoCEv2 specific HCA resources.
 *
 * @dev: RoCE IB device.
 *
 * Returns 0 on success, otherwise an error.
 */
int crdma_hca_disable(struct crdma_ibdev *dev);

/*
 * Write MTT entry input mailbox parameter format
 */
struct crdma_mtt_write_entry {
	__le32		paddr_h;
	__le32		paddr_l;
} __packed;

struct crdma_mtt_write_param {
	__le32		rsvd;
	__le32		base_mtt_ndx;
	struct crdma_mtt_write_entry entry[];
} __packed;

#define CRDMA_MTT_PER_WRITE_CMD	((CRDMA_CMDIF_MBOX_SIZE - sizeof(u64))	\
				/ sizeof(struct crdma_mtt_write_entry))

/**
 * Write a consecutive block of MTT entries for translation of I/O
 * virtual addresses to DMA bus addresses.
 *
 * @dev: The RoCE IB device.
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
int crdma_mtt_write_sg(struct crdma_ibdev *dev, struct scatterlist *sg_list,
			int num_sg, u32 base_mtt, u32 num_mtt,
			unsigned long page_size, int comp_page, int comp_order);

/*
 * Create a microcode event queue.
 */
enum {
	CRDMA_EQ_CREATE_EQN_MASK		= 0x01F,

	CRDMA_EQ_CREATE_LOG2_PAGE_SZ_SHIFT	= 27,
	CRDMA_EQ_CREATE_PHYS_BIT_SHIFT		= 24,
	CRDMA_EQ_CREATE_EQ_PAGE_OFF_MASK	= 0x00FFFFFF
};

struct crdma_eq_params {
	u8		eqn;
	u8		eqe_log2;
	__le16		intr;
	__le32		page_info;
	__le32		mtt_index;
	__le16		time_mod;
	__le16		event_mod;
} __packed;

struct crdma_eq;

struct crdma_eq_map_params {
	__le32		reserved1;
	__le32		event:8;
	__le32		unused1:8;
	__le32		reserved2:16;
} __packed;

/**
 * Create a microcode event queue control object.
 *
 * @dev: RoCE IB device.
 * @eq: The driver EQ object.
 *
 * Returns 0 on success, otherwise an error.
 */
int crdma_eq_create_cmd(struct crdma_ibdev *dev, struct crdma_eq *eq);

/**
 * Destroy a microcode event queue control object.
 *
 * @dev: RoCE IB device.
 * @eq: The driver EQ object.
 *
 * Returns 0 on success, otherwise an error.
 */
int crdma_eq_destroy_cmd(struct crdma_ibdev *dev, struct crdma_eq *eq);

/**
 * Map event types to an existing EQ.
 *
 * @dev: RoCE IB device.
 * @eqn: The EQ number.
 * @events: The new event mask to map.
 *
 * Returns 0 on success, otherwise an error.
 */
int crdma_eq_map_cmd(struct crdma_ibdev *dev, u32 eqn, u32 events);

/**
 * Initialize the microcode event driven command interface
 *
 * @dev: RoCE IB device.
 *
 * Returns 0 on success, otherwise an error code.
 */
int crdma_init_event_cmdif(struct crdma_ibdev *dev);

/**
 * Release microcode event driven command interface resources.
 *
 * @dev: RoCE IB device.
 */
void crdma_cleanup_event_cmdif(struct crdma_ibdev *dev);

/*
 * Completion Queue Entry (CQE) format and accessors.
 */
enum {
	CRDMA_CQE_QPN_MASK		= 0x00FFFFFF,
	CRDMA_CQE_REM_QPN_MASK		= 0x00FFFFFF,
	CRDMA_CQE_SENDQ_FLAG_BIT	= 1 << 5,
	CRDMA_CQE_GRH_FLAG_BIT		= 1 << 6,
	CRDMA_CQE_OWNERSHIP_BIT		= 1
};

enum {
	CRDMA_CQE_NO_ERR		= 0,
	CRDMA_CQE_BAD_RESPONSE_ERR	= 1,
	CRDMA_CQE_LOCAL_LENGTH_ERR	= 2,
	CRDMA_CQE_LOCAL_ACCESS_ERR	= 3,
	CRDMA_CQE_LOCAL_QP_PROT_ERR	= 4,
	CRDMA_CQE_LOCAL_QP_OP_ERR	= 5,
	CRDMA_CQE_MEMORY_MGMT_OP_ERR	= 6,
	CRDMA_CQE_REMOTE_ACCESS_ERR	= 7,
	CRDMA_CQE_REMOTE_INV_REQ_ERR	= 8,
	CRDMA_CQE_REMOTE_OP_ERR		= 9,
	CRDMA_CQE_RNR_RETRY_ERR		= 10,
	CRDMA_CQE_TRANSPORT_RETRY_ERR	= 11,
	CRDMA_CQE_ABORTED_ERR		= 12,
	CRDMA_CQE_FLUSHED_ERR		= 13
};

struct crdma_cqe {
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
	CRDMA_CQ_CREATE_CQN_MASK		= 0x00FFFFFF,
	CRDMA_CQ_CREATE_LOG2_PAGE_SZ_SHIFT	= 27,
	CRDMA_CQ_CREATE_PHYS_BIT_SHIFT		= 24,
};

struct crdma_cq_params {
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
	CRDMA_CQ_MBOX_CONSUMER_NDX_MASK		= 0x00FFFFFF,
};

struct crdma_cq_resize_params {
	u8		rsvd1;
	u8		cq_log2_pg_sz;
	u8		rsvd2;
	u8		cqe_log2;
	__le32		cq_page_offset;
	__le32		cq_mtt_index;
};

struct crdma_ci_mbox {
	__le32		ci;		/* Consumer Index */
	__le32		last_db_state;
};

/*
 * Create a microcode shared receive queue.
 */
enum {
	CRDMA_SRQ_CREATE_LOG2_SWQE_MASK		= 0xFF,
	CRDMA_SRQ_CREATE_LOG2_PAGE_SZ_SHIFT	= 27,
	CRDMA_SRQ_CREATE_PHYS_BIT_SHIFT		= 24,
	CRDMA_SRQ_CREATE_LOG2_SWQE_SHIFT	= 16,
};

struct crdma_srq_params {
	__le16		max_srq_wr;
	__le16		max_sge_num;
	__le32		srq_limit;
	__le32		page_info;
	__le32		mtt_index;
} __packed;

struct crdma_cq;
struct crdma_uar;
struct crdma_srq;

/**
 * Create a completion queue control object.
 *
 * @dev: RoCE IB device.
 * @cq: The driver CQ object.
 * @uar: The UAR that may be used to ring the CQ's doorbell.
 *
 * Returns 0 on success, otherwise an error.
 */
int crdma_cq_create_cmd(struct crdma_ibdev *dev, struct crdma_cq *cq,
		struct crdma_uar *uar);

/**
 * Resize a completion queue.
 *
 * @dev: RoCE IB device.
 * @cq: The driver CQ object.
 *
 * Returns 0 on success, otherwise an error.
 */
int crdma_cq_resize_cmd(struct crdma_ibdev *dev, struct crdma_cq *cq);

/**
 * Destroy a microcode completion queue control object.
 *
 * @dev: RoCE IB device.
 * @cq: The driver CQ object.
 *
 * Returns 0 on success, otherwise an error.
 */
int crdma_cq_destroy_cmd(struct crdma_ibdev *dev, struct crdma_cq *cq);

/**
 * Create a share receive queue control object.
 *
 * @dev: RoCE IB device.
 * @csrq: The driver SRQ object.
 *
 * Returns 0 on success, otherwise an error.
 */
int crdma_srq_create_cmd(struct crdma_ibdev *dev, struct crdma_srq *csrq);

/**
 * Set arm limit for  a share receive queue.
 *
 * @dev: RoCE IB device.
 * @csrq: The driver SRQ object.
 *
 * Returns 0 on success, otherwise an error.
 */
int crdma_srq_set_arm_limit_cmd(struct crdma_ibdev *dev,
				struct crdma_srq *csrq);

/**
 * Destroy a share receive queue control object.
 *
 * @dev: RoCE IB device.
 * @csrq: The driver SRQ object.
 *
 * Returns 0 on success, otherwise an error.
 */
int crdma_srq_destroy_cmd(struct crdma_ibdev *dev, struct crdma_srq *csrq);

/* Queue Pair attributes that can be set and modified. */
/* QP control object parameters set on QP RESET to INIT transition */
enum {
	CRDMA_QP_ATTR_QPN_MASK			= 0x00FFFFFF,
	CRDMA_QP_ATTR_ACCESS_MASK		= 0x0F,
	CRDMA_QP_ATTR_MTU_SHIFT			= 4
};

struct crdma_qp_attr_params {
	u8		lb_mode;
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
	struct crdma_av	av;
} __packed;

/* QP control object parameters set on QP RESET to INIT transition */
enum {
	CRDMA_QP_CTRL_QPN_MASK			= 0x00FFFFFF,
	CRDMA_QP_CTRL_GSI_BIT_SHIFT		= 26,
	CRDMA_QP_CTRL_PHYS_BIT_SHIFT		= 27,
	CRDMA_QP_CTRL_SIGALL_BIT_SHIFT		= 28,
	CRDMA_QP_CTRL_SRQ_BIT_SHIFT		= 29,
	CRDMA_QP_CTRL_FRMR_BIT_SHIFT		= 30,
	CRDMA_QP_CTRL_R_LKEY_BIT_SHIFT		= 31,

	CRDMA_QP_CTRL_PD_MASK			= 0x00FFFFFF,
	CRDMA_QP_CTRL_SWQE_LOG2_MASK		= 0x0F,
	CRDMA_QP_CTRL_SWQE_LOG2_SHIFT		= 28,
	CRDMA_QP_CTRL_RWQE_LOG2_MASK		= 0x0F,
	CRDMA_QP_CTRL_RWQE_LOG2_SHIFT		= 24,

	CRDMA_QP_CTRL_SCQN_MASK			= 0x00FFFFFF,
	CRDMA_QP_CTRL_QPTYPE_SHIFT		= 28,
	CRDMA_QP_CTRL_RCQN_MASK			= 0x00FFFFFF,
	CRDMA_QP_CTRL_LOG2_PAGE_SZ_SHIFT	= 27,
	CRDMA_QP_CTRL_SRQN_MASK			= 0x00FFFFFF,
};

struct crdma_qp_ctrl_params {
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

struct crdma_qp_params {
	/* Attribute mask bits are the same as "ib_qp_attr_mask" values */
	__le32				attr_mask;
	struct crdma_qp_attr_params	attr;
	struct crdma_qp_ctrl_params	ctrl;
} __packed;

struct crdma_qp;
struct crdma_mr;

/**
 * Modify a queue pair control object.
 *
 * @dev: RoCE IB device.
 * @qp: The driver QP object.
 * @uar: The UAR that may be used to ring the QP's doorbell.
 * @qp_attr: IB attributes to modify.
 * @qp_attr_mask: Mask of IB attributes to modify/set.
 * @cur_state: The current state of the QP.
 * @new_state: The new state of the QP.
 *
 * Returns 0 on success, otherwise an error.
 */
int crdma_qp_modify_cmd(struct crdma_ibdev *dev, struct crdma_qp *qp,
		struct crdma_uar *uar, struct ib_qp_attr *qp_attr,
		int qp_attr_mask, enum ib_qp_state cur_state,
		enum ib_qp_state new_state);

/**
 * Query a queue pair control object for attributes.
 *
 * @dev: RoCE IB device.
 * @qp: The driver QP object.
 * @qp_attr: Returns IB attributes requested.
 * @qp_attr_mask: Mask of IB attributes requested.
 *
 * Returns 0 on success, otherwise an error.
 */
int crdma_qp_query_cmd(struct crdma_ibdev *dev, struct crdma_qp *qp,
		struct ib_qp_attr *qp_attr, int qp_attr_mask);

/**
 * Destroy a microcode queue pair control object.
 *
 * @dev: RoCE IB device.
 * @qp: The driver QP object.
 *
 * Returns 0 on success, otherwise an error.
 */
int crdma_qp_destroy_cmd(struct crdma_ibdev *dev, struct crdma_qp *qp);

/**
 * Notify microcode to enable RoCEv2 capability on a port.
 *
 * @dev: RoCE IB device.
 * @port: The port number to enable RoCEv2.
 *
 * Returns 0 on success, otherwise an error.
 */
int crdma_port_enable_cmd(struct crdma_ibdev *dev, u8 port);

/**
 * Notify microcode to disable RoCEv2 capability on a port.
 *
 * @dev: RoCE IB device.
 * @port: The port number to enable RoCEv2.
 *
 * Returns 0 on success, otherwise an error.
 */
int crdma_port_disable_cmd(struct crdma_ibdev *dev, u8 port);

/**
 * Transfer port mtu value to microcode.
 *
 * @dev: RoCE IB device.
 * @port: The port number to enable RoCEv2.
 * @mtu: MTU value
 *
 * Returns 0 on success, otherwise an error.
 */
int crdma_set_port_mtu_cmd(struct crdma_ibdev *dev, u8 port, u32 mtu);

/**
 * Enable or Disable dcqcn to microcode.
 *
 * @dev: RoCE IB device.
 * @enabled: TRUE: to enable, FALSE: to disable
 * Returns 0 on success, otherwise an error.
 */
int crdma_dcqcn_enable_cmd(struct crdma_ibdev *dev, u8 enabled);

/**
 * Enable or Disable ooo/timeout retransmit to microcode.
 *
 * @dev: RoCE IB device.
 * @enabled: high 4bits: ooo, low 4bits:
 *           timeout; 0x1: to enable, 0x0: to disable
 * Returns 0 on success, otherwise an error.
 */
int crdma_retrans_enable_cmd(struct crdma_ibdev *dev, u8 enabled);

/**
 * Enable or Disable high performance of bidirtional READ.
 *
 * @dev: RoCE IB device.
 * @enabled:  0x1: to enable, 0x0: to disable
 * Returns 0 on success, otherwise an error.
 */
int crdma_high_perf_read_enable_cmd(struct crdma_ibdev *dev, u8 enabled);

/**
 * Issue microcode MPT create command.
 *
 * @dev: The IB RoCE device.
 * @cmr: The memory region associated with the MPT.
 *
 * Returns 0 on success, otherwise an error.
 */
int crdma_mpt_create_cmd(struct crdma_ibdev *dev, struct crdma_mr *cmr);

/*
 * Create a Memory Access and Protection Table entry.
 */
enum {
	CRDMA_MPT_CREATE_PD_MASK		= 0x00FFFFFF,

	CRDMA_MPT_LOCAL_WRITE_ENABLE		= 1 << 24,
	CRDMA_MPT_REMOTE_READ_ENABLE		= 1 << 25,
	CRDMA_MPT_REMOTE_WRITE_ENABLE		= 1 << 26,
	CRDMA_MPT_ATOMIC_ENABLE			= 1 << 27,
	CRDMA_MPT_DMA				= 1 << 28,
	CRDMA_MPT_INVALIDATE_ENABLE		= 1 << 29,
	CRDMA_MPT_PHYS				= 1 << 30,
	CRDMA_MPT_FRMR_ENABLE			= 1 << 31,
	CRDMA_MPT_LOG2_PAGE_SZ_SHIFT		= 27,
};

struct crdma_mpt_params {
	__le32		key;
	__le32		flags_pd;
	__le32		io_addr_h;
	__le32		io_addr_l;
	__le32		length;
	__le32		page_info;
	__le32		mtt_index;
	__le32		frmr_entries;
	__le32		reserved;
} __packed;

/*
 * Memory and Protection Table command formats.
 */
struct crdma_mr;

/**
 * Issue a microcode MPT query command.
 *
 * @dev: The IB RoCE device.
 * @mpt_index: The MPT control object identifier to query.
 * @param: The MPT param returned from microcode in LE format.
 *
 * Returns 0 on success, otherwise an error.
 */
int crdma_mpt_query_cmd(struct crdma_ibdev *dev, u32 mpt_index,
			struct crdma_mpt_params *param);

/**
 * Initialize a microcode MPT and any associated MTT entries.
 *
 * @dev: The IB RoCE device.
 * @mr: The user memory registration request.
 * @comp_page: The number of compound pages. Zero for DMA
 * memory region.
 * @comp_order: The order of the compound pages. Zero for DMA
 * memory region.
 *
 * Returns 0 on success; otherwise an error.
 */
int crdma_init_mpt(struct crdma_ibdev *dev, struct crdma_mr *mr,
			int comp_pages, int comp_order);

/**
 * Release MPT resources associated with a memory registration.
 *
 * @dev: The IB RoCE device.
 * @mr: The memory registration.
 *
 * Returns 0 on success; otherwise an error.
 */
void crdma_cleanup_mpt(struct crdma_ibdev *dev, struct crdma_mr *mr);

/*
 * We are using a separate structure from the software entry in anticipation
 * that it will be required when table is managed by core software.
 */
enum {
	CRDMA_SGID_PARAM_COUNT_SHIFT		= 16,
	CRDMA_SGID_PARAM_COUNT_MASK		= 0x0FF,
	CRDMA_SGID_PARAM_PORT_NUM_SHIFT		= 24
};

struct crdma_gid_entry_param {
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
 * @dev: The IB RoCE device.
 * @port_num: The port number to update the GID table [0 based].
 * @num_entries: The size of the GID table.
 *
 * Returns 0 on success; otherwise an error.
 */
int crdma_write_sgid_table(struct crdma_ibdev *dev, int port_num,
			int num_entries);

struct crdma_gid_entry;
/**
 * Read a ports GID table.
 *
 * @dev: The IB RoCE device.
 * @port_num: The port number the desired ports GID table [0 based].
 * @entries: The location to be initialized to the GID table entries read.
 * @num_entries: The size of the GID table to read.
 *
 * Returns 0 on success; otherwise an error.
 */
int crdma_read_sgid_table(struct crdma_ibdev *dev, int port_num,
		struct crdma_gid_entry *entries, int num_entries);

/*
 * We are using a separate structure from the software entry in anticipation
 * that it will be required when table is managed by core software.
 */
enum {
	CRDMA_SMAC_PARAM_COUNT_SHIFT		= 16,
	CRDMA_SMAC_PARAM_COUNT_MASK		= 0x0FF,
	CRDMA_SMAC_PARAM_PORT_NUM_SHIFT		= 24
};

/*
 * Note that MAC byte offsets should be stored as mac: 1, 0, and
 * mac_l: 5, 4, 3, 1.
 */
struct crdma_mac_entry_param {
	u8		mac[2];
	u8		valid;
	u8		rsvd;
	u8		mac_l[4];
};

/**
 * Write a ports source MAC table.
 *
 * @dev: The IB RoCE device.
 * @port_num: The port number to update the source MAC table [0 based].
 * @num_entries: The size of the source MAC table.
 *
 * Returns 0 on success; otherwise an error.
 */
int crdma_write_smac_table(struct crdma_ibdev *dev,
			int port_num, int num_entries);

/**
 * Config roce bond.
 *
 * @dev: The IB RoCE device for roce bond function.
 * @mod: Action for the roce bond configure.
 * @tx_bm: Physical ports used for roce bond's traffic, represented by bitmap.
 *
 * Returns 0 on success; otherwise an error.
 */
int crdma_bond_config_cmd(struct crdma_ibdev *dev,
			u8 mod, u64 tx_bm);

/**
 * Simple development test to force microcode to generate EQE and
 * validate.
 *
 * @dev: RoCEe IB device.
 * @eqn: The EQN number.
 * @cnt: Then number of EQE to generate.
 *
 * Returns 0 on success, otherwise and error.
 */
int crdma_test_eq_enqueue(struct crdma_ibdev *dev, int eqn, int cnt);

/**
 * Initialize the microcode command/status interface resources and state.
 *
 * @dev: RoCE IB device.
 *
 * Returns 0 on success, otherwise an error code.
 */
int crdma_init_cmdif(struct crdma_ibdev *dev);

/**
 * Acquire a command input/output DMA buffer for a mailbox.
 *
 * @dev: The RoCE IB device.
 * @mbox: The mail box to assign the DMA buffer too.
 *
 * 0 on success, otherwise -ENOMEM.
 */
int crdma_init_mailbox(struct crdma_ibdev *dev,
		struct crdma_cmd_mbox *mbox);

/**
 * Issues an MTT_WRITE to set a block of HCA MTT values. The MTT values to be
 * written should have been initialized in the input mailbox.
 *
 * @dev: The RoCE IB device.
 * @base_mtt: The base MTT index for the first MTT entry in the block.
 * @num_mtt: The number of consecutive MTT entries to write.
 * @in_mbox: Input mailbox initialized with MTT entry values.
 *
 * Returns 0 on success, otherwise an error.
 */
int __crdma_mtt_write(struct crdma_ibdev *dev, u32 base_mtt,
		u32 num_mtt, struct crdma_cmd_mbox *in_mbox);

/**
 * Release mailbox DMA buffer previously acquired with crdma_init_mailbox().
 *
 * @dev: The RoCE IB device.
 * @mbox: The mail box for which the DMA buffer resources are to be released.
 */
void crdma_cleanup_mailbox(struct crdma_ibdev *dev,
		struct crdma_cmd_mbox *mbox);

/**
 * Release microcode command/status interface resources.
 *
 * @dev: RoCE IB device.
 */
void crdma_cleanup_cmdif(struct crdma_ibdev *dev);

/**
 * Return the string representation of a command opcode.
 *
 * @opcode: The opcode desired.
 *
 * Returns the associated string, or the undefined string.
 */
const char * const crdma_opcode_to_str(u8 opcode);

/**
 * Return the string representation of a command status.
 *
 * @status: The status for which the string is desired.
 *
 * Returns the associated string, or the undefined string.
 */
const char * const crdma_status_to_str(u8 status);

/**
 * Return the string representation of an interrupt event
 *
 * @event_type: The event type for which the string is desired.
 *
 * Returns the associated string, or the undefined string.
 */
const char * const crdma_event_to_str(u8 event_type);

#endif /* CRDMA_UCIF_H */
