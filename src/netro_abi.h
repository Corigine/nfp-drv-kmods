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

/*
 * netro_abi.h - Provides Netro RoCEv2 kernel to provider message details.
 */
#ifndef NETRO_ABI_H
#define NETRO_ABI_H

#include <linux/compiler.h>

/* Internal netro provider ABI between user library and kernel driver */
#define NETRO_UVERBS_ABI_VERSION	1

/*
* _resp structures indicate additional data beyond the uverbs default
* passed from entro back to libnetro.
*/
struct netro_ib_alloc_ucontext_resp {
	__u32	model;			/* Chipset family */
	__u32	max_qp;			/* Max for the device */
	__u32   num_cqe;		/* Actual size of CQ */
} __packed;

struct netro_ib_alloc_pd_resp {
	__u32	pd_index;		/* PD object index */
	__u32	rsvd;
} __packed;

struct netro_ib_create_cq_resp {
	__u64	cq_base_addr;		/* Physical address to map */
	__u64	ci_mbox_base_addr;	/* Physical mailbox address to map */
	__u32	cq_size;		/* CQ size for mapping */
	__u32	ci_mbox_size;		/* Mailbox size for mapping */
	__u32	cqn;			/* CQ object index */
	__u32	num_cqe;		/* Actual size of CQ */
} __packed;

 enum {
	NETRO_WQ_WQE_SPARES             = 8
 };

struct netro_ib_create_qp_resp {
	__u64	wq_base_addr;		/* Physical address to map */
	__u32	wq_size;		/* Work queue size for mapping */
	__u32	sq_offset;		/* Offset of SQ in  mapping */
	__u32	rq_offset;		/* Offset of RQ in  mapping */
	__u32	swqe_size;		/* Actual SQ WQE size */
	__u32	num_swqe;		/* Actual number of SQ WQEs */
	__u32	rwqe_size;		/* Actual RQ WQE size */
	__u32	num_rwqe;		/* Actual number of RQ WQEs */
	__u32   spares;         /* Runway of unused WQEs */
	__u32   resvd;
};

enum {
	NETRO_AV_IBSR_IPD_SHIFT         = 24,
	NETRO_AV_PD_MASK                = 0x00FFFFFF,
	NETRO_AV_ROCE_V2_IPV4_GID_TYPE  = 1,
	NETRO_AV_ROCE_V2_IPV6_GID_TYPE  = 2
};

struct netro_av {
       /*
        * Destination MAC is stored in 32-bit word byte swapped
        * form so that this transformation is not done on each
        * SWQE post.  MAC offsets are stored in the following
        * order: 3, 2, 1, 0, 5, 4. The DMA of the SWQE will undo
        * this swap.
        */
       __u8    d_mac[6];
       __le16  vlan;                   /* Deprecated, set to zero */
       __u8    port;                   /* Physical port, 0 based */

       /* We classify GID type as RoCEv2 and indicate IPv4 or IPv6 */
       __u8    gid_type;
       __u8    s_mac_ndx;              /* Deprecated, set to zero */
       __u8    v_id;                   /* Deprecated, set to zero */
       __u8    traffic_class;
       __u8    hop_limit;
       __u8    s_gid_ndx;              /* Source GID table entry to use */
       __u8    service_level;
       __le32  flow_label;             /* Always byte swapped */
       /*
        * Destination GID is stored in 32-bit byte swapped form so that
        * this transformation is not done on each SWQE post.  GID byte
        * offsets are stored in the following order: 3, 2, 1 0, 7, 6, 5, 4,
        * 11, 10, 9, 8, 15, 14, 13, 12. The DMA of the SWQE will undo this
        * swap.
        */
       union {
               __u32   d_gid_word[4];
               __u8    d_gid[16];
       };
       __le32  ib_sr_ipd;
};

enum {
	NETRO_DB_SQ_ADDR_OFFSET         = 4,
	NETRO_DB_CQ_ADDR_OFFSET         = 0x20,
	NETRO_DB_CQCI_ADDR_OFFSET       = 0x24,
	NETRO_DB_WA_BIT                 = 1 << 11,

	NETRO_DB_SQ_MASK                = 0x00FFFFFF,
	NETRO_DB_CQN_MASK               = 0x00FFFFFF,
	NETRO_DB_CQ_CONS_MASK           = 0x00FFFFFF,
	NETRO_DB_CQ_SEQ_SHIFT           = 30,
	NETRO_DB_CQ_ARM_ANY_BIT         = 1 << 24,
	NETRO_DB_FIN_BIT                = 1 << 30,
};

#endif /* NETRO_ABI_H */
