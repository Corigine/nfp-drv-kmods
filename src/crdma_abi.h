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
 * crdma_abi.h - Provides Corigine RoCEv2 kernel to provider message details.
 */
#ifndef CRDMA_ABI_H
#define CRDMA_ABI_H

#include <linux/types.h>

/* Internal crdma provider ABI between user library and kernel driver */
#define CRDMA_UVERBS_ABI_VERSION	1

/*
* _resp structures indicate additional data beyond the uverbs default
* passed from entro back to libcrdma.
*/
struct crdma_ib_alloc_ucontext_resp {
	__u32	max_qp;			/* Max for the device */
	__u32   num_cqe;		/* Actual size of CQ */
};

struct crdma_ib_alloc_pd_resp {
	__u32	pd_index;		/* PD object index */
	__u32	rsvd;
};

struct crdma_ib_create_cq_resp {
	__aligned_u64	cq_base_addr;		/* Physical address to map */
	__aligned_u64	ci_mbox_base_addr;	/* Physical mailbox address to map */
	__u32		cq_size;		/* CQ size for mapping */
	__u32		ci_mbox_size;		/* Mailbox size for mapping */
	__u32		cqn;			/* CQ object index */
	__u32		num_cqe;		/* Actual size of CQ */
};

struct crdma_ib_create_qp_resp {
	__aligned_u64	wq_base_addr;		/* Physical address to map */
	__u32		wq_size;		/* Work queue size for mapping */
	__u32		sq_offset;		/* Offset of SQ in  mapping */
	__u32		rq_offset;		/* Offset of RQ in  mapping */
	__u32		swqe_size;		/* Actual SQ WQE size */
	__u32		num_swqe;		/* Actual number of SQ WQEs */
	__u32		rwqe_size;		/* Actual RQ WQE size */
	__u32		num_rwqe;		/* Actual number of RQ WQEs */
	__u32		spares;			/* Runway of unused WQEs */
	__u32		resvd;
};

struct crdma_ib_create_ah_resp {
	__u16		vlan;			/* VLAN ID */
	__u8		v_id;			/* VLAN is valid or not */
	__u8		gid_type;
	__u8		d_mac[6];
	__u8		traffic_class;		/* Used for Traffic class */
	__u8		rsvd[5];
};

struct crdma_ib_create_srq_resp {
	__aligned_u64	wq_base_addr;		/* WQE memory base address */
	__u32		wq_size;		/* WQE memory map size */
	__u32		wqe_size;		/* Size of WQE */
	__u32		wqe_cnt;		/* Actual number of WQE in Queque */
	__u32		srq_id;			/* Share receive queue ID */
	__u32		spares;			/* Runway of unused WQE */
	__u32		rsvd;
};

extern bool dcqcn_enable;
#endif /* CRDMA_ABI_H */
