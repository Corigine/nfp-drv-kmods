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

#include "nfpcore/nfp.h"
#include "nfpcore/nfp_roce.h"
#include "crdma_ib.h"
#include "crdma_hw.h"

int __crdma_write_cmdif(struct crdma_ibdev *dev, u64 input_param,
		u64 output_param, u32 input_mod, u8 opcode, u8 opcode_mod,
		u16 token, bool event)
{
	struct cmdif_reg __iomem *reg = dev->cmdif;
	unsigned long end_time;
	uint32_t cmd_word;

	if (!reg)
		return -EIO;

	if (pci_channel_offline(dev->nfp_info->pdev))
		return -EIO;

	/*
	 * Make sure if the previous command was non-polled that the
	 * command interface is ready to accept another command.
	 */
	end_time = jiffies + msecs_to_jiffies(CRDMA_CMDIF_GO_TIMEOUT_MS);

	while (crdma_cmdif_busy(dev)) {
		cond_resched();

		if (pci_channel_offline(dev->nfp_info->pdev))
			return -EIO;

		if (time_after_eq(jiffies, end_time)) {
			crdma_dev_err(dev, "Timeout:Command I/F not ready\n");
			return -EAGAIN;
		}
	}

	/*
	 * We are manually swapping from CPU to LE right now since we
	 * want to explicitly control it. Also we are using raw I/O
	 * and controlling the write/read ordering ourselves.
	 */
	__raw_writel((__force u32) cpu_to_le32(input_param >> 32),
				&reg->input_param_high);
	__raw_writel((__force u32) cpu_to_le32(input_param & 0xFFFFFFFFul),
			&reg->input_param_low);
	__raw_writel((__force u32) cpu_to_le32(input_mod), &reg->input_mod);
	__raw_writel((__force u32) cpu_to_le32(output_param >> 32),
				&reg->output_param_high);
	__raw_writel((__force u32) cpu_to_le32(output_param & 0xFFFFFFFFul),
			&reg->output_param_low);
	__raw_writel((__force u32) cpu_to_le32(((u32) token) <<
				CRDMA_CMDIF_TOKEN_SHIFT), &reg->token);

	cmd_word = (1 << CRDMA_CMDIF_GO_BIT) |
			(dev->toggle << CRDMA_CMDIF_TOGGLE_BIT) |
			(event ? (1 << CRDMA_CMDIF_EVENT_BIT) : 0) |
			(opcode_mod << CRDMA_CMDIF_OPCODE_MOD_SHIFT) |
			opcode;

	mb();
	__raw_writel((__force u32) cpu_to_le32(cmd_word),
			&reg->cmd_status);

	dev->toggle = dev->toggle ^ 1;
#if (!(VER_NON_RHEL_GE(5,2) || VER_RHEL_GE(8,0)))
	mmiowb();
#endif
	return 0;
}

bool crdma_cmdif_busy(struct crdma_ibdev *dev)
{
	struct cmdif_reg __iomem *reg = dev->cmdif;
	u32 status;

	if (!reg || pci_channel_offline(dev->nfp_info->pdev))
		return -EIO;

	status = le32_to_cpu(__raw_readl(&reg->cmd_status));
	return (status & (1 << CRDMA_CMDIF_GO_BIT)) ||
		(dev->toggle != !!(status & (1 << CRDMA_CMDIF_TOGGLE_BIT)));
}

int crdma_read_toggle(struct crdma_ibdev *dev)
{
	struct cmdif_reg __iomem *reg = dev->cmdif;
	u32 status;

	if (!reg || pci_channel_offline(dev->nfp_info->pdev))
		return -EIO;

	status = le32_to_cpu(__raw_readl(&reg->cmd_status));
	return !!(status & (1 << CRDMA_CMDIF_TOGGLE_BIT));
}

int __crdma_read_cmdif_results(struct crdma_ibdev *dev,
		u64 *output_param, u8 *status)
{
	struct cmdif_reg __iomem *reg = dev->cmdif;
	u32 out_low;
	u32 out_high;
	u32 cmdsts;

	if (!reg)
		return -EIO;

	if (pci_channel_offline(dev->nfp_info->pdev))
		return -EIO;

	if (output_param) {
		out_high = le32_to_cpu(__raw_readl(&reg->output_param_high));
		out_low  = le32_to_cpu(__raw_readl(&reg->output_param_low));
		*output_param = ((u64) out_high) << 32 | out_low;
	}

	if (status) {
		cmdsts = le32_to_cpu(__raw_readl(&reg->cmd_status));
		*status = (u8) (cmdsts >> CRDMA_CMDIF_STATUS_SHIFT);
	}
	return 0;
}

int crdma_acquire_pci_resources(struct crdma_ibdev *dev)
{
	dev->cmdif = dev->nfp_info->cmdif;
	dev->db_paddr = dev->nfp_info->db_base;
	return 0;
}

void crdma_free_pci_resources(struct crdma_ibdev *dev)
{
	return;
}

void crdma_cleanup_hw(struct crdma_ibdev *dev)
{
	pr_info("CRDMA HW specific cleanup\n");
	return;
}

void crdma_set_sq_db(struct crdma_ibdev *dev, u32 qpn)
{
	void __iomem *addr;
	u32 db;

	db = qpn & CRDMA_DB_SQ_MASK;
	addr = dev->priv_uar.map + CRDMA_DB_SQ_ADDR_OFFSET;
	__raw_writel((__force u32) cpu_to_le32(db), addr);
	mb();

	return;
}

void crdma_set_cq_db(struct crdma_ibdev *dev, u32 cqn, bool solicited)
{
	void __iomem *addr;
	u32 db;
	struct crdma_cq	*ccq;

	if (cqn >= dev->cap.ib.max_cq) {
		crdma_dev_warn(dev, "CQN (%u) is invalid.\n", cqn);
		return;
	}

	ccq = dev->cq_table[cqn];

	db = (ccq->arm_seqn << CRDMA_DB_CQ_SEQ_SHIFT) |
		(solicited ? 0 : CRDMA_DB_CQ_ARM_ANY_BIT) |
		(ccq->cqn & CRDMA_DB_CQN_MASK);
	addr = dev->priv_eq_uar.map + CRDMA_DB_CQ_ADDR_OFFSET;
	__raw_writel((__force u32) cpu_to_le32(db), addr);
	mb();

	return;
}

inline void crdma_set_eq_ci(struct crdma_ibdev *dev,  u32 eqn,
		u32 consumer_index, bool arm)
{
	void __iomem *addr;
	u32 ci;

	ci = (arm ? CRDMA_UAR_EQ_ARM_BIT : 0) |
		(consumer_index & CRDMA_UAR_EQ_CONSUMER_MASK);
	addr = dev->priv_eq_uar.map +
		(eqn * CRDMA_UAR_EQ_ADDR_INTERVAL_IN_PAGE);
	__raw_writel((__force u32) cpu_to_le32(ci), addr);
	mb();

	return;
}

