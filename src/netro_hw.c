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

#include "nfp.h"
#include "nfp_roce.h"
#include "netro_ib.h"
#include "netro_hw.h"
#include "nfp_cpp.h"
#include "nfp_plat.h"

int __netro_write_cmdif(struct netro_ibdev *ndev, u64 input_param,
		u64 output_param, u32 input_mod, u8 opcode, u8 opcode_mod,
		u16 token, bool event)
{
	struct cmdif_reg __iomem *reg = ndev->cmdif;
	unsigned long end_time;
	uint32_t cmd_word;

	if (!reg)
		return -EIO;

	if (pci_channel_offline(ndev->nfp_info->pdev))
		return -EIO;

#if 0 /* XXX: Test only */
	__netro_dump_cmdif(ndev);
#endif

	/*
	 * Make sure if the previous command was non-polled that the
	 * command interface is ready to accept another command.
	 */
	end_time = jiffies + msecs_to_jiffies(NETRO_CMDIF_GO_TIMEOUT_MS);

	while (netro_cmdif_busy(ndev)) {
		cond_resched();

		if (pci_channel_offline(ndev->nfp_info->pdev))
			return -EIO;

		if (time_after_eq(jiffies, end_time)) {
			netro_dev_err(ndev, "Timeout:Command I/F not ready\n");
			return -EAGAIN;
		}
	}

#if NETRO_DETAIL_INFO_DEBUG_FLAG
	pr_info("input_param: 0x%016llx\n", input_param);
	pr_info("output_param: 0x%016llx\n", output_param);
	pr_info("input_mod: 0x%08x\n", input_mod);
	pr_info("opcode (%d), opcode_mod(%d), token: 0x%04x\n",
			opcode, opcode_mod, token);
#endif

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
				NETRO_CMDIF_TOKEN_SHIFT), &reg->token);

	cmd_word = (1 << NETRO_CMDIF_GO_BIT) |
			(ndev->toggle << NETRO_CMDIF_TOGGLE_BIT) |
			(event ? (1 << NETRO_CMDIF_EVENT_BIT) : 0) |
			(opcode_mod << NETRO_CMDIF_OPCODE_MOD_SHIFT) |
			opcode;

#if 0
	pr_info("Current command word:0x%08x\n",
			le32_to_cpu(__raw_readl(&reg->cmd_status)));
#endif
	rmb();

#if NETRO_DETAIL_INFO_DEBUG_FLAG
	pr_info("Command word to post:0x%08X\n", cmd_word);
#endif

	wmb();
	__raw_writel((__force u32) cpu_to_le32(cmd_word),
			&reg->cmd_status);

	ndev->toggle = ndev->toggle ^ 1;
	mmiowb();
	return 0;
}

void __netro_dump_cmdif(struct netro_ibdev *ndev)
{
	struct cmdif_reg __iomem *reg = ndev->cmdif;

	/* For now we use "raw" to explicitly control endian conversion */
	pr_info("Dump of command interface registers: %p\n", reg);
	pr_info("input_parm_high:0x%08x\n",
			le32_to_cpu(__raw_readl(&reg->input_param_high)));
	pr_info("input_parm_low:0x%08x\n",
			le32_to_cpu(__raw_readl(&reg->input_param_low)));
	pr_info("input_mod:0x%08x\n",
			le32_to_cpu(__raw_readl(&reg->input_mod)));
	pr_info("output_parm_high:0x%08x\n",
			le32_to_cpu(__raw_readl(&reg->output_param_high)));
	pr_info("output_parm_low:0x%08x\n",
			le32_to_cpu(__raw_readl(&reg->output_param_low)));
	pr_info("token:0x%08x\n",
			le32_to_cpu(__raw_readl(&reg->token)));
	pr_info("cmd_status:0x%08x\n",
			le32_to_cpu(__raw_readl(&reg->cmd_status)));
}

bool netro_cmdif_busy(struct netro_ibdev *ndev)
{
	struct cmdif_reg __iomem *reg = ndev->cmdif;
	u32 status;

	if (!reg || pci_channel_offline(ndev->nfp_info->pdev))
		return -EIO;

	status = le32_to_cpu(__raw_readl(&reg->cmd_status));
	return (status & (1 << NETRO_CMDIF_GO_BIT)) ||
		(ndev->toggle != !!(status & (1 << NETRO_CMDIF_TOGGLE_BIT)));
}

int __netro_read_cmdif_results(struct netro_ibdev *ndev,
		u64 *output_param, u8 *status)
{
	struct cmdif_reg __iomem *reg = ndev->cmdif;
	u32 out_low;
	u32 out_high;
	u32 cmdsts;

	if (!reg)
		return -EIO;

	if (pci_channel_offline(ndev->nfp_info->pdev))
		return -EIO;

	if (output_param) {
		out_high = le32_to_cpu(__raw_readl(&reg->output_param_high));
		out_low  = le32_to_cpu(__raw_readl(&reg->output_param_low));
		*output_param = ((u64) out_high) << 32 | out_low;
	}

	if (status) {
		cmdsts = le32_to_cpu(__raw_readl(&reg->cmd_status));
		*status = (u8) (cmdsts >> NETRO_CMDIF_STATUS_SHIFT);
	}
	return 0;
}

int netro_acquire_pci_resources(struct netro_ibdev *ndev)
{
	ndev->cmdif = ndev->nfp_info->cmdif;
	if (!ndev->cmdif) {
		netro_info("Command interface iomem passed as NULL\n");
		return -EINVAL;
	}
	pr_info("cmdif_reg IOMEM address:%p\n", ndev->cmdif);

	ndev->db_paddr = ndev->nfp_info->db_base;
	pr_info("DB pages bus/DMA address:0x%016llX\n", ndev->db_paddr);
	return 0;
}

void netro_free_pci_resources(struct netro_ibdev *ndev)
{
	return;
}

void netro_cleanup_hw(struct netro_ibdev *ndev)
{
	pr_info("Netro HW specific cleanup\n");
	return;
}

void corigine_set_sq_db(struct netro_ibdev *ndev, u32 qpn)
{
	void __iomem *addr;
	u32 db;

	if (NFP_CPP_MODEL_IS_3800(ndev->nfp_info->model)) {
		db = qpn & CORIGINE_DB_SQ_MASK;
		addr = ndev->priv_uar.map + CORIGINE_DB_SQ_ADDR_OFFSET_3800;
		pr_info("Write SQ_Doorbell %p with 0x%08X\n", addr, cpu_to_le32(db));
		__raw_writel((__force u32) cpu_to_le32(db), addr);
		mb();
	}
	//Todo model 6000
	return;
}

void corigine_set_cq_db(struct netro_ibdev *ndev, u32 cqn, bool solicited)
{
	void __iomem *addr;
	u32 db;
	struct netro_cq	*ncq = ndev->cq_table[cqn];

	if (NFP_CPP_MODEL_IS_3800(ndev->nfp_info->model)) {
		db = (ncq->arm_seqn << CORIGINE_DB_CQ_SEQ_SHIFT) |
			 (solicited ? 0 : CORIGINE_DB_CQ_ARM_ANY_BIT) |
			 (ncq->cqn & CORIGINE_DB_CQN_MASK);
		addr = ndev->priv_eq_uar.map + CORIGINE_DB_CQ_ADDR_OFFSET_3800;
		pr_info("Write CQ_Doorbell %p with 0x%08X\n", addr, cpu_to_le32(db));
		__raw_writel((__force u32) cpu_to_le32(db), addr);
		mb();
	}
	//Todo model 6000
	return;
}

inline void corigine_set_eq_ci(struct netro_ibdev *ndev,  u32 eqn,
		u32 consumer_index, bool arm)
{
	void __iomem *addr;
	u32 ci;

	pr_info("corigine_set_eq_ci, eqn %d, ci 0x%08X, arm interrupt %d\n",
			eqn, consumer_index, arm);
	if (NFP_CPP_MODEL_IS_3800(ndev->nfp_info->model)) {
		ci = (arm ? NETRO_UAR_EQ_ARM_BIT : 0) |
				(consumer_index & NETRO_UAR_EQ_CONSUMER_MASK);
		addr = ndev->priv_eq_uar.map + (eqn * CORIGINE_UAR_EQ_ADDR_INTERVAL_IN_PAGE);
	} else {
		ci = (arm ? NETRO_UAR_EQ_ARM_BIT : 0) | NETRO_UAR_EQ_FIN_BIT |
				(consumer_index & NETRO_UAR_EQ_CONSUMER_MASK);
		addr = ndev->priv_eq_uar.map + NETRO_UAR_EQ_ADDR_WA_BIT + (eqn * sizeof(u32) * 2);
	}


	if (!NFP_CPP_MODEL_IS_3800(ndev->nfp_info->model)) {
	/* Dump values for debug */
#if 0
	pr_info("EQ_Doorbell UAR w/WA address %p\n", addr);
	pr_info("EQ_Doorbell UAR wo/WA address %p\n", addr -
			NETRO_UAR_EQ_ADDR_WA_BIT);
#endif

	/*
	 * NOTE that we ignore the EQ finish bit since each EQ
	 * has it's own address (in 0x6000) and the latest
	 * write is always what we want ultimately.
	 */
#if 0
	pr_info("Current EQ doorbell value 0x%08X\n", le32_to_cpu(
			__raw_readl(addr - NETRO_UAR_EQ_ADDR_WA_BIT)));
	rmb();
#endif
	}

	pr_info("Write EQ_Doorbell %p with 0x%08X\n", addr, cpu_to_le32(ci));
	__raw_writel((__force u32) cpu_to_le32(ci), addr);
	mb();
	return;
}


int netro_set_chip_details(struct netro_ibdev *ndev, u32 model)
{
    #if 0
	if (!NFP_CPP_MODEL_IS_6000(model)) {
		netro_info("Chipset family 0x%08X not supported\n",
				model);
		return -EINVAL;
	}
	#endif

	/*
	 * Place holder for initializing device parameters that
	 * are chipset family specific.
	 */

	/* XXX: Todo add doorbell routines */

	return 0;
}
