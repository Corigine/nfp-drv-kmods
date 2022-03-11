// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright (C) 2019 Netronome Systems, Inc. */

#include "kcompat.h"

#include <linux/dma-mapping.h>
#include <linux/kernel.h>

#include "nfp_dev.h"

const struct nfp_dev_info nfp_dev_info[NFP_DEV_CNT] = {
	[NFP_DEV_NFP6000] = {
		.dma_mask		= DMA_BIT_MASK(40),
		.qc_idx_mask		= GENMASK(7, 0),
		.qc_addr_offset		= 0x80000,

		.chip_names		= "NFP4000/NFP5000/NFP6000",
		.pcie_cfg_expbar_offset	= 0x0400,
		.pcie_expl_offset	= 0x1000,
		.qc_area_sz		= 0x80000,
	},
	[NFP_DEV_NFP6000_VF] = {
		.dma_mask		= DMA_BIT_MASK(40),
		.qc_idx_mask		= GENMASK(7, 0),
		.qc_addr_offset		= 0,
	},
};