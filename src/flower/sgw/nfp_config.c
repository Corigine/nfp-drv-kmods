/* Copyright (C) 2024 Corigine, Inc. */

#include <linux/string.h>

#include "nfp_config.h"

/* nfp nic setup configuration */
const struct nfp_nic_setup_cfg nfp_setup_config[NFP_NIC_TYPE_MAX] = {
	[NFP_NIC_TYPE_DFT] = {
		/* mainly support 0 a or 0 4 a e */
		.phy_repr_ring_info = {
			[0] = {
				.nb_rx_ring = 8,
				.nb_tx_ring = 8,
				.nb_rx_ring_max = 8,
				.nb_tx_ring_max = 8,
			},
			[1] = {
				.nb_rx_ring = 8,
				.nb_tx_ring = 8,
				.nb_rx_ring_max = 8,
				.nb_tx_ring_max = 8,
			},
			[2] = {
				.nb_rx_ring = 8,
				.nb_tx_ring = 8,
				.nb_rx_ring_max = 8,
				.nb_tx_ring_max = 8,
			},
			[3] = {
				.nb_rx_ring = 8,
				.nb_tx_ring = 8,
				.nb_rx_ring_max = 8,
				.nb_tx_ring_max = 8,
			},
			[4] = {
				.nb_rx_ring = 8,
				.nb_tx_ring = 8,
				.nb_rx_ring_max = 8,
				.nb_tx_ring_max = 8,
			},
			[5] = {
				.nb_rx_ring = 8,
				.nb_tx_ring = 8,
				.nb_rx_ring_max = 8,
				.nb_tx_ring_max = 8,
			},
			[6] = {
				.nb_rx_ring = 8,
				.nb_tx_ring = 8,
				.nb_rx_ring_max = 8,
				.nb_tx_ring_max = 8,
			},
			[7] = {
				.nb_rx_ring = 8,
				.nb_tx_ring = 8,
				.nb_rx_ring_max = 8,
				.nb_tx_ring_max = 8,
			},
			[8] = {
				.nb_rx_ring = 8,
				.nb_tx_ring = 8,
				.nb_rx_ring_max = 8,
				.nb_tx_ring_max = 8,
			},
			[9] = {
				.nb_rx_ring = 8,
				.nb_tx_ring = 8,
				.nb_rx_ring_max = 8,
				.nb_tx_ring_max = 8,
			},
			[10] = {
				.nb_rx_ring = 8,
				.nb_tx_ring = 8,
				.nb_rx_ring_max = 8,
				.nb_tx_ring_max = 8,
			},
			[11] = {
				.nb_rx_ring = 8,
				.nb_tx_ring = 8,
				.nb_rx_ring_max = 8,
				.nb_tx_ring_max = 8,
			},
			[12] = {
				.nb_rx_ring = 8,
				.nb_tx_ring = 8,
				.nb_rx_ring_max = 8,
				.nb_tx_ring_max = 8,
			},
			[13] = {
				.nb_rx_ring = 8,
				.nb_tx_ring = 8,
				.nb_rx_ring_max = 8,
				.nb_tx_ring_max = 8,
			},
			[14] = {
				.nb_rx_ring = 8,
				.nb_tx_ring = 8,
				.nb_rx_ring_max = 8,
				.nb_tx_ring_max = 8,
			},
			[15] = {
				.nb_rx_ring = 8,
				.nb_tx_ring = 8,
				.nb_rx_ring_max = 8,
				.nb_tx_ring_max = 8,
			},
			[16] = {
				.nb_rx_ring = 8,
				.nb_tx_ring = 8,
				.nb_rx_ring_max = 8,
				.nb_tx_ring_max = 8,
			},
			[17] = {
				.nb_rx_ring = 8,
				.nb_tx_ring = 8,
				.nb_rx_ring_max = 8,
				.nb_tx_ring_max = 8,
			},
			[18] = {
				.nb_rx_ring = 8,
				.nb_tx_ring = 8,
				.nb_rx_ring_max = 8,
				.nb_tx_ring_max = 8,
			},
			[19] = {
				.nb_rx_ring = 8,
				.nb_tx_ring = 8,
				.nb_rx_ring_max = 8,
				.nb_tx_ring_max = 8,
			},
		},
	},
	[NFP_NIC_TYPE_KEVB] = {
		.phy_repr_ring_info = {
			/* 2*40G phy */
			[0] = {
				.nb_rx_ring = 8,
				.nb_tx_ring = 8,
				.nb_rx_ring_max = 8,
				.nb_tx_ring_max = 8,
			},
			[10] = {
				.nb_rx_ring = 8,
				.nb_tx_ring = 8,
				.nb_rx_ring_max = 8,
				.nb_tx_ring_max = 8,
			},
			/* 8*10G phy */
			[8] = {
				.nb_rx_ring = 4,
				.nb_tx_ring = 4,
				.nb_rx_ring_max = 4,
				.nb_tx_ring_max = 4,
			},
			[9] = {
				.nb_rx_ring = 4,
				.nb_tx_ring = 4,
				.nb_rx_ring_max = 4,
				.nb_tx_ring_max = 4,
			},
			[14] = {
				.nb_rx_ring = 4,
				.nb_tx_ring = 4,
				.nb_rx_ring_max = 4,
				.nb_tx_ring_max = 4,
			},
			[15] = {
				.nb_rx_ring = 4,
				.nb_tx_ring = 4,
				.nb_rx_ring_max = 4,
				.nb_tx_ring_max = 4,
			},
			[16] = {
				.nb_rx_ring = 4,
				.nb_tx_ring = 4,
				.nb_rx_ring_max = 4,
				.nb_tx_ring_max = 4,
			},
			[17] = {
				.nb_rx_ring = 4,
				.nb_tx_ring = 4,
				.nb_rx_ring_max = 4,
				.nb_tx_ring_max = 4,
			},
			[18] = {
				.nb_rx_ring = 4,
				.nb_tx_ring = 4,
				.nb_rx_ring_max = 4,
				.nb_tx_ring_max = 4,
			},
			[19] = {
				.nb_rx_ring = 4,
				.nb_tx_ring = 4,
				.nb_rx_ring_max = 4,
				.nb_tx_ring_max = 4,
			},
			/* 4*1G phy */
			[4] = {
				.nb_rx_ring = 1,
				.nb_tx_ring = 1,
				.nb_rx_ring_max = 1,
				.nb_tx_ring_max = 1,
			},
			[5] = {
				.nb_rx_ring = 1,
				.nb_tx_ring = 1,
				.nb_rx_ring_max = 1,
				.nb_tx_ring_max = 1,
			},
			[6] = {
				.nb_rx_ring = 1,
				.nb_tx_ring = 1,
				.nb_rx_ring_max = 1,
				.nb_tx_ring_max = 1
			},
			[7] = {
				.nb_rx_ring = 1,
				.nb_tx_ring = 1,
				.nb_rx_ring_max = 1,
				.nb_tx_ring_max = 1,
			},
		},
	},
	[NFP_NIC_TYPE_KEVB_TEST] = {
		.phy_repr_ring_info = {
			/* 20*10G phy */
			[0] = {
				.nb_rx_ring = 2,
				.nb_tx_ring = 2,
				.nb_rx_ring_max = 2,
				.nb_tx_ring_max = 2,
			},
			[1] = {
				.nb_rx_ring = 2,
				.nb_tx_ring = 2,
				.nb_rx_ring_max = 2,
				.nb_tx_ring_max = 2,
			},
			[2] = {
				.nb_rx_ring = 2,
				.nb_tx_ring = 2,
				.nb_rx_ring_max = 2,
				.nb_tx_ring_max = 2,
			},
			[3] = {
				.nb_rx_ring = 2,
				.nb_tx_ring = 2,
				.nb_rx_ring_max = 2,
				.nb_tx_ring_max = 2,
			},
			[4] = {
				.nb_rx_ring = 2,
				.nb_tx_ring = 2,
				.nb_rx_ring_max = 2,
				.nb_tx_ring_max = 2,
			},
			[5] = {
				.nb_rx_ring = 2,
				.nb_tx_ring = 2,
				.nb_rx_ring_max = 2,
				.nb_tx_ring_max = 2,
			},
			[6] = {
				.nb_rx_ring = 2,
				.nb_tx_ring = 2,
				.nb_rx_ring_max = 2,
				.nb_tx_ring_max = 2,
			},
			[7] = {
				.nb_rx_ring = 2,
				.nb_tx_ring = 2,
				.nb_rx_ring_max = 2,
				.nb_tx_ring_max = 2,
			},
			[8] = {
				.nb_rx_ring = 2,
				.nb_tx_ring = 2,
				.nb_rx_ring_max = 2,
				.nb_tx_ring_max = 2,
			},
			[9] = {
				.nb_rx_ring = 2,
				.nb_tx_ring = 2,
				.nb_rx_ring_max = 2,
				.nb_tx_ring_max = 2,
			},
			[10] = {
				.nb_rx_ring = 2,
				.nb_tx_ring = 2,
				.nb_rx_ring_max = 2,
				.nb_tx_ring_max = 2,
			},
			[11] = {
				.nb_rx_ring = 2,
				.nb_tx_ring = 2,
				.nb_rx_ring_max = 2,
				.nb_tx_ring_max = 2,
			},
			[12] = {
				.nb_rx_ring = 2,
				.nb_tx_ring = 2,
				.nb_rx_ring_max = 2,
				.nb_tx_ring_max = 2,
			},
			[13] = {
				.nb_rx_ring = 2,
				.nb_tx_ring = 2,
				.nb_rx_ring_max = 2,
				.nb_tx_ring_max = 2,
			},
			[14] = {
				.nb_rx_ring = 2,
				.nb_tx_ring = 2,
				.nb_rx_ring_max = 2,
				.nb_tx_ring_max = 2,
			},
			[15] = {
				.nb_rx_ring = 2,
				.nb_tx_ring = 2,
				.nb_rx_ring_max = 2,
				.nb_tx_ring_max = 2,
			},
			[16] = {
				.nb_rx_ring = 2,
				.nb_tx_ring = 2,
				.nb_rx_ring_max = 2,
				.nb_tx_ring_max = 2,
			},
			[17] = {
				.nb_rx_ring = 2,
				.nb_tx_ring = 2,
				.nb_rx_ring_max = 2,
				.nb_tx_ring_max = 2,
			},
			[18] = {
				.nb_rx_ring = 2,
				.nb_tx_ring = 2,
				.nb_rx_ring_max = 2,
				.nb_tx_ring_max = 2,
			},
			[19] = {
				.nb_rx_ring = 2,
				.nb_tx_ring = 2,
				.nb_rx_ring_max = 2,
				.nb_tx_ring_max = 2,
			},
		},
	},
};

enum nfp_nic_type
nfp_nic_type_get(const char *partno)
{
	if (NULL == partno)
		return NFP_NIC_TYPE_MAX;

	if (strncmp(partno, NFP_NIC_KEVB_PREFIX, 9) == 0 ||
	    strncmp(partno, NFP_NIC_OAMDA1002_PREFIX, 9) == 0)
		return NFP_NIC_TYPE_KEVB;

	if (strncmp(partno, NFP_NIC_KEVB_TEST_PREFIX, 8) == 0)
		return NFP_NIC_TYPE_KEVB_TEST;

	if (strncmp(partno, NFP_NIC_OAMDA_NULL_PREFIX, 9) == 0)
		return NFP_NIC_TYPE_MIN;

	return NFP_NIC_TYPE_DFT;
}

const struct nfp_nic_setup_cfg *
nfp_nic_setup_cfg_get(enum nfp_nic_type type)
{
	if (type >= NFP_NIC_TYPE_MAX || type <= NFP_NIC_TYPE_MIN)
		return NULL;

	return &nfp_setup_config[type];
}

const struct phy_repr_ring_cfg *
nfp_phy_ring_setup_cfg_get(enum nfp_nic_type type, u32 eidx)
{
	const struct nfp_nic_setup_cfg *setup_cfg;

	setup_cfg = nfp_nic_setup_cfg_get(type);

	if (NULL == setup_cfg)
		return NULL;

	if (eidx >= PHY_REPR_MAX)
		return NULL;

	return &setup_cfg->phy_repr_ring_info[eidx];
}
