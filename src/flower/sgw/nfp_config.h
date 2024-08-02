/* Copyright (C) 2024 Corigine, Inc. */

#ifndef _NFP_CONFIG_H_
#define _NFP_CONFIG_H_

enum nfp_nic_type {
	NFP_NIC_TYPE_MIN = -1,
	NFP_NIC_TYPE_DFT = 0,
	NFP_NIC_TYPE_KEVB,
	NFP_NIC_TYPE_KEVB_TEST,
	NFP_NIC_TYPE_MAX,
};

#define NFP_NIC_KEVB_PREFIX		"OAMDA1001"
#define NFP_NIC_OAMDA1002_PREFIX	"OAMDA1002"
#define NFP_NIC_KEVB_TEST_PREFIX	"ALEA0162"
#define NFP_NIC_OAMDA_NULL_PREFIX	"OAMDA0000"

struct phy_repr_ring_cfg {
	u16 nb_rx_ring;
	u16 nb_rx_ring_max;
	u16 nb_tx_ring;
	u16 nb_tx_ring_max;
};

#define PHY_REPR_MAX	20

struct nfp_nic_setup_cfg {
	struct phy_repr_ring_cfg phy_repr_ring_info[PHY_REPR_MAX];
};

enum nfp_nic_type nfp_nic_type_get(const char *partno);
const struct nfp_nic_setup_cfg *nfp_nic_setup_cfg_get(enum nfp_nic_type type);
const struct phy_repr_ring_cfg *nfp_phy_ring_setup_cfg_get(enum nfp_nic_type type,
							   u32 eidx);

#endif /* _NFP_CONFIG_H_ */
