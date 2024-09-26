/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright (C) 2023 Corigine, Inc. */

#ifndef __NFP_NIC_H__
#define __NFP_NIC_H__ 1

#include <linux/netdevice.h>

#ifdef CONFIG_DCB
#define NFP_LLDPDU_SIZE			1500
#define NFP_TLV_TYPE_END		0
#define NFP_TLV_TYPE_ORG		127
#define NFP_CEE_MAX_FEAT_TYPE		3

#define NFP_TLV_STATUS_OPER		0x1
#define NFP_TLV_STATUS_SYNC		0x2
#define NFP_TLV_STATUS_ERR		0x4
#define NFP_CEE_OPER_MAX_APPS		3
#define NFP_APP_PROTOID_FCOE		0x8906
#define NFP_APP_PROTOID_ISCSI		0x0cbc
#define NFP_APP_PROTOID_FIP		0x8914
#define NFP_APP_SEL_ETHTYPE		0x1
#define NFP_APP_SEL_TCPIP		0x2
#define NFP_CEE_APP_SEL_ETHTYPE		0x0
#define NFP_CEE_APP_SEL_TCPIP		0x1

#define NFP_IEEE_8021QAZ_OUI		0x0080C2
#define NFP_IEEE_SUBTYPE_ETS_CFG	9
#define NFP_IEEE_SUBTYPE_ETS_REC	10
#define NFP_IEEE_SUBTYPE_PFC_CFG	11
#define NFP_IEEE_SUBTYPE_APP_PRI	12

#define NFP_CEE_DCBX_OUI		0x001b21
#define NFP_CEE_DCBX_TYPE		2

#define NFP_CEE_SUBTYPE_CTRL		1
#define NFP_CEE_SUBTYPE_PG_CFG		2
#define NFP_CEE_SUBTYPE_PFC_CFG		3
#define NFP_CEE_SUBTYPE_APP_PRI		4

/* Defines for LLDP TLV header */
#define NFP_LLDP_TLV_LEN_SHIFT		0
#define NFP_LLDP_TLV_LEN_MASK		(0x01FF << NFP_LLDP_TLV_LEN_SHIFT)
#define NFP_LLDP_TLV_TYPE_SHIFT		9
#define NFP_LLDP_TLV_TYPE_MASK		(0x7F << NFP_LLDP_TLV_TYPE_SHIFT)
#define NFP_LLDP_TLV_SUBTYPE_SHIFT	0
#define NFP_LLDP_TLV_SUBTYPE_MASK	(0xFF << NFP_LLDP_TLV_SUBTYPE_SHIFT)
#define NFP_LLDP_TLV_OUI_SHIFT		8
#define NFP_LLDP_TLV_OUI_MASK		(0xFFFFFF << NFP_LLDP_TLV_OUI_SHIFT)

/* Defines for IEEE PFC TLV */
#define NFP_DCB_PFC_ENABLED		2
#define NFP_DCB_PFC_FORCED_NUM_TC	2
#define NFP_IEEE_PFC_CAP_SHIFT		0
#define NFP_IEEE_PFC_CAP_MASK		(0xF << NFP_IEEE_PFC_CAP_SHIFT)
#define NFP_IEEE_PFC_MBC_SHIFT		6
#define NFP_IEEE_PFC_MBC_MASK		BIT(NFP_IEEE_PFC_MBC_SHIFT)
#define NFP_IEEE_PFC_WILLING_SHIFT	7
#define NFP_IEEE_PFC_WILLING_MASK	BIT(NFP_IEEE_PFC_WILLING_SHIFT)

/* Defines for IEEE APP TLV */
#define NFP_IEEE_APP_SEL_SHIFT		0
#define NFP_IEEE_APP_SEL_MASK		(0x7 << NFP_IEEE_APP_SEL_SHIFT)
#define NFP_IEEE_APP_PRIO_SHIFT	5
#define NFP_IEEE_APP_PRIO_MASK		(0x7 << NFP_IEEE_APP_PRIO_SHIFT)

/* Defines for IEEE ETS TLV */
#define NFP_IEEE_ETS_MAXTC_SHIFT	0
#define NFP_IEEE_ETS_MAXTC_MASK		(0x7 << NFP_IEEE_ETS_MAXTC_SHIFT)
#define NFP_IEEE_ETS_CBS_SHIFT		6
#define NFP_IEEE_ETS_CBS_MASK		BIT(NFP_IEEE_ETS_CBS_SHIFT)
#define NFP_IEEE_ETS_WILLING_SHIFT	7
#define NFP_IEEE_ETS_WILLING_MASK	BIT(NFP_IEEE_ETS_WILLING_SHIFT)
#define NFP_IEEE_ETS_PRIO_0_SHIFT	0
#define NFP_IEEE_ETS_PRIO_0_MASK	(0x7 << NFP_IEEE_ETS_PRIO_0_SHIFT)
#define NFP_IEEE_ETS_PRIO_1_SHIFT	4
#define NFP_IEEE_ETS_PRIO_1_MASK	(0x7 << NFP_IEEE_ETS_PRIO_1_SHIFT)
#define NFP_CEE_PGID_PRIO_0_SHIFT	0
#define NFP_CEE_PGID_PRIO_0_MASK	(0xF << NFP_CEE_PGID_PRIO_0_SHIFT)
#define NFP_CEE_PGID_PRIO_1_SHIFT	4
#define NFP_CEE_PGID_PRIO_1_MASK	(0xF << NFP_CEE_PGID_PRIO_1_SHIFT)
#define NFP_CEE_PGID_STRICT		15

/* DCB feature definitions */
#define NFP_NET_MAX_DSCP	64
#define NFP_NET_MAX_TC		IEEE_8021QAZ_MAX_TCS
#define NFP_NET_MAX_PRIO	8
#define NFP_NET_MAX_PFC_QUEUE_NUM 8
#define NFP_DCB_CFG_STRIDE	256
#define NFP_DCBX_MAX_APPS		32

/* IEEE 802.1AB LLDP Organization specific TLV */
struct nfp_lldp_org_tlv {
	u16 typelength;
	u32 ouisubtype;
	u8 tlvinfo[1];
} __packed;

struct nfp_cee_app_prio {
	__be16 protocol;
	u8 upper_oui_sel; /* Bits: |Upper OUI(6)|Selector(2)| */
#define NFP_CEE_APP_SELECTOR_MASK	0x03
	__be16 lower_oui;
	u8 prio_map;
};

struct nfp_dcb {
	u8 ets_willing;
	u8 cbs;
	u8 maxtcs;
	u8 dscp2prio[NFP_NET_MAX_DSCP];
	u8 prio2tc[NFP_NET_MAX_PRIO];
	u8 tc2idx[IEEE_8021QAZ_MAX_TCS];
	u64 tc_maxrate[IEEE_8021QAZ_MAX_TCS];
	u8 tc_tx_pct[IEEE_8021QAZ_MAX_TCS];
	u8 tc_tsa[IEEE_8021QAZ_MAX_TCS];
	u8 dscp_cnt;
	u8 trust_status;
	u8 pfc_willing;
	u8 pfc_en;
	u8 dcb_cap;
	u8 dcbx_cap;
	bool rate_init;
	bool ets_init;
	u8 dcb_cee_state;

	struct nfp_cpp_area *dcbcfg_tbl_area;
	u8 __iomem *dcbcfg_tbl;
	u32 cfg_offset;
};

struct nfp_cee_tlv_hdr {
	__be16 typelen;
	u8 operver;
	u8 maxver;
};

struct nfp_cee_ctrl_tlv {
	struct nfp_cee_tlv_hdr hdr;
	__be32 seqno;
	__be32 ackno;
};

/* CEE or IEEE 802.1Qaz ETS Configuration data */
struct nfp_dcb_ets_config {
	u8 willing;
	u8 cbs;
	u8 maxtcs;
	u8 prioritytable[NFP_NET_MAX_TC];
	u8 tcbwtable[NFP_NET_MAX_TC];
	u8 tsatable[NFP_NET_MAX_TC];
};

/* CEE or IEEE 802.1Qaz PFC Configuration data */
struct nfp_dcb_pfc_config {
	u8 willing;
	u8 mbc;
	u8 pfccap;
	u8 pfcenable;
};

/* CEE or IEEE 802.1Qaz Application Priority data */
struct nfp_dcb_app_priority_table {
	u8  priority;
	u8  selector;
	u16 protocolid;
};

struct nfp_dcbx_config {
	bool  lldp_rx_enable;
	u8  dcbx_mode;
	u8  app_mode;
	u32 numapps;
	u32 tlv_status; /* CEE mode TLV status */
	struct nfp_dcb_ets_config etscfg;
	struct nfp_dcb_ets_config etsrec;
	struct nfp_dcb_pfc_config pfc;
	struct nfp_dcb_app_priority_table app[NFP_DCBX_MAX_APPS];
};

struct nfp_cee_feat_tlv {
	struct nfp_cee_tlv_hdr hdr;
	u8 en_will_err; /* Bits: |En|Will|Err|Reserved(5)| */
#define NFP_CEE_FEAT_TLV_ENABLE_MASK	0x80
#define NFP_CEE_FEAT_TLV_WILLING_MASK	0x40
#define NFP_CEE_FEAT_TLV_ERR_MASK	0x20
	u8 subtype;
	u8 tlvinfo[1];
};

int nfp_nic_dcb_init(struct nfp_net *nn);
void nfp_nic_dcb_clean(struct nfp_net *nn);
int nfp_dcb_select_tclass(struct nfp_app *app, struct nfp_net *nn,
			  struct sk_buff *skb);
bool nfp_dcb_pfc_is_enable(struct nfp_app *app, struct nfp_net *nn);
int nfp_setup_tc_mqprio_dcb(struct nfp_net *nn, u8 tc);
void
nfp_nic_lldp_rx_parse(struct net_device *netdev, const void *data,
		      unsigned int len);
#else
static inline int nfp_nic_dcb_init(struct nfp_net *nn) { return 0; }
static inline void nfp_nic_dcb_clean(struct nfp_net *nn) {}
static inline int nfp_dcb_select_tclass(struct nfp_app *app, struct nfp_net *nn,
					struct sk_buff *skb)
{
	return -EOPNOTSUPP;
}

static inline int nfp_setup_tc_mqprio_dcb(struct nfp_net *nn, u8 tc)
{
	return -EOPNOTSUPP;
}

static inline bool nfp_dcb_pfc_is_enable(struct nfp_app *app, struct nfp_net *nn)
{
	return false;
}

static void nfp_nic_lldp_rx_parse(struct net_device *netdev, const void *data,
				  unsigned int len)
{
}
#endif

int nfp_configure_tc_ring(struct nfp_net *nn);

struct nfp_app_nic_private {
#ifdef CONFIG_DCB
	struct nfp_dcb dcb;
	struct nfp_dcbx_config remote_dcbx;
#endif
};

#endif
