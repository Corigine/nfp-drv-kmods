// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright (C) 2024 Corigine, Inc. */

#include <linux/device.h>
#include <linux/netdevice.h>
#include <net/dcbnl.h>
#include <net/dsfield.h>

#include "../nfp_app.h"
#include "../nfp_net.h"
#include "../nfp_main.h"
#include "../nfpcore/nfp_cpp.h"
#include "../nfpcore/nfp_nffw.h"
#include "../nfp_net_sriov.h"
#include "../nfp_port.h"
#include "main.h"

/**
 * nfp_parse_ieee_etscfg_tlv
 * @tlv: IEEE 802.1Qaz ETS CFG TLV
 * @dcbcfg: Local store to update ETS CFG data
 *
 * Parses IEEE 802.1Qaz ETS CFG TLV
 **/
static void nfp_parse_ieee_etscfg_tlv(struct nfp_lldp_org_tlv *tlv,
				      struct nfp_dcbx_config *dcbcfg)
{
	struct nfp_dcb_ets_config *etscfg;
	u8 *buf = tlv->tlvinfo;
	u16 offset = 0;
	u8 priority;
	int i;

	/* First Octet post subtype
	 * --------------------------
	 * |will-|CBS  | Re-  | Max |
	 * |ing  |     |served| TCs |
	 * --------------------------
	 * |1bit | 1bit|3 bits|3bits|
	 */
	etscfg = &dcbcfg->etscfg;
	etscfg->willing = (u8)((buf[offset] & NFP_IEEE_ETS_WILLING_MASK) >>
				NFP_IEEE_ETS_WILLING_SHIFT);
	etscfg->cbs = (u8)((buf[offset] & NFP_IEEE_ETS_CBS_MASK) >>
			    NFP_IEEE_ETS_CBS_SHIFT);
	etscfg->maxtcs = (u8)((buf[offset] & NFP_IEEE_ETS_MAXTC_MASK) >>
			       NFP_IEEE_ETS_MAXTC_SHIFT);

	/* Move offset to Priority Assignment Table */
	offset++;

	/* Priority Assignment Table (4 octets)
	 * Octets:|    1    |    2    |    3    |    4    |
	 *        -----------------------------------------
	 *        |pri0|pri1|pri2|pri3|pri4|pri5|pri6|pri7|
	 *        -----------------------------------------
	 *   Bits:|7  4|3  0|7  4|3  0|7  4|3  0|7  4|3  0|
	 *        -----------------------------------------
	 */
	for (i = 0; i < 4; i++) {
		priority = (u8)((buf[offset] & NFP_IEEE_ETS_PRIO_1_MASK) >>
				 NFP_IEEE_ETS_PRIO_1_SHIFT);
		etscfg->prioritytable[i * 2] =  priority;
		priority = (u8)((buf[offset] & NFP_IEEE_ETS_PRIO_0_MASK) >>
				 NFP_IEEE_ETS_PRIO_0_SHIFT);
		etscfg->prioritytable[i * 2 + 1] = priority;
		offset++;
	}

	/* TC Bandwidth Table (8 octets)
	 * Octets:| 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 |
	 *        ---------------------------------
	 *        |tc0|tc1|tc2|tc3|tc4|tc5|tc6|tc7|
	 *        ---------------------------------
	 */
	for (i = 0; i < NFP_NET_MAX_TC; i++)
		etscfg->tcbwtable[i] = buf[offset++];

	/* TSA Assignment Table (8 octets)
	 * Octets:| 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 |
	 *        ---------------------------------
	 *        |tc0|tc1|tc2|tc3|tc4|tc5|tc6|tc7|
	 *        ---------------------------------
	 */
	for (i = 0; i < NFP_NET_MAX_TC; i++)
		etscfg->tsatable[i] = buf[offset++];
}

/**
 * nfp_parse_ieee_etsrec_tlv
 * @tlv: IEEE 802.1Qaz ETS REC TLV
 * @dcbcfg: Local store to update ETS REC data
 *
 * Parses IEEE 802.1Qaz ETS REC TLV
 **/
static void nfp_parse_ieee_etsrec_tlv(struct nfp_lldp_org_tlv *tlv,
				      struct nfp_dcbx_config *dcbcfg)
{
	u8 *buf = tlv->tlvinfo;
	u16 offset = 0;
	u8 priority;
	int i;

	/* Move offset to priority table */
	offset++;

	/* Priority Assignment Table (4 octets)
	 * Octets:|    1    |    2    |    3    |    4    |
	 *        -----------------------------------------
	 *        |pri0|pri1|pri2|pri3|pri4|pri5|pri6|pri7|
	 *        -----------------------------------------
	 *   Bits:|7  4|3  0|7  4|3  0|7  4|3  0|7  4|3  0|
	 *        -----------------------------------------
	 */
	for (i = 0; i < 4; i++) {
		priority = (u8)((buf[offset] & NFP_IEEE_ETS_PRIO_1_MASK) >>
				 NFP_IEEE_ETS_PRIO_1_SHIFT);
		dcbcfg->etsrec.prioritytable[i * 2] =  priority;
		priority = (u8)((buf[offset] & NFP_IEEE_ETS_PRIO_0_MASK) >>
				 NFP_IEEE_ETS_PRIO_0_SHIFT);
		dcbcfg->etsrec.prioritytable[i * 2 + 1] = priority;
		offset++;
	}

	/* TC Bandwidth Table (8 octets)
	 * Octets:| 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 |
	 *        ---------------------------------
	 *        |tc0|tc1|tc2|tc3|tc4|tc5|tc6|tc7|
	 *        ---------------------------------
	 */
	for (i = 0; i < NFP_NET_MAX_TC; i++)
		dcbcfg->etsrec.tcbwtable[i] = buf[offset++];

	/* TSA Assignment Table (8 octets)
	 * Octets:| 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 |
	 *        ---------------------------------
	 *        |tc0|tc1|tc2|tc3|tc4|tc5|tc6|tc7|
	 *        ---------------------------------
	 */
	for (i = 0; i < NFP_NET_MAX_TC; i++)
		dcbcfg->etsrec.tsatable[i] = buf[offset++];
}

/**
 * nfp_parse_ieee_pfccfg_tlv
 * @tlv: IEEE 802.1Qaz PFC CFG TLV
 * @dcbcfg: Local store to update PFC CFG data
 *
 * Parses IEEE 802.1Qaz PFC CFG TLV
 **/
static void nfp_parse_ieee_pfccfg_tlv(struct nfp_lldp_org_tlv *tlv,
				      struct nfp_dcbx_config *dcbcfg)
{
	u8 *buf = tlv->tlvinfo;

	/* ----------------------------------------
	 * |will-|MBC  | Re-  | PFC |  PFC Enable  |
	 * |ing  |     |served| cap |              |
	 * -----------------------------------------
	 * |1bit | 1bit|2 bits|4bits| 1 octet      |
	 */
	dcbcfg->pfc.willing = (u8)((buf[0] & NFP_IEEE_PFC_WILLING_MASK) >>
				    NFP_IEEE_PFC_WILLING_SHIFT);
	dcbcfg->pfc.mbc = (u8)((buf[0] & NFP_IEEE_PFC_MBC_MASK) >>
				NFP_IEEE_PFC_MBC_SHIFT);
	dcbcfg->pfc.pfccap = (u8)((buf[0] & NFP_IEEE_PFC_CAP_MASK) >>
				    NFP_IEEE_PFC_CAP_SHIFT);
	dcbcfg->pfc.pfcenable = buf[1];
}

/**
 * nfp_parse_ieee_app_tlv
 * @tlv: IEEE 802.1Qaz APP TLV
 * @dcbcfg: Local store to update APP PRIO data
 *
 * Parses IEEE 802.1Qaz APP PRIO TLV
 **/
static void nfp_parse_ieee_app_tlv(struct nfp_lldp_org_tlv *tlv,
				   struct nfp_dcbx_config *dcbcfg)
{
	u16 typelength;
	u16 offset = 0;
	u16 length;
	int i = 0;
	u8 *buf;

	typelength = ntohs(tlv->typelength);
	length = (u16)((typelength & NFP_LLDP_TLV_LEN_MASK) >>
			NFP_LLDP_TLV_LEN_SHIFT);
	buf = tlv->tlvinfo;

	/* The App priority table starts 5 octets after TLV header */
	length -= (sizeof(tlv->ouisubtype) + 1);

	/* Move offset to App Priority Table */
	offset++;

	/* Application Priority Table (3 octets)
	 * Octets:|         1          |    2    |    3    |
	 *        -----------------------------------------
	 *        |Priority|Rsrvd| Sel |    Protocol ID    |
	 *        -----------------------------------------
	 *   Bits:|23    21|20 19|18 16|15                0|
	 *        -----------------------------------------
	 */
	while (offset < length) {
		dcbcfg->app[i].priority = (u8)((buf[offset] &
						NFP_IEEE_APP_PRIO_MASK) >>
						NFP_IEEE_APP_PRIO_SHIFT);
		dcbcfg->app[i].selector = (u8)((buf[offset] &
						NFP_IEEE_APP_SEL_MASK) >>
						NFP_IEEE_APP_SEL_SHIFT);
		dcbcfg->app[i].protocolid = (buf[offset + 1] << 0x8) |
					     buf[offset + 2];
		/* Move to next app */
		offset += 3;
		i++;
		if (i >= NFP_DCBX_MAX_APPS)
			break;
	}

	dcbcfg->numapps = i;
}

static void nfp_parse_ieee_tlv(struct nfp_lldp_org_tlv *tlv,
			       struct nfp_dcbx_config *dcbcfg)
{
	u32 ouisubtype;
	u8 subtype;

	ouisubtype = ntohl(tlv->ouisubtype);
	subtype = (u8)((ouisubtype & NFP_LLDP_TLV_SUBTYPE_MASK) >>
			NFP_LLDP_TLV_SUBTYPE_SHIFT);
	switch (subtype) {
	case NFP_IEEE_SUBTYPE_ETS_CFG:
		nfp_parse_ieee_etscfg_tlv(tlv, dcbcfg);
		break;
	case NFP_IEEE_SUBTYPE_ETS_REC:
		nfp_parse_ieee_etsrec_tlv(tlv, dcbcfg);
		break;
	case NFP_IEEE_SUBTYPE_PFC_CFG:
		nfp_parse_ieee_pfccfg_tlv(tlv, dcbcfg);
		break;
	case NFP_IEEE_SUBTYPE_APP_PRI:
		nfp_parse_ieee_app_tlv(tlv, dcbcfg);
		break;
	default:
		break;
	}
}

static void nfp_parse_cee_pgcfg_tlv(struct nfp_cee_feat_tlv *tlv,
				    struct nfp_dcbx_config *dcbcfg)
{
	struct nfp_dcb_ets_config *etscfg;
	u8 *buf = tlv->tlvinfo;
	u16 offset = 0;
	u8 priority;
	int i;

	etscfg = &dcbcfg->etscfg;

	if (tlv->en_will_err & NFP_CEE_FEAT_TLV_WILLING_MASK)
		etscfg->willing = 1;

	etscfg->cbs = 0;
	/* Priority Group Table (4 octets)
	 * Octets:|    1    |    2    |    3    |    4    |
	 *        -----------------------------------------
	 *        |pri0|pri1|pri2|pri3|pri4|pri5|pri6|pri7|
	 *        -----------------------------------------
	 *   Bits:|7  4|3  0|7  4|3  0|7  4|3  0|7  4|3  0|
	 *        -----------------------------------------
	 */
	for (i = 0; i < 4; i++) {
		priority = (u8)((buf[offset] & NFP_CEE_PGID_PRIO_1_MASK) >>
				 NFP_CEE_PGID_PRIO_1_SHIFT);
		etscfg->prioritytable[i * 2] =  priority;
		priority = (u8)((buf[offset] & NFP_CEE_PGID_PRIO_0_MASK) >>
				 NFP_CEE_PGID_PRIO_0_SHIFT);
		etscfg->prioritytable[i * 2 + 1] = priority;
		offset++;
	}

	/* PG Percentage Table (8 octets)
	 * Octets:| 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 |
	 *        ---------------------------------
	 *        |pg0|pg1|pg2|pg3|pg4|pg5|pg6|pg7|
	 *        ---------------------------------
	 */
	for (i = 0; i < NFP_NET_MAX_TC; i++)
		etscfg->tcbwtable[i] = buf[offset++];

	/* Number of TCs supported (1 octet) */
	etscfg->maxtcs = buf[offset];
}

/**
 * nfp_parse_cee_pfccfg_tlv
 * @tlv: CEE DCBX PFC CFG TLV
 * @dcbcfg: Local store to update PFC CFG data
 *
 * Parses CEE DCBX PFC CFG TLV
 **/
static void nfp_parse_cee_pfccfg_tlv(struct nfp_cee_feat_tlv *tlv,
				     struct nfp_dcbx_config *dcbcfg)
{
	u8 *buf = tlv->tlvinfo;

	if (tlv->en_will_err & NFP_CEE_FEAT_TLV_WILLING_MASK)
		dcbcfg->pfc.willing = 1;

	/* ------------------------
	 * | PFC Enable | PFC TCs |
	 * ------------------------
	 * | 1 octet    | 1 octet |
	 */
	dcbcfg->pfc.pfcenable = buf[0];
	dcbcfg->pfc.pfccap = buf[1];
}

/**
 * nfp_parse_cee_app_tlv
 * @tlv: CEE DCBX APP TLV
 * @dcbcfg: Local store to update APP PRIO data
 *
 * Parses CEE DCBX APP PRIO TLV
 **/
static void nfp_parse_cee_app_tlv(struct nfp_cee_feat_tlv *tlv,
				  struct nfp_dcbx_config *dcbcfg)
{
	u16 length, typelength, offset = 0;
	struct nfp_cee_app_prio *app;
	u8 i;

	typelength = ntohs(tlv->hdr.typelen);
	length = (u16)((typelength & NFP_LLDP_TLV_LEN_MASK) >>
			NFP_LLDP_TLV_LEN_SHIFT);

	dcbcfg->numapps = length / sizeof(*app);

	if (!dcbcfg->numapps)
		return;
	if (dcbcfg->numapps > NFP_DCBX_MAX_APPS)
		dcbcfg->numapps = NFP_DCBX_MAX_APPS;

	for (i = 0; i < dcbcfg->numapps; i++) {
		u8 up, selector;

		app = (struct nfp_cee_app_prio *)(tlv->tlvinfo + offset);
		for (up = 0; up < NFP_NET_MAX_PRIO; up++) {
			if (app->prio_map & BIT(up))
				break;
		}
		dcbcfg->app[i].priority = up;

		/* Get Selector from lower 2 bits, and convert to IEEE */
		selector = (app->upper_oui_sel & NFP_CEE_APP_SELECTOR_MASK);
		switch (selector) {
		case NFP_CEE_APP_SEL_ETHTYPE:
			dcbcfg->app[i].selector = NFP_APP_SEL_ETHTYPE;
			break;
		case NFP_CEE_APP_SEL_TCPIP:
			dcbcfg->app[i].selector = NFP_APP_SEL_TCPIP;
			break;
		default:
			/* Keep selector as it is for unknown types */
			dcbcfg->app[i].selector = selector;
		}

		dcbcfg->app[i].protocolid = ntohs(app->protocol);
		/* Move to next app */
		offset += sizeof(*app);
	}
}

static void nfp_parse_cee_tlv(struct nfp_lldp_org_tlv *tlv,
			      struct nfp_dcbx_config *dcbcfg)
{
	u16 len, tlvlen, sublen, typelength;
	struct nfp_cee_feat_tlv *sub_tlv;
	u8 subtype, feat_tlv_count = 0;
	u32 ouisubtype;

	ouisubtype = ntohl(tlv->ouisubtype);
	subtype = (u8)((ouisubtype & NFP_LLDP_TLV_SUBTYPE_MASK) >>
			NFP_LLDP_TLV_SUBTYPE_SHIFT);
	/* Return if not CEE DCBX */
	if (subtype != NFP_CEE_DCBX_TYPE)
		return;

	typelength = ntohs(tlv->typelength);
	tlvlen = (u16)((typelength & NFP_LLDP_TLV_LEN_MASK) >>
			  NFP_LLDP_TLV_LEN_SHIFT);
	len = sizeof(tlv->typelength) + sizeof(ouisubtype) +
	      sizeof(struct nfp_cee_ctrl_tlv);
	/* Return if no CEE DCBX Feature TLVs */
	if (tlvlen <= len)
		return;

	sub_tlv = (struct nfp_cee_feat_tlv *)((char *)tlv + len);
	while (feat_tlv_count < NFP_CEE_MAX_FEAT_TYPE) {
		typelength = ntohs(sub_tlv->hdr.typelen);
		sublen = (u16)((typelength &
				NFP_LLDP_TLV_LEN_MASK) >>
				NFP_LLDP_TLV_LEN_SHIFT);
		subtype = (u8)((typelength & NFP_LLDP_TLV_TYPE_MASK) >>
				NFP_LLDP_TLV_TYPE_SHIFT);
		switch (subtype) {
		case NFP_CEE_SUBTYPE_PG_CFG:
			nfp_parse_cee_pgcfg_tlv(sub_tlv, dcbcfg);
			break;
		case NFP_CEE_SUBTYPE_PFC_CFG:
			nfp_parse_cee_pfccfg_tlv(sub_tlv, dcbcfg);
			break;
		case NFP_CEE_SUBTYPE_APP_PRI:
			nfp_parse_cee_app_tlv(sub_tlv, dcbcfg);
			break;
		default:
			return; /* Invalid Sub-type return */
		}
		feat_tlv_count++;
		/* Move to next sub TLV */
		sub_tlv = (struct nfp_cee_feat_tlv *)((char *)sub_tlv +
						sizeof(sub_tlv->hdr.typelen) +
						sublen);
	}
}

static void nfp_parse_org_tlv(struct nfp_lldp_org_tlv *tlv,
			      struct nfp_dcbx_config *dcbcfg)
{
	u32 ouisubtype;
	u32 oui;

	ouisubtype = ntohl(tlv->ouisubtype);
	oui = (u32)((ouisubtype & NFP_LLDP_TLV_OUI_MASK) >>
		    NFP_LLDP_TLV_OUI_SHIFT);

	switch (oui) {
	case NFP_IEEE_8021QAZ_OUI:
		nfp_parse_ieee_tlv(tlv, dcbcfg);
		break;
	case NFP_CEE_DCBX_OUI:
		nfp_parse_cee_tlv(tlv, dcbcfg);
		break;
	default:
		break;
	}
}

void
nfp_nic_lldp_rx_parse(struct net_device *netdev, const void *data,
		      unsigned int len)
{
	struct nfp_net *nn = netdev_priv(netdev);
	struct nfp_dcbx_config *remote_dcbcfg;
	struct nfp_lldp_org_tlv *tlv;
	u16 typelength;
	u16 offset = 0;
	u8 *buf = NULL;
	u16 length;
	u16 type;

	remote_dcbcfg = &((struct nfp_app_nic_private *)nn->app_priv)->remote_dcbx;
	if (!remote_dcbcfg || !nn->rx_lldp)
		return;

	buf = (u8 *)((u8 *)data + ETH_HLEN);

	tlv = (struct nfp_lldp_org_tlv *)buf;
	while (offset < (len - ETH_HLEN)) {
		typelength = ntohs(tlv->typelength);
		type = (u16)((typelength & NFP_LLDP_TLV_TYPE_MASK) >>
			      NFP_LLDP_TLV_TYPE_SHIFT);
		length = (u16)((typelength & NFP_LLDP_TLV_LEN_MASK) >>
				NFP_LLDP_TLV_LEN_SHIFT);
		offset += sizeof(typelength) + length;
		/* END TLV or beyond LLDPDU size */
		if (type == NFP_TLV_TYPE_END || offset > NFP_LLDPDU_SIZE)
			break;

		if (type == NFP_TLV_TYPE_ORG)
			nfp_parse_org_tlv(tlv, remote_dcbcfg);

		/* Move to next TLV */
		tlv = (struct nfp_lldp_org_tlv *)((char *)tlv +
						   sizeof(tlv->typelength) +
						   length);
	}
}
