/*
 * Copyright (C) 2017 Netronome Systems, Inc.
 *
 * This software is dual licensed under the GNU General License Version 2,
 * June 1991 as shown in the file COPYING in the top-level directory of this
 * source tree or the BSD 2-Clause License provided below.  You have the
 * option to license this software under the complete terms of either license.
 *
 * The BSD 2-Clause License:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      1. Redistributions of source code must retain the above
 *         copyright notice, this list of conditions and the following
 *         disclaimer.
 *
 *      2. Redistributions in binary form must reproduce the above
 *         copyright notice, this list of conditions and the following
 *         disclaimer in the documentation and/or other materials
 *         provided with the distribution.
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

#ifndef _NFP_PORT_H_
#define _NFP_PORT_H_

struct net_device;
struct nfp_app;
struct nfp_port;

/**
 * enum nfp_port_type - type of port NFP can switch traffic to
 * @NFP_PORT_INVALID:	port is invalid, %NFP_PORT_PHYS_PORT transitions to this
 *			state when port disappears because of FW fault or config
 *			change
 * @NFP_PORT_PHYS_PORT:	external NIC port
 */
enum nfp_port_type {
	NFP_PORT_INVALID,
	NFP_PORT_PHYS_PORT,
};

/**
 * struct nfp_port - structure representing NFP port
 * @netdev:	backpointer to associated netdev
 * @type:	what port type does the entity represent
 * @app:	backpointer to the app structure
 * @eth_id:	for %NFP_PORT_PHYS_PORT port ID in NFP enumeration scheme
 * @eth_port:	for %NFP_PORT_PHYS_PORT translated ETH Table port entry
 */
struct nfp_port {
	struct net_device *netdev;
	enum nfp_port_type type;

	struct nfp_app *app;

	unsigned int eth_id;
	struct nfp_eth_table_port *eth_port;
};

struct nfp_port *nfp_port_from_netdev(struct net_device *netdev);
struct nfp_eth_table_port *__nfp_port_get_eth_port(struct nfp_port *port);

int
nfp_port_get_phys_port_name(struct net_device *netdev, char *name, size_t len);

struct nfp_port *
nfp_port_alloc(struct nfp_app *app, enum nfp_port_type type,
	       struct net_device *netdev);
void nfp_port_free(struct nfp_port *port);

#ifdef CONFIG_NFP_NET_PF
int nfp_net_refresh_eth_port(struct nfp_port *port);
void nfp_net_refresh_port_table(struct nfp_port *port);
#else
static inline int nfp_net_refresh_eth_port(struct nfp_port *port)
{
	return -ENODEV;
}

static inline void nfp_net_refresh_port_table(struct nfp_port *port)
{
}
#endif

#endif
