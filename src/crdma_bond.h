/*
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

#ifndef CRDMA_BOND_H
#define CRDMA_BOND_H

#include <net/bonding.h>
#include <linux/workqueue.h>
#include <linux/mutex.h>
#include <linux/kref.h>

#include "crdma_ib.h"

#define CRDMA_BOND_MAX_PORT	2

/*
 * Bond slaves' state info, used for collection of slaves' netdev
 * event info.
 */
struct bond_group {
	enum netdev_lag_tx_type tx_type;
	struct netdev_lag_lower_state_info slave_state[CRDMA_BOND_MAX_PORT];
	unsigned int is_bonded:1;
	unsigned int has_inactive:1;
};

struct nfp_roce;

/**
 * struct crdma_bond - crdma data for link aggregation
 * Each NIC maintains one of this data.
 * @netdev_nb: Work queue for do configs to roce bond
 * @actived: Indicate whether bond is activated
 * @roce: RoCE devices belongs to this crdma_bond
 * @group: Track bond group's slaves state
 * @bond_work: Work queue for do configs to roce bond
 * @ref: Ref cnt of this struct
 * @lock: Lock to protect crdma_bond
 */
struct crdma_bond {
	struct notifier_block netdev_nb;

	int actived;
	struct nfp_roce *roce[CRDMA_BOND_MAX_PORT];
	struct bond_group group;

	struct delayed_work bond_work;
	struct kref	ref;
	struct mutex lock;
};

int crdma_bond_add_ibdev(struct nfp_roce *roce);
void crdma_bond_del_ibdev(struct nfp_roce *roce);
int crdma_bond_is_actived(struct crdma_ibdev *crdma_dev);
struct net_device *crdma_bond_get_netdev(struct crdma_ibdev *crdma_dev);

#endif /* CRDMA_BOND_H */