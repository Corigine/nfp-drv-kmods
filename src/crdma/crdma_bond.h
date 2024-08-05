/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright (C) 2023 Corigine, Inc. */

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

/**
 * struct crdma_bond - crdma data for link aggregation
 * Each NIC maintains one of this data.
 * @netdev_nb: Work queue for do configs to crdma bond
 * @active: Indicate whether bond is activated
 * @node_list: crdma devices node list belongs to this crdma_bond
 * @group: Track bond group's slaves state
 * @bond_work: Delay Work for do configs to crdma bond
 * @wq: Work queue for do configs to crdma bond
 * @ref: Ref cnt of this struct
 * @lock: Lock to protect crdma_bond
 */
struct crdma_bond {
	struct notifier_block netdev_nb;

	int active;
	struct crdma_device_node *node_list[CRDMA_BOND_MAX_PORT];
	struct bond_group group;

	struct delayed_work bond_work;
	struct workqueue_struct *wq;
	struct kref	ref;
	struct mutex lock;
};

int crdma_bond_add_ibdev(struct crdma_device_node *node);
void crdma_bond_del_ibdev(struct crdma_device_node *node);
int crdma_bond_is_active(struct crdma_ibdev *crdma_dev);
struct net_device *crdma_bond_get_netdev(struct crdma_ibdev *crdma_dev);

struct crdma_bond *crdma_bond_fetch_bdev(struct crdma_device_node *node);

#endif /* CRDMA_BOND_H */
