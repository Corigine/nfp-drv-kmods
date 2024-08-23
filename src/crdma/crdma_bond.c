// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright (C) 2023 Corigine, Inc. */

#include <net/bonding.h>

#include "nfpcore/nfp_roce.h"
#include "crdma_ib.h"
#include "crdma_ucif.h"
#include "crdma_bond.h"

static void crdma_bond_unregister_slave_ibdev(struct crdma_device_node **node)
{
	int i;

	for (i = 0; i < CRDMA_BOND_MAX_PORT; i++) {
		if (!node[i])
			continue;

		if (node[i]->crdma_dev) {
			crdma_remove_dev(node[i]->crdma_dev);
			node[i]->crdma_dev = NULL;
		}
	}
}

static void crdma_bond_register_slave_ibdev(struct crdma_device_node **node)
{
	struct crdma_ibdev *crdma_dev;
	int i;

	for (i = 0; i < CRDMA_BOND_MAX_PORT; i++) {
		if (!node[i])
			continue;

		crdma_dev = crdma_add_dev(node[i]->info);
		if (!crdma_dev)
			return;

		node[i]->crdma_dev = crdma_dev;
		crdma_dev->dev_node = node[i];
	}
}

static void crdma_bond_register_bond_ibdev(struct crdma_device_node **node)
{
	/* ibdevice for bond use the 1st pf's resources */
	struct crdma_ibdev *crdma_dev;

	crdma_dev = crdma_add_dev(node[0]->info);
	if (!crdma_dev)
		return;

	node[0]->crdma_dev = crdma_dev;
	crdma_dev->dev_node = node[0];
}

static void crdma_bond_unregister_bond_ibdev(struct crdma_device_node **node)
{
	/* ibdevice for bond use the 1st pf's resources */
	if (!node[0])
		return;

	if (node[0]->crdma_dev) {
		crdma_remove_dev(node[0]->crdma_dev);
		node[0]->crdma_dev = NULL;
	}
}

static void crdma_bond_tx_mapping(struct bond_group *group,
					   u64 *tx_bm)
{
	if (group->slave_state[0].link_up &&
		group->slave_state[0].tx_enabled)
		*tx_bm |= 1<<0;

	if (group->slave_state[1].link_up &&
		group->slave_state[1].tx_enabled)
		*tx_bm |= 1<<1;
}

static void crdma_bond_create_bond(struct crdma_device_node **node,
				   struct bond_group *group)
{
	int err;
	u64 tx_bm = 0;
	struct crdma_ibdev *dev = node[0]->crdma_dev;

	if (!dev)
		return;

	crdma_bond_tx_mapping(group, &tx_bm);

	err = crdma_bond_config_cmd(dev, CRDMA_BOND_MOD_CREATE, tx_bm);
	if (err)
		crdma_err("Failed to create LAG (%d)\n", err);
}

static void crdma_bond_mod_bond(struct crdma_device_node **node,
				struct bond_group *group)
{
	int err;
	u64 tx_bm = 0;
	struct crdma_ibdev *dev = node[0]->crdma_dev;

	if (!dev)
		return;

	crdma_bond_tx_mapping(group, &tx_bm);

	err = crdma_bond_config_cmd(dev, CRDMA_BOND_MOD_UPDATE, tx_bm);
	if (err)
		crdma_err("Failed to modify LAG (%d)\n", err);
}

static void crdma_bond_destroy_bond(struct crdma_device_node **node)
{
	int err;
	struct crdma_ibdev *dev = node[0]->crdma_dev;

	if (!dev)
		return;

	err = crdma_bond_config_cmd(dev, CRDMA_BOND_MOD_DESTROY, 0);
	if (err)
		crdma_err("Failed to create LAG (%d)\n", err);
}

static void crdma_do_bond(struct crdma_bond *bdev)
{
	bool do_bond;
	int active;
	struct bond_group group = {0};
	struct crdma_device_node *node_list[CRDMA_BOND_MAX_PORT] = {0};

	/* crdma_do_bond will sleep and be scheduled out, it is not allowed to
	 * rmmod crdma module when crdma_do_bond is not commpleted, we use mutex
	 * to avoid this race.
	 */
	mutex_lock(&crdma_global_mutex);

	mutex_lock(&bdev->lock);
	memcpy(node_list, bdev->node_list,
	       sizeof(struct crdma_device_node *) * CRDMA_BOND_MAX_PORT);
	active = bdev->active;
	group = bdev->group;
	mutex_unlock(&bdev->lock);

	do_bond = group.is_bonded;
	if (do_bond && !active) {
		crdma_bond_unregister_slave_ibdev(node_list);

		mutex_lock(&bdev->lock);
		bdev->active = 1;
		mutex_unlock(&bdev->lock);

		msleep(2000);
		crdma_bond_register_bond_ibdev(node_list);
		crdma_bond_create_bond(node_list, &group);
	} else if (do_bond && active) {
		crdma_bond_mod_bond(node_list, &group);
	} else if (!do_bond && active) {
		crdma_bond_destroy_bond(node_list);
		crdma_bond_unregister_bond_ibdev(node_list);

		mutex_lock(&bdev->lock);
		bdev->active = 0;
		mutex_unlock(&bdev->lock);

		msleep(5000);
		crdma_bond_register_slave_ibdev(node_list);
	}

	mutex_unlock(&crdma_global_mutex);
}

static void crdma_do_bond_work(struct work_struct *work)
{
	struct delayed_work *delayed_work = to_delayed_work(work);
	struct crdma_bond *bdev = container_of(delayed_work, struct crdma_bond,
					     bond_work);

	crdma_do_bond(bdev);
}

static int crdma_bond_dev_get_netdev_idx(struct crdma_bond *bdev,
				struct net_device *ndev)
{
	int i;

	for (i = 0; i < CRDMA_BOND_MAX_PORT; i++) {
		if (!bdev->node_list[i])
			continue;

		if (bdev->node_list[i]->info->netdev == ndev)
			return i;
	}

	return -ENOENT;
}

static int
crdma_bond_changeupper_event(struct crdma_bond *bdev,
			     struct bond_group *group,
			     struct netdev_notifier_changeupper_info *info)
{
	struct net_device *upper = info->upper_dev, *ndev_tmp;
	struct netdev_lag_upper_info *lag_upper_info = NULL;
	bool is_bonded, is_in_lag, mode_supported;
	bool has_inactive = 0;
	struct slave *slave;
	u8 bond_status = 0;
	int num_slaves = 0;
	int changed = 0;
	int idx;

	if (!netif_is_lag_master(upper))
		return 0;

	if (info->linking)
		lag_upper_info = info->upper_info;

	/* The event may still be of interest if the netdev does not belong to
	 * us, but is enslaved to a master which has one or more of our netdevs
	 * joined in (e.g., if a new netdev is added to a master that bonds two
	 * of our netdevs, we should unbond).
	 */
	rcu_read_lock();
	for_each_netdev_in_bond_rcu(upper, ndev_tmp) {
		idx = crdma_bond_dev_get_netdev_idx(bdev, ndev_tmp);
		if (idx >= 0) {
			slave = bond_slave_get_rcu(ndev_tmp);
			if (slave)
				has_inactive |= bond_is_slave_inactive(slave);
			bond_status |= (1 << idx);
		}

		num_slaves++;
	}
	rcu_read_unlock();

	/* None of this bdev's netdevs are added to this master. */
	if (!(bond_status & GENMASK(CRDMA_BOND_MAX_PORT - 1, 0)))
		return 0;

	if (lag_upper_info)
		group->tx_type = lag_upper_info->tx_type;

	group->has_inactive = has_inactive;
	/* Determine bonding status:
	 * A device is considered bonded if both its physical ports are added
	 * to the same lag master, and only them.
	 */
	is_in_lag = (num_slaves == CRDMA_BOND_MAX_PORT) &&
		bond_status == GENMASK(CRDMA_BOND_MAX_PORT - 1, 0);

	/* Bond mode must be activebackup or hash. */
	mode_supported = group->tx_type == NETDEV_LAG_TX_TYPE_ACTIVEBACKUP ||
			 group->tx_type == NETDEV_LAG_TX_TYPE_HASH;

	is_bonded = is_in_lag && mode_supported;
	if (group->is_bonded != is_bonded) {
		group->is_bonded = is_bonded;
		changed = 1;
	}

	if (!is_in_lag)
		return changed;

	if (!mode_supported)
		crdma_err("Can't activate LAG offload, TX type isn't supported");

	return changed;
}

static int
crdma_bond_changelowerstate_event(struct crdma_bond *bdev,
				  struct bond_group *group,
				  struct net_device *ndev,
				  struct netdev_notifier_changelowerstate_info *info)
{
	struct netdev_lag_lower_state_info *lag_lower_info;
	int idx;

	if (!netif_is_lag_port(ndev))
		return 0;

	idx = crdma_bond_dev_get_netdev_idx(bdev, ndev);
	if (idx < 0)
		return 0;

	lag_lower_info = info->lower_state_info;
	if (!lag_lower_info)
		return 0;

	group->slave_state[idx] = *lag_lower_info;

	return 1;
}

static int crdma_bond_changeinfodata_event(struct crdma_bond *bdev,
					   struct bond_group *group,
					   struct net_device *ndev)
{
	struct net_device *ndev_tmp;
	struct slave *slave;
	bool has_inactive = 0;
	int idx;

	if (!netif_is_lag_master(ndev))
		return 0;

	rcu_read_lock();
	for_each_netdev_in_bond_rcu(ndev, ndev_tmp) {
		idx = crdma_bond_dev_get_netdev_idx(bdev, ndev_tmp);
		if (idx < 0)
			continue;

		slave = bond_slave_get_rcu(ndev_tmp);
		if (slave)
			has_inactive |= bond_is_slave_inactive(slave);
	}
	rcu_read_unlock();

	if (group->has_inactive == has_inactive)
		return 0;

	group->has_inactive = has_inactive;

	return 1;
}


/**
 * net_device notifier callback handler.
 *
 * @nb: Pointer to the notifier block.
 * @event: The notification event code.
 * @ptr: The pointer to private data (net_device).
 *
 * Returns NOTIFY_DONE.
 */
static int crdma_bond_netdev_event(struct notifier_block *nb,
				   unsigned long event, void *ptr)
{
	struct net_device *netdev = netdev_notifier_info_to_dev(ptr);
	struct crdma_bond *bdev;
	struct bond_group group = {0};
	int changed = 0;

	if (event != NETDEV_CHANGEUPPER &&
	    event != NETDEV_CHANGELOWERSTATE &&
	    event != NETDEV_CHANGEINFODATA)
		return NOTIFY_DONE;

	bdev = container_of(nb, struct crdma_bond, netdev_nb);

	mutex_lock(&bdev->lock);
	group = bdev->group;
	mutex_unlock(&bdev->lock);

	switch (event) {
	case NETDEV_CHANGEUPPER:
		changed = crdma_bond_changeupper_event(bdev, &group, ptr);
		break;
	case NETDEV_CHANGELOWERSTATE:
		changed = crdma_bond_changelowerstate_event(bdev, &group,
							netdev, ptr);
		break;
	case NETDEV_CHANGEINFODATA:
		changed = crdma_bond_changeinfodata_event(bdev, &group, netdev);
		break;
	default:
		break;
	}

	mutex_lock(&bdev->lock);
	bdev->group = group;
	mutex_unlock(&bdev->lock);

	if (changed)
		queue_delayed_work(bdev->wq, &bdev->bond_work, 0);

	return NOTIFY_DONE;
}

static void crdma_bond_dev_free(struct kref *ref)
{
	struct crdma_bond *bdev = container_of(ref, struct crdma_bond, ref);

	if (bdev->netdev_nb.notifier_call)
		unregister_netdevice_notifier(&bdev->netdev_nb);

	cancel_delayed_work_sync(&bdev->bond_work);
	destroy_workqueue(bdev->wq);
	mutex_destroy(&bdev->lock);
	kfree(bdev);
}

static struct crdma_bond *crdma_bond_dev_alloc(void)
{
	struct crdma_bond *bdev;

	bdev = kzalloc(sizeof(*bdev), GFP_KERNEL);
	if (!bdev)
		return NULL;

	bdev->wq = create_singlethread_workqueue("crdma_bond");
	if (!bdev->wq) {
		kfree(bdev);
		return NULL;
	}

	mutex_init(&bdev->lock);
	INIT_DELAYED_WORK(&bdev->bond_work, crdma_do_bond_work);

	bdev->netdev_nb.notifier_call = crdma_bond_netdev_event;
	if (register_netdevice_notifier(&bdev->netdev_nb)) {
		bdev->netdev_nb.notifier_call = NULL;
		crdma_err("Failed to register bond netdev notifier\n");
	}

	return bdev;
}

static void crdma_bdev_put(struct crdma_bond *bdev)
{
	kref_put(&bdev->ref, crdma_bond_dev_free);
}

static void crdma_bdev_get(struct crdma_bond *bdev)
{
	kref_get(&bdev->ref);
}

static void crdma_bdev_add_ibdev(struct crdma_bond *bdev,
				 struct crdma_device_node *node)
{
	unsigned int fn = PCI_FUNC(node->info->pdev->devfn);

	bdev->node_list[fn] = node;
	node->bdev = bdev;
}

static void crdma_bdev_del_ibdev(struct crdma_bond *bdev,
				 struct crdma_device_node *node)
{
	unsigned int fn = PCI_FUNC(node->info->pdev->devfn);

	bdev->node_list[fn] = NULL;
	node->bdev = NULL;
}

int crdma_bond_add_ibdev(struct crdma_device_node *node)
{
	struct crdma_bond *bdev;

	bdev = crdma_bond_fetch_bdev(node);
	if (!bdev) {
		bdev = crdma_bond_dev_alloc();
		if (!bdev) {
			crdma_err("Failed to alloc bond dev\n");
			return 0;
		}
		kref_init(&bdev->ref);
	} else {
		crdma_bdev_get(bdev);
	}

	mutex_lock(&bdev->lock);
	crdma_bdev_add_ibdev(bdev, node);
	mutex_unlock(&bdev->lock);

	return 0;
}

void crdma_bond_del_ibdev(struct crdma_device_node *node)
{
	struct crdma_bond *bdev;

	bdev = node->bdev;
	if (!bdev)
		return;

	mutex_lock(&bdev->lock);
	crdma_bdev_del_ibdev(bdev, node);
	mutex_unlock(&bdev->lock);

	crdma_bdev_put(bdev);
}

int crdma_bond_is_active(struct crdma_ibdev *crdma_dev)
{
	int active;
	struct crdma_bond *bdev;

	if (!crdma_dev->dev_node)
		return 0;

	bdev = crdma_dev->dev_node->bdev;
	if (!bdev)
		return 0;

	mutex_lock(&bdev->lock);
	active = bdev->active;
	mutex_unlock(&bdev->lock);

	return active;
}

struct net_device *crdma_bond_get_netdev(struct crdma_ibdev *crdma_dev)
{
	int i;
	struct crdma_bond *bdev;
	struct net_device *ndev = NULL;

	if (!crdma_dev->dev_node)
		goto out;

	bdev = crdma_dev->dev_node->bdev;
	if (!bdev)
		goto out;

	mutex_lock(&bdev->lock);
	if (!bdev->active)
		goto unlock;

	if (bdev->group.tx_type == NETDEV_LAG_TX_TYPE_ACTIVEBACKUP) {
		for (i = 0; i < CRDMA_BOND_MAX_PORT; i++)
			if (bdev->group.slave_state[i].tx_enabled)
				ndev = bdev->node_list[i]->info->netdev;
		if (!ndev)
			ndev = bdev->node_list[0]->info->netdev;
	} else {
		ndev = bdev->node_list[0]->info->netdev;
	}

	if (ndev)
		dev_hold(ndev);

unlock:
	mutex_unlock(&bdev->lock);
out:
	return ndev;
}
