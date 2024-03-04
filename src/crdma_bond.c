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
#include <net/bonding.h>

#include "nfp_roce.h"
#include "crdma_ib.h"
#include "crdma_ucif.h"
#include "crdma_bond.h"

static void crdma_bond_unregister_slave_ibdev(struct nfp_roce **roce)
{
	int i;

	for (i = 0; i < CRDMA_BOND_MAX_PORT; i++) {
		if (!roce[i])
			continue;

		nfp_unregister_roce_ibdev(roce[i]);
	}
}

static void crdma_bond_register_slave_ibdev(struct nfp_roce **roce)
{
	int i;

	for (i = 0; i < CRDMA_BOND_MAX_PORT; i++) {
		if (!roce[i])
			continue;

		nfp_register_roce_ibdev(roce[i]);
	}
}

static void crdma_bond_register_bond_ibdev(struct nfp_roce **roce)
{
	/* ibdevice for bond use the 1st pf's resources */
	nfp_register_roce_ibdev(roce[0]);
}

static void crdma_bond_unregister_bond_ibdev(struct nfp_roce **roce)
{
	/* ibdevice for bond use the 1st pf's resources */
	nfp_unregister_roce_ibdev(roce[0]);
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

static void crdma_bond_create_bond(struct nfp_roce **roce, struct bond_group *group)
{
	int err;
	u64 tx_bm = 0;
	struct crdma_ibdev *dev = roce[0]->ibdev;

	if (!dev)
		return;

	crdma_bond_tx_mapping(group, &tx_bm);

	err = crdma_bond_config_cmd(dev, CRDMA_BOND_MOD_CREATE, tx_bm);
	if (err)
		crdma_err("Failed to create LAG (%d)\n", err);
}

static void crdma_bond_mod_bond(struct nfp_roce **roce, struct bond_group *group)
{
	int err;
	u64 tx_bm = 0;
	struct crdma_ibdev *dev = roce[0]->ibdev;

	if (!dev)
		return;

	crdma_bond_tx_mapping(group, &tx_bm);

	err = crdma_bond_config_cmd(dev, CRDMA_BOND_MOD_UPDATE, tx_bm);
	if (err)
		crdma_err("Failed to modify LAG (%d)\n", err);
}

static void crdma_bond_destroy_bond(struct nfp_roce **roce)
{
	int err;
	struct crdma_ibdev *dev = roce[0]->ibdev;

	if (!dev)
		return;

	err = crdma_bond_config_cmd(dev, CRDMA_BOND_MOD_DESTROY, 0);
	if (err)
		crdma_err("Failed to create LAG (%d)\n", err);
}

static void crdma_do_bond(struct crdma_bond *bdev)
{
	bool do_bond;
	int actived;
	struct bond_group group = {0};
	struct nfp_roce *roce[CRDMA_BOND_MAX_PORT] = {0};

	mutex_lock(&bdev->lock);
	memcpy(roce, bdev->roce, sizeof(struct nfp_roce *) * CRDMA_BOND_MAX_PORT);
	actived = bdev->actived;
	group = bdev->group;
	mutex_unlock(&bdev->lock);

	do_bond = group.is_bonded;
	if (do_bond && !actived) {
		crdma_bond_unregister_slave_ibdev(roce);

		mutex_lock(&bdev->lock);
		bdev->actived = 1;
		mutex_unlock(&bdev->lock);
		crdma_bond_register_bond_ibdev(roce);
		crdma_bond_create_bond(roce, &group);
	} else if (do_bond && actived) {
		crdma_bond_mod_bond(roce, &group);
	} else if (!do_bond && actived) {
		crdma_bond_destroy_bond(roce);
		crdma_bond_unregister_bond_ibdev(roce);

		mutex_lock(&bdev->lock);
		bdev->actived = 0;
		mutex_unlock(&bdev->lock);
		crdma_bond_register_slave_ibdev(roce);
	}
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

	for (i = 0; i < CRDMA_BOND_MAX_PORT; i++)
		if (bdev->roce[i]->info->netdev == ndev)
			return i;

	return -ENOENT;
}

static int crdma_bond_changeupper_event(struct crdma_bond *bdev,
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

	if (lag_upper_info) {
		group->tx_type = lag_upper_info->tx_type;
	}

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

static int crdma_bond_changelowerstate_event(struct crdma_bond *bdev,
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

	switch(event)
	{
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
		schedule_delayed_work(&bdev->bond_work, 0);

	return NOTIFY_DONE;
}

static void crdma_bond_dev_free(struct kref *ref)
{
	struct crdma_bond *bdev = container_of(ref, struct crdma_bond, ref);

	if (bdev->netdev_nb.notifier_call)
		unregister_netdevice_notifier(&bdev->netdev_nb);

	cancel_delayed_work_sync(&bdev->bond_work);
	mutex_destroy(&bdev->lock);
	kfree(bdev);
}

static struct crdma_bond *crdma_bond_dev_alloc(void)
{
	struct crdma_bond *bdev;

	bdev = kzalloc(sizeof(*bdev), GFP_KERNEL);
	if (!bdev)
		return NULL;

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

static u32 crdma_gen_dev_pci(const struct nfp_roce *roce)
{
	struct pci_dev *pdev;

	pdev = roce->info->pdev;
	return (u32)((pci_domain_nr(pdev->bus) << 16) |
		     (pdev->bus->number << 8) |
		     PCI_SLOT(pdev->devfn));
}

static struct crdma_bond *crdma_bond_fetch_bdev(struct nfp_roce *roce)
{
	struct nfp_roce *tmp_roce;

	list_for_each_entry(tmp_roce, &nfp_roce_list, list) {
		if ((tmp_roce == roce) ||
			(crdma_gen_dev_pci(tmp_roce) != crdma_gen_dev_pci(roce)) ||
			!tmp_roce->bdev)
			continue;

		return tmp_roce->bdev;
	}

	return NULL;
}

static void crdma_bdev_add_ibdev(struct crdma_bond *bdev,
			       struct nfp_roce *roce)
{
	unsigned int fn = PCI_FUNC(roce->info->pdev->devfn);

	bdev->roce[fn] = roce;
	roce->info->bdev = roce->bdev = bdev;
}

static void crdma_bdev_del_ibdev(struct crdma_bond *bdev,
			       struct nfp_roce *roce)
{
	unsigned int fn = PCI_FUNC(roce->info->pdev->devfn);

	bdev->roce[fn] = NULL;
	roce->bdev = NULL;

	if (roce->ibdev && roce->ibdev->nfp_info)
		roce->ibdev->nfp_info->bdev = NULL;

	if (roce->info)
		roce->info->bdev = NULL;
}

int crdma_bond_add_ibdev(struct nfp_roce *roce)
{
	struct crdma_bond *bdev = NULL;

	bdev = crdma_bond_fetch_bdev(roce);
	if (!bdev) {
		bdev = crdma_bond_dev_alloc();
		if (!bdev) {
			crdma_err("Failed to alloc bond dev\n");
			return 0;
		}
	}

	mutex_lock(&bdev->lock);
	crdma_bdev_add_ibdev(bdev, roce);
	mutex_unlock(&bdev->lock);

	crdma_bdev_get(bdev);

	return 0;
}

void crdma_bond_del_ibdev(struct nfp_roce *roce)
{
	struct crdma_bond *bdev = NULL;

	bdev = roce->bdev;
	if (!bdev)
		return;

	mutex_lock(&bdev->lock);
	crdma_bdev_del_ibdev(bdev, roce);
	mutex_unlock(&bdev->lock);

	crdma_bdev_put(bdev);
}

int crdma_bond_is_actived(struct crdma_ibdev *crdma_dev)
{
	int actived = 0;
	struct crdma_bond *bdev = NULL;

	bdev = crdma_dev->nfp_info->bdev;

	if (!bdev)
		return actived;

	mutex_lock(&bdev->lock);
	actived = bdev->actived;
	mutex_unlock(&bdev->lock);

	return actived;
}

struct net_device *crdma_bond_get_netdev(struct crdma_ibdev *crdma_dev)
{
	int i;
	struct crdma_bond *bdev = NULL;
	struct net_device *ndev = NULL;

	bdev = crdma_dev->nfp_info->bdev;

	if (!bdev)
		goto out;

	mutex_lock(&bdev->lock);
	if (!bdev->actived)
		goto unlock;

	if (bdev->group.tx_type == NETDEV_LAG_TX_TYPE_ACTIVEBACKUP) {
		for (i = 0; i < CRDMA_BOND_MAX_PORT; i++)
			if (bdev->group.slave_state[i].tx_enabled)
				ndev = bdev->roce[i]->info->netdev;
		if (!ndev)
			ndev = bdev->roce[0]->info->netdev;
	} else {
		ndev = bdev->roce[0]->info->netdev;
	}

	if (ndev)
		dev_hold(ndev);

unlock:
	mutex_unlock(&bdev->lock);
out:
	return ndev;
}
