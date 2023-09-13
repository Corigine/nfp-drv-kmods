// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

/* Authors: Guibin Xia <guibin.xia@corigine.com> */
/*          Kunlun Mao <kunlun.mao@corigine.com> */
/* Copyright (C) 2015, Netronome, Inc. */
/* Copyright (C) 2022-2025 Corigine, Inc. */

#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/module.h>
#include <linux/list.h>

#include "nfp.h"
#include "nfp_roce.h"
#include "nfp_nffw.h"
#include "nfp_main.h"

#include "nfp6000/nfp6000.h"

struct nfp_roce {
	struct list_head list;
	struct nfp_roce_info *info;
	struct crdma_ibdev *ibdev;
};

static LIST_HEAD(nfp_roce_list);

static DEFINE_MUTEX(roce_driver_mutex);
static struct nfp_roce_drv *roce_driver;

/**
 * nfp_register_roce_driver() - Register the RoCE driver with NFP core.
 * @drv:		RoCE driver callback function table.
 *
 * This routine is called by the Corigine RoCEv2 kernel driver to
 * notify the NFP NIC/core driver that the RoCE driver has been loaded. If
 * RoCE is not enabled or the ABI version is not supported, the NFP NIC/core
 * should return an error. Otherwise, the NFP NIC/core should invoke the
 * add_device() callback for each NIC instance.
 *
 * Return: 0, or -ERRNO
 */
int nfp_register_roce_driver(struct nfp_roce_drv *drv)
{
	struct nfp_roce *roce;

	if (!drv || drv->abi_version != NFP_ROCE_ABI_VERSION)
		return -EINVAL;

	mutex_lock(&roce_driver_mutex);
	if (roce_driver) {
		mutex_unlock(&roce_driver_mutex);
		return -EBUSY;
	}
	roce_driver = drv;

	list_for_each_entry(roce, &nfp_roce_list, list) {
		WARN_ON(roce->ibdev);
		roce->ibdev = roce_driver->add_device(roce->info);

		if (IS_ERR_OR_NULL(roce->ibdev)) {
			int err = roce->ibdev ? PTR_ERR(roce->ibdev) : -ENODEV;

			dev_warn(&roce->info->pdev->dev,
				 "RoCE: Can't register device: %d\n", err);
			roce->ibdev = NULL;
		}
	}

	mutex_unlock(&roce_driver_mutex);

	return 0;
}
EXPORT_SYMBOL_GPL(nfp_register_roce_driver);

/**
 * nfp_unregister_roce_driver() - Unregister the RoCE driver with NFP core.
 * @drv:	The callback function table passed in the associated
 *		nfp_register_roce_driver() call.
 *
 * This routine is called by the Corigine RoCEv2 driver to notify the NFP
 * NIC/core driver that the RoCE driver is unloading. The NFP NIC
 * driver invokes the remove_device routine for each Corigine RoCE device
 * that has been added.
 */
void nfp_unregister_roce_driver(struct nfp_roce_drv *drv)
{
	mutex_lock(&roce_driver_mutex);
	if (drv == roce_driver) {
		struct nfp_roce *roce;

		list_for_each_entry(roce, &nfp_roce_list, list) {
			if (!roce->ibdev)
				continue;
			roce_driver->remove_device(roce->ibdev);
			roce->ibdev = NULL;
		}
		roce_driver = NULL;
	}
	mutex_unlock(&roce_driver_mutex);
}
EXPORT_SYMBOL_GPL(nfp_unregister_roce_driver);

/**
 * nfp_roce_acquire_configure_resource() - Acquire configure resources for RoCE.
 * @pf:             NFP Device PF handle
 *
 * This routine can be called in NFP driver, it will acquire cpp resource for
 * RoCE including configure interace and doorbell.
 *
 * Return: 0 on success, or -errno on failure
 */
int nfp_roce_acquire_configure_resource(struct nfp_pf *pf)
{
	const char *cmd_symbol = "_cmd_iface_reg";
	const struct nfp_rtsym *cmd;
	unsigned long barsz;
	u64 cpp_addr;
	u32 cpp_id;

	if (!nfp_roce_enabled)
		return 0;

	/* acquire configure */
	cmd = nfp_rtsym_lookup(pf->rtbl, cmd_symbol);
	if (!cmd) {
		nfp_err(pf->cpp, "RoCE: rtsym '%s' does not exist\n",
			cmd_symbol);
		return -ENOENT;
	}

	if (pf->multi_pf.en) {
		cpp_id = NFP_CPP_ISLAND_ID(cmd->target, NFP_CPP_ACTION_RW,
					   0, cmd->domain);
		cpp_addr = cmd->addr +
			   NFP_ROCE_CONFIGURE_SZ * pf->multi_pf.id;
		barsz = NFP_ROCE_CONFIGURE_SZ;
	} else {
		/* Single PF mode, one pf prode allocate all
		 * roce device resources
		 */
		cpp_id = NFP_CPP_ISLAND_ID(cmd->target, NFP_CPP_ACTION_RW,
					   0, cmd->domain);
		cpp_addr = cmd->addr;
		barsz = NFP_ROCE_CONFIGURE_SZ * NFP_ROCE_DEVICE_NUMS_IN_PF;
	}

	pf->roce_command_area =
		nfp_cpp_area_alloc_acquire(pf->cpp, "roce-cmd",
					   cpp_id, cpp_addr, barsz);
	if (!(pf->roce_command_area)) {
		nfp_err(pf->cpp, "RoCE: aqcuire roce command cpp failed.\n");
		return -ENOMEM;
	}

	pf->roce_cmdif = nfp_cpp_area_iomem(pf->roce_command_area);

	return 0;
}

void nfp_roce_free_configure_resource(struct nfp_pf *pf)
{
	if (pf->roce_command_area) {
		nfp_cpp_area_release_free(pf->roce_command_area);
		pf->roce_command_area = NULL;
		pf->roce_cmdif = NULL;
	}
}

int nfp_roce_irqs_wanted(void)
{
	int vecs;

	if (!nfp_roce_enabled)
		return 0;

	vecs = min_t(int, nfp_roce_ints_num, NFP_NET_MAX_ROCE_VECTORS);
	return min_t(int, vecs, num_online_cpus());
}

void nfp_roce_irqs_assign(struct nfp_net *nn, struct msix_entry *irq_entries,
			  unsigned int entry_num)
{
	int i;

	if (!nfp_roce_enabled)
		return;

	/* There is no irq needed for RoCE */
	if (entry_num == 0)
		return;

	if (entry_num > NFP_NET_MAX_ROCE_VECTORS) {
		dev_warn(nn->dp.dev,
			"Unmatched irq numbers, assigned %d, max: %d.\n",
			 NFP_NET_MAX_ROCE_VECTORS, entry_num);
		return;
	}

	nn->num_roce_vecs = entry_num;
	memcpy(nn->roce_irq_entries, irq_entries,
	       sizeof(*irq_entries) * entry_num);

	/* Debug for */
	for (i = 0; i < entry_num; i++) {
		dev_dbg(nn->dp.dev, "roce msix: id: %d, entry: %d, vector: %d\n",
			i, irq_entries[i].entry, irq_entries[i].vector);
	}
}


int nfp_net_add_roce(struct nfp_pf *pf, struct nfp_net *nn)
{
	struct nfp_roce_info *info;
	struct nfp_roce *roce;
	struct device *dev;
	int err, i;

	if ((nn->cap_w1 & NFP_NET_CFG_CTRL_ROCEV2) == 0) {
		nfp_warn(pf->cpp, "Firmware has no RoCEv2 capacity\n");
		return 0;
	}

	if (!nfp_roce_enabled) {
		nn->dp.ctrl_w1 &= ~NFP_NET_CFG_CTRL_ROCEV2;
		return 0;
	}

	/* First, let's validate that the NFP device is
	 * a PCI interface.
	 */
	if (!pf || !(pf->cpp))
		return -EINVAL;

	/* configure interface or doorbell is not mapped */
	if (!(pf->roce_cmdif) || !(pf->db_iomem)) {
		nfp_warn(pf->cpp,
			"RoCE resources are not mapped successfully, %p, %p\n",
			pf->roce_cmdif, pf->db_iomem);
		return -EINVAL;
	}

	if (nn->id >= NFP_ROCE_DEVICE_NUMS_IN_PF) {
		nfp_warn(pf->cpp,
			"RoCE vnic ID is invalid, current vnic: %d, max vnic: %d\n",
			nn->id, NFP_ROCE_DEVICE_NUMS_IN_PF - 1);
		return -EINVAL;
	}

	dev = nfp_cpp_device(pf->cpp);
	if (!dev || !dev->parent)
		return -ENODEV;

	dev = dev->parent;

	if (!dev_is_pci(dev))
		return -EINVAL;

	if (!nn->dp.netdev)
		return -EINVAL;

	roce = kzalloc(sizeof(*roce), GFP_KERNEL);
	if (!roce)
		return -ENOMEM;

	roce->info = kzalloc(sizeof(struct nfp_roce_info) +
			     sizeof(struct msix_entry) * nn->num_roce_vecs,
			     GFP_KERNEL);
	if (!roce->info) {
		kfree(roce);
		return -ENOMEM;
	}

	info = roce->info;
	info->pdev = to_pci_dev(dev);
	info->netdev = nn->dp.netdev;
	if (pf->multi_pf.en) {
		info->cmdif =  pf->roce_cmdif;
		info->db_base = pf->db_phys + DOORBELL_ROCE_OFFSET;
	} else {
		info->cmdif = pf->roce_cmdif + nn->id * NFP_ROCE_CONFIGURE_SZ;
		info->db_base = pf->db_phys + DOORBELL_ROCE_OFFSET +
				nn->id * NFP_ROCE_DOORBELL_SZ;
	}
	info->db_length = NFP_ROCE_DOORBELL_SZ;
	info->num_vectors = nn->num_roce_vecs;
	for (i = 0; i < nn->num_roce_vecs; i++)
		info->msix[i] = nn->roce_irq_entries[i];

	nn->roce = roce;

	mutex_lock(&roce_driver_mutex);
	list_add_tail(&roce->list, &nfp_roce_list);

	if (roce_driver) {
		roce->ibdev = roce_driver->add_device(info);
		if (IS_ERR_OR_NULL(roce->ibdev)) {
			err = roce->ibdev ? PTR_ERR(roce->ibdev) : -ENODEV;
			nfp_warn(pf->cpp,
				"RoCE: Can't create interface: %d\n", err);
			roce->ibdev = NULL;
		}
	}
	mutex_unlock(&roce_driver_mutex);

	nn->dp.ctrl_w1 |= NFP_NET_CFG_CTRL_ROCEV2;

	return 0;
}

/**
 * nfp_net_remove_roce() - remove a RoCE device
 * @nn:		NFP net device handle
 *
 * This routine detachs a RoCE interface and releases resource related.
 */
void nfp_net_remove_roce(struct nfp_net *nn)
{
	if (IS_ERR_OR_NULL(nn->roce))
		return;

	mutex_lock(&roce_driver_mutex);
	list_del(&nn->roce->list);

	if (nn->roce->ibdev)
		roce_driver->remove_device(nn->roce->ibdev);

	kfree(nn->roce->info);
	kfree(nn->roce);
	nn->roce = NULL;
	mutex_unlock(&roce_driver_mutex);
}

