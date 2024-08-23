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

#ifdef KERNEL_SUPPORT_AUXI
static DEFINE_XARRAY_ALLOC1(nfp_aux_id);
#else
LIST_HEAD(rdma_device_list);
EXPORT_SYMBOL(rdma_device_list);

static DEFINE_MUTEX(roce_driver_mutex);
static struct nfp_roce_drv *roce_driver;
#endif


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
	if (!cmd)
		return -ENOENT;

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

	pf->roce_port_cnts_mem = nfp_rtsym_map(pf->rtbl, "rtlm_port_counters",
				"roce-port-cnts", NFP_ROCE_STATISTICS_PORT_SZ,
				&pf->roce_port_cnts_area);
	if (IS_ERR(pf->roce_port_cnts_mem) || !pf->roce_port_cnts_mem) {
		pf->roce_port_cnts_mem = NULL;
		pf->roce_port_cnts_area = NULL;
		nfp_warn(pf->cpp, "RoCE: aqcuire roce port counters cpp failed.\n");
	}

	pf->roce_qp_cnts_mem = nfp_rtsym_map(pf->rtbl, "rtlm_qp_counters",
				"roce-qp-cnts", NFP_ROCE_STATISTICS_QP_SZ,
				&pf->roce_qp_cnts_area);
	if (IS_ERR(pf->roce_qp_cnts_mem) || !pf->roce_qp_cnts_mem) {
		pf->roce_qp_cnts_mem = NULL;
		pf->roce_qp_cnts_area = NULL;
		nfp_warn(pf->cpp, "RoCE: aqcuire roce qp counters cpp failed.\n");
	}

	return 0;
}

void nfp_roce_free_configure_resource(struct nfp_pf *pf)
{
	if (pf->roce_command_area) {
		nfp_cpp_area_release_free(pf->roce_command_area);
		pf->roce_command_area = NULL;
		pf->roce_cmdif = NULL;
	}

	if (pf->roce_port_cnts_area) {
		nfp_cpp_area_release_free(pf->roce_port_cnts_area);
		pf->roce_port_cnts_area = NULL;
		pf->roce_port_cnts_mem = NULL;
	}

	if (pf->roce_qp_cnts_area) {
		nfp_cpp_area_release_free(pf->roce_qp_cnts_area);
		pf->roce_qp_cnts_area = NULL;
		pf->roce_qp_cnts_mem = NULL;
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

static void nfp_fill_crdma_resource(struct nfp_pf *pf, struct nfp_net *nn,
				    struct crdma_res_info *info)
{
	struct device *dev;
	int i;

	dev = nfp_cpp_device(pf->cpp);
	dev = dev->parent;

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

	if (pf->roce_port_cnts_mem)
		info->port_cnts = pf->roce_port_cnts_mem + nn->id *
				NFP_ROCE_STATISTICS_DEV_PORT_SZ;
	if (pf->roce_qp_cnts_mem)
		info->qp_cnts = pf->roce_qp_cnts_mem + nn->id *
				NFP_ROCE_STATISTICS_DEV_QP_SZ;

	info->dev_is_pf = 1;
	info->rdma_verbs_version = CRDMA_VERBS_VERSION_1;
}

#ifdef KERNEL_SUPPORT_AUXI
/**
 * nfp_adev_release - function to be mapped to AUX dev's release op
 * @dev: pointer to device to free
 */
static void nfp_adev_release(struct device *dev)
{
	struct crdma_auxiliary_device *cadev;

	cadev = container_of(dev, struct crdma_auxiliary_device, adev.dev);
	kfree(cadev);
}

int nfp_plug_aux_dev(struct nfp_pf *pf, struct nfp_roce *roce)
{
	struct crdma_auxiliary_device *cadev;
	struct auxiliary_device *adev;
	int ret;

	cadev = kzalloc(sizeof(*cadev), GFP_KERNEL);
	if (!cadev)
		return -ENOMEM;

	ret = xa_alloc(&nfp_aux_id, &cadev->aux_idx, NULL, XA_LIMIT(1, INT_MAX),
	       GFP_KERNEL);
	if (ret)
		goto err_xa_alloc;

	cadev->info = roce->info;
	adev = &cadev->adev;
	adev->id = cadev->aux_idx;
	adev->dev.release = nfp_adev_release;
	adev->dev.parent = &pf->pdev->dev;
	adev->name = "roce";

	ret = auxiliary_device_init(adev);
	if (ret)
		goto err_device_init;

	ret = auxiliary_device_add(adev);
	if (ret)
		goto err_device_add;

	roce->cadev = cadev;

	return 0;
err_device_add:
	auxiliary_device_uninit(adev);
err_device_init:
	xa_erase(&nfp_aux_id, cadev->aux_idx);
err_xa_alloc:
	kfree(cadev);
	return ret;
}

void nfp_unplug_aux_dev(struct nfp_pf *pf, struct nfp_roce *roce)
{
	struct crdma_auxiliary_device *cadev;

	cadev = roce->cadev;
	if (!cadev)
		return;

	auxiliary_device_delete(&cadev->adev);
	auxiliary_device_uninit(&cadev->adev);
	xa_erase(&nfp_aux_id, cadev->aux_idx);
	roce->cadev = NULL;
}
#else
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
	struct crdma_device_node *dev_node;

	if (!drv || drv->abi_version != NFP_ROCE_ABI_VERSION)
		return -EINVAL;

	mutex_lock(&roce_driver_mutex);
	if (roce_driver) {
		mutex_unlock(&roce_driver_mutex);
		return -EBUSY;
	}
	roce_driver = drv;

	list_for_each_entry(dev_node, &rdma_device_list, list) {
		WARN_ON(dev_node->crdma_dev);
		dev_node->crdma_dev = roce_driver->add_device(dev_node->info);

		if (IS_ERR_OR_NULL(dev_node->crdma_dev)) {
			int err = dev_node->crdma_dev ?
				PTR_ERR(dev_node->crdma_dev) : -ENODEV;
			dev_warn(&dev_node->info->pdev->dev,
				 "RoCE: Can't register device: %d\n", err);
			dev_node->crdma_dev = NULL;
		}

		if (roce_driver->bond_add_ibdev)
			roce_driver->bond_add_ibdev(dev_node);
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
		struct crdma_device_node *dev_node;

		list_for_each_entry(dev_node, &rdma_device_list, list) {
			if (dev_node->crdma_dev) {
				roce_driver->remove_device(dev_node->crdma_dev);
				dev_node->crdma_dev = NULL;
			}

			if (roce_driver->bond_del_ibdev)
				roce_driver->bond_del_ibdev(dev_node);
		}
		roce_driver = NULL;
	}
	mutex_unlock(&roce_driver_mutex);
}
EXPORT_SYMBOL_GPL(nfp_unregister_roce_driver);

/**
 * nfp_unregister_roce_ibdev() - Unregister the RoCE device.
 * @roce:       The RoCE info used to unregister a RoCE device.
 *
 * This routine is called by the Corigine RoCEv2 driver to unregister a
 * RoCE device.
 */
void nfp_unregister_roce_ibdev(struct crdma_device_node *dev_node)
{
	mutex_lock(&roce_driver_mutex);
	if (roce_driver && dev_node->crdma_dev) {
		roce_driver->remove_device(dev_node->crdma_dev);
		dev_node->crdma_dev = NULL;
	}
	mutex_unlock(&roce_driver_mutex);
}
EXPORT_SYMBOL_GPL(nfp_unregister_roce_ibdev);

/**
 * nfp_register_roce_ibdev() - Register the RoCE device.
 * @roce:       The RoCE info used to register a RoCE device.
 *
 * This routine is called by the Corigine RoCEv2 driver to register a
 * RoCE device.
 */
void nfp_register_roce_ibdev(struct crdma_device_node *dev_node)
{
	mutex_lock(&roce_driver_mutex);
	if (roce_driver && !dev_node->crdma_dev)
		dev_node->crdma_dev = roce_driver->add_device(dev_node->info);
	mutex_unlock(&roce_driver_mutex);
}
EXPORT_SYMBOL_GPL(nfp_register_roce_ibdev);

int nfp_probe_crdma_device_by_callback(struct nfp_roce *roce)
{
	struct crdma_device_node *dev_node;

	dev_node = kzalloc(sizeof(*dev_node), GFP_KERNEL);
	if (!dev_node)
		return -ENOMEM;

	mutex_lock(&roce_driver_mutex);
	if (roce_driver) {
		dev_node->crdma_dev = roce_driver->add_device(roce->info);
		if ((!dev_node->crdma_dev)) {
			kfree(dev_node);
			mutex_unlock(&roce_driver_mutex);
			return -ENOMEM;
		}

		if (roce_driver->bond_add_ibdev)
			roce_driver->bond_add_ibdev(dev_node);
	}
	dev_node->info = roce->info;
	list_add_tail(&dev_node->list, &rdma_device_list);
	mutex_unlock(&roce_driver_mutex);

	roce->dev_node = dev_node;
	return 0;
}

int nfp_unprobe_crdma_device_by_callback(struct nfp_roce *roce)
{
	struct crdma_device_node *dev_node = roce->dev_node;

	if (!dev_node)
		return 0;

	mutex_lock(&roce_driver_mutex);
	if (dev_node->crdma_dev) {
		roce_driver->remove_device(dev_node->crdma_dev);
		if (roce_driver->bond_del_ibdev)
			roce_driver->bond_del_ibdev(dev_node);
	}
	list_del(&dev_node->list);
	mutex_unlock(&roce_driver_mutex);
	kfree(dev_node);

	return 0;
}
#endif

int nfp_net_add_roce(struct nfp_pf *pf, struct nfp_net *nn)
{
	struct nfp_roce *roce;
	int ret;

	if ((nn->cap_w1 & NFP_NET_CFG_CTRL_ROCEV2) == 0)
		return 0;

	if (!nfp_roce_enabled) {
		nn->dp.ctrl_w1 &= ~NFP_NET_CFG_CTRL_ROCEV2;
		return 0;
	}

	roce = kzalloc(sizeof(*roce), GFP_KERNEL);
	if (!roce)
		return -ENOMEM;

	roce->info = kzalloc(sizeof(struct crdma_res_info) +
			     sizeof(struct msix_entry) * nn->num_roce_vecs,
			     GFP_KERNEL);
	if (!roce->info) {
		kfree(roce);
		return -ENOMEM;
	}

	nfp_fill_crdma_resource(pf, nn, roce->info);

#ifdef KERNEL_SUPPORT_AUXI
	ret = nfp_plug_aux_dev(pf, roce);
#else
	ret = nfp_probe_crdma_device_by_callback(roce);
#endif
	if (ret) {
		kfree(roce->info);
		kfree(roce);
		return ret;
	}

	nn->roce = roce;
	nn->dp.ctrl_w1 |= NFP_NET_CFG_CTRL_ROCEV2;

	return 0;
}

/**
 * nfp_net_remove_roce() - remove a RoCE device
 * @nn:		NFP net device handle
 *
 * This routine detachs a RoCE interface and releases resource related.
 */
void nfp_net_remove_roce(struct nfp_pf *pf, struct nfp_net *nn)
{
	if (IS_ERR_OR_NULL(nn->roce))
		return;

#ifdef KERNEL_SUPPORT_AUXI
	nfp_unplug_aux_dev(pf, nn->roce);
#else
	nfp_unprobe_crdma_device_by_callback(nn->roce);
#endif

	kfree(nn->roce->info);
	kfree(nn->roce);
	nn->roce = NULL;
}

