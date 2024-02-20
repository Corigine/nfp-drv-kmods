/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */

/* Authors: Guibin Xia <guibin.xia@corigine.com> */
/*          Kunlun Mao <kunlun.mao@corigine.com> */
/* Copyright (C) 2015, Netronome, Inc. */
/* Copyright (C) 2022-2025 Corigine, Inc. */

#ifndef NFPCORE_NFP_ROCE_H
#define NFPCORE_NFP_ROCE_H

#include <linux/pci.h>
#include <linux/if_ether.h>

#include "nfpcore/kcompat.h"

struct nfp_pf;
struct nfp_net;

#define DOORBELL_ROCE_OFFSET 0

/* ABI version of RoCE HCA,
 * Upper 8 bits for Major, lower 8 bits for Minor.
 */
#define NFP_ROCE_ABI_VERSION        0x0100
/* Space of configure of each RoCE device */
#define NFP_ROCE_CONFIGURE_SZ       32
/* Space of doorbell of each RoCE device */
#define NFP_ROCE_DOORBELL_SZ	    (128 * 1024)
/* The number of roce device related to one pf */
#define NFP_ROCE_DEVICE_NUMS_IN_PF  2

/**
 * struct nfp_roce_info - NFP RoCE subdriver interface
 * @pdev:		PCI Device parent of CPP interface
 * @netdev:		Network devices to attach RoCE ports to
 * @cmdif:		Command interface iomem
 * @db_base:		DMAable page area
 * @db_length:		Size of DMAable page area
 * @num_vectors:	Number of MSI-X vectors for RoCE's use
 * @msix:		MSI-X vectors (resized to num_vectors)
 */
struct nfp_roce_info {
	struct pci_dev	*pdev;
	struct net_device *netdev;

	/*
	 * PCI Resources allocated by the NFP core and
	 * acquired/released by the RoCE driver:
	 * 1) Driver/ME command interface
	 * 2) DB area (first page is for EQs, the remainder for SQ/CQ)
	 */
	void __iomem *cmdif;
	phys_addr_t  db_base;
	u32 db_length;		/* The length of the physical doorbell area */

	/*
	 * Pool of interrupt vectors that RoCE driver can use for
	 * setting up EQ interrupts.
	 */
	u32	num_vectors;
	struct msix_entry	msix[];
};

struct crdma_ibdev;

/**
 * struct nfp_roce_drv - NFP RoCE driver interface
 * @abi_version:	Must be NFP_ROCE_ABI_VERSION
 * @add_device:		Callback to create a new RoCE device
 * @remove_device:	Callback to remove an existing RoCE device
 * @event_notifier:	Callback to update an existing RoCE device's state
 *
 * NFP RoCE register driver input parameters. Passed to the NFP core
 * in the nfp_register_roce_driver() and nfp_unregister_roce_driver()
 * functions.
 *
 * The add_device() call back will return the RoCE device.
 * This is opaque to the NIC, but should be passed in remove_device()
 * or state_change() callbacks.
 *
 * The event_notifier() call back is a state change handler
 * used to pass NFP device state changes from NFP driver to RoCE driver.
 */
struct nfp_roce_drv {
	u32	abi_version;
	struct crdma_ibdev *(*add_device)(struct nfp_roce_info *roce_info);
	void	(*remove_device)(struct crdma_ibdev *ibdev);
	void	(*event_notifier)(struct crdma_ibdev *ibdev,
				  int port, u32 state);
};

int nfp_register_roce_driver(struct nfp_roce_drv *drv);
void nfp_unregister_roce_driver(struct nfp_roce_drv *drv);

#ifdef CONFIG_NFP_ROCE
extern unsigned int nfp_roce_ints_num;
extern bool nfp_roce_enabled;
struct nfp_roce;

int nfp_net_add_roce(struct nfp_pf *pf, struct nfp_net *nn);
void nfp_net_remove_roce(struct nfp_net *nn);

int nfp_roce_irqs_wanted(void);
void nfp_roce_irqs_assign(struct nfp_net *nn, struct msix_entry *irq_entries,
			  unsigned int entry_num);
int nfp_roce_acquire_configure_resource(struct nfp_pf *pf);
void nfp_roce_free_configure_resource(struct nfp_pf *pf);

#else /* !CONFIG_NFP_ROCE */

static inline
int nfp_net_add_roce(struct nfp_pf *pf, struct nfp_net *nn)
{
	return 0;
}
static inline
void nfp_net_remove_roce(struct nfp_net *nn)
{
}

static inline
int nfp_roce_irqs_wanted(void)
{
	return 0;
}
static inline
void nfp_roce_irqs_assign(struct nfp_net *nn, struct msix_entry *irq_entries,
			  unsigned int entry_num)
{
}
static inline
int nfp_roce_acquire_configure_resource(struct nfp_pf *pf)
{
	return 0;
}
static inline
void nfp_roce_free_configure_resource(struct nfp_pf *pf)
{
}

#endif

#endif /* NFPCORE_NFP_ROCE_H */