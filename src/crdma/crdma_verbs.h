/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright (C) 2023 Corigine, Inc. */

#ifndef CRDMA_VERBS_H
#define CRDMA_VERBS_H

#include <linux/compiler.h>
#include "crdma_ib.h"

#define CRDMA_DEFAULT_PKEY	0xFFFF
/*
 * This is a temporary value. We may change this later according
 * to the value in rdma_driver_id.
 */

#ifndef RDMA_DRIVER_CRDMA
#define RDMA_DRIVER_CRDMA	19
#endif

/*
 * This is a temporary bit that allows an application to specifically
 * ask for internal loop-back. This is a debug helper using for using
 * a single card during development (without external loop-back).
 */
enum {
	CRDMA_IB_SEND_LOOPBACK	= 1 << 8
};

/**
 * Register IB device with the IB core.
 *
 * @dev: RoCE IB device.
 */
int crdma_register_verbs(struct crdma_ibdev *dev);

/**
 * Unregister IB device from the IB core.
 *
 * @dev: RoCE IB device.
 */
void crdma_unregister_verbs(struct crdma_ibdev *dev);

#endif /* CRDMA_VERBS_H */
