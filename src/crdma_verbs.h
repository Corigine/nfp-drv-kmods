/*
 * Copyright (c) 2015, Netronome, Inc.  All rights reserved.
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

#ifndef CRDMA_VERBS_H
#define CRDMA_VERBS_H

#include <linux/compiler.h>
#include "crdma_ib.h"

/*
 * This is a temporary value. We may change this later according
 * to the value in rdma_driver_id.
 */
#define RDMA_DRIVER_CORIGINE       19
/*
 * This is a temporary bit that allows an application to specifically
 * ask for internal loop-back. This is a debug helper using for using
 * a single card during development (without external loop-back).
 */
enum {
       CRDMA_IB_SEND_LOOPBACK                  = 1 << 8
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
