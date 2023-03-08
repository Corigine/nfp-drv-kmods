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

#ifndef CRDMA_HW_H
#define CRDMA_HW_H

#include <linux/compiler.h>
#include "crdma_ib.h"
/*
 * crdma_hw.h - Encapsulates NFP BSP/platform provided functions and
 * hardware specific operations that are based on ASIC family.
 */

/**
 * Microcode command/status interface in HCA PCI BAR I/O memory space.
 *
 * The kernel driver configures/commands microcode by posting commands
 * through this interface. Status is returned either directly through this
 * interface (polled mode), or via EQ notification (blocking mode).
 * The register is written as a series of 32-bit words.
 *
 * The interface is serialized with a mutex since it will not be
 * accessed in an interrupt or softirq context.
 */
enum {
	/* Token word */
	CRDMA_CMDIF_TOKEN_SHIFT         = 16,

	/* Command status word */
	CRDMA_CMDIF_OPCODE_MOD_SHIFT    = 8,
	CRDMA_CMDIF_TOGGLE_BIT          = 21,
	CRDMA_CMDIF_EVENT_BIT           = 22,
	CRDMA_CMDIF_GO_BIT              = 23,
	CRDMA_CMDIF_STATUS_SHIFT        = 24,
};

/*
 * Register is defined in little endian for host accesses; data is
 * converted to big endian for microcode by hardware byte swap as it is
 * written to NFP.
 */
struct cmdif_reg {
	__le32	input_param_high;
	__le32	input_param_low;
	__le32	input_mod;
	__le32	output_param_high;
	__le32	output_param_low;
	__le32	token;
	__le32	cmd_status;
} __packed;

/**
 * Write a command to the micro-code command interface. The command
 * interface mutex should be held outside of the function.
 *
 * @dev: RoCE IB device.
 * @input_param: The input parameter value.
 * @output_param: The output parameter value.
 * @input_mod: The input modifier.
 * @opcode: The command opcode.
 * @opcode_mod: The opcode modifier.
 * @token: The token associated with the command.
 * @event: Use event mode completion notification.
 *
 * Returns 0 on success; otherwise error code.
 */
int __crdma_write_cmdif(struct crdma_ibdev *dev, u64 input_param,
		u64 output_param, u32 input_mod, u8 opcode, u8 opcode_mod,
		u16 token, bool event);

/**
 * Read polled command status from the micro-code command interface. The
 * command interface mutex should be held outside of the function.
 *
 * @dev: RoCE IB device.
 * @output_param: Pointer to read output parameter into (set to NULL to ignore).
 * @status: Pointer to return command status (set to NULL to ignore).
 *
 * Returns 0 on success; otherwise error code.
 */
int __crdma_read_cmdif_results(struct crdma_ibdev *dev,
		u64 *output_param, u8 *status);

/**
 * Report whether the command/status interface is in use.
 *
 * @dev: RoCE IB device.
 *
 * Return true if command interface is in use; otherwise false.
 */
bool crdma_cmdif_busy(struct crdma_ibdev *dev);

/*
 * Microcode provides a User Access Region (UAR) in the PCI BAR space
 * that contains doorbell register pages that may be mapped at the page level.
 */
enum {
	/* EQ Access Region Register */
	CRDMA_UAR_EQ_PER_PAGE		    = 8,
	CRDMA_UAR_EQ_ADDR_WA_BIT	    = (1 << 11),
	CRDMA_UAR_EQ_CONSUMER_MASK	    = 0x00FFFFFF,
	CRDMA_UAR_EQ_ARM_BIT		    = (1 << 31),
	CRDMA_UAR_EQ_FIN_BIT		    = (1 << 30),
	CRDMA_UAR_EQ_ADDR_INTERVAL_IN_PAGE  =  0x10,
};

/*
 * The EQ doorbell UAR page is mapped for kernel only access. For Harrier the
 * first physical UAR page holds the EQ doorbells.
 */
struct eq_uar {
	struct {
		__le32	eq;
		__le32	rsvd;
	} db[CRDMA_UAR_EQ_PER_PAGE] __packed;
} __packed;

/*
 * 3800 microcode provides a User Access Region (UAR) in the PCI BAR space
 * that contains doorbell register pages that may be mapped at the page level.
 */
enum {
	/* SQ Doorbell Register */
	CRDMA_DB_SQ_ADDR_OFFSET         =  (0x200 * 4),
	CRDMA_DB_SQ_MASK                =  0x00FFFFFF,

	/* CQ Doorbell Register */
	CRDMA_DB_CQ_ADDR_OFFSET         =  (0x210 * 4),
	CRDMA_DB_CQ_SEQ_SHIFT           =  30,
	CRDMA_DB_CQN_MASK               =  0x00FFFFFF,
	CRDMA_DB_CQ_ARM_ANY_BIT         =  (1 << 24),
	CRDMA_DB_CQCI_ADDR_OFFSET       =  0x24,
	CRDMA_DB_WA_BIT                 =  1 << 11,
	CRDMA_DB_CQ_CONS_MASK           =  0x00FFFFFF,
	CRDMA_DB_FIN_BIT                =  1 << 30,
};

/**
 * Update an SQ doorbell with the qp number
 *
 * @dev: RoCE IB device.
 * @qpn: The number of the QP.
 */
void crdma_set_sq_db(struct crdma_ibdev *dev, u32 qpn);

/**
 * Update an CQ doorbell with the cp number
 *
 * @dev: RoCE IB device.
 * @cqn: The number of the CP.
 * @solicited: If true, an event will be generated only for the next solicited CQ entry.
 *             If false, any CQ entry, solicited or not, will generate an event.
 */
void crdma_set_cq_db(struct crdma_ibdev *dev, u32 cqn, bool solicited);

/**
 * Update an EQ doorbell with the consumer index and optionally enable
 * the EQ's interrupts.
 *
 * @dev: RoCE IB device.
 * @eqn: The number of the EQ.
 * @consumer_index: The value of the EQ consumer index to write.
 * @arm: If true, enable interrupts for the EQ when updating the index.
 */
void crdma_set_eq_ci(struct crdma_ibdev *dev,  u32 eqn,
		u32 consumer_index, bool arm);

/**
 * Acquire PCI BAR based resources assigned by NFP BSP.
 *
 * @dev: RoCE IB device.
 *
 * Return 0 on success; otherwise error code.
 */
int crdma_acquire_pci_resources(struct crdma_ibdev *dev);

/**
 * Free PCI BAR based resources previously acquired.
 *
 * @dev: RoCE IB device.
 */
void crdma_free_pci_resources(struct crdma_ibdev *dev);

/**
 * Hardware specific RoCE HCA initialization.
 *
 * @dev: RoCE IB device.
 *
 * Return 0 on success; otherwise error code.
 */
int crdma_init_hw(struct crdma_ibdev *dev);

/**
 * Hardware specific RoCE HCA cleanup.
 *
 * @dev: RoCE IB device.
 */
void crdma_cleanup_hw(struct crdma_ibdev *dev);


#endif /* CRDMA_HW_H */
