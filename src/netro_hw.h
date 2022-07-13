/*
 * Copyright (c) 2015, Netronome, Inc.  All rights reserved.
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

#ifndef NETRO_HW_H
#define NETRO_HW_H

#include <linux/compiler.h>
#include "netro_ib.h"
/*
 * netro_hw.h - Encapsulates NFP BSP/platform provided functions and
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
	NETRO_CMDIF_TOKEN_SHIFT         = 16,

	/* Command status word */
	NETRO_CMDIF_OPCODE_MOD_SHIFT    = 8,
	NETRO_CMDIF_TOGGLE_BIT          = 21,
	NETRO_CMDIF_EVENT_BIT           = 22,
	NETRO_CMDIF_GO_BIT              = 23,
	NETRO_CMDIF_STATUS_SHIFT        = 24,
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

void __netro_dump_cmdif(struct netro_ibdev *ndev);

/**
 * Write a command to the micro-code command interface. The command
 * interface mutex should be held outside of the function.
 *
 * @ndev: RoCE IB device.
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
int __netro_write_cmdif(struct netro_ibdev *ndev, u64 input_param,
		u64 output_param, u32 input_mod, u8 opcode, u8 opcode_mod,
		u16 token, bool event);

/**
 * Read polled command status from the micro-code command interface. The
 * command interface mutex should be held outside of the function.
 *
 * @ndev: RoCE IB device.
 * @output_param: Pointer to read output parameter into (set to NULL to ignore).
 * @status: Pointer to return command status (set to NULL to ignore).
 *
 * Returns 0 on success; otherwise error code.
 */
int __netro_read_cmdif_results(struct netro_ibdev *ndev,
		u64 *output_param, u8 *status);

/**
 * Report whether the command/status interface is in use.
 *
 * @ndev: RoCE IB device.
 *
 * Return true if command interface is in use; otherwise false.
 */
bool netro_cmdif_busy(struct netro_ibdev *ndev);

/*
 * Microcode provides a User Access Region (UAR) in the PCI BAR space
 * that contains doorbell register pages that may be mapped at the page level.
 */
enum {
	/* EQ Access Region Register */
	NETRO_UAR_EQ_PER_PAGE		= 8,
	NETRO_UAR_EQ_ADDR_WA_BIT	= (1 << 11),
	NETRO_UAR_EQ_CONSUMER_MASK	= 0x00FFFFFF,
	NETRO_UAR_EQ_ARM_BIT		= (1 << 31),
	NETRO_UAR_EQ_FIN_BIT		= (1 << 30),
    CORIGINE_UAR_EQ_ADDR_INTERVAL_IN_PAGE  =  0x10,
};

/*
 * The EQ doorbell UAR page is mapped for kernel only access. For Harrier the
 * first physical UAR page holds the EQ doorbells.
 */
struct eq_uar {
	struct {
		__le32	eq;
		__le32	rsvd;
	} db[NETRO_UAR_EQ_PER_PAGE] __packed;
} __packed;

/*
 * 3800 microcode provides a User Access Region (UAR) in the PCI BAR space
 * that contains doorbell register pages that may be mapped at the page level.
 */
enum {
	/* SQ Doorbell Register */
	CORIGINE_DB_SQ_ADDR_OFFSET_3800 =  (0x200 * 4),
	CORIGINE_DB_SQ_MASK	           	=  0x00FFFFFF,

	/* CQ Doorbell Register */
	CORIGINE_DB_CQ_ADDR_OFFSET_3800 =  (0x210 * 4),
	CORIGINE_DB_CQ_SEQ_SHIFT        =  30,
	CORIGINE_DB_CQN_MASK		=  0x00FFFFFF,
	CORIGINE_DB_CQ_ARM_ANY_BIT      =  (1 << 24),
};

/**
 * Update an SQ doorbell with the qp number
 *
 * @ndev: RoCE IB device.
 * @qpn: The number of the QP.
 */
void corigine_set_sq_db(struct netro_ibdev *ndev, u32 qpn);

/**
 * Update an CQ doorbell with the cp number
 *
 * @ndev: RoCE IB device.
 * @cqn: The number of the CP.
 * @solicited: If true, an event will be generated only for the next solicited CQ entry.
 *             If false, any CQ entry, solicited or not, will generate an event.
 */
void corigine_set_cq_db(struct netro_ibdev *ndev, u32 cqn, bool solicited);

/**
 * Update an EQ doorbell with the consumer index and optionally enable
 * the EQ's interrupts.
 *
 * @ndev: RoCE IB device.
 * @eqn: The number of the EQ.
 * @consumer_index: The value of the EQ consumer index to write.
 * @arm: If true, enable interrupts for the EQ when updating the index.
 */
void corigine_set_eq_ci(struct netro_ibdev *ndev,  u32 eqn,
		u32 consumer_index, bool arm);

/**
 * Acquire PCI BAR based resources assigned by NFP BSP.
 *
 * @ndev: RoCE IB device.
 *
 * Return 0 on success; otherwise error code.
 */
int netro_acquire_pci_resources(struct netro_ibdev *ndev);

/**
 * Free PCI BAR based resources previously acquired.
 *
 * @ndev: RoCE IB device.
 */
void netro_free_pci_resources(struct netro_ibdev *ndev);

/**
 * Hardware specific RoCE HCA initialization.
 *
 * @ndev: RoCE IB device.
 *
 * Return 0 on success; otherwise error code.
 */
int netro_init_hw(struct netro_ibdev *ndev);

/**
 * Hardware specific RoCE HCA cleanup.
 *
 * @ndev: RoCE IB device.
 */
void netro_cleanup_hw(struct netro_ibdev *ndev);

/**
 * Initialize IB device values that are dependent on the specific
 * chipset model family associated with this device.
 *
 * @ndev: RoCE IB device.
 * @model: The model family associated with this device.
 */
int netro_set_chip_details(struct netro_ibdev *ndev, u32 model);

#endif /* NETRO_HW_H */
