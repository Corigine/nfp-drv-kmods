/*
 * Copyright (c) 2015, Netronome, Inc. All rights reserved.
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
 *	copyright notice, this list of conditions and the following
 *	disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *	copyright notice, this list of conditions and the following
 *	disclaimer in the documentation and/or other materials
 *	provided with the distribution.
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

#include <linux/module.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/pci.h>
#include <linux/interrupt.h>

#include "nfp_roce.h"
#include "crdma_ib.h"
#include "crdma_hw.h"
#include "crdma_util.h"
#include "crdma_ucif.h"

#define	CRDMA_UNDEFINED		"Undefined"

/**
 * Map a IB Verbs QP transition to the QP_MODIFY command opcode modifier.
 *
 * @cur_state: The QP current state.
 * @new_state: The QP state to transition to.
 *
 * Returns the command opcode modifier or -EINVAL.
 */
static int crdma_qp_modify_opcode_mod(enum ib_qp_state cur_state,
		enum ib_qp_state new_state)
{
	int modifier;
	static const u16 opcode_mod[IB_QPS_ERR+1][IB_QPS_ERR+1] = {
		[IB_QPS_RESET] = {
			[IB_QPS_RESET]	= CRDMA_QP_MODIFY_2RST,
			[IB_QPS_INIT]	= CRDMA_QP_MODIFY_RST2INIT,
			[IB_QPS_ERR]	= CRDMA_QP_MODIFY_2ERR,
		},
		[IB_QPS_INIT] = {
			[IB_QPS_RESET]	= CRDMA_QP_MODIFY_2RST,
			[IB_QPS_INIT]	= CRDMA_QP_MODIFY_INIT2INIT,
			[IB_QPS_RTR]	= CRDMA_QP_MODIFY_INIT2RTR,
			[IB_QPS_ERR]	= CRDMA_QP_MODIFY_2ERR,
		},
		[IB_QPS_RTR] = {
			[IB_QPS_RESET]	= CRDMA_QP_MODIFY_2RST,
			[IB_QPS_RTS]	= CRDMA_QP_MODIFY_RTR2RTS,
			[IB_QPS_ERR]	= CRDMA_QP_MODIFY_2ERR,
		},
		[IB_QPS_RTS] = {
			[IB_QPS_RESET]	= CRDMA_QP_MODIFY_2RST,
			[IB_QPS_RTS]	= CRDMA_QP_MODIFY_RTS2RTS,
			[IB_QPS_SQD]	= CRDMA_QP_MODIFY_RTS2SQD,
			[IB_QPS_ERR]	= CRDMA_QP_MODIFY_2ERR,
		},
		[IB_QPS_SQD] = {
			[IB_QPS_RESET]	= CRDMA_QP_MODIFY_2RST,
			[IB_QPS_RTS]	= CRDMA_QP_MODIFY_SQD2RTS,
			[IB_QPS_SQD]	= CRDMA_QP_MODIFY_SQD2SQD,
			[IB_QPS_ERR]	= CRDMA_QP_MODIFY_2ERR,
		},
		[IB_QPS_SQE] = {
			[IB_QPS_RESET]	= CRDMA_QP_MODIFY_2RST,
			[IB_QPS_RTS]	= CRDMA_QP_MODIFY_SQER2RTS,
			[IB_QPS_ERR]	= CRDMA_QP_MODIFY_2ERR,
		},
		[IB_QPS_ERR] = {
			[IB_QPS_RESET]	= CRDMA_QP_MODIFY_2RST,
			[IB_QPS_ERR]	= CRDMA_QP_MODIFY_2ERR,
		}
	};

	if (cur_state > IB_QPS_ERR || new_state > IB_QPS_ERR)
		return -EINVAL;

	modifier = opcode_mod[cur_state][new_state];
	if (!modifier)
		modifier = -EINVAL;
	return modifier;
}

/**
 * Map microcode command opcode to string.
 *
 * @opcode: The command opcode.
 *
 * Returns the associated string.
 */
const char *crdma_opcode_to_str(u8 opcode)
{
	static const char *cmd_to_str[] = {
		[0]				= CRDMA_UNDEFINED,
		[CRDMA_CMD_NO_OP]		= "NO-OP",
		[CRDMA_CMD_QUERY_DEV_CAP]	= "QUERY_DEV_CAP",
		[CRDMA_CMD_QUERY_UCODE]		= "QUERY_UCODE",
		[CRDMA_CMD_QUERY_NIC]		= "QUERY_NIC",
		[CRDMA_CMD_QUERY_HCA]		= CRDMA_UNDEFINED,
		[CRDMA_CMD_QUERY_PORT]		= CRDMA_UNDEFINED,
		[CRDMA_CMD_HCA_ENABLE]		= "HCA_ENABLE",
		[CRDMA_CMD_HCA_DISABLE]		= "HCA_DISABLE",
		[CRDMA_CMD_ROCE_PORT_ENABLE]	= "ROCE_PORT_ENABLE",
		[CRDMA_CMD_ROCE_PORT_DISABLE]	= "ROCE_PORT_DISABLE",
		[CRDMA_CMD_SET_BS_HOST_MEM_SIZE] = "SET_BS_HOST_MEM_SIZE",
		[CRDMA_CMD_MAP_BS_HOST_MEM]	= "MAP_BS_HOST_MEM",
		[CRDMA_CMD_UNMAP_BS_HOST_MEM]	= "UNMAP_BS_HOST_MEM",
		[CRDMA_CMD_MPT_CREATE]		= "MPT_CREATE",
		[CRDMA_CMD_MPT_DESTROY]		= "MPT_DESTROY",
		[CRDMA_CMD_MPT_QUERY]		= "MPT_QUERY",
		[CRDMA_CMD_MTT_WRITE]		= "MTT_WRITE",
		[CRDMA_CMD_MTT_READ]		= "MTT_READ",
		[CRDMA_CMD_MAPT_SYNC]		= "MAPT_SYNC",
		[CRDMA_CMD_SET_PORT_GID_TABLE]	= "SET_PORT_GID_TABLE",
		[CRDMA_CMD_GET_PORT_GID_TABLE]	= "GET_PORT_GID_TABLE",
		[CRDMA_CMD_SET_PORT_MAC_TABLE]	= "SET_PORT_MAC_TABLE",
		[CRDMA_CMD_GET_PORT_MAC_TABLE]	= "GET_PORT_MAC_TABLE",
		[CRDMA_CMD_SET_PORT_VLAN_TABLE]	= "SET_PORT_VLAN_TABLE",
		[CRDMA_CMD_GET_PORT_VLAN_TABLE]	= "GET_PORT_VLAN_TABLE",
		[CRDMA_CMD_EQ_CREATE]		= "EQ_CREATE",
		[CRDMA_CMD_EQ_DESTROY]		= "EQ_DESTROY",
		[CRDMA_CMD_EQ_MAP]		= "EQ_MAP",
		[CRDMA_CMD_QP_MODIFY]		= "QP_MODIFY",
		[CRDMA_CMD_QP_QUERY]		= "QP_QUERY",
		[CRDMA_CMD_QP_SUSPEND]		= "QP_SUSPEND",
		[CRDMA_CMD_QP_RESUME]		= "QP_RESUME",
		[CRDMA_CMD_CQ_CREATE]		= "CQ_CREATE",
		[CRDMA_CMD_CQ_DESTROY]		= "CQ_DESTROY",
		[CRDMA_CMD_CQ_MODIFY]		= "CQ_MODIFY",
		[CRDMA_CMD_CQ_RESIZE]		= "CQ_RESIZE",
		[CRDMA_CMD_CQ_RESIZE]           = "CQ_RESIZE",
		[CRDMA_CMD_SRQ_CREATE]          = "SRQ_CREATE",
		[CRDMA_CMD_SRQ_DESTROY]         = "SRQ_DESTROY",
		[CRDMA_CMD_SRQ_SET_ARM_LIMIT]   = "SRQ_SET_ARM_LIMIT",
		[CRDMA_CMD_MCG_CREATE]          = "MCG_CREATE",
		[CRDMA_CMD_MCG_DESTROY]         = "MCG_DESTROY",
		[CRDMA_CMD_MCG_ATTACH]          = "MCG_ATTACH",
		[CRDMA_CMD_MCG_DETACH]          = "MCG_DETACH"
	};

	if (opcode < ARRAY_SIZE(cmd_to_str))
		return cmd_to_str[opcode];
	else
		return CRDMA_UNDEFINED;
}

/**
 * Map microcode command status to a string.
 *
 * @status: The status.
 *
 * Returns the associated string.
 */
const char *crdma_status_to_str(u8 status)
{
	static const char *status_to_str[] = {
		[CRDMA_STS_OK]			= "success",
		[CRDMA_STS_UCODE_CORRUPTED]	= "microcode corrupted",
		[CRDMA_STS_UCODE_INTERNAL_ERR]	= "microcode internal error",
		[CRDMA_STS_UNSUPPORTED_OPCODE]	= "opcode not supported",
		[CRDMA_STS_BAD_PARAMETER]	= "bad parameter",
		[CRDMA_STS_BAD_SYSTEM_STATE]	= "bad system state",
		[CRDMA_STS_BAD_CNTRL_OBJ_REF]	=
					"bad control object reference",
		[CRDMA_STS_CNTRL_OBJ_BUSY]	= "control object in use",
		[CRDMA_STS_EXCEEDS_HCA_LIMITS]	= "exceeds device capabilities",
		[CRDMA_STS_BAD_CNTRL_OBJ_STATE]	= "bad control object state",
		[CRDMA_STS_INVALID_INDEX]	= "invalid index",
		[CRDMA_STS_BAD_QP_STATE]	= "bad QP state",
		[CRDMA_STS_BAD_SIZE]		= "bad size specified",
		[CRDMA_STS_INVALID_PORT]	= "bad size specified"
	};

	if (status < ARRAY_SIZE(status_to_str))
		return status_to_str[status];
	else
		return CRDMA_UNDEFINED;
}

/**
 * Map microcode interrupt event type to a string.
 *
 * @event_type: The event type.
 *
 * Returns the associated string.
 */
const char *crdma_event_to_str(u8 event_type)
{
	static const char *event_to_str[] = {
		[0]				= CRDMA_UNDEFINED,
		[CRDMA_EQ_CQ_COMPLETION_NOTIFY]	= "CQ completion",
		[CRDMA_EQ_CQ_ERROR]		= "CQ error",

		[CRDMA_EQ_QP_COMM_ESTABLISHED]	=
					"QP communication established",
		[CRDMA_EQ_QP_SQ_DRAINED]	= "QP SQ drained",
		[CRDMA_EQ_QP_SQ_LAST_WQE]	= "QP SQ last WQE",
		[CRDMA_EQ_QP_CATASTROPHIC_ERROR] = "QP catastrophic error",
		[CRDMA_EQ_QP_INVALID_REQUEST]	= "QP invalid request",
		[CRDMA_EQ_QP_ACCESS_ERROR]	= "QP access error",

		[CRDMA_EQ_SRQ_LIMIT_REACHED]	= "SRQ limit reached",
		[CRDMA_EQ_SRQ_CATASTROPHIC_ERROR] = "SRQ catastrophic error",

		[CRDMA_EQ_EQ_OVERRUN_ERROR]	= "EQ overrun",
		[CRDMA_EQ_CMDIF_COMPLETE]	= "Command complete",
		[CRDMA_EQ_LOCAL_CATASTROPHIC_ERROR] =
					"Local catastrophic error",
		[CRDMA_EQ_PORT_CHANGE]		= "Port change",
		[CRDMA_EQ_MGMT_PORT_CHANGE]	= "Management port change",
		[CRDMA_EQ_MICROCODE_WARNING]	= "Microcode warning"
	};

	if (event_type < ARRAY_SIZE(event_to_str))
		return event_to_str[event_type];
	else
		return CRDMA_UNDEFINED;
}

/**
 * Issue a micro-code command in polled mode. In polled mode, only a single
 * command can be processed at a time; therefore polled mode is typically
 * reserved for driver initialization before the event delivery infrastructure
 * has been initialized.
 *
 * @dev: RoCE IB device.
 * @cmd: The microcode interface command parameters.
 *
 * Returns 0 if command completed; otherwise error code.
 */
static int crdma_polled_cmd(struct crdma_ibdev *dev, struct crdma_cmd *cmd)
{
	unsigned long max_time;
	u64 output_param;
	int ret;

	down(&dev->poll_sem);
	mutex_lock(&dev->cmdif_mutex);

	/* Issue command to microcode */
	ret = __crdma_write_cmdif(dev, cmd->input_param, cmd->output_param,
			cmd->input_mod, cmd->opcode, cmd->opcode_mod,
			CRDMA_CMDIF_POLL_TOKEN, false);

	/* Poll for completion */
	max_time = msecs_to_jiffies(cmd->timeout) + jiffies;
	while (crdma_cmdif_busy(dev)) {
		if (time_after_eq(jiffies, max_time)) {
			crdma_info("UCODE %s cmd timed out\n",
					crdma_opcode_to_str(cmd->opcode));
			ret = -EIO;
			goto done;
		}
		cond_resched();
		if (pci_channel_offline(dev->nfp_info->pdev)) {
			ret = -EIO;
			goto done;
		}
	}

	crdma_info("==== UCODE %s cmd done\n",
			crdma_opcode_to_str(cmd->opcode));

	/* Get polled results */
	if (__crdma_read_cmdif_results(dev, &output_param, &cmd->status)) {
		ret = -EIO;
		goto done;
	}

	crdma_info("==== UCODE Status: %s\n", crdma_status_to_str(cmd->status));

	if (cmd->output_imm)
		cmd->output_param = output_param;

done:
	mutex_unlock(&dev->cmdif_mutex);
	up(&dev->poll_sem);
	return ret;
}

static struct crdma_eqe *crdma_next_eqe(struct crdma_eq *eq);
static irqreturn_t crdma_interrupt(int irq, void *eq_ptr);

/**
 * Issue a micro-code command in an event driven mode. Command status/results
 * will be indicated via an EQ completion notification. The driver limits
 * the number of concurrent event driven commands to the maximum supported
 * by micro-code.
 *
 * @dev: RoCE IB device.
 * @cmd: The microcode interface command parameters.
 *
 * Returns 0 if command completed; otherwise error code.
 */
static int crdma_waited_cmd(struct crdma_ibdev *dev, struct crdma_cmd *cmd)
{
	struct crdma_event_cmd *cmd_state;
	int ret;

	/* Wait for command state availability */
	down(&dev->event_sem);
	spin_lock(&dev->cmd_q_lock);
	cmd_state = & dev->cmd_q[dev->cmd_q_free];
	cmd_state->token += dev->max_cmds_out;
	dev->cmd_q_free = cmd_state->next;
	init_completion(&cmd_state->comp);
	spin_unlock(&dev->cmd_q_lock);

	crdma_info("==== crdma_waited_cmd UCODE %s \n", crdma_opcode_to_str(cmd->opcode));

	/* Issue command to microcode */
	mutex_lock(&dev->cmdif_mutex);
	ret = __crdma_write_cmdif(dev, cmd->input_param, cmd->output_param,
			cmd->input_mod, cmd->opcode, cmd->opcode_mod,
			cmd_state->token, true);
	if (ret) {
		mutex_unlock(&dev->cmdif_mutex);
		crdma_dev_warn(dev, "Command initiation failure %d\n", ret);
		goto done;
	}

	mutex_unlock(&dev->cmdif_mutex);

	if (!wait_for_completion_timeout(&cmd_state->comp,
				msecs_to_jiffies(cmd->timeout))) {
		crdma_dev_warn(dev, "Command timeout failure\n");

		crdma_info("==== UCODE %s cmd timeout\n",
				crdma_opcode_to_str(cmd->opcode));
		ret = -EBUSY;
		goto done;
	}

	crdma_info("==== UCODE %s cmd done\n",
			crdma_opcode_to_str(cmd->opcode));
	cmd->status = cmd_state->status;
	crdma_info("==== UCODE Status: %s\n",
			crdma_status_to_str(cmd->status));

	if (cmd->output_imm)
		cmd->output_param = cmd_state->output_param;
done:
	/* Indicate state entry is available for new command */
	spin_lock(&dev->cmd_q_lock);
	cmd_state->next = dev->cmd_q_free;
	dev->cmd_q_free = cmd_state - dev->cmd_q;
	spin_unlock(&dev->cmd_q_lock);

	up(&dev->event_sem);
	return ret;
}

/**
 * Process waited command completion.
 *
 * @dev: RoCE IB device.
 * @token: The token associated with the completion.
 * @param_h: Upper 32 bits of output parameter (or DMA address).
 * @param_l: lower 32 bits of output parameter (or DMA address).
 * @status: Command status.
 */
static void crdma_cmd_complete(struct crdma_ibdev *dev, u16 token,
		u32 param_h, u32 param_l, u8 status)
{
	struct crdma_event_cmd *cmd_state;

	cmd_state = &dev->cmd_q[token & (dev->max_cmds_out - 1)];
	crdma_info("Cmd comp. token 0x%04X\n", token);
	crdma_info("    State token 0x%08X\n", cmd_state->token);

	if (cmd_state->token != token) {
		crdma_warn("Command completed with stale token\n");
		return;
	}

	cmd_state->output_param = ((u64) param_h) << 32 | param_l;
	cmd_state->status = status;
	cmd_state->token = token;

	/* Wake up command initiator */
	complete(&cmd_state->comp);
	return;
}

/**
 * Initiate a command in either polled or event driven mode.
 *
 * @dev: RoCE IB device.
 * @cmd: The microcode interface command parameters.
 *
 * Returns command status on success, otherwise < 0 if command
 * processing did not complete.
 */
static int crdma_cmd(struct crdma_ibdev *dev, struct crdma_cmd *cmd)
{
	int err;

	crdma_dev_warn(dev, "\n==== UCODE %s Command\n",
		crdma_opcode_to_str(cmd->opcode));

	/*
	 * Verify device is on-line then issue command based
	 * on current command mode.
	 */
	if (pci_channel_offline(dev->nfp_info->pdev))
		return -EIO;

	if (dev->use_event_cmds)
		err = crdma_waited_cmd(dev, cmd);
	else
		err = crdma_polled_cmd(dev, cmd);

	if (!err && cmd->status)
		crdma_dev_warn(dev, "\n==== UCODE cmd %s failed, status: %s\n",
				crdma_opcode_to_str(cmd->opcode),
				crdma_status_to_str(cmd->status));
	else
		crdma_dev_warn(dev, "\n==== UCODE cmd %s success, status: %s\n",
				crdma_opcode_to_str(cmd->opcode),
				crdma_status_to_str(cmd->status));

	return err ? err : cmd->status;
}

/**
 * Acquire a command input/output DMA buffer for a mailbox.
 *
 * @dev: The RoCE IB device.
 * @mbox: The mail box to assign the DMA buffer too.
 *
 * 0 on success, otherwise -ENOMEM.
 */
static int crdma_init_mailbox(struct crdma_ibdev *dev,
		struct crdma_cmd_mbox *mbox)
{
	mbox->buf = dma_pool_alloc(dev->mbox_pool, GFP_KERNEL,
			&mbox->dma_addr);
	if (!mbox->buf) {
		crdma_dev_warn(dev, "Command mailbox allocation failure\n");
		return -ENOMEM;
	}
	memset(mbox->buf, 0, CRDMA_CMDIF_MBOX_SIZE);
	return 0;
}

/**
 * Release mailbox DMA buffer previously acquired with crdma_init_mailbox().
 *
 * @dev: The RoCE IB device.
 * @mbox: The mail box for which the DMA buffer resources are to be released.
 */
static void crdma_cleanup_mailbox(struct crdma_ibdev *dev,
		struct crdma_cmd_mbox *mbox)
{
	if (!mbox->buf)
		return;

	dma_pool_free(dev->mbox_pool, mbox->buf, mbox->dma_addr);
}

/**
 * Return the next available EQE in an EQ.
 *
 * @eq: The EQ for which the next EQE is desired.
 *
 * Return a pointer to the next EQE, or NULL.
 */
static struct crdma_eqe *crdma_next_eqe(struct crdma_eq *eq)
{
	struct crdma_eqe *eqe;

	eqe = &eq->eqe[eq->consumer_cnt & eq->consumer_mask];

	/*
	 * Microcode alternates writing 1 or 0 to the EQ an ownership bit
	 * every pass through the EQ, starting with writing a 1 on the
	 * first pass, followed by a 0 on the second, ....
	 */
	if (!!(eqe->rsvd_owner & CRDMA_EQ_OWNER_BIT) ==
			!!(eq->consumer_cnt & (1 << eq->num_eqe_log2)))
		return NULL;

	print_hex_dump(KERN_DEBUG, "EQE(LE):", DUMP_PREFIX_OFFSET, 8, 1,
			eqe, sizeof(*eqe), 0);

	/* No EQE reads should be issued prior to validation of EQE */
	rmb();
	return eqe;
}

/**
 * Process a QP affiliated asynchronous event notification.
 *
 * @dev: The CRDMA RoCE device associated with the event.
 * @eqe: The event queue entry for the event.
 */
static void crdma_qp_async_event(struct crdma_ibdev *dev,
				struct crdma_eqe *eqe)
{
	struct crdma_qp *cqp;
	uint32_t qpn;
	struct ib_event event;

	qpn = le32_to_cpu(eqe->affiliated.obj_num & (dev->cap.ib.max_qp - 1));
	crdma_info("QPN %d, %s\n", qpn, crdma_event_to_str(eqe->type));

	spin_lock(&dev->qp_lock);
	cqp = radix_tree_lookup(&dev->qp_tree, qpn);
	if (cqp)
		atomic_inc(&cqp->ref_cnt);
	spin_unlock(&dev->qp_lock);

	if (!cqp) {
		crdma_warn("QPN %d not found\n", qpn);
		return;
	}

	if (cqp->ib_qp.event_handler) {
		event.device	 = cqp->ib_qp.device;
		event.element.qp = &cqp->ib_qp;

		switch(eqe->type) {
		case CRDMA_EQ_QP_COMM_ESTABLISHED:
			event.event = IB_EVENT_COMM_EST;
			break;

		case CRDMA_EQ_QP_SQ_DRAINED:
			event.event = IB_EVENT_SQ_DRAINED;
			break;

		case CRDMA_EQ_QP_SQ_LAST_WQE:
			event.event = IB_EVENT_QP_LAST_WQE_REACHED;
			break;

		case CRDMA_EQ_QP_CATASTROPHIC_ERROR:
			event.event = IB_EVENT_QP_FATAL;
			break;

		case CRDMA_EQ_QP_INVALID_REQUEST:
			event.event = IB_EVENT_QP_REQ_ERR;
			break;

		case CRDMA_EQ_QP_ACCESS_ERROR:
			event.event = IB_EVENT_QP_ACCESS_ERR;
			break;

		default:
			crdma_warn("Async QP event not handled, QPN "
					"%d, event %d\n", qpn, eqe->type);
			return;
		}

		/* Dispatch */
		cqp->ib_qp.event_handler(&event, cqp->ib_qp.qp_context);
	}
	if (atomic_dec_and_test(&cqp->ref_cnt))
		complete(&cqp->free);

	return;
}

/**
 * Event queue MSI/MSI-X interrupt handler, dispatch events.
 *
 * irq: Interrupt vector.
 * eq_ptr: The EQ associated with the interrupt vector.
 *
 * Returns IRQ_HANDLED.
 */
static irqreturn_t crdma_interrupt(int irq, void *eq_ptr)
{
	struct crdma_eq *eq = eq_ptr;
	struct crdma_ibdev *dev = eq->dev;
	struct crdma_cq *ccq;
	struct crdma_eqe *eqe;
	struct ib_event event;
	uint32_t cqn;
	int eqe_cnt = 0;

	/* Get the next available EQE and process */
	while ((eqe  = crdma_next_eqe(eq))) {

#if 1 /* Early debug */
		crdma_info("eq->eqe %p, type %d, sub_type %d\n", eq->eqe,
				eqe->type, eqe->sub_type);
#endif

		switch (eqe->type) {
		case CRDMA_EQ_CQ_COMPLETION_NOTIFY:
			cqn = le32_to_cpu(eqe->affiliated.obj_num);
			if (cqn >= dev->cap.ib.max_cq) {
				crdma_dev_warn(dev, "Bad CQN %d\n", cqn);
				break;
			}
			ccq = dev->cq_table[cqn];
#if 1
			/* XXX: Just for debug, will remove */
			if (!ccq->ib_cq.comp_handler) {
				crdma_dev_warn(dev, "No CQ handler CQN %d\n",
						cqn);
				break;
			}
#endif
			ccq->arm_seqn++;
			atomic_inc(&ccq->ref_cnt);

			crdma_info("CQN %d, %s\n", cqn,
					crdma_event_to_str(eqe->type));
			/*
			 * Call back into the Verbs core to dispatch
			 * the completion notification.
			 */
			ccq->ib_cq.comp_handler(&ccq->ib_cq,
					ccq->ib_cq.cq_context);

			if (atomic_dec_and_test(&ccq->ref_cnt))
				complete(&ccq->free);
			break;

		case CRDMA_EQ_CQ_ERROR:
			cqn = le32_to_cpu(eqe->affiliated.obj_num);
			if (cqn >= dev->cap.ib.max_cq) {
				crdma_dev_warn(dev, "Bad CQN %d\n", cqn);
				break;
			}
			ccq = dev->cq_table[cqn];
			atomic_inc(&ccq->ref_cnt);

			crdma_info("CQN %d, %s\n", cqn,
					crdma_event_to_str(eqe->type));

			/*
			 * Call back into the Verbs core to dispatch
			 * the asynchronous event.
			 */
			if (ccq->ib_cq.event_handler) {
				event.device	= ccq->ib_cq.device;
				event.event	= IB_EVENT_CQ_ERR;
				event.element.cq = &ccq->ib_cq;
				ccq->ib_cq.event_handler(&event,
						ccq->ib_cq.cq_context);
			}

			if (atomic_dec_and_test(&ccq->ref_cnt))
				complete(&ccq->free);
			break;

		case CRDMA_EQ_CMDIF_COMPLETE:
			crdma_cmd_complete(dev, le16_to_cpu(eqe->cmdif.token),
				le32_to_cpu(eqe->cmdif.output_param_h),
				le32_to_cpu(eqe->cmdif.output_param_l),
				eqe->cmdif.status);
			break;

		case CRDMA_EQ_QP_COMM_ESTABLISHED:
		case CRDMA_EQ_QP_SQ_DRAINED:
		case CRDMA_EQ_QP_SQ_LAST_WQE:
		case CRDMA_EQ_QP_CATASTROPHIC_ERROR:
		case CRDMA_EQ_QP_INVALID_REQUEST:
		case CRDMA_EQ_QP_ACCESS_ERROR:
			crdma_qp_async_event(dev, eqe);
			break;

		case CRDMA_EQ_SRQ_LIMIT_REACHED:
		case CRDMA_EQ_SRQ_CATASTROPHIC_ERROR:
			crdma_dev_info(dev, "SRQ event %s not implemented\n",
					crdma_event_to_str(eqe->type));
			break;

		case CRDMA_EQ_EQ_OVERRUN_ERROR:
			crdma_dev_warn(dev, "EQ%d, %s EQN%d\n",
					eq->eq_num,
					crdma_event_to_str(eqe->type),
					le32_to_cpu(eqe->affiliated.obj_num));
			break;

		case CRDMA_EQ_MICROCODE_WARNING:
			crdma_dev_warn(dev, "EQ%d, microcode warning %d\n",
					eq->eq_num, eqe->sub_type);
			break;

		case CRDMA_EQ_LOCAL_CATASTROPHIC_ERROR:
			crdma_dev_warn(dev, "EQ%d, HCA catastrophic error\n",
					eq->eq_num);
			break;

		case CRDMA_EQ_PORT_CHANGE:
			crdma_dev_info(dev, "unaffiliated event %s "
				       "not implemented\n",
					crdma_event_to_str(eqe->type));
			break;

		case CRDMA_EQ_MGMT_PORT_CHANGE:
		default:
			crdma_dev_info(dev, "unaffiliated event %s "
				       "not implemented\n",
					crdma_event_to_str(eqe->type));
			break;
		}
		eq->consumer_cnt++;
		eqe_cnt++;

		/*
		 * If we read at least half the EQ, update doorbell
		 * without requesting another interrupt.
		 */
		if (eqe_cnt > (1 << (eq->num_eqe_log2 - 1)))
			crdma_set_eq_ci(dev, eq->eq_num,
				eq->consumer_cnt, false);
	}

	/* Update doorbell and request interrupts */
	crdma_set_eq_ci(dev, eq->eq_num,
			eq->consumer_cnt,
			dev->have_interrupts ? true : false);

	return IRQ_HANDLED;
}

int crdma_init_eq(struct crdma_ibdev *dev, int index, int entries_log2,
		u16 intr, u32 vector, u32 events)
{
	struct crdma_eq *eq = &dev->eq_table.eq[index];
	int mem_size;
	int ret;

	if ((1 << entries_log2) > dev->cap.max_eqe) {
		crdma_warn("EQ size too large for microcode %d\n",
				1 << entries_log2);
		return -EINVAL;
	}
	crdma_dev_info(dev, "=== crdma_init_eq === \n");

	mem_size = dev->cap.eqe_size  * (1 << entries_log2);

	pr_info(" crdma_alloc_dma_mem \n");
	/* Coherent memory for sharing with microcode */
	eq->mem = crdma_alloc_dma_mem(dev, true,
			CRDMA_MEM_DEFAULT_ORDER, mem_size);
	if (IS_ERR(eq->mem)) {
		crdma_dev_err(dev, "Unable to allocate EQ memory\n");
		return -ENOMEM;
	}

	pr_info("  EQN            %d\n", index);
	pr_info("  Intr:          %d\n", intr);
	pr_info("  Vector:        %d\n", vector);
	pr_info("  Num EQE:       %d\n", 1 << entries_log2);
	pr_info("  EQ memory size %d\n", eq->mem->tot_len);
	pr_info("  EQ num allocs  %d\n", eq->mem->num_allocs);
	pr_info("  EQ min order   %d\n", eq->mem->min_order);
	pr_info("  EQ num SG      %d\n", eq->mem->num_sg);
	pr_info("  EQ needs       %d MTT entry(s)\n", eq->mem->num_mtt);

	pr_info(" crdma_mtt_write_sg \n");
	ret = crdma_mtt_write_sg(dev, eq->mem->alloc, eq->mem->num_sg,
			eq->mem->base_mtt_ndx, eq->mem->num_mtt,
			eq->mem->min_order + PAGE_SHIFT,
			eq->mem->num_sg, 0);
	if (ret) {
		crdma_info("crdma_mtt_write_sg returned %d\n", ret);
		goto free_mem;
	}

	/*
	 * Get virtual address of memory for EQ consumer processing and
	 * initialize each EQE to default ownership state.
	 */
	eq->eqe = sg_virt(eq->mem->alloc);
	memset(eq->eqe, 0, eq->mem->tot_len);

	eq->dev = dev;
	eq->eq_num = index;
	eq->consumer_cnt = 0;
	eq->consumer_mask = (1 << entries_log2) - 1;
	eq->num_eqe_log2 = entries_log2;
	eq->intr = intr;
	eq->vector = vector;

	scnprintf(eq->irq_name, 32, "crdma_%d-%d", dev->id, index);
	eq->event_map = events;
	eq->cq_cnt = 0;

	pr_info(" crdma_eq_create_cmd \n");
	/* CREAE EQ and MAP requested events */
	ret = crdma_eq_create_cmd(dev, eq);
	if (ret) {
		crdma_info("crdma_eq_create_cmd faild, returned %d\n", ret);
		goto free_mem;
	}

	pr_info(" crdma_eq_map_cmd \n");
	ret = crdma_eq_map_cmd(dev, eq->eq_num, eq->event_map);
	if (ret) {
		crdma_info("crdma_eq_map_cmd faild, returned %d\n", ret);
		goto destroy_eq;
	}

	if (dev->have_interrupts) {
		crdma_dev_info(dev, "Request IRQ %d\n", eq->vector);
		ret = request_irq(eq->vector, crdma_interrupt, 0,
				eq->irq_name, eq);
		if (ret) {
			crdma_info("request_irq error %d\n", ret);
			goto destroy_eq;
		}
	}

	/* Set EQ initial consumer index and ARM EQ */
	crdma_set_eq_ci(dev, eq->eq_num, 0,
			dev->have_interrupts ? true : false);

	crdma_dev_info(dev, "=== crdma_init_eq done === \n");
	return 0;

destroy_eq:
	crdma_eq_destroy_cmd(dev, eq);
free_mem:
	crdma_free_dma_mem(dev, eq->mem);
	eq->mem = NULL;
	return ret;
}

void crdma_cleanup_eq(struct crdma_ibdev *dev, int eqn)
{
	struct crdma_eq *eq = &dev->eq_table.eq[eqn];

	/* Make sure interrupt is disabled at EQ */
	crdma_set_eq_ci(dev, eq->eq_num,
			eq->consumer_cnt & eq->consumer_mask, false);

	if (dev->have_interrupts) {
		crdma_dev_info(dev, "Free EQ %d IRQ %d\n",
				eq->eq_num, eq->vector);
		free_irq(eq->vector, eq);
	}

	if (crdma_eq_destroy_cmd(dev, eq))
		crdma_warn("Destroy of ucode EQ %d failed\n", eq->eq_num);

	crdma_free_dma_mem(dev, eq->mem);
	eq->mem = NULL;
	return;
}

/**
 * Generic no parameter microcode command initiation.
 *
 * @dev: RoCE IB device.
 * @opcode: Command opcode.
 * @opcode_mod: Command opcode modifier.
 * @input_mod: Command input modifier.
 * @timeout_ms: Command timeout in milliseconds.
 *
 * Returns 0 on success, otherwise error code.
 */
static int __crdma_no_param_cmd(struct crdma_ibdev *dev, u8 opcode,
		u8 opcode_mod, u32 input_mod, u32 timeout_ms)
{
	struct crdma_cmd cmd;
	int status;

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode = opcode;
	cmd.opcode_mod = opcode_mod;
	cmd.input_mod = input_mod;
	cmd.timeout = timeout_ms;
	status = crdma_cmd(dev, &cmd);

	return status;
}

int crdma_noop(struct crdma_ibdev *dev)
{
	return __crdma_no_param_cmd(dev, CRDMA_CMD_NO_OP, 0, 0,
			CRDMA_CMDIF_GEN_TIMEOUT_MS);
}

/**
 * Dump microcode attributes structure
 *
 * @attr: Structure that has been initialized with microcode attributes.
 */
static void crdma_dump_query_ucode(struct crdma_query_ucode_attr *attr)
{
	crdma_info("Dump of query ucode results in default order\n");

	pr_info("UC maj_rev:       0x%04X\n", le16_to_cpu(attr->maj_rev));
	pr_info("UC min_rev:       0x%04X\n", le16_to_cpu(attr->min_rev));
	pr_info("cmd_abi_rev:      0x%04X\n", le16_to_cpu(attr->cmd_abi_rev));
	pr_info("max_cmds_out:     0x%04X\n", le16_to_cpu(attr->max_cmds_out));
	pr_info("build_id_high:    0x%08X\n", le32_to_cpu(attr->build_id_high));
	pr_info("build_id_low:     0x%08X\n", le32_to_cpu(attr->build_id_low));
	pr_info("rsvd1:            0x%08X\n", le32_to_cpu(attr->deprecated_1));
	pr_info("rsvd2:            0x%08X\n", le32_to_cpu(attr->deprecated_2));
	pr_info("mhz_clock:        0x%08X\n", le32_to_cpu(attr->mhz_clock));
	return;
}

int crdma_query_ucode(struct crdma_ibdev *dev,
		struct crdma_query_ucode_attr *attr)
{
	struct crdma_cmd_mbox out_mbox;
	struct crdma_cmd cmd;
	int status;

	memset(&cmd, 0, sizeof(cmd));
	if (crdma_init_mailbox(dev, &out_mbox))
		return -1;

	cmd.opcode = CRDMA_CMD_QUERY_UCODE;
	cmd.timeout = CRDMA_CMDIF_GEN_TIMEOUT_MS;
	cmd.output_param = out_mbox.dma_addr;

	status = crdma_cmd(dev, &cmd);
	if (status)
		goto free_mbox;

	memcpy(attr, out_mbox.buf, sizeof(*attr));

#if CRDMA_DETAIL_INFO_DEBUG_FLAG
	crdma_info("QP_QUERY Output Mailbox\n");
	print_hex_dump(KERN_DEBUG, "OUT:", DUMP_PREFIX_OFFSET, 8, 1,
			out_mbox.buf, sizeof(*attr), 0);
#endif

	crdma_dump_query_ucode(attr);
free_mbox:
	crdma_cleanup_mailbox(dev, &out_mbox);
	return status;
}

/**
 * Dump microcode capabilities for device.
 *
 * @caps: Initialized capabilities structure to dump.
 */
static void crdma_dump_query_dev_cap(struct crdma_dev_cap_param *cap)
{
	crdma_info("Dump of query_dev_cap results in default order\n");

	pr_info("flags:                      0x%02X\n", cap->flags);
	pr_info("ports_rsvd:                 0x%02X\n", cap->ports_rsvd);
	pr_info("req_bs_size_mb:             0x%04X\n", le16_to_cpu(cap->req_bs_size_mb));
	pr_info("max_qp_log2:                0x%02X\n", cap->max_qp_log2);
	pr_info("max_qp_wr_log2:             0x%02X\n", cap->max_qp_wr_log2);
	pr_info("max_sq_sge:                 0x%02X\n", cap->max_sq_sge);
	pr_info("max_rq_sge:                 0x%02X\n", cap->max_rq_sge);
	pr_info("max_swqe_size_log2:         0x%02X\n", cap->max_swqe_size_log2);
	pr_info("max_rwqe_size_log2:         0x%02X\n", cap->max_rwqe_size_log2);
	pr_info("rsvd_qp:                    0x%02X\n", cap->rsvd_qp);
	pr_info("max_rdma_res_log2:          0x%02X\n", cap->max_rdma_res_log2);
	pr_info("max_qp_req_res_log2:        0x%02X\n", cap->max_qp_req_res_log2);
	pr_info("max_qp_rsp_res_log2:        0x%02X\n", cap->max_qp_rsp_res_log2);
	pr_info("max_cq_log2:                0x%02X\n", cap->max_cq_log2);
	pr_info("max_cqe_log2:               0x%02X\n", cap->max_cqe_log2);
	pr_info("cqe_size_log2:              0x%02X\n", cap->cqe_size_log2);
	pr_info("max_eq_log2:                0x%02X\n", cap->max_eq_log2);
	pr_info("max_eqe_log2:               0x%02X\n", cap->max_eqe_log2);
	pr_info("eqe_size_log2:              0x%02X\n", cap->eqe_size_log2);
	pr_info("max_srq_log2:               0x%02X\n", cap->max_srq_log2);
	pr_info("max_srq_wr_log2:            0x%02X\n", cap->max_srq_wr_log2);
	pr_info("max_srq_rwqe_size_log2:     0x%02X\n",
			cap->max_srq_rwqe_size_log2);
	pr_info("max_mcg_log2:               0x%02X\n", cap->max_mcg_log2);
	pr_info("max_mcg_qp_log2:            0x%02X\n", cap->max_mcg_qp_log2);
	pr_info("max_mr_size_log2:           0x%02X\n", cap->max_mr_size_log2);
	pr_info("vlan_table_size_log2:       0x%02X\n", cap->vlan_table_size_log2);
	pr_info("smac_table_size:            0x%02X\n", cap->smac_table_size);
	pr_info("sgid_table_size:            0x%02X\n", cap->sgid_table_size);
	pr_info("max_uar_pages_log2:         0x%02X\n", cap->max_uar_pages_log2);
	pr_info("min_page_size_log2:         0x%02X\n", cap->min_page_size_log2);
	pr_info("max_inline_data:            0x%04X\n", le16_to_cpu(cap->max_inline_data));
	pr_info("max_mpt:                    0x%08X\n", cap->max_mpt);
	pr_info("max_mtt:                    0x%08X\n", cap->max_mtt);

	return;
}

int crdma_query_dev_cap(struct crdma_ibdev *dev,
		struct crdma_dev_cap_param *cap)
{
	struct crdma_cmd_mbox out_mbox;
	struct crdma_cmd cmd;
	int status;

	memset(&cmd, 0, sizeof(cmd));
	if (crdma_init_mailbox(dev, &out_mbox))
		return -1;

	cmd.opcode = CRDMA_CMD_QUERY_DEV_CAP;
	cmd.timeout = CRDMA_CMDIF_GEN_TIMEOUT_MS;
	cmd.output_param = out_mbox.dma_addr;

	status = crdma_cmd(dev, &cmd);
	if (status)
		goto free_mbox;

	memcpy(cap, out_mbox.buf, sizeof(*cap));

#if CRDMA_DETAIL_INFO_DEBUG_FLAG
	crdma_info("QUERY_DEV_CAP Output MBox\n");
	print_hex_dump(KERN_DEBUG, "OUT:", DUMP_PREFIX_OFFSET, 8, 1,
			out_mbox.buf, sizeof(query_dev_cap_out), 0);
#endif

	crdma_dump_query_dev_cap(cap);
free_mbox:
	crdma_cleanup_mailbox(dev, &out_mbox);
	return status;
}

int crdma_query_nic(struct crdma_ibdev *dev, uint32_t *boardid)
{
	struct crdma_cmd cmd;
	int status;

	memset(&cmd, 0, sizeof(cmd));

	cmd.opcode = CRDMA_CMD_QUERY_NIC;
	cmd.timeout = CRDMA_CMDIF_GEN_TIMEOUT_MS;
	cmd.output_imm = true;

	status = crdma_cmd(dev, &cmd);
	if (status == CRDMA_STS_OK) {
		crdma_dev_info(dev, "cmd.output_param 0%016llx\n",
			cmd.output_param);
		*boardid = cmd.output_param & 0x0FFFFFFFFull;
		crdma_dev_info(dev, "board_id 0%08x\n", *boardid);
	}

	return status;
}

int crdma_set_bs_mem_size(struct crdma_ibdev *dev, int num_mtt,
		int order, int size_mb)
{
	struct crdma_cmd cmd;
	int status;
	int page_sz_log2;

	if (order <= 0) {
		crdma_err("Bad order specified %d\n", order);
		return -EINVAL;
	}

	if (num_mtt & ~CRDMA_SET_BS_NUM_MTT_MASK) {
		crdma_err("MTT count to large %d\n", num_mtt);
		return -EINVAL;
	}

	/* order represents the multiple of PAGE_SIZE */
	page_sz_log2 = order + PAGE_SHIFT;
	if (page_sz_log2 > CRDMA_MTT_MAX_PAGESIZE_LOG2) {
		crdma_err("Order specified to large %d\n", order);
		return -EINVAL;
	}

	crdma_info("Dump of crdma_set_bs_mem_size para\n");
	pr_info("order:                      %d\n", order);
	pr_info("page_sz_log2:               %d\n", page_sz_log2);
	pr_info("size_mb:                    %d\n", size_mb);
	pr_info("num_mtt:                    %d\n", num_mtt);

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode = CRDMA_CMD_SET_BS_HOST_MEM_SIZE;
	cmd.timeout = CRDMA_CMDIF_GEN_TIMEOUT_MS;
	cmd.input_param = ((u64)(page_sz_log2 << CRDMA_SET_BS_PAGE_SHIFT |
				num_mtt)) << 32 |
				(size_mb & CRDMA_SET_BS_SIZE_MASK);
	crdma_info("SET_BS input_param host order 0x%016llx\n",
			cmd.input_param);
	status = crdma_cmd(dev, &cmd);
	return status;
}

int crdma_bs_map_mem(struct crdma_ibdev *dev, u64 vaddr, int size_mb,
		int num_mtt, int order)
{
	struct crdma_bs_map_mem *map;
	struct crdma_cmd_mbox in_mbox;
	struct crdma_cmd cmd;
	int status;
	int page_sz_log2;

	if (order <= 0) {
		crdma_err("Bad order specified %d\n", order);
		return -EINVAL;
	}

	if (num_mtt & ~CRDMA_SET_BS_NUM_MTT_MASK) {
		crdma_err("MTT count to large %d\n", num_mtt);
		return -EINVAL;
	}

	/* order represents the multiple of PAGE_SIZE */
	page_sz_log2 = order + PAGE_SHIFT;
	if (page_sz_log2 > CRDMA_MTT_MAX_PAGESIZE_LOG2) {
		crdma_err("Order specified to large %d\n", order);
		return -EINVAL;
	}

	if (crdma_init_mailbox(dev, &in_mbox))
		return -1;

	map = in_mbox.buf;
	map->vaddr_h	= cpu_to_le32(vaddr >> 32);
	map->vaddr_l	= cpu_to_le32(vaddr & 0x0FFFFFFFFull);
	map->rsvd	= 0;
	map->bs_mb_size = cpu_to_le16(size_mb & CRDMA_SET_BS_SIZE_MASK);
	map->pg_sz_mtts = cpu_to_le32(page_sz_log2 << CRDMA_SET_BS_PAGE_SHIFT |
				num_mtt);
	crdma_info("Map BS Memory (LE)\n");
	pr_info("  vaddr_h 0x%08X, vaddr_l 0x%08X\n",
			map->vaddr_h, map->vaddr_l);
	pr_info("  Size MB %d, pg_sz_mtts 0x%08X\n",
			map->bs_mb_size, map->pg_sz_mtts);

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode = CRDMA_CMD_MAP_BS_HOST_MEM;
	cmd.timeout = CRDMA_CMDIF_GEN_TIMEOUT_MS;
	cmd.input_param = in_mbox.dma_addr;
	status = crdma_cmd(dev, &cmd);

	crdma_cleanup_mailbox(dev, &in_mbox);
	return status;
}

int crdma_bs_unmap_mem(struct crdma_ibdev *dev)
{
	return __crdma_no_param_cmd(dev, CRDMA_CMD_UNMAP_BS_HOST_MEM, 0, 0,
			CRDMA_CMDIF_GEN_TIMEOUT_MS);
}

int crdma_hca_enable(struct crdma_ibdev *dev)
{
	int status;

	status = __crdma_no_param_cmd(dev, CRDMA_CMD_HCA_ENABLE, 0, 0,
							CRDMA_CMDIF_GEN_TIMEOUT_MS);
	/*
	* Microcode currently does not support HCA Enable command, so
	* we over-ride the status if error is unsupported.
	*/
	if (status == CRDMA_STS_UNSUPPORTED_OPCODE) {
		crdma_warn("Microcode returned unsupported opcode, "
						"ignoring\n");
		status = CRDMA_STS_OK;
	}
	return status;
}

int crdma_hca_disable(struct crdma_ibdev *dev)
{
	int status;

	status = __crdma_no_param_cmd(dev, CRDMA_CMD_HCA_DISABLE, 0, 0,
							CRDMA_CMDIF_GEN_TIMEOUT_MS);
	/*
	* Microcode currently does not support HCA Disable command, so
	* we over-ride the status if error is unsupported.
	*/
	if (status == CRDMA_STS_UNSUPPORTED_OPCODE) {
		crdma_warn("Microcode returned unsupported opcode, "
						"ignoring\n");
		status = CRDMA_STS_OK;
	}
	return status;
}

/**
 * Issues an MTT_WRITE to set a block of HCA MTT values. The MTT values to be
 * written should have been initialized in the input mailbox.
 *
 * @dev: The RoCE IB device.
 * @base_mtt: The base MTT index for the first MTT entry in the block.
 * @num_mtt: The number of consecutive MTT entries to write.
 * @in_mbox: Input mailbox initialized with MTT entry values.
 *
 * Returns 0 on success, otherwise an error.
 */
static int __crdma_mtt_write(struct crdma_ibdev *dev, u32 base_mtt,
		u32 num_mtt, struct crdma_cmd_mbox *in_mbox)
{
	struct crdma_mtt_write_param *mtt_param = in_mbox->buf;
	struct crdma_cmd cmd;
	int status;
	int i;

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode = CRDMA_CMD_MTT_WRITE;
	cmd.timeout = CRDMA_CMDIF_GEN_TIMEOUT_MS;
	cmd.input_mod = num_mtt;
	cmd.input_param = in_mbox->dma_addr;

	mtt_param->rsvd = 0;
	mtt_param->base_mtt_ndx = cpu_to_le32(base_mtt);

	pr_info("\n=== __crdma_mtt_write ===\n");
	pr_info("  base MTT: 0x%08X\n", mtt_param->base_mtt_ndx);
	pr_info("  MTT num:  %d\n", num_mtt);
	for (i = 0; i < num_mtt; i++)
		pr_info("  LE paddr_h 0x%08X paddr_l 0x%08X\n",
				mtt_param->entry[i].paddr_h,
				mtt_param->entry[i].paddr_l);

	status = crdma_cmd(dev, &cmd);

	/* While command not supported provide hard-code response */
	if (status == CRDMA_STS_UNSUPPORTED_OPCODE) {
		crdma_info("Using hard coded WRITE_MTT results\n");
		status = CRDMA_STS_OK;
	}

	pr_info("\n=== __crdma_mtt_write done %d ===\n", status);
	return status;
}

int crdma_mtt_write_sg(struct crdma_ibdev *dev,
			struct scatterlist *sg_list, int num_sg, u32 base_mtt,
			u32 num_mtt, unsigned long page_shift,
			int comp_pages, int comp_order)
{
	struct scatterlist *sg;
	struct crdma_mtt_write_param *mtt_param;
	struct crdma_cmd_mbox in_mbox;
	u64 base_addr;
	unsigned long page_size = (1 << page_shift);
	unsigned long comp_mask = (1 << (comp_order + page_shift)) - 1;
	unsigned long length;
	int status = 0;
	int entry;
	int mtt_cnt;

	if (comp_order < 0) {
		crdma_err("Bad compound page order: %d\n", comp_order);
		return -EINVAL;
	}

	if (comp_order + page_shift > CRDMA_MTT_MAX_PAGESIZE_LOG2) {
		crdma_err("Compound order too large: %d, page size %ld\n",
				comp_order, page_size);
		return -EINVAL;
	}

	if (crdma_init_mailbox(dev, &in_mbox))
		return -ENOMEM;

	/*
	 * Pass MTT entry information to microcode, collapsing "page_size"
	 * pages into compound pages if requested.
	 */
	mtt_param = in_mbox.buf;
	mtt_cnt = 0;

	for_each_sg(sg_list, sg, num_sg, entry) {
		base_addr = sg_dma_address(sg);
		length = sg_dma_len(sg);

#if CRDMA_DETAIL_INFO_DEBUG_FLAG
		crdma_debug("New  SG 0x%016llx, len: %ld\n", base_addr, length);
#endif
		while (length && mtt_cnt < num_mtt) {
			if (!(base_addr & comp_mask)) {
				crdma_debug("MTT Comp_Page  Addr 0x%016llx\n",
						base_addr);
				mtt_param->entry[mtt_cnt].paddr_h =
					cpu_to_le32(base_addr >> 32);
				mtt_param->entry[mtt_cnt].paddr_l =
					cpu_to_le32(base_addr & ~comp_mask);
				mtt_cnt++;

				/* As required write MTT entries */
				if (mtt_cnt >= CRDMA_MTT_PER_WRITE_CMD) {
					status = __crdma_mtt_write(dev,
							base_mtt, mtt_cnt,
							&in_mbox);
					if (status) {
						crdma_warn("MTT_WRITE failed "
								"%d\n", status);
						return status;
					}
					base_mtt += mtt_cnt;
					num_mtt -= mtt_cnt;
					mtt_cnt = 0;
				}
			}
			base_addr += page_size;
			length -= page_size;
		}
	}

	/* Write any remaining MTT entries */
	if (mtt_cnt) {
		status = __crdma_mtt_write(dev, base_mtt,
					mtt_cnt, &in_mbox);
		if (status)
			crdma_warn("MTT_WRITE failed %d\n", status);
	}
	crdma_debug("MTT_WRITE %d MTT entries written\n", mtt_cnt);
	crdma_cleanup_mailbox(dev, &in_mbox);
	return status;
}

int crdma_eq_create_cmd(struct crdma_ibdev *dev, struct crdma_eq *eq)
{
	struct crdma_eq_params *param;
	struct crdma_cmd_mbox in_mbox;
	struct crdma_cmd cmd;
	u32 page_info;
	int status;

	if (crdma_init_mailbox(dev, &in_mbox))
		return -1;

	param		= in_mbox.buf;
	param->eqn	= eq->eq_num & CRDMA_EQ_CREATE_EQN_MASK;
	param->eqe_log2	= eq->num_eqe_log2;
	param->intr	= cpu_to_le16(eq->intr);

	page_info = (eq->mem->min_order + PAGE_SHIFT) <<
				CRDMA_EQ_CREATE_LOG2_PAGE_SZ_SHIFT;

	/* Set PHYS flag if single block and device supports it */
	if (eq->mem->num_mtt == 1 &&
			(dev->cap.opt_flags & CRDMA_DEV_CAP_FLAG_PHYS))
		page_info |= 1 << CRDMA_EQ_CREATE_PHYS_BIT_SHIFT;

	param->page_info = cpu_to_le32(page_info);
	param->mtt_index = cpu_to_le32(eq->mem->base_mtt_ndx);
	param->time_mod  = 0;
	param->event_mod = 0;

	crdma_info("EQ_CREATE input values (LE)\n");
	pr_info("  EQN:              %d\n", param->eqn);
	pr_info("  Num EQE Log2:     %d", param->eqe_log2);
	pr_info("  Device Interrupt: %d\n", param->intr);
	pr_info("  Pg_Info_Word:     0x%08x", param->page_info);
	pr_info("  MTT Index:        0x%08X\n", param->mtt_index);
	pr_info("  Time:             0x%04X, Event: 0x%04X\n",
			param->time_mod, param->event_mod);

	crdma_info("EQ_CREATE Input Mailbox\n");

#if CRDMA_DETAIL_INFO_DEBUG_FLAG
	print_hex_dump(KERN_DEBUG, "IN:",
			DUMP_PREFIX_OFFSET, 8, 1, in_mbox.buf, 16, 0);
#endif

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode = CRDMA_CMD_EQ_CREATE;
	cmd.timeout = CRDMA_CMDIF_GEN_TIMEOUT_MS;
	cmd.input_param = in_mbox.dma_addr;
	cmd.input_mod = eq->eq_num;
	status = crdma_cmd(dev, &cmd);

	/* While command not supported provide hard-code response */
	if (status == CRDMA_STS_UNSUPPORTED_OPCODE) {
		crdma_info("Using hard coded EQ_CREATE results\n");
		status = CRDMA_STS_OK;
	}

	crdma_cleanup_mailbox(dev, &in_mbox);
	return status;
}

int crdma_eq_destroy_cmd(struct crdma_ibdev *dev, struct crdma_eq *eq)
{
	return __crdma_no_param_cmd(dev, CRDMA_CMD_EQ_DESTROY, 0,
			eq->eq_num, CRDMA_CMDIF_GEN_TIMEOUT_MS);
}

int crdma_eq_map_cmd(struct crdma_ibdev *dev, u32 eqn, u32 events)
{
	struct crdma_cmd cmd;
	int status;

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode	= CRDMA_CMD_EQ_MAP;
	cmd.input_mod	= eqn;
	cmd.timeout	= CRDMA_CMDIF_GEN_TIMEOUT_MS;
	cmd.input_param = events & CRDMA_EQ_EVENT_MASK;

	status = crdma_cmd(dev, &cmd);

	/* While command not supported provide hard-code response */
	if (status == CRDMA_STS_UNSUPPORTED_OPCODE) {
		crdma_info("Using hard coded EQ_MAP results\n");
		status = CRDMA_STS_OK;
	}
	return status;
}

int crdma_init_event_cmdif(struct crdma_ibdev *dev)
{
	int i;

	crdma_info("crdma_init_event_cmdif\n");

	if (!dev->have_interrupts) {
		crdma_info("No interrupt support, continue polled mode\n");
		return 0;
	}

	/*
	 * Use the largest power of 2 <= the microcode supported
	 * outstanding command limit to control the number of
	 * outstanding event driven commands we allow.
	 */
	dev->max_cmds_log2 = 0;
	while ((1 << (dev->max_cmds_log2 + 1)) <= dev->cap.max_cmds_out)
		dev->max_cmds_log2++;
	dev->max_cmds_out = 1 << dev->max_cmds_log2;

	crdma_dev_info(dev, "Max of %d concurrent commands\n",
			dev->max_cmds_out);
	crdma_dev_info(dev, "Command token mask 0x%04X\n",
			dev->max_cmds_out - 1);

	/*
	 * Allocate and initialize command queue used to maintain
	 * state for microcode commands in progress.
	 */
	dev->cmd_q = kcalloc(dev->max_cmds_out,
				sizeof(struct crdma_event_cmd), GFP_KERNEL);
	if (!dev->cmd_q) {
		crdma_dev_info(dev, "Unable to alloc cmd event queue\n");
		return -ENOMEM;
	}
	spin_lock_init(&dev->cmd_q_lock);
	for (i = 0; i < dev->max_cmds_out; i++) {
		dev->cmd_q[i].token = i;
		dev->cmd_q[i].next = i + 1;
	}
	dev->cmd_q[dev->max_cmds_out-1].next = -1;
	dev->cmd_q_free = 0;

	sema_init(&dev->event_sem, dev->max_cmds_out);
	dev->use_event_cmds = true;
	return 0;
}

void crdma_cleanup_event_cmdif(struct crdma_ibdev *dev)
{
	int i;

	crdma_info("crdma_cleanup_event_cmdif\n");

	/* No working interrupts, so really never entered event mode */
	if (!dev->have_interrupts)
		return;

	/*
	 * Ensure that a polled command does not begin execution before
	 * all outstanding event driven commands complete processing.
	 */
	down(&dev->poll_sem);
	dev->use_event_cmds = false;
	for (i = 0; i < dev->max_cmds_out; i++)
		down(&dev->event_sem);
	up(&dev->poll_sem);

	dev->cmd_q_free = -1;
	kfree(dev->cmd_q);
	return;
}

int crdma_cq_create_cmd(struct crdma_ibdev *dev, struct crdma_cq *cq,
		struct crdma_uar *uar)
{
	struct crdma_cq_params *param;
	struct crdma_cmd_mbox in_mbox;
	struct crdma_cmd cmd;
	u64 pfn;
	u32 page_info;
	int status;

	if (crdma_init_mailbox(dev, &in_mbox))
		return -1;

	param		= in_mbox.buf;
	param->rsvd_cqn = cpu_to_le32(cq->cqn & CRDMA_CQ_CREATE_CQN_MASK);
	param->eqn	= cq->eq_num & CRDMA_EQ_CREATE_EQN_MASK;
	param->cqe_log2 = 0;
	while ((1 << param->cqe_log2) < cq->num_cqe)
		param->cqe_log2++;

	page_info = (cq->mem->min_order + PAGE_SHIFT) <<
				CRDMA_CQ_CREATE_LOG2_PAGE_SZ_SHIFT;

	/* Set PHYS flag if single block and device supports it */
	if (cq->mem->num_mtt == 1 &&
			(dev->cap.opt_flags & CRDMA_DEV_CAP_FLAG_PHYS))
		page_info |= 1 << CRDMA_CQ_CREATE_PHYS_BIT_SHIFT;

	param->page_info = cpu_to_le32(page_info);
	param->mtt_index = cpu_to_le32(cq->mem->base_mtt_ndx);
	param->time_mod  = 0;
	param->event_mod = 0;

	param->ci_addr_high = cpu_to_le32(cq->ci_mbox_paddr >> 32);
	param->ci_addr_low = cpu_to_le32(cq->ci_mbox_paddr & 0x0FFFFFFFFull);

	pfn = crdma_uar_pfn(dev, uar);
	param->uar_pfn_high = cpu_to_le32(pfn >> 32);
	param->uar_pfn_low = cpu_to_le32((pfn & 0x0FFFFFFFFull) << PAGE_SHIFT);

	crdma_info("CQ create values (LE)\n");
	pr_info("  CQN:          %d\n", param->rsvd_cqn);
	pr_info("  EQN:          %d\n", param->eqn);
	pr_info("  Num CQE Log2: %d", param->cqe_log2);
	pr_info("  Pg_Info_Word: 0x%08x", param->page_info);
	pr_info("  MTT Index:    0x%08X\n", param->mtt_index);
	pr_info("  Time:         0x%04X, Event: 0x%04X\n",
			param->time_mod, param->event_mod);
	pr_info("  CI addr high: 0x%08X\n", param->ci_addr_high);
	pr_info("  CI addr low:  0x%08X\n", param->ci_addr_low);
	pr_info("  UAR PFN high: 0x%08X\n", param->uar_pfn_high);
	pr_info("  UAR PFN low:  0x%08X\n", param->uar_pfn_low);

#if CRDMA_DETAIL_INFO_DEBUG_FLAG
	print_hex_dump(KERN_DEBUG, "IN:",
			DUMP_PREFIX_OFFSET, 8, 1, in_mbox.buf, 16, 0);
#endif

	crdma_info("Send CQ_CREATE to Firmware\n");
	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode = CRDMA_CMD_CQ_CREATE;
	cmd.timeout = CRDMA_CMDIF_GEN_TIMEOUT_MS;
	cmd.input_param = in_mbox.dma_addr;
	cmd.input_mod = cq->cqn;
	status = crdma_cmd(dev, &cmd);

	/* While command not supported provide hard-coded response */
	if (status == CRDMA_STS_UNSUPPORTED_OPCODE) {
		crdma_info("Using hard coded CQ_CREATE results\n");
		status = CRDMA_STS_OK;
	}
	crdma_info("Get status [%d] from Firmware\n", status);

	crdma_cleanup_mailbox(dev, &in_mbox);
	return status;
}

int crdma_cq_resize_cmd(struct crdma_ibdev *dev, struct crdma_cq *cq)
{
	struct crdma_cq_resize_params *param;
	struct crdma_cmd_mbox in_mbox;
	struct crdma_cmd cmd;
	int status;

	if (crdma_init_mailbox(dev, &in_mbox))
		return -1;

	param = in_mbox.buf;
	while ((1 << param->cqe_log2) < cq->num_cqe)
		param->cqe_log2++;

	param->cq_log2_pg_sz = cq->mem->min_order + PAGE_SHIFT;
	param->cq_page_offset = 0;
	param->cq_mtt_index = cpu_to_le32(cq->mem->base_mtt_ndx);

	crdma_info("CQ resize values (LE)\n");
	pr_info("  Num CQE Log2: %d", param->cqe_log2);
	pr_info("  Pg_Sz log2: 0x%08x", param->cq_log2_pg_sz);
	pr_info("  MTT Index:    0x%08X\n", param->cq_mtt_index);
	

#if CRDMA_DETAIL_INFO_DEBUG_FLAG
	print_hex_dump(KERN_DEBUG, "IN:",
			DUMP_PREFIX_OFFSET, 8, 1, in_mbox.buf, 16, 0);
#endif

	crdma_info("Send CQ_RESIZE to Firmware\n");
	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode = CRDMA_CMD_CQ_RESIZE;
	cmd.timeout = CRDMA_CMDIF_GEN_TIMEOUT_MS;
	cmd.input_param = in_mbox.dma_addr;
	cmd.input_mod = cq->cqn;
	status = crdma_cmd(dev, &cmd);

	/* While command not supported provide hard-coded response */
	if (status == CRDMA_STS_UNSUPPORTED_OPCODE) {
		crdma_info("Using hard coded CQ_RESIZE results\n");
		status = CRDMA_STS_OK;
	}
	crdma_info("Get status [%d] from Firmware\n", status);

	crdma_cleanup_mailbox(dev, &in_mbox);
	return status;
}

int crdma_cq_destroy_cmd(struct crdma_ibdev *dev, struct crdma_cq *cq)
{
	return __crdma_no_param_cmd(dev, CRDMA_CMD_CQ_DESTROY, 0,
			cq->cqn, CRDMA_CMDIF_GEN_TIMEOUT_MS);
}

/**
 * Build QP control object parameters used to initialize QP state.
 *
 * @dev: The crdma IB RoCE device.
 * @qp: The crdma QP state used to initialize parameters.
 * @uar: The user access region used for QP doorbell access.
 * @ctrl: Returns the initialized QP control object parameters.
 */
static void crdma_set_qp_ctrl(struct crdma_ibdev *dev,
		struct crdma_qp *qp, struct crdma_uar *uar,
		struct crdma_qp_ctrl_params *ctrl)
{
	u64 pfn;
	u32 word = 0;

	if (qp->mem->num_mtt == 1 && (dev->cap.opt_flags &
			CRDMA_DEV_CAP_FLAG_PHYS))
		word = 1 << CRDMA_QP_CTRL_PHYS_BIT_SHIFT;
	if (qp->sq_sig_type == IB_SIGNAL_ALL_WR)
		word |= 1 << CRDMA_QP_CTRL_SIGALL_BIT_SHIFT;

	/* Special QP are a anomaly, set QP1 and add GSI flag */
	if (unlikely(qp->ib_qp.qp_type == IB_QPT_GSI))
		word |= (1 << CRDMA_QP_CTRL_GSI_BIT_SHIFT) | 1;
	else
		word |= qp->qp_index & CRDMA_QP_CTRL_QPN_MASK;

	ctrl->flags_qpn = cpu_to_le32(word);

	word = (ilog2(qp->sq.wqe_size) & CRDMA_QP_CTRL_SWQE_LOG2_MASK) <<
			CRDMA_QP_CTRL_SWQE_LOG2_SHIFT;
	word |= (ilog2(qp->rq.wqe_size) & CRDMA_QP_CTRL_RWQE_LOG2_MASK) <<
			CRDMA_QP_CTRL_RWQE_LOG2_SHIFT;
	word |= qp->pdn & CRDMA_QP_CTRL_PD_MASK;
	ctrl->wqe_pd = cpu_to_le32(word);

	word = qp->ib_qp.qp_type == IB_QPT_RC ?
				1 << CRDMA_QP_CTRL_QPTYPE_SHIFT : 0;
	word |= qp->send_cqn & CRDMA_QP_CTRL_SCQN_MASK;
	ctrl->type_send_cqn = cpu_to_le32(word);

	ctrl->recv_cqn = cpu_to_le32(qp->recv_cqn & CRDMA_QP_CTRL_RCQN_MASK);
	ctrl->max_recv_wr = cpu_to_le16(qp->rq.wqe_cnt);
	ctrl->max_send_wr = cpu_to_le16(qp->sq.wqe_cnt);
	ctrl->max_inline_data = cpu_to_le16(qp->max_inline);
	ctrl->max_recv_sge = qp->rq.max_sg;
	ctrl->max_send_sge = qp->sq.max_sg;

	word = (qp->mem->min_order + PAGE_SHIFT) <<
				CRDMA_QP_CTRL_LOG2_PAGE_SZ_SHIFT;
	ctrl->page_info = cpu_to_le32(word);

	ctrl->mtt_index = cpu_to_le32(qp->mem->base_mtt_ndx);
	ctrl->sq_base_off = cpu_to_le32(qp->sq_offset);
	ctrl->rq_base_off = cpu_to_le32(qp->rq_offset);
	ctrl->srqn = cpu_to_le32(qp->srqn & CRDMA_QP_CTRL_SRQN_MASK);

	pfn = crdma_uar_pfn(dev, uar);
	ctrl->uar_pfn_high = cpu_to_le32(pfn >> 32);
	ctrl->uar_pfn_low = cpu_to_le32((pfn & 0x0FFFFFFFFull) <<
					PAGE_SHIFT);

	crdma_info("QP MODIFY control object values (LE)\n");
	if (unlikely(qp->ib_qp.qp_type == IB_QPT_GSI))
		pr_debug("       GSI QP: physical port %d, control object %d\n",
					qp->qp1_port, qp->qp1_port);
	else
		pr_debug("          QPN: %d\n", qp->qp_index);
	pr_info("    flags_qpn: 0x%08X\n", ctrl->flags_qpn);
	pr_info("       wqe_pd: 0x%08X\n", ctrl->wqe_pd);
	pr_info("    type_scqn: 0x%08X\n", ctrl->type_send_cqn);
	pr_info("         rcqn: 0x%08X\n", ctrl->recv_cqn);
	pr_info("  max_recv_wr: 0x%04X\n", ctrl->max_recv_wr);
	pr_info("  max_send_wr: 0x%04X\n", ctrl->max_send_wr);
	pr_info("  inline_data: 0x%04X\n", ctrl->max_inline_data);
	pr_info("  max_recv_sg: 0x%02X\n", ctrl->max_recv_sge);
	pr_info("  max_send_sg: 0x%02X\n", ctrl->max_send_sge);
	pr_info("    page_info: 0x%08X\n", ctrl->page_info);
	pr_info("    mtt_index: 0x%08X\n", ctrl->mtt_index);
	pr_info("  sq_base_off: 0x%08X\n", ctrl->sq_base_off);
	pr_info("  rq_base_off: 0x%08X\n", ctrl->rq_base_off);
	pr_info("         srqn: 0x%08X\n", ctrl->srqn);
	pr_info("     pfn_high: 0x%08X\n", ctrl->uar_pfn_high);
	pr_info("      pfn_low: 0x%08X\n", ctrl->uar_pfn_low);
	return;
}

/**
 * Build QP modify attribute parameters used to set/update QP state.
 *
 * @dev: The crdma IB RoCE device.
 * @qp: The crdma QP state used to initialize parameters.
 * @ib_attr: The requested IB verbs attributes.
 * @ib_attr_mask: The requested IB verbs attributes mask.
 * @attr: Returns the initialized QP modify attributes parameters.
 * @attr_mask: Returns the initialized QP modify attributes mask.
 *
 * Returns 0 on success, otherwise error code.
 */
static int crdma_set_qp_attr(struct crdma_ibdev *dev,
		struct crdma_qp *qp, struct ib_qp_attr *ib_attr,
		int ib_attr_mask, struct crdma_qp_attr_params *attr,
		u32 *attr_mask)
{
	if (ib_attr_mask & IB_QP_STATE)
		attr->qp_state = ib_attr->qp_state;

	if (ib_attr_mask & IB_QP_ACCESS_FLAGS)
		attr->mtu_access = ib_attr->qp_access_flags &
			(IB_ACCESS_REMOTE_WRITE | IB_ACCESS_REMOTE_READ);

	if (ib_attr_mask & IB_QP_PKEY_INDEX)
		attr->pkey_index = cpu_to_le16(ib_attr->pkey_index);

	if (ib_attr_mask & IB_QP_PORT)
		attr->phys_port_num = ib_attr->port_num - 1;

	if (ib_attr_mask & IB_QP_QKEY)
		attr->qkey = cpu_to_le32(ib_attr->qkey);

	if (ib_attr_mask & IB_QP_AV) {
		/* Get mac address */
		memcpy(attr->av.d_mac, ib_attr->ah_attr.roce.dmac, ETH_ALEN);

		/* Todo vlan*/
		//attr->av.vlan = cpu_to_le16(ib_attr->ah_attr.vlan_id);
		attr->av.port = ib_attr->ah_attr.port_num - 1;
		/* TODO: Can't set correctly yet, use IPv4 */
		attr->av.gid_type = CRDMA_ROCE_V2_IPV4_GID_TYPE;
		/* TODO: Can't set correclty yet, use 0 */
		attr->av.s_mac_ndx = 0;
		/* TODO: Can't set correctly yet */
		attr->av.v_id = 0;
		attr->av.traffic_class = ib_attr->ah_attr.grh.traffic_class;
		attr->av.hop_limit = ib_attr->ah_attr.grh.hop_limit;
		attr->av.s_gid_ndx = ib_attr->ah_attr.grh.sgid_index;
		attr->av.service_level = ib_attr->ah_attr.sl;
		attr->av.flow_label =
			__swab32(ib_attr->ah_attr.grh.flow_label);
		/*
		 * Maintain destination GID byte swapped on 32-bit boundary
		 * so that it need not be done each time the address handle
		 * is used in a work request.
		 */
		memcpy(attr->av.d_gid, ib_attr->ah_attr.grh.dgid.raw, 16);

		/* XXX: For now we only allow maximum rate, no IPD */
		attr->av.ib_sr_ipd =
			cpu_to_le32((0 << CRDMA_AV_IBSR_IPD_SHIFT) |
					(to_crdma_pd(qp->ib_qp.pd)->pd_index &
					CRDMA_AV_PD_MASK));
	}	

	if (ib_attr_mask & IB_QP_PATH_MTU)
		attr->mtu_access |= (ib_attr->path_mtu + 7) <<
					CRDMA_QP_ATTR_MTU_SHIFT;

	if (ib_attr_mask & IB_QP_TIMEOUT)
		attr->timeout = ib_attr->timeout;

	if (ib_attr_mask & IB_QP_RETRY_CNT)
		attr->retry_count = ib_attr->retry_cnt;

	if (ib_attr_mask & IB_QP_RNR_RETRY)
		attr->rnr_retry = ib_attr->rnr_retry;

	if (ib_attr_mask & IB_QP_RQ_PSN)
		attr->rq_psn = cpu_to_le32(ib_attr->rq_psn);

	if (ib_attr_mask & IB_QP_MAX_QP_RD_ATOMIC)
		attr->rdma_init_depth = ib_attr->max_rd_atomic;;

	if (ib_attr_mask & IB_QP_ALT_PATH)
		/* Not supported */;

	if (ib_attr_mask & IB_QP_MIN_RNR_TIMER)
		attr->min_rnr_timer = ib_attr->min_rnr_timer;

	if (ib_attr_mask & IB_QP_SQ_PSN)
		attr->sq_psn = cpu_to_le32(ib_attr->sq_psn);

	if (ib_attr_mask & IB_QP_MAX_DEST_RD_ATOMIC)
		attr->rdma_rsp_res = ib_attr->max_dest_rd_atomic;

	if (ib_attr_mask & IB_QP_PATH_MIG_STATE)
		/* Not supported */;

	if (ib_attr_mask & IB_QP_CAP)
		;

	if (ib_attr_mask & IB_QP_DEST_QPN)
		attr->dest_qpn = cpu_to_le32(ib_attr->dest_qp_num &
					CRDMA_QP_ATTR_QPN_MASK);

	crdma_debug("QP MODIFY attribute values (LE)\n");
	if (ib_attr_mask & IB_QP_STATE)
		pr_debug("        state: %d\n", attr->qp_state);
	if (ib_attr_mask & IB_QP_EN_SQD_ASYNC_NOTIFY)
		pr_debug("   SQD Nofity: Requested\n");
	if (ib_attr_mask & IB_QP_ACCESS_FLAGS)
		pr_debug(" access flags: 0x%X\n", attr->mtu_access);
	if (ib_attr_mask & IB_QP_PKEY_INDEX)
		pr_debug("   pkey_index: %d\n", attr->pkey_index);
	if (ib_attr_mask & IB_QP_PORT)
		pr_debug("    phys port: %d\n", attr->phys_port_num);
	if (ib_attr_mask & IB_QP_QKEY)
		pr_debug("         qkey: 0x%08X\n", attr->qkey);
	if (ib_attr_mask & IB_QP_AV) {
		pr_debug("     av.d_mac:%02X:%02X:%02X:%02X:%02X:%02X\n",
				attr->av.d_mac[0], attr->av.d_mac[1],
				attr->av.d_mac[2], attr->av.d_mac[3],
				attr->av.d_mac[4], attr->av.d_mac[5]);
		pr_debug("      av.vlan:0x%04X\n", attr->av.vlan);
		pr_debug("  av.port_num:%d\n", attr->av.port);
		pr_debug("  av.gid_type:%d\n", attr->av.gid_type);
		pr_debug(" av.s_mac_ndx:%d\n", attr->av.s_mac_ndx);
		pr_debug("      av.v_id:0x%08X\n", attr->av.v_id);
		pr_debug("   av.t_class:0x%08X\n", attr->av.traffic_class);
		pr_debug(" av.hop_limit:%d\n", attr->av.hop_limit);
		pr_debug(" av.s_gid_ndx:%d\n", attr->av.s_gid_ndx);
		pr_debug("        av.sl:0x%02X\n", attr->av.service_level);
		pr_debug("av.flow_label:0x%08X\n", attr->av.flow_label);
		pr_debug("     av.d_gid:0x:%016llX:%016llX\n",
			*(u64 *)(attr->av.d_gid),
			*((u64 *)(attr->av.d_gid) + 1));
		/* TODO: convert SR to IPD? */
		pr_debug("av.ib_sr_ipd:0x%02X\n", attr->av.ib_sr_ipd);
	}
	if (ib_attr_mask & IB_QP_PATH_MTU)
		pr_debug("   mtu_access: 0x%02X\n", attr->mtu_access);
	if (ib_attr_mask & IB_QP_TIMEOUT)
		pr_debug("       timeout: %d\n", attr->timeout);
	if (ib_attr_mask & IB_QP_RETRY_CNT)
		pr_debug("   retry_count: %d\n", attr->retry_count);
	if (ib_attr_mask & IB_QP_RNR_RETRY)
		pr_debug("     rnr_retry: %d\n", attr->rnr_retry);
	if (ib_attr_mask & IB_QP_RQ_PSN)
		pr_debug("        rq_psn: 0x%08x\n", attr->rq_psn);
	if (ib_attr_mask & IB_QP_MAX_QP_RD_ATOMIC)
		pr_debug("rdma_init_deptth: %d\n", attr->rdma_init_depth);
	if (ib_attr_mask & IB_QP_SQ_PSN)
		pr_debug("       SQ PSN: 0x%08x\n", attr->sq_psn);
	if (ib_attr_mask & IB_QP_MAX_DEST_RD_ATOMIC)
		pr_debug(" rdma_rsp_res: %d\n", attr->rdma_rsp_res);
	if (ib_attr_mask & IB_QP_PATH_MIG_STATE)
		/* Not supported */;
	if (ib_attr_mask & IB_QP_CAP)
		/* TODO: */;
	if (ib_attr_mask & IB_QP_DEST_QPN)
		pr_debug("     dest_qpn: 0x%08X\n", attr->dest_qpn);

	/* Our attribute mask matches IB attribute mask bits */
	*attr_mask = cpu_to_le32(ib_attr_mask);
	return 0;
}

int crdma_qp_modify_cmd(struct crdma_ibdev *dev, struct crdma_qp *qp,
		struct crdma_uar *uar, struct ib_qp_attr *qp_attr,
		int qp_attr_mask, enum ib_qp_state cur_state,
		enum ib_qp_state new_state)
{
	struct crdma_qp_params *param;
	struct crdma_cmd_mbox in_mbox;
	struct crdma_cmd cmd;
	int status;
	int modifier;

	modifier = crdma_qp_modify_opcode_mod(cur_state, new_state);
	if (modifier < 0) {
		crdma_info("Illegal state transition\n");
		return -EINVAL;
	}
	crdma_info("QP transition: %d\n", modifier);

	if (crdma_init_mailbox(dev, &in_mbox))
		return -1;

	param		= in_mbox.buf;

	/*
	 * If we are in the RESET state and going to the INIT state,
	 * we need to provide microcode the QP control object parameters.
	 */
	if (cur_state == IB_QPS_RESET && new_state == IB_QPS_INIT)
		crdma_set_qp_ctrl(dev, qp, uar, &param->ctrl);

	/*
	 * Initialize QP attribute mask and values based on parameters
	 * indicated (both required and optional attributes for the
	 * QP transition were previously verified in the attribute mask.
	 */
	if (crdma_set_qp_attr(dev, qp, qp_attr, qp_attr_mask,
			&param->attr, &param->attr_mask)) {
		crdma_info("Illegal QP attribute detected\n");
		status = -EINVAL;
		goto out;
	}

	crdma_info("QP_MODIFY Input Mailbox\n");
	print_hex_dump(KERN_DEBUG, "IN:", DUMP_PREFIX_OFFSET, 8, 1,
			in_mbox.buf, sizeof(*param), 0);

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode = CRDMA_CMD_QP_MODIFY;
	cmd.opcode_mod = modifier;
	cmd.timeout = CRDMA_CMDIF_GEN_TIMEOUT_MS;
	cmd.input_param = in_mbox.dma_addr;
	/*
	* Special QP1 use the dedicated port number control object, all
	* other QP use the allocated control object index.
	*/
	cmd.input_mod = qp->ib_qp.qp_type == IB_QPT_GSI ?
								qp->qp1_port : qp->qp_index;
	status = crdma_cmd(dev, &cmd);

	/* While command not supported provide hard-coded response */
	if (status == CRDMA_STS_UNSUPPORTED_OPCODE) {
		crdma_info("Using hard coded QP_MODIFY results\n");
		status = CRDMA_STS_OK;
	}

	/* Save new state in QP */
	if (status == CRDMA_STS_OK)
		qp->qp_state = new_state;
out:
	crdma_cleanup_mailbox(dev, &in_mbox);
	return status;
}

int crdma_qp_query_cmd(struct crdma_ibdev *dev, struct crdma_qp *qp,
		struct ib_qp_attr *qp_attr, int qp_attr_mask)
{
	struct crdma_qp_attr_params *param;
	struct crdma_cmd_mbox out_mbox;
	struct crdma_cmd cmd;
	union ib_gid *dgid;
	int status;

	if (crdma_init_mailbox(dev, &out_mbox))
		return -1;

	param		= out_mbox.buf;

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode = CRDMA_CMD_QP_QUERY;
	cmd.timeout = CRDMA_CMDIF_GEN_TIMEOUT_MS;
	cmd.output_param = out_mbox.dma_addr;
	cmd.input_mod = qp->qp_index;
	status = crdma_cmd(dev, &cmd);

	if (status != CRDMA_STS_OK)
		goto free_mbox;

	qp_attr->qp_state = param->qp_state;
	qp_attr->port_num = param->phys_port_num + 1;
	qp_attr->pkey_index = le16_to_cpu(param->pkey_index);
	qp_attr->qkey = le32_to_cpu(param->qkey);
	qp_attr->sq_psn = le32_to_cpu(param->sq_psn);
	qp_attr->rq_psn = le32_to_cpu(param->rq_psn);
	qp_attr->min_rnr_timer = param->min_rnr_timer;
	qp_attr->rnr_retry = param->rnr_retry;
	qp_attr->retry_cnt = param->retry_count;
	qp_attr->timeout = param->timeout;
	qp_attr->dest_qp_num = le32_to_cpu(param->dest_qpn) &
							CRDMA_QP_ATTR_QPN_MASK;
	qp_attr->max_rd_atomic = param->rdma_init_depth;
	qp_attr->max_dest_rd_atomic = param->rdma_rsp_res;
	qp_attr->qp_access_flags = param->mtu_access &
							CRDMA_QP_ATTR_ACCESS_MASK;
	qp_attr->path_mtu = (param->mtu_access >>
									CRDMA_QP_ATTR_MTU_SHIFT) - 7;

	crdma_debug("QP query attribute values\n");
	pr_debug("        state: %d\n", qp_attr->qp_state);
	pr_debug("         port: %d\n", qp_attr->port_num);
	pr_debug("   pkey_index: %d\n", qp_attr->pkey_index);
	pr_debug("       SQ PSN: %d\n", qp_attr->sq_psn);
	pr_debug("       RQ PSN: %d\n", qp_attr->rq_psn);
	pr_debug("min_rnr_timer: %d\n", qp_attr->min_rnr_timer);
	pr_debug("    rnr_retry: %d\n", qp_attr->rnr_retry);
	pr_debug("    retry_cnt: %d\n", qp_attr->retry_cnt);
	pr_debug("      timeout: %d\n", qp_attr->timeout);
	pr_debug("  dest_qp_num: 0x%08X\n", qp_attr->dest_qp_num);
	pr_debug("  max_rd_atomic(init depth): %d\n", qp_attr->max_rd_atomic);
	pr_debug("max_dest_rd_atomic(rsp res): %d\n",
					qp_attr->max_dest_rd_atomic);
	pr_debug(" access_flags: 0x%02X\n", qp_attr->qp_access_flags);
	pr_debug("     path_mtu: 0x%02X\n", qp_attr->path_mtu);
	if (qp_attr_mask & IB_QP_AV) {
		qp_attr->ah_attr.roce.dmac[3] = param->av.d_mac[0];
		qp_attr->ah_attr.roce.dmac[2] = param->av.d_mac[1];
		qp_attr->ah_attr.roce.dmac[1] = param->av.d_mac[2];
		qp_attr->ah_attr.roce.dmac[0] = param->av.d_mac[3];
		qp_attr->ah_attr.roce.dmac[5] = param->av.d_mac[4];
		qp_attr->ah_attr.roce.dmac[4] = param->av.d_mac[5];

		//qp_attr->ah_attr.vlan_id = le16_to_cpu(param->av.vlan);
		qp_attr->ah_attr.port_num = param->av.port + 1;
		/* TODO: Can't return GID Type yet */
		/* TODO: We don't return SMAC yet */

		qp_attr->ah_attr.grh.traffic_class = param->av.traffic_class;
		qp_attr->ah_attr.grh.hop_limit = param->av.hop_limit;
		qp_attr->ah_attr.grh.sgid_index = param->av.s_gid_ndx;
		qp_attr->ah_attr.sl = param->av.service_level;
		qp_attr->ah_attr.grh.flow_label =
						__swab32(param->av.flow_label);

		dgid = &qp_attr->ah_attr.grh.dgid;
#if defined(__BIG_ENDIAN)
		dgid->global.subnet_prefix =
				((u64)__swab32(param->av.d_gid_word[0]) << 32) |
				__swab32(param->av.d_gid_word[1]);
		dgid->global.interface_id =
				((u64)__swab32(param->av.d_gid_word[2]) << 32) |
				__swab32(param->av.d_gid_word[3]);
#elif defined(__LITTLE_ENDIAN)
		dgid->global.subnet_prefix =
				((u64)__swab32(param->av.d_gid_word[1]) << 32) |
				__swab32(param->av.d_gid_word[0]);
		dgid->global.interface_id =
				((u64)__swab32(param->av.d_gid_word[3]) << 32) |
				__swab32(param->av.d_gid_word[2]);
#else
#error Host endianness not defined
#endif
		/* XXX: We only allow full rate for now */
		qp_attr->ah_attr.static_rate = 0;

		pr_debug("         dmac:%02X:%02X:%02X:%02X:%02X:%02X\n",
				qp_attr->ah_attr.roce.dmac[0],
				qp_attr->ah_attr.roce.dmac[1],
				qp_attr->ah_attr.roce.dmac[2],
				qp_attr->ah_attr.roce.dmac[3],
				qp_attr->ah_attr.roce.dmac[4],
				qp_attr->ah_attr.roce.dmac[5]);
		//pr_debug("      vlan_id:0x%04X\n", qp_attr->ah_attr.vlan_id);
		pr_debug("     port_num:%d\n", qp_attr->ah_attr.port_num);
		pr_debug("      t_class:0x%08X\n",
						qp_attr->ah_attr.grh.traffic_class);
		pr_debug("    hop_limit:%d\n", qp_attr->ah_attr.grh.hop_limit);
		pr_debug("    s_gid_ndx:%d\n", qp_attr->ah_attr.grh.sgid_index);
		pr_debug("           sl:0x%02X\n", qp_attr->ah_attr.sl);
		pr_debug("   flow_label:0x%08X\n",
						qp_attr->ah_attr.grh.flow_label);
		pr_debug("        d_gid:0x:%016llX:%016llX\n",
				qp_attr->ah_attr.grh.dgid.global.subnet_prefix,
				qp_attr->ah_attr.grh.dgid.global.interface_id);
		pr_debug(" static rate:0x%02X\n", qp_attr->ah_attr.static_rate);
	}

free_mbox:
        crdma_cleanup_mailbox(dev, &out_mbox);
        return status;
}

int crdma_qp_destroy_cmd(struct crdma_ibdev *dev, struct crdma_qp *qp)
{
	struct crdma_qp_params *param;
	struct crdma_cmd_mbox in_mbox;
	struct crdma_cmd cmd;
	int status;

	if (crdma_init_mailbox(dev, &in_mbox))
		return -1;

	param	= in_mbox.buf;
	param->attr_mask = IB_QP_STATE;
	param->attr.qp_state = IB_QPS_RESET;

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode = CRDMA_CMD_QP_MODIFY;
	cmd.opcode_mod = CRDMA_QP_MODIFY_2RST;
	cmd.timeout = CRDMA_CMDIF_GEN_TIMEOUT_MS;
	cmd.input_param = in_mbox.dma_addr;
	cmd.input_mod = qp->ib_qp.qp_type == IB_QPT_GSI ?
		qp->qp1_port : qp->qp_index;
	status = crdma_cmd(dev, &cmd);

	/* Save new state in QP */
	if (status == CRDMA_STS_OK)
		qp->qp_state = IB_QPS_RESET;
	crdma_cleanup_mailbox(dev, &in_mbox);
	return status;
}

int crdma_port_enable_cmd(struct crdma_ibdev *dev, u8 port)
{
	return __crdma_no_param_cmd(dev, CRDMA_CMD_ROCE_PORT_ENABLE, 0,
			port, CRDMA_CMDIF_GEN_TIMEOUT_MS);
}

int crdma_port_disable_cmd(struct crdma_ibdev *dev, u8 port)
{
	return __crdma_no_param_cmd(dev, CRDMA_CMD_ROCE_PORT_DISABLE, 0,
			port, CRDMA_CMDIF_GEN_TIMEOUT_MS);
}

/**
 * Issue microcode MPT create command.
 *
 * @dev: The IB RoCE device.
 * @mr: The memory region associated with the MPT.
 *
 * Returns 0 on success, otherwise an error.
 */
static int crdma_mpt_create_cmd(struct crdma_ibdev *dev, struct crdma_mr *cmr)
{
	struct crdma_mpt_params *param;
	struct crdma_cmd_mbox in_mbox;
	struct crdma_cmd cmd;
	u32 page_info;
	u32 flags_pdn;
	int status;

	if (crdma_init_mailbox(dev, &in_mbox))
		return -1;

	param		= in_mbox.buf;
	param->key	= cpu_to_le32(cmr->key);

	flags_pdn	= cmr->pdn & CRDMA_MPT_CREATE_PD_MASK;
	flags_pdn	|= ((cmr->access & IB_ACCESS_LOCAL_WRITE) ?
				CRDMA_MPT_LOCAL_WRITE_ENABLE : 0) |
			((cmr->access & IB_ACCESS_REMOTE_WRITE) ?
				CRDMA_MPT_REMOTE_WRITE_ENABLE : 0) |
			((cmr->access & IB_ACCESS_REMOTE_READ) ?
				CRDMA_MPT_REMOTE_READ_ENABLE : 0) |
			(cmr->umem ? 0 : CRDMA_MPT_DMA);

	/* Set PHYS flag if only a single MTT entry and it is supported */
	if (cmr->num_mtt == 1 && (dev->cap.opt_flags &
			CRDMA_DEV_CAP_FLAG_PHYS))
		flags_pdn |= CRDMA_MPT_PHYS;
	param->flags_pd	= cpu_to_le32(flags_pdn);

	param->io_addr_h = cpu_to_le32(cmr->io_vaddr >> 32);
	param->io_addr_l = cpu_to_le32(cmr->io_vaddr & 0x0FFFFFFFF);
	param->length	= cpu_to_le32(cmr->len);
	param->mtt_index= cpu_to_le32(cmr->base_mtt);

	page_info = (cmr->mpt_order + cmr->page_shift) <<
				CRDMA_MPT_LOG2_PAGE_SZ_SHIFT;
	param->page_info = cpu_to_le32(page_info);
	param->mtt_index = cpu_to_le32(cmr->base_mtt);
	param->frmr_entries = 0;
	param->reserved = 0;

	crdma_debug("MPT_CREATE input values (LE)\n");
	pr_debug("         Key: 0x%08X\n", param->key);
	pr_debug("   Flags/PDN: 0x%08X\n", param->flags_pd);
	pr_debug("   IO Addr_h: 0x%08X\n", param->io_addr_h);
	pr_debug("   IO Addr_l: 0x%08X\n", param->io_addr_l);
	pr_debug("      Length: %d\n", param->length);
	pr_debug("Pg_Info_Word: 0x%08X\n", param->page_info);
	pr_debug("   MTT Index: 0x%08X\n", param->mtt_index);
	pr_debug("FRMR Entries: 0x%08X\n", param->frmr_entries);
	pr_debug("    reserved: 0x%08X\n", param->reserved);

	crdma_info("MPT_CREATE Input Mailbox\n");
	print_hex_dump(KERN_DEBUG, "IN:",
			DUMP_PREFIX_OFFSET, 8, 1, in_mbox.buf, 32, 0);

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode = CRDMA_CMD_MPT_CREATE;
	cmd.timeout = CRDMA_CMDIF_GEN_TIMEOUT_MS;
	cmd.input_param = in_mbox.dma_addr;
	cmd.input_mod = cmr->mpt_index;
	status = crdma_cmd(dev, &cmd);
	crdma_cleanup_mailbox(dev, &in_mbox);

	return status;
}

int crdma_init_mpt(struct crdma_ibdev *dev, struct crdma_mr *cmr,
		int comp_pages, int comp_order)
{
	struct ib_umem *umem = cmr->umem;
	int ret;

	crdma_info("crdma_init_mpt \n");

	if (umem) {
		cmr->num_mtt = comp_pages;
		cmr->base_mtt = crdma_alloc_bitmap_area(&dev->mtt_map,
						cmr->num_mtt);
		if (cmr->base_mtt < 0)
			return -ENOMEM;

#if (VER_NON_RHEL_GE(5,3) || VER_RHEL_GE(8,0))
		ret = crdma_mtt_write_sg(dev, umem->sg_head.sgl, umem->nmap,
				cmr->base_mtt, cmr->num_mtt, PAGE_SHIFT,
				comp_pages, comp_order);
#else
		ret = crdma_mtt_write_sg(dev, umem->sg_head.sgl, umem->nmap,
				cmr->base_mtt, cmr->num_mtt, umem->page_shift,
				comp_pages, comp_order);
#endif
		if (ret) {
			crdma_err("Error writing MTT entries %d\n", ret);
			goto free_mtt;
		}
	} else {
		/* DMA memory region */
		cmr->num_mtt = 0;
		cmr->base_mtt = 0;
	}

	/* Issue MPT Create Command */
	ret = crdma_mpt_create_cmd(dev, cmr);
	if (ret) {
		crdma_dev_info(dev, "crdma_mpt_create_cmd failed, "
				"returned %d\n", ret);
		goto free_mtt;
	}
	return 0;

free_mtt:
	if (umem)
		crdma_free_bitmap_area(&dev->mtt_map, cmr->base_mtt,
					cmr->num_mtt);
	return -ENOMEM;
}

void crdma_cleanup_mpt(struct crdma_ibdev *dev, struct crdma_mr *cmr)
{
	__crdma_no_param_cmd(dev, CRDMA_CMD_MPT_DESTROY, 0,
			cmr->mpt_index, CRDMA_CMDIF_GEN_TIMEOUT_MS);
	crdma_free_bitmap_area(&dev->mtt_map, cmr->base_mtt, cmr->num_mtt);
	return;
}

int crdma_mpt_query_cmd(struct crdma_ibdev *dev, u32 mpt_index,
			struct crdma_mpt_params *param)
{
	struct crdma_cmd_mbox out_mbox;
	struct crdma_cmd cmd;
	int status;

	memset(&cmd, 0, sizeof(cmd));
	if (crdma_init_mailbox(dev, &out_mbox))
		return -1;

	cmd.opcode = CRDMA_CMD_MPT_QUERY;
	cmd.timeout = CRDMA_CMDIF_GEN_TIMEOUT_MS;
	cmd.output_param = out_mbox.dma_addr;
	cmd.input_mod = mpt_index;

	status = crdma_cmd(dev, &cmd);
	if (status == CRDMA_STS_OK) {
		memcpy(param, out_mbox.buf, sizeof(*param));
		crdma_debug("MPT_QUERY returned values (LE)\n");
		pr_debug("         Key: 0x%08X\n", param->key);
		pr_debug("   Flags/PDN: 0x%08X\n", param->flags_pd);
		pr_debug("   IO Addr_h: 0x%08X\n", param->io_addr_h);
		pr_debug("   IO Addr_l: 0x%08X\n", param->io_addr_l);
		pr_debug("      Length: %d\n", param->length);
		pr_debug("Pg_Info_Word: 0x%08X\n", param->page_info);
		pr_debug("   MTT Index: 0x%08X\n", param->mtt_index);
		pr_debug("FRMR Entries: 0x%08X\n", param->frmr_entries);

		crdma_info("MPT_QUERY Output Mailbox\n");
		print_hex_dump(KERN_DEBUG, "OUT:",
				DUMP_PREFIX_OFFSET, 8, 1, out_mbox.buf, 32, 0);
	}
	crdma_cleanup_mailbox(dev, &out_mbox);
	return status;
}

int crdma_write_sgid_table(struct crdma_ibdev *dev,
			int port_num, int num_entries)
{
	struct crdma_gid_entry_param *param;
	struct crdma_gid_entry *entry;
	struct crdma_cmd_mbox in_mbox;
	struct crdma_cmd cmd;
	unsigned long flags;
	u32 port_gid_cnt;
	int i;
	int status;

	crdma_debug("port_num %d, entries %d\n", port_num, num_entries);

	if (crdma_init_mailbox(dev, &in_mbox))
		return -1;

	if ((num_entries * sizeof(*param)) > CRDMA_CMDIF_MBOX_SIZE) {
		crdma_warn("GID table size of %d entries too large\n",
				num_entries);
		return -1;
	}

	param = in_mbox.buf;
	entry = dev->port.gid_table_entry;

	spin_lock_irqsave(&dev->port.table_lock, flags);
	for (i = 0; i < num_entries; i++, entry++, param++) {
		param->gid_type = entry->type;
		if (entry->valid)
			param->valid = 1;
		/*
		 * Perform a 32-bit byte swap on the GIDs that will
		 * be undone by the DMA.
		 */
#if defined(__BIG_ENDIAN)
		param->gid_word[0] =
			__swab32(entry->gid.global.subnet_prefix >> 32);
		param->gid_word[1] =
			__swab32(entry->gid.global.subnet_prefix & 0x0FFFFFFFF);
		param->gid_word[2] =
			__swab32(entry->gid.global.interface_id >> 32);
		param->gid_word[3] =
			__swab32(entry->gid.global.interface_id & 0x0FFFFFFFF);
#elif defined(__LITTLE_ENDIAN)
		param->gid_word[0] =
			__swab32(entry->gid.global.subnet_prefix & 0x0FFFFFFFF);
		param->gid_word[1] =
			__swab32(entry->gid.global.subnet_prefix >> 32);
		param->gid_word[2] =
			__swab32(entry->gid.global.interface_id & 0x0FFFFFFFF);
		param->gid_word[3] =
			__swab32(entry->gid.global.interface_id >> 32);
#else
#error Host endianness not defined
#endif
	}
	spin_unlock_irqrestore(&dev->port.table_lock, flags);

	port_gid_cnt = (port_num << CRDMA_SGID_PARAM_PORT_NUM_SHIFT) |
			((num_entries & CRDMA_SGID_PARAM_COUNT_MASK) <<
			 CRDMA_SGID_PARAM_COUNT_SHIFT);
	crdma_debug("SET_PORT_GID_TABLE port_gid_cnt 0x%08X (LE)\n",
			cpu_to_le32(port_gid_cnt));
	crdma_debug("SET_PORT_GID_TABLE input entries\n");
	print_hex_dump(KERN_DEBUG, "IN:",
			DUMP_PREFIX_OFFSET, 8, 1, in_mbox.buf,
			num_entries * 20, 0);

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode = CRDMA_CMD_SET_PORT_GID_TABLE;
	cmd.timeout = CRDMA_CMDIF_GEN_TIMEOUT_MS;
	cmd.input_param = in_mbox.dma_addr;
	cmd.input_mod = port_gid_cnt;
	status = crdma_cmd(dev, &cmd);
	crdma_cleanup_mailbox(dev, &in_mbox);

	return status;
}

int crdma_read_sgid_table(struct crdma_ibdev *dev, int port_num,
		struct crdma_gid_entry *entries, int num_entries)
{
	struct crdma_gid_entry_param *param;
	struct crdma_gid_entry *entry;
	struct crdma_cmd_mbox out_mbox;
	struct crdma_cmd cmd;
	u32 port_gid_cnt;
	int i;
	int status;

	crdma_debug("phys port_num %d, entries %d\n", port_num, num_entries);

	if (crdma_init_mailbox(dev, &out_mbox))
		return -1;

	if ((num_entries * sizeof(*param)) > CRDMA_CMDIF_MBOX_SIZE) {
		crdma_warn("GID table size of %d entries too large\n",
				num_entries);
		return -1;
	}

	port_gid_cnt = (port_num << CRDMA_SGID_PARAM_PORT_NUM_SHIFT) |
			((num_entries & CRDMA_SGID_PARAM_COUNT_MASK) <<
			 CRDMA_SGID_PARAM_COUNT_SHIFT);
	crdma_debug("GET_PORT_GID_TABLE port_gid_cnt 0x%08X (LE)\n",
			cpu_to_le32(port_gid_cnt));

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode = CRDMA_CMD_GET_PORT_GID_TABLE;
	cmd.timeout = CRDMA_CMDIF_GEN_TIMEOUT_MS;
	cmd.output_param = out_mbox.dma_addr;
	cmd.input_mod = port_gid_cnt;
	status = crdma_cmd(dev, &cmd);
	if (status != CRDMA_STS_OK)
		goto free_mbox;

	crdma_debug("GET_PORT_GID_TABLE num output entries\n");
	print_hex_dump(KERN_DEBUG, "OUT:",
			DUMP_PREFIX_OFFSET, 8, 1, out_mbox.buf,
			num_entries * 20, 0);

	param = out_mbox.buf;
	entry = entries;
	for (i = 0; i < num_entries; i++, entry++, param++) {
		entry->type = param->gid_type;
		if (param->valid)
			entry->valid = 1;

#if defined(__BIG_ENDIAN)
		entry->gid.global.subnet_prefix =
			((u64)__swab32(param->gid_word[0]) << 32) |
			__swab32(param->gid_word[1]);
		entry->gid.global.interface_id =
			((u64)__swab32(param->gid_word[2]) << 32) |
			__swab32(param->gid_word[3]);
#elif defined(__LITTLE_ENDIAN)
		entry->gid.global.subnet_prefix =
			((u64)__swab32(param->gid_word[1]) << 32) |
			__swab32(param->gid_word[0]);
		entry->gid.global.interface_id =
			((u64)__swab32(param->gid_word[3]) << 32) |
			__swab32(param->gid_word[2]);
#else
#error Host endianness not defined
#endif
	}

free_mbox:
	crdma_cleanup_mailbox(dev, &out_mbox);
	return status;
}

int crdma_write_smac_table(struct crdma_ibdev *dev,
			int port_num, int num_entries)
{
	struct crdma_mac_entry_param *param;
	struct crdma_mac_entry *entry;
	struct crdma_cmd_mbox in_mbox;
	struct crdma_cmd cmd;
	unsigned long flags;
	u32 port_mac_cnt;
	int i;
	int status;

	crdma_debug("phys port_num %d, entries %d\n", port_num, num_entries);

	if (crdma_init_mailbox(dev, &in_mbox))
		return -1;

	if ((num_entries * sizeof(*param)) > CRDMA_CMDIF_MBOX_SIZE) {
		crdma_warn("MAC table size of %d entries too large\n",
				num_entries);
		return -1;
	}

	param = in_mbox.buf;
	entry = dev->port.mac_table_entry;

	spin_lock_irqsave(&dev->port.table_lock, flags);
	for (i = 0; i < num_entries; i++, entry++, param++) {
		if (entry->ref_cnt > 0) {
			param->valid = 1;
			/*
			 * Swap bytes within 32-bit words, this will
			 * be undone by the microcode DMA.
			 */
			param->mac[0] = entry->mac[1];
			param->mac[1] = entry->mac[0];
			param->mac_l[0] = entry->mac[5];
			param->mac_l[1] = entry->mac[4];
			param->mac_l[2] = entry->mac[3];
			param->mac_l[3] = entry->mac[2];
		}
	}
	spin_unlock_irqrestore(&dev->port.table_lock, flags);

	port_mac_cnt = (port_num << CRDMA_SMAC_PARAM_PORT_NUM_SHIFT) |
			((num_entries & CRDMA_SMAC_PARAM_COUNT_MASK) <<
			 CRDMA_SMAC_PARAM_COUNT_SHIFT);
	crdma_debug("SET_PORT_MAC_TABLE port_mac_cnt 0x%08X (LE)\n",
			cpu_to_le32(port_mac_cnt));
	crdma_debug("SET_PORT_MAC_TABLE input entries\n");
	print_hex_dump(KERN_DEBUG, "IN:",
			DUMP_PREFIX_OFFSET, 8, 1, in_mbox.buf,
			num_entries * 8, 0);

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode = CRDMA_CMD_SET_PORT_MAC_TABLE;
	cmd.timeout = CRDMA_CMDIF_GEN_TIMEOUT_MS;
	cmd.input_param = in_mbox.dma_addr;
	cmd.input_mod = port_mac_cnt;
	status = crdma_cmd(dev, &cmd);
	crdma_cleanup_mailbox(dev, &in_mbox);

	return status;
}

struct eqe_param {
	__le32 cnt;
	__le32 eqe_specific[3];
	__le16 owner_rsvd;
	u8 sub_type;
	u8 event_type;
};

int crdma_test_eq_enqueue(struct crdma_ibdev *dev, int eqn, int cnt)
{
	struct crdma_cmd_mbox in_mbox;
	struct eqe_param *param;
	struct crdma_cmd cmd;
	int status;

	if (crdma_init_mailbox(dev, &in_mbox))
		return -1;

	param = in_mbox.buf;
	param->cnt = cpu_to_le32(1);
	param->eqe_specific[0] = cpu_to_le32(0x00000001);
	param->eqe_specific[1] = 0;
	param->eqe_specific[2] = 0;
	param->owner_rsvd = 0;
	param->sub_type = 0;
	param->event_type = 1;

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode = 205;
	cmd.timeout = CRDMA_CMDIF_GEN_TIMEOUT_MS;
	cmd.input_param = in_mbox.dma_addr;
	cmd.input_mod = eqn;
	status = crdma_cmd(dev, &cmd);

	crdma_cleanup_mailbox(dev, &in_mbox);
	if (status == CRDMA_STS_OK)
		crdma_interrupt(0, &dev->eq_table.eq[eqn]);

	return status;
}

int crdma_init_cmdif(struct crdma_ibdev *dev)
{
	mutex_init(&dev->cmdif_mutex);
	sema_init(&dev->poll_sem, 1);

	dev->toggle = 1;
	dev->token = 1;
	dev->use_event_cmds = false;
	dev->max_cmds_out = CRDMA_CMDIF_DRIVER_MAX_CMDS;

	dev->mbox_pool = dma_pool_create("crdma_cmd", &dev->nfp_info->pdev->dev,
			CRDMA_CMDIF_MBOX_SIZE, CRDMA_CMDIF_MBOX_SIZE, 0);
	if (!dev->mbox_pool) {
		crdma_dev_info(dev, "RoCEv2 command mailbox pool create"
			       " failure\n");
		return -ENOMEM;
	}
	return 0;
}

void crdma_cleanup_cmdif(struct crdma_ibdev *dev)
{
	dma_pool_destroy(dev->mbox_pool);
	return;
}
