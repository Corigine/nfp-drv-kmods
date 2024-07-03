// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright (C) 2023 Corigine, Inc. */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/pci.h>
#include <linux/interrupt.h>

#include "nfpcore/nfp_roce.h"
#include "crdma_ib.h"
#include "crdma_hw.h"
#include "crdma_util.h"
#include "crdma_ucif.h"

#define	CRDMA_UNDEFINED		"Undefined"

#define MAX_BIDIRECTIONAL_SEGMENT		4
#define MAX_DEFAULT_BIDIRECTIONAL_SEGMENT	3

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
const char * const crdma_opcode_to_str(u8 opcode)
{
	static const char * const cmd_to_str[] = {
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
		[CRDMA_CMD_MCG_DETACH]          = "MCG_DETACH",
		[CRDMA_CMD_SET_PORT_MTU]	= "SET_PORT_MTU",
		[CRDMA_CMD_DCQCN_ENABLE]	= "DCQCN_ENABLE",
		[CRDMA_CMD_RETRANS_ENABLE]	= "RETRANS_ENABLE",
		[CRDMA_CMD_BOND_CONFIG]		= "BOND_CONFIG",
		[CRDMA_CMD_HIGH_PERF_READ_ENABLE]	= "HIGH_PERF_READ_ENABLE"
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
const char * const crdma_status_to_str(u8 status)
{
	static const char * const status_to_str[] = {
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
const char * const crdma_event_to_str(u8 event_type)
{
	static const char * const event_to_str[] = {
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


	/* Get polled results */
	if (__crdma_read_cmdif_results(dev, &output_param, &cmd->status)) {
		ret = -EIO;
		goto done;
	}

	if (cmd->output_imm)
		cmd->output_param = output_param;

done:
	mutex_unlock(&dev->cmdif_mutex);
	up(&dev->poll_sem);
	return ret;
}

static struct crdma_eqe *crdma_next_eqe(struct crdma_eq *eq);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
static void crdma_eq_poll(struct tasklet_struct *t);
#else
static void crdma_eq_poll(unsigned long arg);
#endif

#ifdef CRDMA_EVENT_CMDS
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
	cmd_state = &dev->cmd_q[dev->cmd_q_free];
	cmd_state->token += dev->max_cmds_out;
	dev->cmd_q_free = cmd_state->next;
	init_completion(&cmd_state->comp);
	spin_unlock(&dev->cmd_q_lock);

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

	cmd->status = cmd_state->status;

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
#endif

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

	if (cmd_state->token != token) {
		crdma_warn("Command completed with stale token\n");
		return;
	}

	cmd_state->output_param = ((u64) param_h) << 32 | param_l;
	cmd_state->status = status;
	cmd_state->token = token;

	/* Wake up command initiator */
	complete(&cmd_state->comp);
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

	/*
	 * Verify device is on-line then issue command based
	 * on current command mode.
	 */
	if (pci_channel_offline(dev->nfp_info->pdev))
		return -EIO;

#ifdef CRDMA_EVENT_CMDS
	if (dev->use_event_cmds)
		err = crdma_waited_cmd(dev, cmd);
	else
#endif
		err = crdma_polled_cmd(dev, cmd);

	if (!err && cmd->status)
		crdma_dev_warn(dev, "\n==== UCODE cmd %s failed, status: %s\n",
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
int crdma_init_mailbox(struct crdma_ibdev *dev,
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
void crdma_cleanup_mailbox(struct crdma_ibdev *dev,
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

		switch (eqe->type) {
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
			crdma_warn("Async QP %d event %d not handled\n",
				qpn, eqe->type);
			return;
		}

		/* Dispatch */
		cqp->ib_qp.event_handler(&event, cqp->ib_qp.qp_context);
	}
	if (atomic_dec_and_test(&cqp->ref_cnt))
		complete(&cqp->free);
}

/**
 * Event queue MSI/MSI-X interrupt handler.
 *
 * irq: Interrupt vector.
 * eq_ptr: The EQ associated with the interrupt vector.
 *
 * Returns IRQ_HANDLED.
 */
irqreturn_t crdma_eq_irq_handler(int irq, void *eq_ptr)
{
        struct crdma_eq *eq = eq_ptr;

        tasklet_schedule(&eq->tasklet);

        return IRQ_HANDLED;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
static void crdma_eq_poll(struct tasklet_struct *t)
#else
static void crdma_eq_poll(unsigned long arg)
#endif
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
	struct crdma_eq *eq = from_tasklet(eq, t, tasklet);
#else
	struct crdma_eq *eq = (void *)arg;
#endif
	struct crdma_ibdev *dev = eq->dev;
	struct crdma_cq *ccq;
	struct crdma_eqe *eqe;
	struct ib_event event;
	uint32_t cqn;
	int eqe_cnt = 0;

	/* Get the next available EQE and process */
	while ((eqe  = crdma_next_eqe(eq))) {


		switch (eqe->type) {
		case CRDMA_EQ_CQ_COMPLETION_NOTIFY:
			cqn = le32_to_cpu(eqe->affiliated.obj_num);
			if (cqn >= dev->cap.ib.max_cq) {
				crdma_dev_warn(dev, "Bad CQN %d\n", cqn);
				break;
			}
			ccq = dev->cq_table[cqn];

			ccq->arm_seqn++;
			atomic_inc(&ccq->ref_cnt);

			/*
			 * Call back into the Verbs core to dispatch
			 * the completion notification.
			 */
			if (ccq->ib_cq.comp_handler) {
				ccq->ib_cq.comp_handler(&ccq->ib_cq,
					ccq->ib_cq.cq_context);
			}

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
			crdma_dev_info(dev, "event %s not implemented\n",
				       crdma_event_to_str(eqe->type));
			break;

		case CRDMA_EQ_MGMT_PORT_CHANGE:
		default:
			crdma_dev_info(dev, "event %s not implemented\n",
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

	mem_size = dev->cap.eqe_size  * (1 << entries_log2);

	/* Coherent memory for sharing with microcode */
	eq->mem = crdma_alloc_dma_mem(dev, true,
			CRDMA_MEM_DEFAULT_ORDER, mem_size);
	if (IS_ERR(eq->mem)) {
		crdma_dev_err(dev, "Unable to allocate EQ memory\n");
		return -ENOMEM;
	}

	ret = crdma_mtt_write_sg(dev, eq->mem->alloc, eq->mem->num_sg,
			eq->mem->base_mtt_ndx, eq->mem->num_mtt,
			eq->mem->min_order + PAGE_SHIFT,
			eq->mem->num_sg, 0);
	if (ret)
		goto free_mem;

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

	/* CREAE EQ and MAP requested events */
	ret = crdma_eq_create_cmd(dev, eq);
	if (ret) {
		crdma_warn("crdma_mtt_write_sg returned %d\n", ret);
		goto free_mem;
	}

	ret = crdma_eq_map_cmd(dev, eq->eq_num, eq->event_map);
	if (ret) {
		crdma_warn("crdma_eq_map_cmd failed, returned %d\n", ret);
		goto destroy_eq;
	}

	if (dev->have_interrupts) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
		tasklet_setup(&eq->tasklet, crdma_eq_poll);
#else
		tasklet_init(&eq->tasklet, crdma_eq_poll, (unsigned long)eq);
#endif
		ret = request_irq(eq->vector, crdma_eq_irq_handler, 0,
				  eq->irq_name, eq);
		if (ret) {
			crdma_err("request_irq error %d\n", ret);
			goto destroy_eq;
		}
	}

	/* Set EQ initial consumer index and ARM EQ */
	crdma_set_eq_ci(dev, eq->eq_num, 0,
			dev->have_interrupts ? true : false);

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
		tasklet_kill(&eq->tasklet);
		free_irq(eq->vector, eq);
	}

	if (crdma_eq_destroy_cmd(dev, eq))
		crdma_warn("Destroy of ucode EQ %d failed\n", eq->eq_num);

	crdma_free_dma_mem(dev, eq->mem);
	eq->mem = NULL;
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

free_mbox:
	crdma_cleanup_mailbox(dev, &out_mbox);
	return status;
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

free_mbox:
	crdma_cleanup_mailbox(dev, &out_mbox);
	return status;
}

int crdma_query_nic(struct crdma_ibdev *dev, uint32_t *boardid)
{
	struct crdma_cmd_mbox out_mbox;
	struct crdma_cmd cmd;
	int status;
	uint32_t val;

	memset(&cmd, 0, sizeof(cmd));
	if (crdma_init_mailbox(dev, &out_mbox))
		return -1;

	cmd.opcode = CRDMA_CMD_QUERY_NIC;
	cmd.timeout = CRDMA_CMDIF_GEN_TIMEOUT_MS;
	cmd.output_param = out_mbox.dma_addr;

	status = crdma_cmd(dev, &cmd);
	if (status == CRDMA_STS_OK) {
		memcpy(&val, out_mbox.buf, sizeof(val));
		*boardid = le32_to_cpu(val);
	}

	crdma_cleanup_mailbox(dev, &out_mbox);
	return status;
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
		crdma_warn("Microcode unsupported opcode, ignoring\n");
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
	if (status == CRDMA_STS_UNSUPPORTED_OPCODE)
		status = CRDMA_STS_OK;

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
int __crdma_mtt_write(struct crdma_ibdev *dev, u32 base_mtt,
		u32 num_mtt, struct crdma_cmd_mbox *in_mbox)
{
	struct crdma_mtt_write_param *mtt_param = in_mbox->buf;
	struct crdma_cmd cmd;
	int status;

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode = CRDMA_CMD_MTT_WRITE;
	cmd.timeout = CRDMA_CMDIF_GEN_TIMEOUT_MS;
	cmd.input_mod = num_mtt;
	cmd.input_param = in_mbox->dma_addr;

	mtt_param->rsvd = 0;
	mtt_param->base_mtt_ndx = cpu_to_le32(base_mtt);

	status = crdma_cmd(dev, &cmd);

	/* While command not supported provide hard-code response */
	if (status == CRDMA_STS_UNSUPPORTED_OPCODE)
		status = CRDMA_STS_OK;

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

		while (length && mtt_cnt < num_mtt) {
			if (!(base_addr & comp_mask)) {
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
					if (status)
						return status;

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

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode = CRDMA_CMD_EQ_CREATE;
	cmd.timeout = CRDMA_CMDIF_GEN_TIMEOUT_MS;
	cmd.input_param = in_mbox.dma_addr;
	cmd.input_mod = eq->eq_num;
	status = crdma_cmd(dev, &cmd);

	/* While command not supported provide hard-code response */
	if (status == CRDMA_STS_UNSUPPORTED_OPCODE)
		status = CRDMA_STS_OK;

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
	struct crdma_eq_map_params *param;
	struct crdma_cmd cmd;
	struct crdma_cmd_mbox in_mbox;
	int status;

	if (crdma_init_mailbox(dev, &in_mbox))
		return -1;

	param		= in_mbox.buf;
	param->event    = cpu_to_le32(events & CRDMA_EQ_EVENT_MASK);

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode	= CRDMA_CMD_EQ_MAP;
	cmd.input_mod	= eqn;
	cmd.timeout	= CRDMA_CMDIF_GEN_TIMEOUT_MS;
	cmd.input_param = in_mbox.dma_addr;
	status = crdma_cmd(dev, &cmd);

	/* While command not supported provide hard-code response */
	if (status == CRDMA_STS_UNSUPPORTED_OPCODE)
		status = CRDMA_STS_OK;

	crdma_cleanup_mailbox(dev, &in_mbox);
	return status;
}

int crdma_init_event_cmdif(struct crdma_ibdev *dev)
{
	int i;


	if (!dev->have_interrupts)
		return 0;

	/*
	 * Use the largest power of 2 <= the microcode supported
	 * outstanding command limit to control the number of
	 * outstanding event driven commands we allow.
	 */
	dev->max_cmds_log2 = 0;
	while ((1 << (dev->max_cmds_log2 + 1)) <= dev->cap.max_cmds_out)
		dev->max_cmds_log2++;
	dev->max_cmds_out = 1 << dev->max_cmds_log2;

	/*
	 * Allocate and initialize command queue used to maintain
	 * state for microcode commands in progress.
	 */
	dev->cmd_q = kcalloc(dev->max_cmds_out,
				sizeof(struct crdma_event_cmd), GFP_KERNEL);
	if (!dev->cmd_q)
		return -ENOMEM;

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

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode = CRDMA_CMD_CQ_CREATE;
	cmd.timeout = CRDMA_CMDIF_GEN_TIMEOUT_MS;
	cmd.input_param = in_mbox.dma_addr;
	cmd.input_mod = cq->cqn;
	status = crdma_cmd(dev, &cmd);

	/* While command not supported provide hard-coded response */
	if (status == CRDMA_STS_UNSUPPORTED_OPCODE)
		status = CRDMA_STS_OK;

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

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode = CRDMA_CMD_CQ_RESIZE;
	cmd.timeout = CRDMA_CMDIF_GEN_TIMEOUT_MS;
	cmd.input_param = in_mbox.dma_addr;
	cmd.input_mod = cq->cqn;
	status = crdma_cmd(dev, &cmd);

	/* While command not supported provide hard-coded response */
	if (status == CRDMA_STS_UNSUPPORTED_OPCODE)
		status = CRDMA_STS_OK;

	crdma_cleanup_mailbox(dev, &in_mbox);
	return status;
}

int crdma_cq_destroy_cmd(struct crdma_ibdev *dev, struct crdma_cq *cq)
{
	return __crdma_no_param_cmd(dev, CRDMA_CMD_CQ_DESTROY, 0,
			cq->cqn, CRDMA_CMDIF_GEN_TIMEOUT_MS);
}

int crdma_srq_create_cmd(struct crdma_ibdev *dev, struct crdma_srq *csrq)
{
	struct crdma_srq_params *param;
	struct crdma_cmd_mbox in_mbox;
	struct crdma_cmd cmd;
	u32 page_info;
	int status;

	if (crdma_init_mailbox(dev, &in_mbox))
		return -1;

	param              = in_mbox.buf;
	param->srq_limit   = csrq->srq_limit;
	param->max_srq_wr  = csrq->wq.wqe_cnt;
	param->max_sge_num = csrq->wq.max_sg;

	page_info = (csrq->mem->min_order + PAGE_SHIFT) <<
		CRDMA_SRQ_CREATE_LOG2_PAGE_SZ_SHIFT;
	page_info = (ilog2(csrq->wq.wqe_size) &
		     CRDMA_SRQ_CREATE_LOG2_SWQE_MASK) <<
		     CRDMA_SRQ_CREATE_LOG2_SWQE_SHIFT;

	/* Set PHYS flag if single block and device supports it */
	if (csrq->mem->num_mtt == 1 &&
			(dev->cap.opt_flags & CRDMA_DEV_CAP_FLAG_PHYS))
		page_info |= 1 << CRDMA_SRQ_CREATE_PHYS_BIT_SHIFT;

	param->page_info = cpu_to_le32(page_info);
	param->mtt_index = cpu_to_le32(csrq->mem->base_mtt_ndx);

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode = CRDMA_CMD_SRQ_CREATE;
	cmd.timeout = CRDMA_CMDIF_GEN_TIMEOUT_MS;
	cmd.input_param = in_mbox.dma_addr;
	cmd.input_mod = csrq->srq_index;
	status = crdma_cmd(dev, &cmd);

	crdma_cleanup_mailbox(dev, &in_mbox);
	return status;
}

int crdma_srq_destroy_cmd(struct crdma_ibdev *dev, struct crdma_srq *csrq)
{
	struct crdma_srq_params *param;
	struct crdma_cmd_mbox in_mbox;
	struct crdma_cmd cmd;
	int status;

	if (crdma_init_mailbox(dev, &in_mbox))
		return -1;

	param   = in_mbox.buf;

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode = CRDMA_CMD_SRQ_DESTROY;
	cmd.timeout = CRDMA_CMDIF_GEN_TIMEOUT_MS;
	cmd.input_param = in_mbox.dma_addr;
	cmd.input_mod = csrq->srq_index;
	status = crdma_cmd(dev, &cmd);

	crdma_cleanup_mailbox(dev, &in_mbox);
	return status;
}

int crdma_srq_set_arm_limit_cmd(struct crdma_ibdev *dev, struct crdma_srq *csrq)
{
	struct crdma_srq_params *param;
	struct crdma_cmd_mbox in_mbox;
	struct crdma_cmd cmd;
	int status;

	if (crdma_init_mailbox(dev, &in_mbox))
		return -1;

	param = in_mbox.buf;
	param->srq_limit = csrq->srq_limit;

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode = CRDMA_CMD_SRQ_SET_ARM_LIMIT;
	cmd.timeout = CRDMA_CMDIF_GEN_TIMEOUT_MS;
	cmd.input_param = in_mbox.dma_addr;
	cmd.input_mod = csrq->srq_index;
	status = crdma_cmd(dev, &cmd);

	crdma_cleanup_mailbox(dev, &in_mbox);
	return status;
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
	if (qp->sq_sig_all)
		word |= 1 << CRDMA_QP_CTRL_SIGALL_BIT_SHIFT;
	if (qp->srqn)
		word |= 1 << CRDMA_QP_CTRL_SRQ_BIT_SHIFT;

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
		crdma_set_av(qp->ib_qp.pd, &attr->av, &ib_attr->ah_attr);
		crdma_set_loopback_mode(dev, qp, &ib_attr->ah_attr);
		if (qp->lb_mode)
			attr->lb_mode = 1;
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
		attr->rdma_init_depth = ib_attr->max_rd_atomic;

	if (ib_attr_mask & IB_QP_ALT_PATH)
		;

	if (ib_attr_mask & IB_QP_MIN_RNR_TIMER)
		attr->min_rnr_timer = ib_attr->min_rnr_timer;

	if (ib_attr_mask & IB_QP_SQ_PSN)
		attr->sq_psn = cpu_to_le32(ib_attr->sq_psn);

	if (ib_attr_mask & IB_QP_MAX_DEST_RD_ATOMIC)
		attr->rdma_rsp_res = ib_attr->max_dest_rd_atomic;

	if (ib_attr_mask & IB_QP_PATH_MIG_STATE)
		;

	if (ib_attr_mask & IB_QP_CAP)
		;

	if (ib_attr_mask & IB_QP_DEST_QPN)
		attr->dest_qpn = cpu_to_le32(ib_attr->dest_qp_num &
					CRDMA_QP_ATTR_QPN_MASK);

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
		crdma_warn("Illegal state transition\n");
		return -EINVAL;
	}
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
		crdma_warn("Illegal QP attribute detected\n");
		status = -EINVAL;
		goto out;
	}

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode = CRDMA_CMD_QP_MODIFY;
	cmd.opcode_mod = modifier;
	cmd.timeout = CRDMA_CMDIF_GEN_TIMEOUT_MS;
	cmd.input_param = in_mbox.dma_addr;
	cmd.input_mod = qp->qp_index;
	status = crdma_cmd(dev, &cmd);

	/* While command not supported provide hard-coded response */
	if (status == CRDMA_STS_UNSUPPORTED_OPCODE)
		status = CRDMA_STS_OK;

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
	qp_attr->qp_access_flags =
		param->mtu_access & CRDMA_QP_ATTR_ACCESS_MASK;
	qp_attr->path_mtu = (param->mtu_access >> CRDMA_QP_ATTR_MTU_SHIFT) - 7;

	if (qp_attr_mask & IB_QP_AV) {
		qp_attr->ah_attr.roce.dmac[3] = param->av.d_mac[0];
		qp_attr->ah_attr.roce.dmac[2] = param->av.d_mac[1];
		qp_attr->ah_attr.roce.dmac[1] = param->av.d_mac[2];
		qp_attr->ah_attr.roce.dmac[0] = param->av.d_mac[3];
		qp_attr->ah_attr.roce.dmac[5] = param->av.d_mac[4];
		qp_attr->ah_attr.roce.dmac[4] = param->av.d_mac[5];

		//qp_attr->ah_attr.vlan_id = le16_to_cpu(param->av.vlan);
		rdma_ah_set_port_num(&qp_attr->ah_attr, param->av.port + 1);
		/* TODO: Can't return GID Type yet */
		/* TODO: We don't return SMAC yet */

		rdma_ah_set_sl(&qp_attr->ah_attr, param->av.service_level);
		rdma_ah_set_grh(&qp_attr->ah_attr, NULL,
				__swab32(param->av.flow_label),
				param->av.s_gid_ndx, param->av.hop_limit,
				param->av.traffic_class);

		dgid = &qp_attr->ah_attr.grh.dgid;
		((u32 *)dgid->raw)[0] = __swab32(param->av.d_gid_word[0]);
		((u32 *)dgid->raw)[1] = __swab32(param->av.d_gid_word[1]);
		((u32 *)dgid->raw)[2] = __swab32(param->av.d_gid_word[2]);
		((u32 *)dgid->raw)[3] = __swab32(param->av.d_gid_word[3]);

		/* XXX: We only allow full rate for now */
		rdma_ah_set_static_rate(&qp_attr->ah_attr, 0);
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
	cmd.input_mod = qp->qp_index;
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

int crdma_dcqcn_enable_cmd(struct crdma_ibdev *dev, u8 enbaled)
{
	return __crdma_no_param_cmd(dev, CRDMA_CMD_DCQCN_ENABLE, 0,
			enbaled, CRDMA_CMDIF_GEN_TIMEOUT_MS);
}

int crdma_retrans_enable_cmd(struct crdma_ibdev *dev, u8 enbaled)
{
	return __crdma_no_param_cmd(dev, CRDMA_CMD_RETRANS_ENABLE, 0,
			enbaled, CRDMA_CMDIF_GEN_TIMEOUT_MS);
}

int crdma_high_perf_read_enable_cmd(struct crdma_ibdev *dev, u8 enbaled)
{
	return __crdma_no_param_cmd(dev, CRDMA_CMD_HIGH_PERF_READ_ENABLE, 0,
			(enbaled ? MAX_BIDIRECTIONAL_SEGMENT : MAX_DEFAULT_BIDIRECTIONAL_SEGMENT),
			CRDMA_CMDIF_GEN_TIMEOUT_MS);
}

int crdma_set_port_mtu_cmd(struct crdma_ibdev *dev, u8 port, u32 mtu)
{
	struct crdma_cmd cmd;
	int status;

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode = CRDMA_CMD_SET_PORT_MTU;
	cmd.timeout = CRDMA_CMDIF_GEN_TIMEOUT_MS;
	cmd.input_mod = port;
	cmd.input_param = mtu;
	status = crdma_cmd(dev, &cmd);

	return status;
}

/**
 * Config roce bond.
 *
 * @dev: The IB RoCE device for roce bond function.
 * @mod: Action for the roce bond configure.
 * @tx_bm: Physical ports used for roce bond's traffic, represented by bitmap.
 *
 * Returns 0 on success; otherwise an error.
 */
int crdma_bond_config_cmd(struct crdma_ibdev *dev, u8 mod, u64 tx_bm)
{
	struct crdma_cmd cmd;
	int status;

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode = CRDMA_CMD_BOND_CONFIG;
	cmd.opcode_mod = mod;
	cmd.timeout = CRDMA_CMDIF_GEN_TIMEOUT_MS;
	cmd.input_param = tx_bm;
	status = crdma_cmd(dev, &cmd);

	return status;
}

/**
 * Issue microcode MPT create command.
 *
 * @dev: The IB RoCE device.
 * @mr: The memory region associated with the MPT.
 *
 * Returns 0 on success, otherwise an error.
 */
int crdma_mpt_create_cmd(struct crdma_ibdev *dev, struct crdma_mr *cmr)
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
			(cmr->umem ? 0 : ((cmr->type == CRDMA_MR_TYPE_FRMR) ?
				0 : CRDMA_MPT_DMA));

	/* Set PHYS flag if only a single MTT entry and it is supported */
	if (cmr->num_mtt == 1 && (dev->cap.opt_flags &
			CRDMA_DEV_CAP_FLAG_PHYS))
		flags_pdn |= CRDMA_MPT_PHYS;
	/* CRDMA_MPT_INVALIDATE_ENABLE needed by microcode. */
	if (cmr->type == CRDMA_MR_TYPE_FRMR) {
		flags_pdn |= CRDMA_MPT_FRMR_ENABLE;
		flags_pdn |= CRDMA_MPT_INVALIDATE_ENABLE;
		param->frmr_entries = cpu_to_le32(cmr->num_mtt);
	} else {
		param->frmr_entries = 0;
	}
	param->flags_pd	= cpu_to_le32(flags_pdn);

	param->io_addr_h = cpu_to_le32(cmr->io_vaddr >> 32);
	param->io_addr_l = cpu_to_le32(cmr->io_vaddr & 0x0FFFFFFFF);
	param->length	 = cpu_to_le32(cmr->len);
	param->mtt_index = cpu_to_le32(cmr->base_mtt);

	page_info = (cmr->mpt_order + cmr->page_shift) <<
				CRDMA_MPT_LOG2_PAGE_SZ_SHIFT;
	param->page_info = cpu_to_le32(page_info);
	param->mtt_index = cpu_to_le32(cmr->base_mtt);
	param->reserved  = 0;

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

	if (umem) {
		cmr->num_mtt = comp_pages;
		cmr->base_mtt = crdma_alloc_bitmap_area(&dev->mtt_map,
						cmr->num_mtt);
		if (cmr->base_mtt < 0)
			return -ENOMEM;

#if (VER_NON_RHEL_GE(5, 15) || RHEL_RELEASE_GE(8, 365, 0, 0))
		ret = crdma_mtt_write_sg(dev, umem->sgt_append.sgt.sgl,
					 umem->sgt_append.sgt.nents,
					 cmr->base_mtt, cmr->num_mtt,
					 PAGE_SHIFT, comp_pages, comp_order);
#elif (VER_NON_RHEL_OR_KYL_GE(5, 3) || VER_RHEL_GE(8, 0) || VER_KYL_GE(10, 3))
		ret = crdma_mtt_write_sg(dev, umem->sg_head.sgl, umem->nmap,
					 cmr->base_mtt, cmr->num_mtt,
					 PAGE_SHIFT, comp_pages, comp_order);
#else
		ret = crdma_mtt_write_sg(dev, umem->sg_head.sgl, umem->nmap,
					 cmr->base_mtt, cmr->num_mtt,
					 umem->page_shift, comp_pages,
					 comp_order);
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
	if (ret)
		goto free_mtt;

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
			cmr->key, CRDMA_CMDIF_GEN_TIMEOUT_MS);
	crdma_free_bitmap_area(&dev->mtt_map, cmr->base_mtt, cmr->num_mtt);
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
	if (status == CRDMA_STS_OK)
		memcpy(param, out_mbox.buf, sizeof(*param));

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
		memcpy(param->gid, entry->gid.raw, 16);
		param->gid_word[0] = __swab32(param->gid_word[0]);
		param->gid_word[1] = __swab32(param->gid_word[1]);
		param->gid_word[2] = __swab32(param->gid_word[2]);
		param->gid_word[3] = __swab32(param->gid_word[3]);
	}
	spin_unlock_irqrestore(&dev->port.table_lock, flags);

	port_gid_cnt = (port_num << CRDMA_SGID_PARAM_PORT_NUM_SHIFT) |
			((num_entries & CRDMA_SGID_PARAM_COUNT_MASK) <<
			 CRDMA_SGID_PARAM_COUNT_SHIFT);

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

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode = CRDMA_CMD_GET_PORT_GID_TABLE;
	cmd.timeout = CRDMA_CMDIF_GEN_TIMEOUT_MS;
	cmd.output_param = out_mbox.dma_addr;
	cmd.input_mod = port_gid_cnt;
	status = crdma_cmd(dev, &cmd);
	if (status != CRDMA_STS_OK)
		goto free_mbox;

	param = out_mbox.buf;
	entry = entries;
	for (i = 0; i < num_entries; i++, entry++, param++) {
		entry->type = param->gid_type;
		if (param->valid)
			entry->valid = 1;

		((u32 *)entry->gid.raw)[0] = __swab32(param->gid_word[0]);
		((u32 *)entry->gid.raw)[1] = __swab32(param->gid_word[1]);
		((u32 *)entry->gid.raw)[2] = __swab32(param->gid_word[2]);
		((u32 *)entry->gid.raw)[3] = __swab32(param->gid_word[3]);
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
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
		crdma_eq_poll(&dev->eq_table.eq[eqn].tasklet);
#else
		crdma_eq_poll((unsigned long)&dev->eq_table.eq[eqn]);
#endif

	return status;
}

int crdma_init_cmdif(struct crdma_ibdev *dev)
{
	mutex_init(&dev->cmdif_mutex);
	sema_init(&dev->poll_sem, 1);

	// synchronize toggle value from firmware
	dev->toggle = crdma_read_toggle(dev);
	dev->token = 1;
	dev->use_event_cmds = false;
	dev->max_cmds_out = CRDMA_CMDIF_DRIVER_MAX_CMDS;

	dev->mbox_pool = dma_pool_create("crdma_cmd", &dev->nfp_info->pdev->dev,
			CRDMA_CMDIF_MBOX_SIZE, CRDMA_CMDIF_MBOX_SIZE, 0);
	if (!dev->mbox_pool)
		return -ENOMEM;

	return 0;
}

void crdma_cleanup_cmdif(struct crdma_ibdev *dev)
{
	dma_pool_destroy(dev->mbox_pool);
}
