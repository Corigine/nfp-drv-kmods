// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright (C) 2023 Corigine, Inc. */

#include "nfpcore/kcompat.h"

#include "crdma_ib.h"
#include "crdma_counters.h"
#include "crdma_ucif.h"

#if (VER_RHEL_GE(8, 7) && !(VER_RHEL_EQ(9, 0)))
static const struct rdma_stat_desc crdma_counter_name[] = {
	[CRDMA_CNT_RDMA_SEND].name         =  "rdma_sends",
	[CRDMA_CNT_RDMA_RECV].name         =  "rdma_recvs",
	[CRDMA_CNT_RDMA_WRITE].name        =  "rdma_writes",
	[CRDMA_CNT_RDMA_READ].name         =  "rdma_reads",
	[CRDMA_CNT_RDMA_ATOM].name         =  "rdma_atomics",

	[CRDMA_CNT_TX_PKTS].name           =  "tx_pkts",
	[CRDMA_CNT_TX_BYTES].name          =  "tx_bytes",
	[CRDMA_CNT_RX_PKTS].name           =  "rx_pkts",
	[CRDMA_CNT_RX_BYTES].name          =  "rx_bytes",

	[CRDMA_CNT_TX_SEND_PKTS].name      =  "tx_send_pkts",
	[CRDMA_CNT_TX_WRITE_PKTS].name     =  "tx_write_pkts",
	[CRDMA_CNT_TX_READ_REQ_PKTS].name  =  "tx_read_request_pkts",
	[CRDMA_CNT_TX_READ_RSP_PKTS].name  =  "tx_read_respond_pkts",
	[CRDMA_CNT_TX_ATOM_PKTS].name      =  "tx_atomic_pkts",
	[CRDMA_CNT_TX_ACK_PKTS].name       =  "tx_ack_pkts",
	[CRDMA_CNT_TX_NAK_PKTS].name       =  "tx_nak_pkts",
	[CRDMA_CNT_RX_SEND_PKTS].name      =  "rx_send_pkts",
	[CRDMA_CNT_RX_WRITE_PKTS].name     =  "rx_write_pkts",
	[CRDMA_CNT_RX_READ_REQ_PKTS].name  =  "rx_read_request_pkts",
	[CRDMA_CNT_RX_READ_RSP_PKTS].name  =  "rx_read_respond_pkts",
	[CRDMA_CNT_RX_ATOM_PKTS].name      =  "rx_atomic_pkts",
	[CRDMA_CNT_RX_ACK_PKTS].name       =  "rx_ack_pkts",
	[CRDMA_CNT_RX_NAK_PKTS].name       =  "rx_nak_pkts",

	[CRDMA_CNT_CNP_TX_PKTS].name       =  "cnp_tx_pkts",
	[CRDMA_CNT_CNP_RX_PKTS].name       =  "cnp_rx_pkts",
	[CRDMA_CNT_ECN_MARKED_PKTS].name   =  "ecn_marked_pkts",

	[CRDMA_CNT_DUP_REQ].name           =  "duplicate_psn_pkts",
	[CRDMA_CNT_OUT_OF_SEQ_REQ].name    =  "out_of_order_psn_pkts",
	[CRDMA_CNT_PKT_ERR].name           =  "error_pkts",
};
#else
static const char * const crdma_counter_name[] = {
	[CRDMA_CNT_RDMA_SEND]         =  "rdma_sends",
	[CRDMA_CNT_RDMA_RECV]         =  "rdma_recvs",
	[CRDMA_CNT_RDMA_WRITE]        =  "rdma_writes",
	[CRDMA_CNT_RDMA_READ]         =  "rdma_reads",
	[CRDMA_CNT_RDMA_ATOM]         =  "rdma_atomics",

	[CRDMA_CNT_TX_PKTS]           =  "tx_pkts",
	[CRDMA_CNT_TX_BYTES]          =  "tx_bytes",
	[CRDMA_CNT_RX_PKTS]           =  "rx_pkts",
	[CRDMA_CNT_RX_BYTES]          =  "rx_bytes",

	[CRDMA_CNT_TX_SEND_PKTS]      =  "tx_send_pkts",
	[CRDMA_CNT_TX_WRITE_PKTS]     =  "tx_write_pkts",
	[CRDMA_CNT_TX_READ_REQ_PKTS]  =  "tx_read_request_pkts",
	[CRDMA_CNT_TX_READ_RSP_PKTS]  =  "tx_read_respond_pkts",
	[CRDMA_CNT_TX_ATOM_PKTS]      =  "tx_atomic_pkts",
	[CRDMA_CNT_TX_ACK_PKTS]       =  "tx_ack_pkts",
	[CRDMA_CNT_TX_NAK_PKTS]       =  "tx_nak_pkts",
	[CRDMA_CNT_RX_SEND_PKTS]      =  "rx_send_pkts",
	[CRDMA_CNT_RX_WRITE_PKTS]     =  "rx_write_pkts",
	[CRDMA_CNT_RX_READ_REQ_PKTS]  =  "rx_read_request_pkts",
	[CRDMA_CNT_RX_READ_RSP_PKTS]  =  "rx_read_respond_pkts",
	[CRDMA_CNT_RX_ATOM_PKTS]      =  "rx_atomic_pkts",
	[CRDMA_CNT_RX_ACK_PKTS]       =  "rx_ack_pkts",
	[CRDMA_CNT_RX_NAK_PKTS]       =  "rx_nak_pkts",

	[CRDMA_CNT_CNP_TX_PKTS]       =  "cnp_tx_pkts",
	[CRDMA_CNT_CNP_RX_PKTS]       =  "cnp_rx_pkts",
	[CRDMA_CNT_ECN_MARKED_PKTS]   =  "ecn_marked_pkts",

	[CRDMA_CNT_DUP_REQ]           =  "duplicate_psn_pkts",
	[CRDMA_CNT_OUT_OF_SEQ_REQ]    =  "out_of_order_psn_pkts",
	[CRDMA_CNT_PKT_ERR]           =  "error_pkts",
};
#endif

#if (VER_NON_RHEL_OR_KYL_GE(5, 3) || VER_RHEL_GE(8, 2) || VER_KYL_GE(10, 3))
#if (VER_NON_RHEL_OR_KYL_GE(5, 13) || VER_RHEL_GE(8, 6))
static void crdma_qp_counters_hwstat_sum(struct ib_device *ibdev,
			  u32 port, u64 *sum_stats)
#else
static void crdma_qp_counters_hwstat_sum(struct ib_device *ibdev,
			  u8 port, u64 *sum_stats)
#endif
{
	struct crdma_ibdev *dev = to_crdma_ibdev(ibdev);
	unsigned int start_offset;
	unsigned long xa_id = 0;
	unsigned int cnt;
	uint32_t *val;

	if (!dev->qp_cnts)
		return;

	xa_lock(&dev->cntr_xa);
	xa_for_each(&dev->cntr_xa, xa_id, val) {
		start_offset = (xa_id - 1) * ROCE_STATISTICS_CNT_NUM *
				ROCE_STATISTICS_PER_CNT_SZ;
		for (cnt = 0; cnt < ARRAY_SIZE(crdma_counter_name); cnt++)
			sum_stats[cnt] += readq(dev->qp_cnts + start_offset +
					(ROCE_STATISTICS_PER_CNT_SZ * cnt));
	}
	xa_unlock(&dev->cntr_xa);
}
#endif

#if (VER_NON_RHEL_OR_KYL_GE(5, 13) || VER_RHEL_GE(8, 6))
int crdma_ib_get_hw_stats(struct ib_device *ibdev,
			struct rdma_hw_stats *stats,
			u32 port, int index)
#else
int crdma_ib_get_hw_stats(struct ib_device *ibdev,
			struct rdma_hw_stats *stats,
			u8 port, int index)
#endif
{
	struct crdma_ibdev *dev = to_crdma_ibdev(ibdev);
#if (VER_NON_RHEL_OR_KYL_GE(5, 3) || VER_RHEL_GE(8, 2) || VER_KYL_GE(10, 3))
	u64 cntr_sum[CRDMA_NUM_OF_COUNTERS] = {0};
#endif
	unsigned int cnt;

	if (!port || !stats)
		return -EINVAL;

	if (!dev->port_cnts)
		return -EOPNOTSUPP;

#if (VER_NON_RHEL_OR_KYL_GE(5, 3) || VER_RHEL_GE(8, 2) || VER_KYL_GE(10, 3))
	crdma_qp_counters_hwstat_sum(ibdev, port, cntr_sum);
#endif

	for (cnt = 0; cnt < ARRAY_SIZE(crdma_counter_name); cnt++) {
		stats->value[cnt] = readq(dev->port_cnts +
				(ROCE_STATISTICS_PER_CNT_SZ * cnt));

#if (VER_NON_RHEL_OR_KYL_GE(5, 3) || VER_RHEL_GE(8, 2) || VER_KYL_GE(10, 3))
		/* We can count for QP and Port meantime. As the infiniband
		 * kernel driver will add those qp counters' result, so we need
		 * to minus these part first.
		 */
		stats->value[cnt] -= cntr_sum[cnt];
#endif
	}

	return ARRAY_SIZE(crdma_counter_name);
}

#if (VER_NON_RHEL_OR_KYL_GE(5, 14) || VER_RHEL_GE(8, 6))
struct rdma_hw_stats *crdma_ib_alloc_hw_port_stats(struct ib_device *ibdev,
					    u32 port_num)
#elif VER_NON_RHEL_OR_KYL_GE(5, 13)
struct rdma_hw_stats *crdma_ib_alloc_hw_stats(struct ib_device *ibdev,
					    u32 port_num)
#else
struct rdma_hw_stats *crdma_ib_alloc_hw_stats(struct ib_device *ibdev,
					    u8 port_num)
#endif
{
	BUILD_BUG_ON(ARRAY_SIZE(crdma_counter_name) != CRDMA_NUM_OF_COUNTERS);
	/* We support only per port stats */
	if (!port_num)
		return NULL;

	return rdma_alloc_hw_stats_struct(crdma_counter_name,
					  ARRAY_SIZE(crdma_counter_name),
					  RDMA_HW_STATS_DEFAULT_LIFESPAN);
}

#if (VER_NON_RHEL_OR_KYL_GE(5, 3) || VER_RHEL_GE(8, 2) || VER_KYL_GE(10, 3))
static struct rdma_hw_stats *
crdma_ib_counter_alloc_qp_stats(struct rdma_counter *counter)
{
	return rdma_alloc_hw_stats_struct(crdma_counter_name,
					  ARRAY_SIZE(crdma_counter_name),
					  RDMA_HW_STATS_DEFAULT_LIFESPAN);
}

static void
crdma_ib_counter_history_stat_clr(struct rdma_counter *counter)
{
	struct ib_device *dev = counter->device;
	struct rdma_port_counter *port_counter;

	port_counter = &dev->port_data[counter->port].port_counter;
	if (!port_counter->hstats)
		return;

	memset(&port_counter->hstats->value[0], 0,
		counter->stats->num_counters * sizeof(u64));
}

static int crdma_ib_counter_dealloc(struct rdma_counter *counter)
{
	struct crdma_ibdev *dev = to_crdma_ibdev(counter->device);

	/* We can count for QP and Port meantime. Don't need to save
	 * previous binded qp counter result in the infiniband kernel
	 * driver history stat.
	 */
	crdma_ib_counter_history_stat_clr(counter);

	if (!counter->id)
		return 0;

	xa_erase(&dev->cntr_xa, counter->id);

	return 0;
}

static int crdma_ib_counter_bind_qp(struct rdma_counter *counter,
				   struct ib_qp *qp)
{
	int ret = 0;
	struct crdma_ibdev *dev = to_crdma_ibdev(counter->device);

	if (!counter->id) {
		ret = xa_alloc(&dev->cntr_xa, &counter->id, &counter->id,
				XA_LIMIT(1, CRDMA_IB_MAX_CNTR_NUM), GFP_KERNEL);
		if (ret)
			goto xa_alloc_err;
		qp->counter = counter;
		ret = crdma_counter_config_cmd(dev, CRDMA_CNTR_MOD_CREATE,
				qp->qp_num, counter->id);
		if (ret)
			goto cntr_create_fail;
		return 0;
	}

	qp->counter = counter;
	ret = crdma_counter_config_cmd(dev, CRDMA_CNTR_MOD_BIND, qp->qp_num,
			counter->id);
	if (ret)
		goto cntr_bind_fail;
	return 0;

cntr_create_fail:
	xa_erase(&dev->cntr_xa, counter->id);
	counter->id = 0;
cntr_bind_fail:
	qp->counter = NULL;
xa_alloc_err:
	return -EOPNOTSUPP;
}

static int crdma_ib_counter_unbind_qp(struct ib_qp *qp)
{
	struct crdma_ibdev *dev = to_crdma_ibdev(qp->device);

	if (qp->counter) {
		crdma_counter_config_cmd(dev, CRDMA_BOND_MOD_UNBIND, qp->qp_num,
				qp->counter->id);
		qp->counter = NULL;
	}

	return 0;
}

static int crdma_ib_counter_update_qp_stats(struct rdma_counter *counter)
{
	unsigned int cnt;
	unsigned int start_offset;
	struct rdma_hw_stats *stats = counter->stats;
	struct crdma_ibdev *dev = to_crdma_ibdev(counter->device);

	if (!dev->qp_cnts)
		return -EOPNOTSUPP;

	if (time_is_after_eq_jiffies(stats->timestamp + stats->lifespan))
		return 0;

	start_offset = (counter->id - 1) * ROCE_STATISTICS_CNT_NUM *
			ROCE_STATISTICS_PER_CNT_SZ;

	for (cnt = 0; cnt < ARRAY_SIZE(crdma_counter_name); cnt++)
		stats->value[cnt] = readq(dev->qp_cnts + start_offset +
					(ROCE_STATISTICS_PER_CNT_SZ * cnt));

	stats->timestamp = jiffies;

	return 0;
}
#endif

#if (VER_NON_RHEL_OR_KYL_GE(5, 0) || VER_RHEL_GE(8, 1) || VER_KYL_GE(10, 3))
static const struct ib_device_ops crdma_hw_stats_ops = {
#if (VER_NON_RHEL_OR_KYL_GE(5, 14) || VER_RHEL_GE(8, 6))
	.alloc_hw_port_stats = crdma_ib_alloc_hw_port_stats,
#else
	.alloc_hw_stats = crdma_ib_alloc_hw_stats,
#endif
	.get_hw_stats = crdma_ib_get_hw_stats,
#if (VER_NON_RHEL_OR_KYL_GE(5, 3) || VER_RHEL_GE(8, 2) || VER_KYL_GE(10, 3))
	.counter_bind_qp = crdma_ib_counter_bind_qp,
	.counter_unbind_qp = crdma_ib_counter_unbind_qp,
	.counter_dealloc = crdma_ib_counter_dealloc,
	.counter_alloc_stats = crdma_ib_counter_alloc_qp_stats,
	.counter_update_stats = crdma_ib_counter_update_qp_stats,
#endif
};
#endif

void crdma_ib_counters_init(struct ib_device *ibdev)
{
#if (VER_NON_RHEL_OR_KYL_GE(5, 0) || VER_RHEL_GE(8, 1) || VER_KYL_GE(10, 3))
	ib_set_device_ops(ibdev, &crdma_hw_stats_ops);
#else
	ibdev->alloc_hw_stats = crdma_ib_alloc_hw_stats;
	ibdev->get_hw_stats = crdma_ib_get_hw_stats;
#endif
}
