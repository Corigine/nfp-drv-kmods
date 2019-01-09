// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright (C) 2015-2018 Netronome Systems, Inc. */

/*
 * nfp_nbi.c
 * Authors: Anthony Egan <tony.egan@netronome.com>
 *          Jason McMullan <jason.mcmullan@netronome.com>
 */

#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/ethtool.h>
#include <linux/module.h>

#include "nfp.h"
#include "nfp_nffw.h"
#include "nfp_nbi.h"

#include "nfp6000/nfp_xpb.h"

/* 'i*.pause_poll_tx_flush_flags' symbol bit masks */
#define TX_FLUSH_FLAG_STOP	(0UL << 0)
#define TX_FLUSH_FLAG_RUN	BIT(0)
#define TX_FLUSH_FLAG_ACK	BIT(31)

#define ME_ISLAND_MIN		1	/* Minimum island # that can have MEs */
#define ME_ISLAND_MAX		62	/* Maximum island # that can have MEs */

struct nfp_nbi_priv {
	struct {
		u32 cpp_id;
		u64 cpp_addr;
	} stats;

	/* For the 'i*.pause_poll_tx_flush_flags' symbol */
	struct {
		bool has_sym;
		struct nfp_rtsym sym;
		unsigned int count;
	} tx_flush_flags;
};

struct nfp_nbi_dev {
	struct nfp_cpp *cpp;
	int nbi;
	struct nfp_nbi_priv *priv;
};

/*
 * Specification of the ports and channels to be monitored.  These are
 * initialized when the daemon is started and can be modified to
 * add ports and channels while the daemon is running. Ports/channels
 * cannot be removed from scan while the daemon is running.
 */
struct nfp_nbi_mac_stats_spec {
	/* One bit for each port to be monitored.  */
	u64 ports;
	/* One bit for each channel [0-63] to be monitored. */
	u64 chans63_0;
	/* One bit for each channel [64-127] to be monitored. */
	u64 chans127_64;
	/* Interlaken channels - one for each ilk core to be monitored. */
	u32 ilk[2];
};

/*
 * Structure used to maintain the state of the statistics daemon.
 *
 * The scan period of the statistics daemon is specified when the
 * daemon is started.  It may be changed while the daemon is running.
 *
 * When the daemon starts it zeroes all statistics registers and
 * cumulative memory counters and sets 'ready' true.
 *
 * Each period the daemon checks "active" to determine what
 * ports/channels must be scanned and then initiates an update of the
 * cumulative statistics for those ports/channels.  When the update is
 * complete the daemon will increment 'updated'.
 *
 * Each cycle the daemon also checks "clear" to see if any counters
 * should be cleared.  When the daemon clears a set of counters it increments
 * the 'clr_count' variable for that port/channel.
 *
 */
struct nfp_nbi_mac_stats_state {
	/* Scan period of the statistics daemon (mS) */
	u32 period;
	/* Flag indicating that the daemon is initialized */
	u32 ready;
	/* Counter incremented every cycle after the daemon completes a scan */
	u64 updated;
	/* Specification of the ports and channels to be monitored. */
	struct nfp_nbi_mac_stats_spec active;
	/* Specification of the port and channel counters to be cleared. */
	struct nfp_nbi_mac_stats_spec clear;
	/* Count of Ethernet port counter clears. */
	u64 portclr_count[24];
	/* Count of channel counter clears. */
	u64 chanclr_count[128];
	/* Count of Interlaken counter clears. */
	u64 ilkclr_count[2];
};

/*
 * Statistics structure for both MACs
 */
struct nfp_nbi_mac_stats {
	/* Port statistics */
	struct nfp_nbi_mac_portstats portstats[24];
	/* Channel statistics */
	struct nfp_nbi_mac_chanstats chanstats[128];
	/*Interlaken statistics */
	struct nfp_nbi_mac_ilkstats ilkstats[2];
	/* Daemon state */
	struct nfp_nbi_mac_stats_state state;
};

#define NFP_NBI_MAC_STATS_MAGIC 0xae6d730000000000ULL /* 0xae,'m','s', 0, .. */

struct nfp_nbi_mac_allstats {
	u64 magic;             /* NFP_NBI_MAC_STATS_MAGIC */
	struct nfp_nbi_mac_stats mac[2];
};

static void *nfp_nbi(struct nfp_cpp *cpp)
{
	struct nfp_rtsym_table *rtbl;
	const struct nfp_rtsym *sym;
	struct nfp_nbi_priv *priv;
	struct nfp_resource *res;
	int i;

	priv = nfp_nbi_cache(cpp);
	if (priv)
		return priv;

	priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return NULL;

	res = nfp_resource_acquire(cpp, NFP_RESOURCE_MAC_STATISTICS);
	if (IS_ERR(res)) {
		kfree(priv);
		return NULL;
	}

	priv->stats.cpp_id = nfp_resource_cpp_id(res);
	priv->stats.cpp_addr = nfp_resource_address(res);
	nfp_resource_release(res);

	rtbl = nfp_rtsym_table_read(cpp);

	for (i = ME_ISLAND_MIN; i <= ME_ISLAND_MAX; i++) {
		char tx_flags_name[32];

		snprintf(tx_flags_name, sizeof(tx_flags_name),
			 "i%hhu.pause_poll_tx_flush_flags", (u8)i);
		tx_flags_name[sizeof(tx_flags_name) - 1] = 0;

		sym = nfp_rtsym_lookup(rtbl, tx_flags_name);
		if (sym) {
			nfp_info(cpp, "NBI: Firmware TX pause control: %s\n",
				 tx_flags_name);
			priv->tx_flush_flags.has_sym = true;
			priv->tx_flush_flags.sym = *sym;
			break;
		}
	}
	kfree(rtbl);

	nfp_nbi_cache_set(cpp, priv);
	return priv;
}

/**
 * nfp_nbi_open() - Acquire NFP NBI device handle
 * @cpp:	NFP CPP handle
 * @nbi_id:	NFP NBI index to open (0..1)
 *
 * Return: struct nfp_nbi_dev *, or NULL
 */
struct nfp_nbi_dev *nfp_nbi_open(struct nfp_cpp *cpp, int nbi_id)
{
	struct nfp_nbi_priv *priv;
	struct nfp_nbi_dev *nbi;

	if (nbi_id < 0 || nbi_id >= 2)
		return NULL;

	priv = nfp_nbi(cpp);
	if (!priv)
		return NULL;

	nbi = kzalloc(sizeof(*nbi), GFP_KERNEL);
	if (!nbi)
		return NULL;

	nbi->cpp = cpp;
	nbi->nbi = nbi_id;
	nbi->priv = priv;

	return nbi;
}

/**
 * nfp_nbi_close() - Release NFP NBI device handle
 * @nbi:	NBI handle
 */
void nfp_nbi_close(struct nfp_nbi_dev *nbi)
{
	kfree(nbi);
}

/**
 * nfp_nbi_index() - Get the NFP NBI index of this NBI handle
 * @nbi:	NBI handle
 *
 * Return: NBI index of the NBI handle
 */
int nfp_nbi_index(struct nfp_nbi_dev *nbi)
{
	return nbi->nbi;
}

/**
 * nfp_nbi_mac_stats_read_port() - Read the statistics for an active port
 * @nbi:	NBI handle
 * @port:	Port number (0..23)
 * @stats:	Pointer to the stats buffer
 *
 * Return: size in bytes of the status area read, or -ERRNO
 */
int nfp_nbi_mac_stats_read_port(struct nfp_nbi_dev *nbi, int port,
				struct nfp_nbi_mac_portstats *stats)
{
	struct nfp_nbi_priv *priv = nbi->priv;
	u64 magic = 0;

	if (port < 0 || port >= 24)
		return -EINVAL;

	/* Check magic */
	nfp_cpp_readq(nbi->cpp, priv->stats.cpp_id, priv->stats.cpp_addr,
		      &magic);
	if (magic != NFP_NBI_MAC_STATS_MAGIC)
		return -EINVAL;

	return nfp_cpp_read(nbi->cpp, priv->stats.cpp_id, priv->stats.cpp_addr +
			    offsetof(struct nfp_nbi_mac_allstats,
				     mac[nbi->nbi].portstats[port]),
			    stats, sizeof(*stats));
}

/**
 * nfp_nbi_mac_stats_read_chan() - Read the statistics for a channel
 * @nbi:	NBI handle
 * @chan:	Channel number (0..127)
 * @stats:	Pointer to the stats buffer
 *
 * Return: size in bytes of the status area read, or -ERRNO
 */
int nfp_nbi_mac_stats_read_chan(struct nfp_nbi_dev *nbi, int chan,
				struct nfp_nbi_mac_chanstats *stats)
{
	struct nfp_nbi_priv *priv = nbi->priv;
	u64 magic = 0;

	if (chan < 0 || chan >= 128)
		return -EINVAL;

	/* Check magic */
	nfp_cpp_readq(nbi->cpp, priv->stats.cpp_id, priv->stats.cpp_addr,
		      &magic);
	if (magic != NFP_NBI_MAC_STATS_MAGIC)
		return -EINVAL;

	return nfp_cpp_read(nbi->cpp, priv->stats.cpp_id, priv->stats.cpp_addr +
			    offsetof(struct nfp_nbi_mac_allstats,
				     mac[nbi->nbi].chanstats[chan]),
			    stats, sizeof(*stats));
}

/**
 * nfp_nbi_mac_stats_read_ilks() - Read the statistics for a ilksnel
 * @nbi:	NBI handle
 * @ilk:	Interlaken (0..1)
 * @stats:	Pointer to the stats buffer
 *
 * Return: size in bytes of the status area read, or -ERRNO
 */
int nfp_nbi_mac_stats_read_ilks(struct nfp_nbi_dev *nbi, int ilk,
				struct nfp_nbi_mac_ilkstats *stats)
{
	struct nfp_nbi_priv *priv = nbi->priv;
	u64 magic = 0;

	if (ilk < 0 || ilk >= 2)
		return -EINVAL;

	/* Check magic */
	nfp_cpp_readq(nbi->cpp, priv->stats.cpp_id, priv->stats.cpp_addr,
		      &magic);
	if (magic != NFP_NBI_MAC_STATS_MAGIC)
		return -EINVAL;

	return nfp_cpp_read(nbi->cpp, priv->stats.cpp_id, priv->stats.cpp_addr +
			    offsetof(struct nfp_nbi_mac_allstats,
				     mac[nbi->nbi].ilkstats[ilk]),
			    stats, sizeof(*stats));
}

static int nfp_nbi_tx_flush_flags(struct nfp_nbi_dev *nbi, u32 flags)
{
	struct nfp_nbi_priv *priv = nbi->priv;
	const struct nfp_rtsym *sym;
	const int timeout_ms = 100;
	u64 wait_until;
	u32 tmp;
	int err;

	/* Lock out the firmware, if present, from modifying MAC
	 * CSRs, by stopping the TX Flush ME
	 */
	if (!priv->tx_flush_flags.has_sym)
		return 0;
	sym = &priv->tx_flush_flags.sym;

	/* Update the flags */
	err = nfp_rtsym_writel(nbi->cpp, sym, 4, flags);
	if (err < 0)
		return err;

	/* Readback to flush the write */
	err = nfp_rtsym_readl(nbi->cpp, sym, 4, &tmp);
	if (err < 0)
		return err;

	/* Readback to wait until acknowledgment */
	wait_until = get_jiffies_64() + msecs_to_jiffies(timeout_ms);

	do {
		err = nfp_rtsym_readl(nbi->cpp, sym, 4, &tmp);
		if (err < 0)
			return err;

		if (tmp & TX_FLUSH_FLAG_ACK)
			return 0;
	} while (time_after64(get_jiffies_64(), wait_until));

	/* Even though we timed out, this is currently a warning,
	 * not an error, as the ME firmware may not be new enough
	 * to set the acknowledgment bit.
	 *
	 * Suppress the warning if transitioning from
	 * STOP to RUN, and there was no ACK.
	 */
	if (flags != TX_FLUSH_FLAG_RUN) {
		nfp_warn(nbi->cpp, "NBI: pause_poll_tx_flush_flags was not acknowledged after %dms.\n",
			 timeout_ms);
	}

	return 0;
}

/**
 * nfp_nbi_mac_acquire() - Acquire exclusive access to the MAC CSRs
 * @nbi:	NBI handle
 *
 * Return: previous reference count, or -ERRNO
 */
int nfp_nbi_mac_acquire(struct nfp_nbi_dev *nbi)
{
	struct nfp_nbi_priv *priv = nbi->priv;

	if (priv->tx_flush_flags.count == 0) {
		int err;

		err = nfp_nbi_tx_flush_flags(nbi, TX_FLUSH_FLAG_STOP);
		if (err < 0)
			return err;
	}

	return priv->tx_flush_flags.count++;
}

/**
 * nfp_nbi_mac_eth_release() - Release exclusive access to the MAC CSRs
 * @nbi:	NBI handle
 *
 * Return: current reference count, or -ERRNO
 */
int nfp_nbi_mac_release(struct nfp_nbi_dev *nbi)
{
	struct nfp_nbi_priv *priv = nbi->priv;

	if (priv->tx_flush_flags.count < 1) {
		WARN_ON(priv->tx_flush_flags.count < 1);
		return 0;
	}

	if (priv->tx_flush_flags.count == 1) {
		int err;

		err = nfp_nbi_tx_flush_flags(nbi, TX_FLUSH_FLAG_RUN);
		if (err < 0)
			return err;
	}

	return --priv->tx_flush_flags.count;
}

/**
 * nfp_nbi_mac_regr() - Read a MAC register
 * @nbi:	NBI handle
 * @base:	Base address, e.g. NFP_NBI_MACX_ETH(1)
 * @reg:	Register, e.g. NFP_NBI_MACX_ETH_MacEthSeg_EthCmdConfig(port)
 * @data:	Value read from register
 *
 * Read the value of a MAC register. The register address is
 * specified as a base plus an offset.
 *
 * Return: 0, or -ERRNO
 */
int nfp_nbi_mac_regr(struct nfp_nbi_dev *nbi, u32 base, u32 reg, u32 *data)
{
	u32 r = NFP_XPB_ISLAND(nbi->nbi + 8) + base + reg;

	return nfp_xpb_readl(nbi->cpp, r, data);
}

/**
 * nfp_nbi_mac_regw() - Write a MAC register
 * @nbi:	NBI handle
 * @base:	Base address, e.g. NFP_NBI_MACX_ETH(1)
 * @reg:	Register, e.g. NFP_NBI_MACX_ETH_MacEthSeg_EthCmdConfig(port)
 * @mask:	Mask specifying the bits that may be changed by data
 * @data:	Value to write to the register
 *
 * Write a value to a MAC register.  The register address is specified
 * as a base plus an offset.
 *
 * The value to be written is specified by the parameters "data" and
 * "mask".  If mask is -1 the register is overwritten with the value
 * of data. Otherwise the register is read first and only the bits
 * specified by mask are allowed to be changed by data when the value
 * is written back.
 *
 * This should be bracketed by nfp_nbi_mac_acquire()/release() for
 * safety.
 *
 * Return: 0, or -ERRNO
 */
int nfp_nbi_mac_regw(struct nfp_nbi_dev *nbi, u32 base, u32 reg,
		     u32 mask, u32 data)
{
	struct nfp_nbi_priv *priv = nbi->priv;
	u32 r = NFP_XPB_ISLAND(nbi->nbi + 8) + base + reg;

	if (priv->tx_flush_flags.has_sym && !priv->tx_flush_flags.count)
		nfp_warn(nbi->cpp, "NBI: nbi_nbi_mac_regw() called outside of nfp_nbi_mac_acquire()/release()\n");

	return nfp_xpb_writelm(nbi->cpp, r, mask, data);
}
