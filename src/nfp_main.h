/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright (C) 2015-2018 Netronome Systems, Inc. */

/*
 * nfp_main.h
 * Author: Jason McMullan <jason.mcmullan@netronome.com>
 */

#ifndef NFP_MAIN_H
#define NFP_MAIN_H

#include "nfp_net_compat.h"

#include <linux/ethtool.h>
#include <linux/list.h>
#include <linux/types.h>
#include <linux/mutex.h>
#include <linux/pci.h>
#include <linux/workqueue.h>
#if COMPAT__HAS_DEVLINK
#include <net/devlink.h>
#endif

struct dentry;
struct device;
struct pci_dev;
struct platform_device;

struct nfp_cpp;
struct nfp_cpp_area;
struct nfp_cpp_area_cache;
struct nfp_eth_table;
struct nfp_hwinfo;
struct nfp_mip;
struct nfp_net;
struct nfp_nsp_identify;
struct nfp_eth_media_buf;
struct nfp_port;
struct nfp_rtsym;
struct nfp_rtsym_table;
struct nfp_shared_buf;

/**
 * struct nfp_dumpspec - NFP FW dump specification structure
 * @size:	Size of the data
 * @data:	Sequence of TLVs, each being an instruction to dump some data
 *		from FW
 */
struct nfp_dumpspec {
	u32 size;
	u8 data[];
};

/**
 * struct nfp_pf - NFP PF-specific device structure
 * @pdev:		Backpointer to PCI device
 * @dev_info:		NFP ASIC params
 * @cpp:		Pointer to the CPP handle
 * @app:		Pointer to the APP handle
 * @nfp_dev_cpp:	Pointer to the NFP Device handle
 * @nfp_net_vnic:	Handle for ARM VNIC device
 * @data_vnic_bar:	Pointer to the CPP area for the data vNICs' BARs
 * @ctrl_vnic_bar:	Pointer to the CPP area for the ctrl vNIC's BAR
 * @qc_area:		Pointer to the CPP area for the queues
 * @mac_stats_bar:	Pointer to the CPP area for the MAC stats
 * @mac_stats_mem:	Pointer to mapped MAC stats area
 * @vf_cfg_bar:		Pointer to the CPP area for the VF configuration BAR
 * @vf_cfg_mem:		Pointer to mapped VF configuration area
 * @vfcfg_tbl2_area:	Pointer to the CPP area for the VF config table
 * @vfcfg_tbl2:		Pointer to mapped VF config table
 * @mbox:		RTSym of per-PCI PF mailbox (under devlink lock)
 * @irq_entries:	Array of MSI-X entries for all vNICs
 * @msix:		Single MSI-X entry for non-netdev mode event monitor
 * @max_vfs:		Number of VFs supported by firmware shared by all PFs
 * @limit_vfs:		Number of VFs supported by firmware (~0 for PCI limit)
 * @num_vfs:		Number of SR-IOV VFs enabled
 * @max_vf_queues:	number of queues can be allocated to VFs
 * @fw_loaded:		Is the firmware loaded?
 * @unload_fw_on_remove:Do we need to unload firmware on driver removal?
 * @ctrl_vnic:		Pointer to the control vNIC if available
 * @debug_ctrl_netdev:	Pointer to "debug pipe" netdev of the control vNIC
 * @mip:		MIP handle
 * @rtbl:		RTsym table
 * @hwinfo:		HWInfo table
 * @dumpspec:		Debug dump specification
 * @dump_flag:		Store dump flag between set_dump and get_dump_flag
 * @dump_len:		Store dump length between set_dump and get_dump_flag
 * @eth_tbl:		NSP ETH table
 * @nspi:		NSP identification info
 * @hwmon_dev:		pointer to hwmon device
 * @ddir:		Per-device debugfs directory
 * @max_data_vnics:	Number of data vNICs app firmware supports
 * @num_vnics:		Number of vNICs spawned
 * @vnics:		Linked list of vNIC structures (struct nfp_net)
 * @ports:		Linked list of port structures (struct nfp_port)
 * @wq:			Workqueue for running works which need to grab @lock
 * @port_refresh_work:	Work entry for taking netdevs out
 * @shared_bufs:	Array of shared buffer structures if FW has any SBs
 * @num_shared_bufs:	Number of elements in @shared_bufs
 * @multi_pf:		Used in multi-PF setup
 * @multi_pf.en:	Is multi-PF setup?
 * @multi_pf.id:	PF index
 * @multi_pf.vf_fid:	Id of first VF that belongs to this PF
 * @multi_pf.beat_timer:Timer for beat to keepalive
 * @multi_pf.beat_area:	Pointer to CPP area for beat to keepalive
 * @multi_pf.beat_addr:	Pointer to mapped beat address used for keepalive
 * @lock:		Protects all fields which may change after probe,
 *			which is replaced by devlink lock after 5.18(inclusive)
 * @db_iomem:		Pointer to mapped doorbell space
 * @db_phys:		Physical base address of doorbell space
 * @db_size:		Size of doorbell space
 * @roce_command_area:  Pointer to CPP area for RoCE command interface
 * @roce_cmdif:         Pointer to IO address for RoCE command interface
 */
struct nfp_pf {
	struct pci_dev *pdev;
	const struct nfp_dev_info *dev_info;

	struct nfp_cpp *cpp;

	struct nfp_app *app;

	struct platform_device *nfp_dev_cpp;
	struct platform_device *nfp_net_vnic;

	struct nfp_cpp_area *data_vnic_bar;
	struct nfp_cpp_area *ctrl_vnic_bar;
	struct nfp_cpp_area *qc_area;
	struct nfp_cpp_area *mac_stats_bar;
	u8 __iomem *mac_stats_mem;
	struct nfp_cpp_area *vf_cfg_bar;
	u8 __iomem *vf_cfg_mem;
	struct nfp_cpp_area *vfcfg_tbl2_area;
	u8 __iomem *vfcfg_tbl2;

	const struct nfp_rtsym *mbox;

	struct msix_entry *irq_entries;

	struct msix_entry msix;

	unsigned int max_vfs;
	unsigned int limit_vfs;
	unsigned int num_vfs;
	unsigned int max_vf_queues;

	bool fw_loaded;
	bool unload_fw_on_remove;

	struct nfp_net *ctrl_vnic;
	struct net_device __rcu *debug_ctrl_netdev;

	const struct nfp_mip *mip;
	struct nfp_rtsym_table *rtbl;
	struct nfp_hwinfo *hwinfo;
	struct nfp_dumpspec *dumpspec;
	u32 dump_flag;
	u32 dump_len;
	struct nfp_eth_table *eth_tbl;
	struct nfp_nsp_identify *nspi;

	struct device *hwmon_dev;

	struct dentry *ddir;

	unsigned int max_data_vnics;
	unsigned int num_vnics;

	struct list_head vnics;
	struct list_head ports;

	struct workqueue_struct *wq;
	struct work_struct port_refresh_work;

	struct nfp_shared_buf *shared_bufs;
	unsigned int num_shared_bufs;

	struct {
		bool en;
		u8 id;
		u8 vf_fid;
		struct timer_list beat_timer;
		struct nfp_cpp_area *beat_area;
		u8 __iomem *beat_addr;
	} multi_pf;

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 18, 0)
	struct mutex lock;
#endif
#ifdef CONFIG_NFP_HARD_DB
	void __iomem *db_iomem;
	phys_addr_t db_phys;
	size_t db_size;
#endif
#ifdef CONFIG_NFP_ROCE
	struct nfp_cpp_area *roce_command_area;
	void __iomem *roce_cmdif;
#endif
};


extern int nfp_dev_cpp;
extern bool nfp_net_vnic;
extern bool force_40b_dma;

extern struct pci_driver nfp_netvf_pci_driver;

extern const struct devlink_ops nfp_devlink_ops;

int nfp_net_pci_probe(struct nfp_pf *pf);
void nfp_net_pci_remove(struct nfp_pf *pf);

int nfp_hwmon_register(struct nfp_pf *pf);
void nfp_hwmon_unregister(struct nfp_pf *pf);

void
nfp_net_get_mac_addr(struct nfp_pf *pf, struct net_device *netdev,
		     struct nfp_port *port);

bool nfp_ctrl_tx(struct nfp_net *nn, struct sk_buff *skb);

int nfp_ctrl_debug_start(struct nfp_pf *pf);
void nfp_ctrl_debug_stop(struct nfp_pf *pf);

#define NFP_DEV_CPP_TYPE	"nfp-dev-cpp"

#ifdef CONFIG_NFP_USER_SPACE_CPP
int nfp_dev_cpp_init(void);
void nfp_dev_cpp_exit(void);
#else
static inline int nfp_dev_cpp_init(void)
{
	return -ENODEV;
}

static inline void nfp_dev_cpp_exit(void)
{
}
#endif

int nfp_pf_rtsym_read_optional(struct nfp_pf *pf, const char *format,
			       unsigned int default_val);
int nfp_net_pf_get_app_id(struct nfp_pf *pf);
u8 __iomem *
nfp_pf_map_rtsym_offset(struct nfp_pf *pf, const char *name, const char *sym_fmt,
			unsigned int offset, unsigned int min_size,
			struct nfp_cpp_area **area);
u8 __iomem *
nfp_pf_map_rtsym(struct nfp_pf *pf, const char *name, const char *sym_fmt,
		 unsigned int min_size, struct nfp_cpp_area **area);
int nfp_mbox_cmd(struct nfp_pf *pf, u32 cmd, void *in_data, u64 in_length,
		 void *out_data, u64 out_length);
int nfp_flash_update_common(struct nfp_pf *pf,
#if VER_NON_RHEL_GE(5, 11) || VER_RHEL_GE(8, 5)
			    const struct firmware *fw,
#else
			    const char *path,
#endif
			    struct netlink_ext_ack *extack);

enum nfp_dump_diag {
	NFP_DUMP_NSP_DIAG = 0,
};

struct nfp_dumpspec *
nfp_net_dump_load_dumpspec(struct nfp_cpp *cpp, struct nfp_rtsym_table *rtbl);
s64 nfp_net_dump_calculate_size(struct nfp_pf *pf, struct nfp_dumpspec *spec,
				u32 flag);
int nfp_net_dump_populate_buffer(struct nfp_pf *pf, struct nfp_dumpspec *spec,
				 struct ethtool_dump *dump_param, void *dest);

int nfp_shared_buf_register(struct nfp_pf *pf);
void nfp_shared_buf_unregister(struct nfp_pf *pf);
int nfp_shared_buf_pool_get(struct nfp_pf *pf, unsigned int sb, u16 pool_index,
			    struct devlink_sb_pool_info *pool_info);
int nfp_shared_buf_pool_set(struct nfp_pf *pf, unsigned int sb,
			    u16 pool_index, u32 size,
			    enum devlink_sb_threshold_type threshold_type);

int nfp_devlink_params_register(struct nfp_pf *pf);
void nfp_devlink_params_unregister(struct nfp_pf *pf);

unsigned int nfp_net_lr2speed(unsigned int linkrate);
unsigned int nfp_net_speed2lr(unsigned int speed);

u8 nfp_get_pf_id(struct nfp_pf *pf);
#endif /* NFP_MAIN_H */
