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
#include <linux/bitmap.h>
#include <linux/bitops.h>
#include <linux/if_vlan.h>
#include <net/ipv6.h>
#include <net/addrconf.h>
#include <rdma/ib_addr.h>

#include "crdma_ib.h"
#include "crdma_util.h"

int crdma_init_bitmap(struct crdma_bitmap *bitmap, u32 min, u32 max)
{
	size_t	size;

	size = BITS_TO_LONGS(max - min + 1) * sizeof(long);
	bitmap->map = kmalloc(size, GFP_KERNEL);
	if (!bitmap->map) {
		crdma_warn("Unable to allocate bitmap\n");
		return -ENOMEM;
	}

	bitmap->num_bits  = max - min + 1;
	bitmap->min_index = min;
	bitmap->max_index = max;
	bitmap->last_index = 0;
	bitmap_zero(bitmap->map, bitmap->num_bits);
	spin_lock_init(&bitmap->lock);

	return 0;
}

void crdma_cleanup_bitmap(struct crdma_bitmap *bitmap)
{
	bitmap->num_bits = 0;
	kfree(bitmap->map);
	return;
}

u32 crdma_alloc_bitmap_index(struct crdma_bitmap *bitmap)
{
	u32 index;
	u32 range;

	range = bitmap->max_index - bitmap->min_index + 1;
	spin_lock(&bitmap->lock);

	index = find_next_zero_bit(bitmap->map, range, bitmap->last_index);
	if (index >= range)
		index = find_first_zero_bit(bitmap->map, range);
	if (index >= range)
		goto full;

	set_bit(index, bitmap->map);
	bitmap->last_index = index;
	index += bitmap->min_index;

	spin_unlock(&bitmap->lock);
	return index;
full:
	spin_unlock(&bitmap->lock);
	return -EAGAIN;
}

void crdma_free_bitmap_index(struct crdma_bitmap *bitmap, u32 index)
{
	crdma_info("free_bitmap_index %d\n", index);

	spin_lock(&bitmap->lock);
	clear_bit(index - bitmap->min_index, bitmap->map);
	spin_unlock(&bitmap->lock);
	return;
}

u32 crdma_alloc_bitmap_area(struct crdma_bitmap *bitmap, u32 count)
{
	u32 index;
	u32 range;

	crdma_info("alloc_bitmap_area count %d\n", count);

	range = bitmap->max_index - bitmap->min_index + 1;
	spin_lock(&bitmap->lock);

	index = bitmap_find_next_zero_area(bitmap->map, range,
			bitmap->last_index, count, 0);
	if (index >= range)
		index = bitmap_find_next_zero_area(bitmap->map,
				range, 0, count, 0);
	if (index >= range)
		goto full;

	bitmap_set(bitmap->map, index, count);
	bitmap->last_index = index + count;
	index += bitmap->min_index;

	spin_unlock(&bitmap->lock);
	return index;
full:
	spin_unlock(&bitmap->lock);
	return -EAGAIN;
}

void crdma_free_bitmap_area(struct crdma_bitmap *bitmap, u32 index, u32 count)
{
	crdma_info("free_bitmap_area index %d count %d\n", index, count);

	spin_lock(&bitmap->lock);
	bitmap_clear(bitmap->map, index - bitmap->min_index, count);
	spin_unlock(&bitmap->lock);
	return;
}

static int __crdma_alloc_mem_coherent(struct crdma_ibdev *dev,
		struct crdma_mem *mem, int num_pages)
{
	void *buf;

	pr_info("=== __crdma_alloc_mem_coherent === \n");
	/*
	 * Reduce translation page size to be the minimum size (order) that
	 * covers the requested number of PAGE_SIZE pages.
	 */
	mem->min_order = 0;
	while ((1 << mem->min_order) < num_pages)
		mem->min_order++;


	/*
	 * In early driver development we require that a coherent memory
	 * allocation be backed by a single block of coherent memory.
	 */
	buf = dma_alloc_coherent(&dev->nfp_info->pdev->dev,
			PAGE_SIZE << mem->min_order,
			&sg_dma_address(mem->alloc),
			GFP_KERNEL | GFP_TRANSHUGE);
	if (!buf)
		return -ENOMEM;

	pr_info("dma_alloc_coherent information:\n");
	pr_info("Order:         %d\n", mem->min_order);
	pr_info("Size:          %ld\n",PAGE_SIZE << mem->min_order);
	pr_info("Virtual Addr:  0x%p\n", buf);
	pr_info("DMA Addr:      0x%016llx\n", sg_dma_address(mem->alloc));

	mem->tot_len = PAGE_SIZE << mem->min_order;
	mem->num_allocs++;

	sg_set_buf(mem->alloc, buf, mem->tot_len);
	sg_dma_len(mem->alloc) = mem->tot_len;
	mem->num_sg = 1;
	mem->num_mtt = 1;
	mem->base_mtt_ndx = crdma_alloc_bitmap_index(&dev->mtt_map);
	if (mem->base_mtt_ndx < 0)
		goto alloc_err;

	pr_info("=== __crdma_alloc_mem_coherent done === \n");

	return 0;

alloc_err:
	dma_free_coherent(&dev->nfp_info->pdev->dev, sg_dma_len(mem->alloc),
			sg_virt(mem->alloc), sg_dma_address(mem->alloc));
	return -ENOMEM;
}

static int __crdma_alloc_mem_pages(struct crdma_ibdev *dev,
		struct crdma_mem *mem, int num_pages)
{
	struct page *page;
	int order = mem->min_order;
	int i;

	crdma_warn("__crdma_alloc_mem_pages page number: %d, order: %d\n",
		num_pages, order);

	/*
	 * Try to reduce number of HCA MTT entries by creating
	 * contiguous allocation blocks of up to the transparent huge page
	 * size for compound pages, but adjust the block size down to what
	 * we can actually allocate.
	 */
	while (num_pages > 0 && mem->num_allocs < CRDMA_MEM_MAX_ALLOCS) {
		page = alloc_pages(GFP_KERNEL | GFP_TRANSHUGE, order);
		if (!page) {
			if (order > 0) {
				order--;
				continue;
			}
			/* We ran out of memory */
			goto alloc_err;
		}
		/*
		 * Update the block with this allocation information
		 * and reduce min_order if necessary.
		 */
		sg_set_page(&mem->alloc[mem->num_allocs++], page,
				PAGE_SIZE << order, 0);
		mem->min_order = min(mem->min_order, order);
		mem->tot_len += PAGE_SIZE << order;
		num_pages -= 1 << order;
	}

	/*
	 * TODO: For initial test any DMA memory allocation can be
	 * backed by up to 512 compound page allocations. As the driver
	 * matures we will circle back so that we can chain an unlimited
	 * number of 512 entry scatter lists together.
	 */
	if (num_pages > 0) {
		crdma_warn("crdma_mem only %d blocks supported at this"
				" point\n", CRDMA_MEM_MAX_ALLOCS);
		goto alloc_err;
	}

	mem->num_sg = pci_map_sg(dev->nfp_info->pdev, mem->alloc,
				mem->num_allocs, PCI_DMA_BIDIRECTIONAL);
	mem->num_mtt = mem->tot_len >> (mem->min_order + PAGE_SHIFT);
	mem->base_mtt_ndx = crdma_alloc_bitmap_area(&dev->mtt_map,
					mem->num_mtt);
	if (mem->base_mtt_ndx < 0)
		goto alloc_err;

	return 0;

alloc_err:
	crdma_warn("Non-coherent DMA memory allocation failed\n");
	for (i = 0; i < mem->num_allocs; i++)
		__free_pages(sg_page(&mem->alloc[i]),
				get_order(mem->alloc[i].length));
	return -ENOMEM;
}

struct crdma_mem *crdma_alloc_dma_mem(struct crdma_ibdev *dev,
		bool coherent, int order, int size)
{
	struct crdma_mem *mem;
	int num_pages;
	int err;

	mem = kcalloc(1, sizeof(*mem), GFP_KERNEL);
	if (!mem)
		return ERR_PTR(-ENOMEM);

	memset(mem, 0, sizeof(*mem));
	mem->max_order = mem->min_order = order;
	num_pages = (size + (PAGE_SIZE-1)) >> PAGE_SHIFT;

	if (!coherent)
		err = __crdma_alloc_mem_pages(dev, mem, num_pages);
	else
		err = __crdma_alloc_mem_coherent(dev, mem, num_pages);

	if (!err)
		return mem;

	crdma_warn("Non-coherent DMA memory allocation failed\n");
	kfree(mem);
	return ERR_PTR(-ENOMEM);
}

void crdma_free_dma_mem(struct crdma_ibdev *dev, struct crdma_mem *mem)
{
	int i;

	if (!mem)
		return;

	/* Release MTT entries backing this memory */
	if (mem->num_mtt)
		crdma_free_bitmap_area(&dev->mtt_map,
				mem->base_mtt_ndx, mem->num_mtt);

	if (mem->coherent) {
		crdma_info("free coherent memory\n");
		dma_free_coherent(&dev->nfp_info->pdev->dev,
				sg_dma_len(mem->alloc),
				sg_virt(mem->alloc),
				sg_dma_address(mem->alloc));
	} else {
		crdma_info("unmap DMA memory\n");
		if (mem->num_sg)
			pci_unmap_sg(dev->nfp_info->pdev, mem->alloc,
					mem->num_allocs, PCI_DMA_BIDIRECTIONAL);

		crdma_info("free DMA memory (num allocs = %d)\n",
				mem->num_allocs);
		for (i = 0; i < mem->num_allocs; i++)
			__free_pages(sg_page(&mem->alloc[i]),
					get_order(mem->alloc[i].length));
	}
	kfree(mem);
	return;
}

int crdma_alloc_uar(struct crdma_ibdev *dev, struct crdma_uar *uar)
{
	uar->index = crdma_alloc_bitmap_index(&dev->uar_map);
	if (uar->index < 0)
		return -ENOMEM;
	uar->map = NULL;
	return 0;
}

void crdma_free_uar(struct crdma_ibdev *dev, struct crdma_uar *uar)
{
	if (uar->map != NULL) {
		iounmap(uar->map);
		uar->map = NULL;
	}
	crdma_free_bitmap_index(&dev->uar_map, uar->index);
	return;
}

u64 crdma_uar_pfn(struct crdma_ibdev *dev,
		struct crdma_uar *uar)
{
	return (dev->db_paddr + (uar->index * PAGE_SIZE)) >> PAGE_SHIFT;
}

/*
 * Much of the code dealing with net_device notifications, source GID
 * management, and source MAC management is similar across RoCE providers.
 * Hence work is underway to extract the common pieces to the RDMA
 * core and implement functions for updating the specific provider.
 * Once this work is done, some of the following routines will probably
 * go away.
 */

/**
 * Convert interface MAC to GID local EUI64
 *
 * @mac: Pointer to MAC address.
 * @vlan_id: The VLAN ID.
 * @guid: Pointer to GUID to initialize.
 */
void crdma_mac_to_guid(u8 *mac, u16 vlan_id, u8 *guid)
{
	memcpy(guid, mac, 3);
	memcpy(guid + 5, mac + 3, 3);
	if (vlan_id < 0x1000) {
		guid[3] = vlan_id >> 8;
		guid[4] = vlan_id  & 0xff;
	} else {
		guid[3] = 0xff;
		guid[4] = 0xfe;
	}
	guid[0] ^= 2;
	return;
}

/**
 * Build a ports default GID
 *
 * @dev: The IB RoCE device.
 * @port: The physical port number [0 based].
 * @gid: Pointer to the GID to initialize.
 */
static void crdma_get_default_gid(struct crdma_ibdev *dev, int port,
			union ib_gid *gid)
{
	gid->global.subnet_prefix = cpu_to_be64(0xfe80000000000000LL);
	crdma_debug("phys port %d\n", port);
	crdma_debug("net_device %p", dev->port.netdev);
	crdma_debug("dev_addr %p",
			dev->port.netdev ?
			dev->port.netdev->dev_addr : 0);
	crdma_mac_to_guid(dev->port.netdev->dev_addr,
			0xFFFF, &gid->raw[8]);
}

/**
 * Check to see if a GID exists in the SGID table
 *
 * @port: The RoCE IB port.
 * @gid: The gid to check.
 * @type: The gid type.
 *
 * The port table lock should be held outside of this call.
 *
 * Returns true if the GID is in the port source GID table, otherwise false.
 */
static bool __crdma_find_gid(struct crdma_port *port,
			union ib_gid *gid, u8 type)
{
	struct crdma_gid_entry *entry = port->gid_table_entry;
	int i;

	for (i = 0; i < port->gid_table_size; i++, entry++) {
		if (entry->valid && !memcmp(&entry->gid, gid,
				sizeof(union ib_gid)) && entry->type == type)
			return true;
	}
	return false;
}

void crdma_mac_swap(u8 *out_mac, u8 *in_mac)
{
	/* byte swap within 32-bit words */
	out_mac[0] = in_mac[3];
	out_mac[1] = in_mac[2];
	out_mac[2] = in_mac[1];
	out_mac[3] = in_mac[0];
	out_mac[4] = in_mac[5];
	out_mac[5] = in_mac[4];
	return;
}

bool crdma_add_sgid(struct crdma_port *port, union ib_gid *gid, u8 type)
{
	struct crdma_gid_entry *entry;
	unsigned long flags;
	int i;

	spin_lock_irqsave(&port->table_lock, flags);
	if (__crdma_find_gid(port, gid, type)) {
		crdma_info("SGID already in SGID table\n");
		goto no_update;
	}

	entry = port->gid_table_entry;
	for (i = 0; i < port->gid_table_size; i++, entry++) {
		if (!entry->valid) {
			memcpy(&entry->gid, gid, sizeof(union ib_gid));
			entry->type = type;
			entry->valid = 1;
			spin_unlock_irqrestore(&port->table_lock, flags);

			crdma_debug("SGID added to port SGID table\n");
			return true;
		}
	}
	crdma_info("SGID table full\n");

no_update:
	spin_unlock_irqrestore(&port->table_lock, flags);

	return false;
}

bool crdma_remove_sgid(struct crdma_port *port, union ib_gid *gid, u8 type)
{
	struct crdma_gid_entry *entry = port->gid_table_entry;
	unsigned long flags;
	int i;

	spin_lock_irqsave(&port->table_lock, flags);
	for (i = 0; i < port->gid_table_size; i++, entry++) {
		if (entry->valid && !memcmp(&entry->gid, gid,
				sizeof(union ib_gid)) && entry->type == type) {
			memset(&entry->gid, 0, sizeof(union ib_gid));
			entry->valid = 0;
			spin_unlock_irqrestore(&port->table_lock, flags);

			return true;
		}
	}
	crdma_info("SGID not found in port SGID table\n");
	spin_unlock_irqrestore(&port->table_lock, flags);

	return false;
}

int crdma_init_sgid_table(struct crdma_ibdev *dev, int port_num)
{
#if (VER_NON_RHEL_GE(5,3) || VER_RHEL_GE(8,0))
	const struct in_ifaddr *ifa;
#endif
	struct in_device *in_dev;
	struct net_device *netdev = dev->port.netdev;
	union ib_gid gid;
#if IS_ENABLED(CONFIG_IPV6)
	struct inet6_dev *in6_dev;
	struct inet6_ifaddr *ifp;
	union ib_gid *pgid;
#endif

	if (netdev->priv_flags & IFF_802_1Q_VLAN)
		netdev = rdma_vlan_dev_real_dev(netdev);

	/* First entry is always the port's default GID */
	crdma_get_default_gid(dev, port_num, &gid);
	crdma_add_sgid(&dev->port, &gid, RDMA_ROCE_V2_GID_TYPE);

	/* Add IPv4 GIDS */
	in_dev = in_dev_get(netdev);
	if (in_dev) {
#if (VER_NON_RHEL_GE(5,3) || VER_RHEL_GE(8,0))
		rcu_read_lock();
		in_dev_for_each_ifa_rcu(ifa, in_dev) {
			ipv6_addr_set_v4mapped(ifa->ifa_address,
					       (struct in6_addr *)&gid);
			crdma_add_sgid(&dev->port,
				       &gid, RDMA_ROCE_V2_GID_TYPE);
		}
		rcu_read_unlock();
#else
		for_ifa(in_dev) {
			ipv6_addr_set_v4mapped(ifa->ifa_address,
					(struct in6_addr *)&gid);
			crdma_add_sgid(&dev->port,
					&gid, RDMA_ROCE_V2_GID_TYPE);
		}
		endfor_ifa(in_dev);
#endif
		in_dev_put(in_dev);
	}

#if IS_ENABLED(CONFIG_IPV6)
	/* Add IPv6 GIDS */
	in6_dev = in6_dev_get(netdev);
	if (in6_dev) {
		read_lock_bh(&in6_dev->lock);
		list_for_each_entry(ifp, &in6_dev->addr_list, if_list) {
			pgid = (union ib_gid *)&ifp->addr;
			crdma_add_sgid(&dev->port, pgid,
					RDMA_ROCE_V2_GID_TYPE);
		}
		read_unlock_bh(&in6_dev->lock);
		in6_dev_put(in6_dev);
	}
#endif
	/* Push the source GID table to microcode */
	return crdma_write_sgid_table(dev, port_num,
			dev->port.gid_table_size);
}

/**
 * Handle net_device callbacks for link/address changes.
 *
 * @netdev: The net_device associated with the notifier callback.
 * @gid: Pointer to the new address.
 * @type: The type of GID: RDMA_ROCE_V2_GID_TYPE only supported currently.
 * @event: The notifier event type.
 *
 * Returns NOTIFY_OK if address updated; otherwise NOTIFY_DONE.
 */
static int crdma_net_addr_event(struct crdma_ibdev *dev,
			struct net_device *netdev, union ib_gid *gid,
			u8 type, unsigned long event)
{
	struct net_device *real_netdev;
	bool updated;

	if (netdev->priv_flags & IFF_802_1Q_VLAN)
		real_netdev = rdma_vlan_dev_real_dev(netdev);
	else
		real_netdev = netdev;

	/*
	 * TODO: Eventually we will need to compare the "real_netdev"
	 * with EACH of the devices ports to determine the specific port
	 * associated with this callback (so we can extend support to more
	 * than one port).
	 */
	if (real_netdev != dev->port.netdev) {
		crdma_info("Event netdev %p, not for us %p\n",
				real_netdev, dev->port.netdev);
		return NOTIFY_DONE;
	}

	crdma_info("ib_gid = 0x%016llX:0x%016llX\n",
			gid->global.subnet_prefix,
			gid->global.interface_id);

	switch (event) {
	case NETDEV_UP:
		crdma_info("Adding SGID type %d\n", type);
		updated = crdma_add_sgid(&dev->port, gid, type);
		break;
	case NETDEV_DOWN:
		crdma_info("Removing SGID type %d\n", type);
		updated = crdma_remove_sgid(&dev->port, gid, type);
		break;
	default:
		crdma_info("Ignoring Event %ld\n", event);
		updated = false;
		break;
	}

	if (updated) {
		/* Push the updated GID table to microcode */
		if (crdma_write_sgid_table(dev, 0,
				dev->port.gid_table_size))
			crdma_dev_info(dev, "Unable to update GID table\n");
		crdma_info("IB GID change events not delivered yet.\n");

		/* TODO: If GID was updated we need to propagate an IB EVENT */
	}

	return NOTIFY_OK;
}

/**
 * net_device IPv4 address notifier callback handler.
 *
 * @nb: Pointer to the notifier block.
 * @event: The notification event code.
 * @ptr: The pointer to private data (net_device).
 *
 * Returns NOTIFY_DONE.
 */
static int crdma_inet_event(struct notifier_block *nb,
			unsigned long event, void *ptr)
{
	struct in_ifaddr *ifaddr = ptr;
	struct net_device *netdev = ifaddr->ifa_dev->dev;
	struct crdma_ibdev *dev;
	union ib_gid gid;

	pr_info("crdma_inet_event()\n");
	pr_info("  netdev: %p\n", netdev);
	pr_info("   event: %ld\n", event);

	dev = container_of(nb, struct crdma_ibdev, nb_inet);
	pr_info("associated RoCE IB device %p\n", dev);

	ipv6_addr_set_v4mapped(ifaddr->ifa_address, (struct in6_addr *)&gid);
	crdma_net_addr_event(dev, netdev, &gid, RDMA_ROCE_V2_GID_TYPE, event);
	return NOTIFY_DONE;
}

#if IS_ENABLED(CONFIG_IPV6)
/**
 * net_device IPv6 address notifier callback handler.
 *
 * @nb: Pointer to the notifier block.
 * @event: The notification event code.
 * @ptr: The pointer to private data (net_device).
 *
 * Returns NOTIFY_DONE.
 */
static int crdma_inet6_event(struct notifier_block *nb,
			unsigned long event, void *ptr)
{
	struct inet6_ifaddr *ifaddr = ptr;
	struct net_device *netdev = ifaddr->idev->dev;
	struct crdma_ibdev *dev;
	union ib_gid *gid = (union ib_gid *) &ifaddr->addr;

	pr_info("crdma_inet6_event()\n");
	pr_info("  netdev: %p\n", netdev);
	pr_info("   event: %ld\n", event);

	dev = container_of(nb, struct crdma_ibdev, nb_inet6);
	pr_info("associated RoCE IB device %p\n", dev);

	crdma_net_addr_event(dev, netdev, gid, RDMA_ROCE_V2_GID_TYPE, event);
	return NOTIFY_DONE;
}
#endif

int crdma_init_net_notifiers(struct crdma_ibdev *dev)
{
	int err;

	crdma_debug("crdma_init_net_notifier()\n");

	if (!dev->nb_inet.notifier_call) {
		dev->nb_inet.notifier_call = crdma_inet_event;
		err = register_inetaddr_notifier(&dev->nb_inet);
		if (err) {
			dev->nb_inet.notifier_call = NULL;
			goto out;
		}
	}
#if IS_ENABLED(CONFIG_IPV6)
	if (!dev->nb_inet6.notifier_call) {
		dev->nb_inet6.notifier_call = crdma_inet6_event;
		err = register_inet6addr_notifier(&dev->nb_inet6);
		if (err) {
			dev->nb_inet6.notifier_call = NULL;
			goto cleanup_inet;
		}
	}
#endif
	return 0;

cleanup_inet:
	unregister_inetaddr_notifier(&dev->nb_inet);
	dev->nb_inet.notifier_call = NULL;
out:
	return err;
}

void crdma_cleanup_net_notifiers(struct crdma_ibdev *dev)
{
	crdma_debug("crdma_cleanup_net_notifier()\n");

	if (dev->nb_inet.notifier_call) {
		unregister_inetaddr_notifier(&dev->nb_inet);
		dev->nb_inet.notifier_call = NULL;
	}

#if IS_ENABLED(CONFIG_IPV6)
	if (dev->nb_inet6.notifier_call) {
		unregister_inet6addr_notifier(&dev->nb_inet6);
		dev->nb_inet6.notifier_call = NULL;
	}
#endif
	return;
}

bool crdma_add_smac(struct crdma_port *port, u8 *mac)
{
	struct crdma_mac_entry *entry = port->mac_table_entry;
	unsigned long flags;
	bool update = false;
	int i;

	spin_lock_irqsave(&port->table_lock, flags);
	/* If source MAC already in table, just add a reference */
	for (i = 0; i < port->mac_table_size; i++, entry++) {
		if (entry->ref_cnt && !memcmp(&entry->mac, mac, ETH_ALEN)) {
			entry->ref_cnt++;
			goto done;
		}
	}

	entry = port->mac_table_entry;
	for (i = 0; i < port->mac_table_size; i++, entry++) {
		if (!entry->ref_cnt) {
			memcpy(&entry->mac, mac, ETH_ALEN);
			entry->ref_cnt = 1;
			update = true;
			goto done;
		}
	}
	crdma_info("S_MAC table full\n");
done:
	spin_unlock_irqrestore(&port->table_lock, flags);

	return update;
}

bool crdma_remove_smac(struct crdma_port *port, u8 *mac)
{
	struct crdma_mac_entry *entry = port->mac_table_entry;
	unsigned long flags;
	bool update = false;
	int i;

	spin_lock_irqsave(&port->table_lock, flags);
	for (i = 0; i < port->mac_table_size; i++, entry++) {
		if (entry->ref_cnt && !memcmp(&entry->mac, mac, ETH_ALEN)) {
			if (--entry->ref_cnt == 0)
				update = true;
		}
	}
	spin_unlock_irqrestore(&port->table_lock, flags);

	return update;
}

int crdma_init_smac_table(struct crdma_ibdev *dev, int port_num)
{
	/* Set the ports default MAC address */
	if (crdma_add_smac(&dev->port,
				dev->port.mac)) {
		crdma_write_smac_table(dev, port_num,
				dev->port.mac_table_size);
	}
	return 0;
}

#if BITS_PER_LONG == 64
#if defined(__LITTLE_ENDIAN)
#define CRDMA_WORDS_TO_LONG(va) ((u64)val[1] << 32 | val[0])
#elif defined(__BIG_ENDIAN)
#define CRDMA_WORDS_TO_LONG(va) ((u64)val[0] << 32 | val[1])
#else
#error Host byte order not defined
#endif
void crdma_write64_db(struct crdma_ibdev *dev,
		u32 val[2], int uar_off)
{
	static int cnt = 0;

	/* Log the first few doorbells as debug helper */
	if (cnt < 4) {
		pr_info("Writing 64-bit DB 0x%016llX to %p\n",
			CRDMA_WORDS_TO_LONG(val),
			(uint64_t *)(dev->priv_uar.map + uar_off));
		cnt++;
	}

	__raw_writeq(CRDMA_WORDS_TO_LONG(val),
			dev->priv_uar.map + uar_off);
	return;
}
#else
void crdma_write64_db(struct crdma_ibdev *dev,
		u32 val[2], int uar_off)
{
	unsigned long flags;

	spin_lock_irqsave(&dev->priv_uar_lock, flags);
	__raw_writel((__force u32) val[0],
			dev->priv_uar.map + uar_off - CRDMA_DB_WA_BIT);
	__raw_writel((__force u32) val[1],
			dev->priv_uar.map + uar_off + 4);
	spin_unlock_irqrestore(&dev->priv_uar_lock, flags);

	return;
}
#endif
