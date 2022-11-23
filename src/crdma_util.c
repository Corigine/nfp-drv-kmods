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
#include <rdma/ib_cache.h>

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

/**
 * net_device notifier callback handler.
 *
 * @nb: Pointer to the notifier block.
 * @event: The notification event code.
 * @ptr: The pointer to private data (net_device).
 *
 * Returns NOTIFY_DONE.
*/
static int crdma_netdev_event(struct notifier_block *nb,
			unsigned long event, void *ptr)
{
	struct net_device *real_netdev, *netdev = netdev_notifier_info_to_dev(ptr);
	struct crdma_ibdev *dev;

	crdma_debug("crdma_netdev_event()\n");
	pr_info("	netdev:  %p\n", netdev);
	pr_info("	event:  %ld\n", event);

	dev = container_of(nb, struct crdma_ibdev, nb_netdev);
	pr_info("associated RoCE IB device %p\n", dev);

	if (netdev->priv_flags & IFF_802_1Q_VLAN)
		real_netdev = rdma_vlan_dev_real_dev(netdev);
	else
		real_netdev = netdev;

	if (real_netdev != dev->port.netdev) {
		crdma_info("Event netdev %p, not for us %p\n",
					real_netdev, dev->port.netdev);
		return NOTIFY_DONE;
	}

	switch(event)
	{
		case NETDEV_UP:
			if (netdev && netdev->name) {
				crdma_info("dev[%s] is up\n", netdev->name);
				crdma_port_enable_cmd(dev, 0);
			}
			break;
		case NETDEV_DOWN:
			if (netdev && netdev->name) {
				crdma_info("dev[%s] is down\n", netdev->name);
				crdma_port_disable_cmd(dev, 0);
			}
			break;
		default:
			break;
	}
	return NOTIFY_DONE;
}

int crdma_init_net_notifiers(struct crdma_ibdev *dev)
{
	int err;
	crdma_debug("crdma_init_net_notifier()\n");

	if (dev->nb_netdev.notifier_call) {
		crdma_warn("netdevice notifier registered twice!\n");
		return 0;
	}
	dev->nb_netdev.notifier_call = crdma_netdev_event;
	err = register_netdevice_notifier(&dev->nb_netdev);
	if (err) {
		dev->nb_netdev.notifier_call = NULL;
		return err;
	}
	return 0;
}

void crdma_cleanup_net_notifiers(struct crdma_ibdev *dev)
{
	crdma_debug("crdma_cleanup_net_notifier()\n");

	if (dev->nb_netdev.notifier_call) {
		unregister_netdevice_notifier(&dev->nb_netdev);
		dev->nb_netdev.notifier_call = NULL;
	}
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

void crdma_ring_db32(struct crdma_ibdev *dev, uint32_t value, int offset)
{
	unsigned long flags;
	spin_lock_irqsave(&dev->priv_uar_lock, flags);
	__raw_writel((__force u32) cpu_to_le32(value), 
		     dev->priv_uar.map + offset);
	spin_unlock_irqrestore(&dev->priv_uar_lock, flags);
	return;
}

void crdma_sq_ring_db32(struct crdma_ibdev *dev, uint32_t value)
{
	crdma_debug("Write priv UAR SQ DB\n");
	value  = value & CRDMA_DB_SQ_MASK;
	crdma_ring_db32(dev, value, CRDMA_DB_SQ_ADDR_OFFSET);
	crdma_debug("SQ doorbell address %p\n",
		    dev->priv_uar.map + CRDMA_DB_SQ_ADDR_OFFSET);
	crdma_debug("SQ doorbell written 0x%08X\n", cpu_to_le32(value));
	return;
}

void crdma_cq_ring_db32(struct crdma_ibdev *dev, uint32_t value)
{
	crdma_ring_db32(dev, value, CRDMA_DB_CQ_ADDR_OFFSET);
	return;
}

int crdma_check_ah_attr(struct crdma_ibdev *dev, struct rdma_ah_attr *attr)
{
	const struct ib_global_route *grh = rdma_ah_read_grh(attr);
	struct crdma_port *port = &dev->port;

	if (attr->type != RDMA_AH_ATTR_TYPE_ROCE) {
		crdma_warn("CRDMA HCA only support RoCE \n");
		return -EINVAL;
	}

	if (!(rdma_ah_get_ah_flags(attr) & IB_AH_GRH)) {
		crdma_warn("RoCE requires GRH\n");
		return -EINVAL;
	}

	if (rdma_is_multicast_addr((struct in6_addr *)grh->dgid.raw)) {
		crdma_warn("CRDMA HCA does not support multicast\n");
		return -EINVAL;
	}

	if (grh->sgid_index >= port->gid_table_size) {
		crdma_warn("Invalid SGID Index %d\n", grh->sgid_index);
		return -EINVAL;
	}

	return 0;
}

int crdma_set_av(struct ib_pd *pd,
		 struct crdma_av *av,
		 struct rdma_ah_attr *ah_attr)
{
	u8 nw_type;
	u16 vlan = 0xffff;

	crdma_info("crdma_set_av\n");

	/* The reason of swap byte order reference the struct crdma_av */
	av->d_mac[0] = ah_attr->roce.dmac[3];
	av->d_mac[1] = ah_attr->roce.dmac[2];
	av->d_mac[2] = ah_attr->roce.dmac[1];
	av->d_mac[3] = ah_attr->roce.dmac[0];
	av->d_mac[4] = ah_attr->roce.dmac[5];
	av->d_mac[5] = ah_attr->roce.dmac[4];

	av->port          = ah_attr->port_num - 1;
	av->service_level = ah_attr->sl;
	av->s_gid_ndx     = ah_attr->grh.sgid_index;
	av->hop_limit     = ah_attr->grh.hop_limit;
	av->traffic_class = ah_attr->grh.traffic_class;

	/* Always swap to account for hardware bus swap */
	av->flow_label    = __swab32(ah_attr->grh.flow_label);
	/* For now using maximum rate, no IPD */
	av->ib_sr_ipd = cpu_to_le32((0 << CRDMA_AV_IBSR_IPD_SHIFT) |
				(to_crdma_pd(pd)->pd_index & CRDMA_AV_PD_MASK));

	/* Get gid type */
	nw_type = rdma_gid_attr_network_type(ah_attr->grh.sgid_attr);
	if (nw_type == RDMA_NETWORK_IPV4)
		av->gid_type = CRDMA_AV_ROCE_V2_IPV4_GID_TYPE;
	else if(nw_type == RDMA_NETWORK_IPV6)
		av->gid_type = CRDMA_AV_ROCE_V2_IPV6_GID_TYPE;
	else {
		crdma_warn("No supported network type %d\n", nw_type);
		return -EINVAL;
	}

	/* Get vlan id*/
#if (VER_NON_RHEL_GE(5,1) || VER_RHEL_GE(8,0))
	if (rdma_read_gid_l2_fields(ah_attr->grh.sgid_attr, &vlan, NULL)) {
		crdma_warn("Get vlan failed from gid_attr\n");
		return -EINVAL;
	}
#else
	if (is_vlan_dev(ah_attr->grh.sgid_attr->ndev))
		vlan = vlan_dev_vlan_id(ah_attr->grh.sgid_attr->ndev);
#endif
	if (vlan < VLAN_CFI_MASK) { /* VLAN ID is valid*/
		av->vlan = cpu_to_le32(vlan);
		av->v_id = 1;
	}
	else
		av->v_id = 0;

	/*
		To DO: check it need swap or not wiht firmare debug
	*/
	memcpy(av->d_gid, ah_attr->grh.dgid.raw, 16);

	return 0;
}
