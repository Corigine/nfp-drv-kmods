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

#ifndef CRDMA_UTIL_H
#define CRDMA_UTIL_H

#include <linux/compiler.h>

/*
 * crdma_util.h - General utility functions used throughout the driver.
 */

/*
 * Bit maps are used to maintain a table of allocated resource
 * identifiers.
 */
struct crdma_bitmap {
	spinlock_t	lock;
	u32		min_index;
	u32		max_index;
	u32		last_index;
	size_t		num_bits;
	unsigned long	*map;
};

/**
 * Initialize a bitmap to have the max - min + 1 entries.
 *
 * @bitmap: Pointer to the bitmap to initialize;
 * @min: Minimum index;
 * @max: Maximum index;
 *
 * Returns 0 on success, otherwise -ENOMEM;
 */
int crdma_init_bitmap(struct crdma_bitmap *bitmap, u32 min, u32 max);

/**
 * Cleanup bitmap releasing bitmap memory.
 *
 * @bitmap: Pointer to the bitmap to cleanup.
 *
 * Returns 0 on success, otherwise -ENOMEM;
 */
void crdma_cleanup_bitmap(struct crdma_bitmap *bitmap);

/**
 * Allocate the next free index in a bitmap.
 *
 * @bitmap: Pointer to the bitmap used for allocation.
 *
 * Returns the bitmap index, or < 0 on error.
 */
u32 crdma_alloc_bitmap_index(struct crdma_bitmap *bitmap);

/**
 * Free an index in the specified bitmap.
 *
 * @bitmap: Pointer to the bitmap used for allocation.
 * @index: The index to free.
 */
void crdma_free_bitmap_index(struct crdma_bitmap *bitmap, u32 index);

/**
 * Allocate a block of free indices in a bitmap.
 *
 * @bitmap: Pointer to the bitmap used for allocation.
 * @count: The number of contiguous bits to allocate.
 *
 * Returns the bitmap index of the first bit, or -1 on error.
 */
u32 crdma_alloc_bitmap_area(struct crdma_bitmap *bitmap, u32 count);

/**
 *Free a contiguous block of previously allocated indices in a bitmap.
 *
 * @bitmap: Pointer to the bitmap used for allocation.
 * @index: The first bit in the contiguous block to free.
 * @count: The number of contiguous bits to free.
 */
void crdma_free_bitmap_area(struct crdma_bitmap *bitmap, u32 index, u32 count);

/*
 * Structure for DMA coherent/non-coherent memory allocation, the
 * backing physical memory can consist of multiple allocations
 * with each representing some number of contiguous physical pages.
 * We attempt to use huge compound pages by default, and reduce
 * the size as appropriate for smaller allocations.
 *
 * NOTE: Since any given area has a single page size, the min order from
 * all the allocations determines the HCA translation page size that will be
 * used (in multiples of host PAGE_SIZE).
 */
enum {
	CRDMA_MEM_DEFAULT_ORDER		= HPAGE_PMD_ORDER,
	CRDMA_MEM_MAX_ALLOCS		= 512
};

struct crdma_mem {
	bool		coherent;	/* If coherent requested */
	int			num_allocs;	/* Number of blocks of pages */
	int			max_order;	/* Largest block allocated */
	int			min_order;	/* Smallest block allocated */
	int			tot_len;	/* Overall memory size */
	u32			base_mtt_ndx;	/* First MTT entry */
	int			num_mtt;	/* Number of MTT entries */
	int			num_sg;		/* Valid scatterlist entries */
	struct scatterlist	alloc[CRDMA_MEM_MAX_ALLOCS];
};

struct crdma_ibdev;

/**
 * Allocate DMA cache non-coherent host memory for the HCA.
 *
 * Non-coherent DMA memory is largely intended to be used for HCA
 * microcode backing store memory.
 *
 * @dev: The RoCE IB device.
 * @coherent: If true DMA memory should be coherent.
 * @order: The desired order size for the memory (i.e. PAGE_SIZE multiple).
 * @size: The size of the memory requested.
 *
 * Returns a pointer to the memory structure or an error pointer.
 */
struct crdma_mem *crdma_alloc_dma_mem(struct crdma_ibdev *dev,
		bool coherent, int order, int size);

/**
 * Free DMA cache non-coherent host memory previously allocated for the HCA.
 *
 * @dev: The RoCE IB device.
 * @mem: Pointer to the mem structure returned by crdma_alloc_dma_mem.
 * This memory is freed as part of this call.
 */
void crdma_free_dma_mem(struct crdma_ibdev *dev, struct crdma_mem *mem);

/**
 * Back a memory area page list with MTT entries.
 *
 */
int crdma_alloc_mtt_entries(struct crdma_ibdev *dev, struct crdma_mem *mem);

struct crdma_uar;

/**
 * Allocate UAR page.
 *
 * @dev: The RoCE IB device.
 * @uar: Pointer to the UAR object to initialize;
 *
 * Returns 0 on success, otherwise error.
 */
int crdma_alloc_uar(struct crdma_ibdev *dev, struct crdma_uar *uar);

/**
 * Free UAR page.
 *
 * @dev: The RoCE IB device.
 * @uar: Pointer to the UAR object for which resources should be released.
 */
void crdma_free_uar(struct crdma_ibdev *dev, struct crdma_uar *uar);

/**
 * Return the Page Frame Number (PFN) associated with a UAR.
 *
 * @dev: The RoCE IB device.
 * @uar: Pointer to the UAR object.
 */
u64  crdma_uar_pfn(struct crdma_ibdev *dev,
		struct crdma_uar *uar);

/**
 * Convert a Ethernet MAC to GUID.
 *
 * @mac: Pointer to the MAC address.
 * @vlan_id: A VLAN ID.
 * @guid: Pointer to the GUID to initialize.
 */
void crdma_mac_to_guid(u8 *mac, u16 vlan_id, u8 *guid);

/**
 * Translate MAC adding/removing byte swap that occurs in DMA to/from
 * microcode memory.
 *
 * @out_mac: The output DMAC to be set.
 * @in_mac: The input DMAC to be swapped.
 */
void crdma_mac_swap(u8 *out_mac, u8 *in_mac);

struct crdma_port;
/**
 * Add a GID to the ports SGID table.
 *
 * @port: The IB RoCE port.
 * @gid: The IB gid.
 * @gid_type: The RoCE gid type.
 *
 * Returns true if the GID is added to the ports SGID table. If the
 * GID already exists in the table then false is returned.
 */
bool crdma_add_sgid(struct crdma_port *port, union ib_gid *gid, u8 gid_type);

/**
 * Remove a GID from the ports SGID table.
 *
 * @port: The IB RoCE port.
 * @gid: The IB gid.
 * @gid_type: The RoCE gid type.
 *
 * Returns true if the GID is deleted from the ports SGID table. If the
 * GID does not exists in the table then false is returned.
 */
bool crdma_remove_sgid(struct crdma_port *port, union ib_gid *gid, u8 gid_type);

/**
 * Initialize a ports SGID table.
 *
 * @dev: The IB RoCE device.
 * @port_num: The port number to initialize [0 based].
 *
 * Returns 0 on success, otherwise an error code.
 */
int crdma_init_sgid_table(struct crdma_ibdev *dev, int port_num);

/**
 * Add a source MAC (or reference) to the ports source MAC table.
 *
 * @port: The IB RoCE port.
 * @mac: The source MAC address.
 *
 * Returns true if the source MAC was added to the ports to the
 * source MAC table. If the source MAC already exists in the table
 * then false is returned.
 */
bool crdma_add_smac(struct crdma_port *port, u8 *mac);

/**
 * Remove a source MAC (or reference) from the ports source MAC table.
 *
 * @port: The IB RoCE port.
 * @mac: The source MAC address.
 *
 * Returns true if the source MAC was removed from the ports
 * source MAC table. If the source MAC still is referenced,
 * then false is returned.
 */
bool crdma_remove_smac(struct crdma_port *port, u8 *mac);

/**
 * Initialize a ports source MAC table.
 *
 * @dev: The IB RoCE device.
 * @port_num: The port number to initialize [0 based].
 *
 * Returns 0 on success, otherwise an error code.
 */
int crdma_init_smac_table(struct crdma_ibdev *dev, int port_num);

/**
 * Initialize IB device net_device notifier call backs.
 *
 * @dev: The RoCE IB device.
 *
 * Returns 0 on success; otherwise an error.
 */
int crdma_init_net_notifiers(struct crdma_ibdev *dev);

/**
 * Remove IB device net_device notifier call backs.
 *
 * @dev: The RoCE IB device.
 */
void crdma_cleanup_net_notifiers(struct crdma_ibdev *dev);

/**
 * Write a 64 bit doorbell using 64-bit write if possible.
 *
 * @dev: The RoCE IB device.
 * @val: Array of the two 32-bit values endian adjusted.
 * @uar_off: The UAR offset to write to.
 */
void crdma_write64_db(struct crdma_ibdev *dev,
		u32 val[2], int uar_off);

#endif /* CRDMA_UTIL_H */
