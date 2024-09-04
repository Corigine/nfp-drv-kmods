/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright (C) 2023 Corigine, Inc. */

#ifndef CRDMA_UTIL_H
#define CRDMA_UTIL_H

#include <linux/compiler.h>

struct crdma_res_info;

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
 * @allocated_index: Pointer to the memory in which index allocated is stored.
 *
 * Returns 0 on success, otherwise -ENOMEM;
 */
int crdma_alloc_bitmap_index(struct crdma_bitmap *bitmap, u32 *allocated_index);

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
 * @first_allocated_index: Pointer to the memory which first index is stored.
 *
 * Returns 0 on success, otherwise -ENOMEM.
 */
int crdma_alloc_bitmap_area(struct crdma_bitmap *bitmap,
			    u32 count,
			    u32 *first_allocated_index);

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
#ifdef CONFIG_TRANSPARENT_HUGEPAGE
	CRDMA_MEM_DEFAULT_ORDER		= HPAGE_PMD_ORDER,
#else
	CRDMA_MEM_DEFAULT_ORDER		= 0,
#endif
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
 * Translate MAC adding/removing byte swap that occurs in DMA to/from
 * microcode memory.
 *
 * @out_mac: The output DMAC to be set.
 * @in_mac: The input DMAC to be swapped.
 */
void crdma_mac_swap(u8 *out_mac, u8 *in_mac);

struct crdma_port;

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

void crdma_ring_db32(struct crdma_ibdev *dev, uint32_t value, int offset);

void crdma_rq_ring_db32(struct crdma_ibdev *dev, uint32_t value);

void crdma_sq_ring_db32(struct crdma_ibdev *dev, uint32_t value);

void crdma_cq_ring_db32(struct crdma_ibdev *dev, uint32_t value);

int crdma_check_ah_attr(struct crdma_ibdev *dev, struct rdma_ah_attr *attr);

int crdma_set_av(struct ib_pd *pd,
		 struct crdma_av *av,
		 struct rdma_ah_attr *ah_attr);

int crdma_get_gid(struct crdma_ibdev *dev, u8 port_num,
		  unsigned int index, union ib_gid *gid);

bool crdma_check_loopback_mode(struct crdma_ibdev *dev,
			       const union ib_gid *dgid,
			       __u8  sgid_index,
			       bool swap);

int crdma_set_loopback_mode(struct crdma_ibdev *dev,
			    struct crdma_qp *qp,
			    struct rdma_ah_attr *ah_attr);

void crdma_remove_dev(struct crdma_ibdev *dev);

struct crdma_ibdev *crdma_add_dev(struct crdma_res_info *info);

#endif /* CRDMA_UTIL_H */
