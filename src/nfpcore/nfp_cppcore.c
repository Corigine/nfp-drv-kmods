// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright (C) 2015-2018 Netronome Systems, Inc. */

/*
 * nfp_cppcore.c
 * Provides low-level access to the NFP's internal CPP bus
 * Authors: Jakub Kicinski <jakub.kicinski@netronome.com>
 *          Jason McMullan <jason.mcmullan@netronome.com>
 *          Rolf Neugebauer <rolf.neugebauer@netronome.com>
 */

#include <asm/unaligned.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/ioport.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/platform_device.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/wait.h>

#include "nfp_arm.h"
#include "nfp_cpp.h"
#include "nfp6000/nfp6000.h"

#define NFP_ARM_GCSR_SOFTMODEL2                              0x0000014c
#define NFP_ARM_GCSR_SOFTMODEL3                              0x00000150

/* Load module regardless of quirk_nfp6000 being on the kernel
 */
static int ignore_quirks;
module_param(ignore_quirks, int, 0644);
MODULE_PARM_DESC(ignore_quirks,
		 "Ignore quirks and load even if the kernel does not have quirk_nfp6000");

struct nfp_cpp_resource {
	struct list_head list;
	const char *name;
	u32 cpp_id;
	u64 start;
	u64 end;
};

/**
 * struct nfp_cpp - main nfpcore device structure
 * Following fields are read-only after probe() exits or netdevs are spawned.
 * @id:			ID of the user space access device
 * @dev:		embedded device structure
 * @kref:		ref counting for userspace?
 * @op:			low-level implementation ops
 * @priv:		private data of the low-level implementation
 * @model:		chip model
 * @interface:		chip interface id we are using to reach it
 * @serial:		chip serial number
 * @imb_cat_table:	CPP Mapping Table
 * @island_mask:	present island mask
 * @mu_locality_lsb:	MU access type bit offset
 * @feature:		array of child platform devices
 *
 * Following fields can be used only in probe() or with rtnl held:
 * @nbi:		NBI state
 *
 * Following fields use explicit locking:
 * @resource_list:	NFP CPP resource list
 * @resource_lock:	protects @resource_list
 *
 * @area_cache_list:	cached areas for cpp/xpb read/write speed up
 * @area_cache_mutex:	protects @area_cache_list
 *
 * @list:		entry on user space access device list,
 *			protected by @nfp_cpp_list_lock
 *
 * @waitq:		area wait queue
 */
struct nfp_cpp {
	int id;
	struct device dev;
	struct kref kref;

	void *priv;

	u32 model;
	u16 interface;
	u8 serial[NFP_SERIAL_LEN];

	const struct nfp_cpp_operations *op;
	struct list_head resource_list;
	rwlock_t resource_lock;
	struct list_head list;
	wait_queue_head_t waitq;

	struct platform_device *feature[32];

	u32 imb_cat_table[16];
	u64 island_mask;
	unsigned int mu_locality_lsb;

	struct mutex area_cache_mutex;
	struct list_head area_cache_list;

	void *nbi;
};

/* Element of the area_cache_list */
struct nfp_cpp_area_cache {
	struct list_head entry;
	u32 id;
	u64 addr;
	u32 size;
	struct nfp_cpp_area *area;
};

struct nfp_cpp_area {
	struct nfp_cpp *cpp;
	struct kref kref;
	atomic_t refcount;
	struct mutex mutex;	/* Lock for the area's refcount */
	unsigned long long offset;
	unsigned long size;
	struct nfp_cpp_resource resource;
	void __iomem *iomem;
	/* Here follows the 'priv' part of nfp_cpp_area. */
};

struct nfp_cpp_explicit {
	struct nfp_cpp *cpp;
	struct nfp_cpp_explicit_command cmd;
	/* Here follows the 'priv' part of nfp_cpp_area. */
};

struct nfp_cpp_event {
	struct nfp_cpp *cpp;
	struct {
		spinlock_t lock;	/* Lock for the callback */
		void (*func)(void *priv);
		void *priv;
	} callback;
	/* Here follows the 'priv' part of nfp_cpp_area. */
};

#define NFP_CPP_MAX	256

static DECLARE_BITMAP(nfp_cpp_id, NFP_CPP_MAX);
static struct mutex nfp_cpp_id_lock;
static struct list_head nfp_cpp_list;
static rwlock_t nfp_cpp_list_lock;

static ssize_t show_area(struct device *dev, struct device_attribute *attr,
			 char *buf)
{
	struct nfp_cpp *cpp = dev_get_drvdata(dev);
	struct nfp_cpp_resource *r;
	int left = PAGE_SIZE;

	read_lock(&cpp->resource_lock);

	list_for_each_entry(r, &cpp->resource_list, list) {
		struct nfp_cpp_area *area =
			container_of(r, struct nfp_cpp_area, resource);
		int count = atomic_read(&area->refcount);
		int len;

		len = snprintf(buf, left, "%d %d:%d:%d:0x%0llx-0x%0llx%s%s\n",
			       count,
			       NFP_CPP_ID_TARGET_of(r->cpp_id),
			       NFP_CPP_ID_ACTION_of(r->cpp_id),
			       NFP_CPP_ID_TOKEN_of(r->cpp_id),
			       r->start, r->end,
			       r->name ? " " : "",
			       r->name ? r->name : "");
		if (len > left) {
			*buf = 0;
			break;
		}

		buf += len;
		left -= len;
	}

	read_unlock(&cpp->resource_lock);

	return PAGE_SIZE - left;
}

static DEVICE_ATTR(area, S_IRUGO, show_area, NULL);

static int nfp_cpp_id_acquire(void)
{
	int id;

	mutex_lock(&nfp_cpp_id_lock);
	id = find_first_zero_bit(nfp_cpp_id, NFP_CPP_MAX);
	if (id < NFP_CPP_MAX)
		set_bit(id, nfp_cpp_id);
	mutex_unlock(&nfp_cpp_id_lock);

	return id < NFP_CPP_MAX ? id : -1;
}

static void nfp_cpp_id_release(int id)
{
	mutex_lock(&nfp_cpp_id_lock);
	clear_bit(id, nfp_cpp_id);
	mutex_unlock(&nfp_cpp_id_lock);
}

static void __resource_add(struct list_head *head, struct nfp_cpp_resource *res)
{
	struct nfp_cpp_resource *tmp;
	struct list_head *pos;

	list_for_each(pos, head) {
		tmp = container_of(pos, struct nfp_cpp_resource, list);

		if (tmp->cpp_id > res->cpp_id)
			break;

		if (tmp->cpp_id == res->cpp_id && tmp->start > res->start)
			break;
	}

	list_add_tail(&res->list, pos);
}

static void __resource_del(struct nfp_cpp_resource *res)
{
	list_del_init(&res->list);
}

static void __release_cpp_area(struct kref *kref)
{
	struct nfp_cpp_area *area =
		container_of(kref, struct nfp_cpp_area, kref);
	struct nfp_cpp *cpp = nfp_cpp_area_cpp(area);

	if (area->cpp->op->area_cleanup)
		area->cpp->op->area_cleanup(area);

	write_lock(&cpp->resource_lock);
	__resource_del(&area->resource);
	write_unlock(&cpp->resource_lock);
	kfree(area);
}

static void nfp_cpp_area_put(struct nfp_cpp_area *area)
{
	kref_put(&area->kref, __release_cpp_area);
}

static struct nfp_cpp_area *nfp_cpp_area_get(struct nfp_cpp_area *area)
{
	kref_get(&area->kref);

	return area;
}

static void __nfp_cpp_release(struct kref *kref)
{
	struct nfp_cpp *cpp = container_of(kref, struct nfp_cpp, kref);
	struct nfp_cpp_area_cache *cache, *ctmp;
	struct nfp_cpp_resource *res, *rtmp;

	device_remove_file(&cpp->dev, &dev_attr_area);

	/* Remove all caches */
	list_for_each_entry_safe(cache, ctmp, &cpp->area_cache_list, entry) {
		list_del(&cache->entry);
		if (cache->id)
			nfp_cpp_area_release(cache->area);
		nfp_cpp_area_free(cache->area);
		kfree(cache);
	}

	/* There should be no dangling areas at this point */
	WARN_ON(!list_empty(&cpp->resource_list));

	/* .. but if they weren't, try to clean up. */
	list_for_each_entry_safe(res, rtmp, &cpp->resource_list, list) {
		struct nfp_cpp_area *area = container_of(res,
							 struct nfp_cpp_area,
							 resource);

		dev_err(cpp->dev.parent, "Dangling area: %d:%d:%d:0x%0llx-0x%0llx%s%s\n",
			NFP_CPP_ID_TARGET_of(res->cpp_id),
			NFP_CPP_ID_ACTION_of(res->cpp_id),
			NFP_CPP_ID_TOKEN_of(res->cpp_id),
			res->start, res->end,
			res->name ? " " : "",
			res->name ? res->name : "");

		if (area->cpp->op->area_release)
			area->cpp->op->area_release(area);

		__release_cpp_area(&area->kref);
	}

	if (cpp->op->free)
		cpp->op->free(cpp);

	kfree(cpp->nbi);

	write_lock(&nfp_cpp_list_lock);
	list_del_init(&cpp->list);
	write_unlock(&nfp_cpp_list_lock);

	device_unregister(&cpp->dev);

	nfp_cpp_id_release(cpp->id);
	kfree(cpp);
}

static struct nfp_cpp *nfp_cpp_get(struct nfp_cpp *cpp)
{
	if (!kref_get_unless_zero(&cpp->kref))
		return NULL;

	return cpp;
}

static void nfp_cpp_put(struct nfp_cpp *cpp)
{
	kref_put(&cpp->kref, __nfp_cpp_release);
}

/**
 * nfp_cpp_from_device_id() - open a CPP by ID
 * @id:		device ID
 *
 * Return: NFP CPP handle, or NULL
 */
struct nfp_cpp *nfp_cpp_from_device_id(int id)
{
	struct nfp_cpp *tmp, *cpp = NULL;

	read_lock(&nfp_cpp_list_lock);
	list_for_each_entry(tmp, &nfp_cpp_list, list) {
		if (tmp->id == id) {
			cpp = nfp_cpp_get(tmp);
			break;
		}
	}
	read_unlock(&nfp_cpp_list_lock);

	return cpp;
}

/**
 * nfp_cpp_free() - free the CPP handle
 * @cpp:	CPP handle
 */
void nfp_cpp_free(struct nfp_cpp *cpp)
{
	nfp_cpp_put(cpp);
}

/**
 * nfp_cpp_device_id() - get device ID of CPP handle
 * @cpp:	CPP handle
 *
 * Return: NFP CPP device ID
 */
int nfp_cpp_device_id(struct nfp_cpp *cpp)
{
	return cpp->id;
}

/**
 * nfp_cpp_model() - Retrieve the Model ID of the NFP
 * @cpp:	NFP CPP handle
 *
 * Return: NFP CPP Model ID
 */
u32 nfp_cpp_model(struct nfp_cpp *cpp)
{
	return cpp->model;
}

/**
 * nfp_cpp_interface() - Retrieve the Interface ID of the NFP
 * @cpp:	NFP CPP handle
 *
 * Return: NFP CPP Interface ID
 */
u16 nfp_cpp_interface(struct nfp_cpp *cpp)
{
	return cpp->interface;
}

/**
 * nfp_cpp_serial() - Retrieve the Serial ID of the NFP
 * @cpp:	NFP CPP handle
 * @serial:	Pointer to NFP serial number
 *
 * Return:  Length of NFP serial number
 */
int nfp_cpp_serial(struct nfp_cpp *cpp, const u8 **serial)
{
	*serial = &cpp->serial[0];
	return sizeof(cpp->serial);
}

void *nfp_nbi_cache(struct nfp_cpp *cpp)
{
	return cpp->nbi;
}

void nfp_nbi_cache_set(struct nfp_cpp *cpp, void *val)
{
	cpp->nbi = val;
}

#define NFP_IMB_TGTADDRESSMODECFG_MODE_of(_x)		(((_x) >> 13) & 0x7)
#define NFP_IMB_TGTADDRESSMODECFG_ADDRMODE		BIT(12)
#define   NFP_IMB_TGTADDRESSMODECFG_ADDRMODE_32_BIT	0
#define   NFP_IMB_TGTADDRESSMODECFG_ADDRMODE_40_BIT	BIT(12)

static int nfp_cpp_set_mu_locality_lsb(struct nfp_cpp *cpp)
{
	unsigned int mode, addr40;
	u32 imbcppat;
	int res;

	imbcppat = cpp->imb_cat_table[NFP_CPP_TARGET_MU];
	mode = NFP_IMB_TGTADDRESSMODECFG_MODE_of(imbcppat);
	addr40 = !!(imbcppat & NFP_IMB_TGTADDRESSMODECFG_ADDRMODE);

	res = nfp_cppat_mu_locality_lsb(mode, addr40);
	if (res < 0)
		return res;
	cpp->mu_locality_lsb = res;

	return 0;
}

unsigned int nfp_cpp_mu_locality_lsb(struct nfp_cpp *cpp)
{
	return cpp->mu_locality_lsb;
}

/**
 * nfp_cpp_area_alloc_with_name() - allocate a new CPP area
 * @cpp:	CPP device handle
 * @dest:	NFP CPP ID
 * @name:	Name of region
 * @address:	Address of region
 * @size:	Size of region
 *
 * Allocate and initialize a CPP area structure.  The area must later
 * be locked down with an 'acquire' before it can be safely accessed.
 *
 * NOTE: @address and @size must be 32-bit aligned values.
 *
 * Return: NFP CPP area handle, or NULL
 */
struct nfp_cpp_area *
nfp_cpp_area_alloc_with_name(struct nfp_cpp *cpp, u32 dest, const char *name,
			     unsigned long long address, unsigned long size)
{
	struct nfp_cpp_area *area;
	u64 tmp64 = address;
	int err, name_len;

	/* Remap from cpp_island to cpp_target */
	err = nfp_target_cpp(dest, tmp64, &dest, &tmp64, cpp->imb_cat_table);
	if (err < 0)
		return NULL;

	address = tmp64;

	if (!name)
		name = "(reserved)";

	name_len = strlen(name) + 1;
	area = kzalloc(sizeof(*area) + cpp->op->area_priv_size + name_len,
		       GFP_KERNEL);
	if (!area)
		return NULL;

	area->cpp = cpp;
	area->resource.name = (void *)area + sizeof(*area) +
		cpp->op->area_priv_size;
	memcpy((char *)area->resource.name, name, name_len);

	area->resource.cpp_id = dest;
	area->resource.start = address;
	area->resource.end = area->resource.start + size - 1;
	INIT_LIST_HEAD(&area->resource.list);

	atomic_set(&area->refcount, 0);
	kref_init(&area->kref);
	mutex_init(&area->mutex);

	if (cpp->op->area_init) {
		int err;

		err = cpp->op->area_init(area, dest, address, size);
		if (err < 0) {
			kfree(area);
			return NULL;
		}
	}

	write_lock(&cpp->resource_lock);
	__resource_add(&cpp->resource_list, &area->resource);
	write_unlock(&cpp->resource_lock);

	area->offset = address;
	area->size = size;

	return area;
}

/**
 * nfp_cpp_area_alloc() - allocate a new CPP area
 * @cpp:	CPP handle
 * @dest:	CPP id
 * @address:	Start address on CPP target
 * @size:	Size of area in bytes
 *
 * Allocate and initialize a CPP area structure.  The area must later
 * be locked down with an 'acquire' before it can be safely accessed.
 *
 * NOTE: @address and @size must be 32-bit aligned values.
 *
 * Return: NFP CPP Area handle, or NULL
 */
struct nfp_cpp_area *
nfp_cpp_area_alloc(struct nfp_cpp *cpp, u32 dest,
		   unsigned long long address, unsigned long size)
{
	return nfp_cpp_area_alloc_with_name(cpp, dest, NULL, address, size);
}

/**
 * nfp_cpp_area_alloc_acquire() - allocate a new CPP area and lock it down
 * @cpp:	CPP handle
 * @name:	Name of region
 * @dest:	CPP id
 * @address:	Start address on CPP target
 * @size:	Size of area
 *
 * Allocate and initialize a CPP area structure, and lock it down so
 * that it can be accessed directly.
 *
 * NOTE: @address and @size must be 32-bit aligned values.
 * The area must also be 'released' when the structure is freed.
 *
 * Return: NFP CPP Area handle, or NULL
 */
struct nfp_cpp_area *
nfp_cpp_area_alloc_acquire(struct nfp_cpp *cpp, const char *name, u32 dest,
			   unsigned long long address, unsigned long size)
{
	struct nfp_cpp_area *area;

	area = nfp_cpp_area_alloc_with_name(cpp, dest, name, address, size);
	if (!area)
		return NULL;

	if (nfp_cpp_area_acquire(area)) {
		nfp_cpp_area_free(area);
		return NULL;
	}

	return area;
}

/**
 * nfp_cpp_area_free() - free up the CPP area
 * @area:	CPP area handle
 *
 * Frees up memory resources held by the CPP area.
 */
void nfp_cpp_area_free(struct nfp_cpp_area *area)
{
	if (atomic_read(&area->refcount))
		nfp_warn(area->cpp, "Warning: freeing busy area\n");
	nfp_cpp_area_put(area);
}

static bool nfp_cpp_area_acquire_try(struct nfp_cpp_area *area, int *status)
{
	*status = area->cpp->op->area_acquire(area);

	return *status != -EAGAIN;
}

static int __nfp_cpp_area_acquire(struct nfp_cpp_area *area)
{
	int err, status;

	if (atomic_inc_return(&area->refcount) > 1)
		return 0;

	if (!area->cpp->op->area_acquire)
		return 0;

	err = wait_event_interruptible(area->cpp->waitq,
				       nfp_cpp_area_acquire_try(area, &status));
	if (!err)
		err = status;
	if (err) {
		nfp_warn(area->cpp, "Warning: area wait failed: %d\n", err);
		atomic_dec(&area->refcount);
		return err;
	}

	nfp_cpp_area_get(area);

	return 0;
}

/**
 * nfp_cpp_area_acquire() - lock down a CPP area for access
 * @area:	CPP area handle
 *
 * Locks down the CPP area for a potential long term activity.  Area
 * must always be locked down before being accessed.
 *
 * Return: 0, or -ERRNO
 */
int nfp_cpp_area_acquire(struct nfp_cpp_area *area)
{
	int ret;

	mutex_lock(&area->mutex);
	ret = __nfp_cpp_area_acquire(area);
	mutex_unlock(&area->mutex);

	return ret;
}

/**
 * nfp_cpp_area_acquire_nonblocking() - lock down a CPP area for access
 * @area:	CPP area handle
 *
 * Locks down the CPP area for a potential long term activity.  Area
 * must always be locked down before being accessed.
 *
 * NOTE: Returns -EAGAIN is no area is available
 *
 * Return: 0, or -ERRNO
 */
int nfp_cpp_area_acquire_nonblocking(struct nfp_cpp_area *area)
{
	mutex_lock(&area->mutex);
	if (atomic_inc_return(&area->refcount) == 1) {
		if (area->cpp->op->area_acquire) {
			int err;

			err = area->cpp->op->area_acquire(area);
			if (err < 0) {
				atomic_dec(&area->refcount);
				mutex_unlock(&area->mutex);
				return err;
			}
		}
	}
	mutex_unlock(&area->mutex);

	nfp_cpp_area_get(area);
	return 0;
}

/**
 * nfp_cpp_area_release() - release a locked down CPP area
 * @area:	CPP area handle
 *
 * Releases a previously locked down CPP area.
 */
void nfp_cpp_area_release(struct nfp_cpp_area *area)
{
	mutex_lock(&area->mutex);
	/* Only call the release on refcount == 0 */
	if (atomic_dec_and_test(&area->refcount)) {
		if (area->cpp->op->area_release) {
			area->cpp->op->area_release(area);
			/* Let anyone waiting for a BAR try to get one.. */
			wake_up_interruptible_all(&area->cpp->waitq);
		}
	}
	mutex_unlock(&area->mutex);

	nfp_cpp_area_put(area);
}

/**
 * nfp_cpp_area_release_free() - release CPP area and free it
 * @area:	CPP area handle
 *
 * Releases CPP area and frees up memory resources held by the it.
 */
void nfp_cpp_area_release_free(struct nfp_cpp_area *area)
{
	nfp_cpp_area_release(area);
	nfp_cpp_area_free(area);
}

/**
 * nfp_cpp_area_read() - read data from CPP area
 * @area:	  CPP area handle
 * @offset:	  offset into CPP area
 * @kernel_vaddr: kernel address to put data into
 * @length:	  number of bytes to read
 *
 * Read data from indicated CPP region.
 *
 * NOTE: @offset and @length must be 32-bit aligned values.
 * Area must have been locked down with an 'acquire'.
 *
 * Return: length of io, or -ERRNO
 */
int nfp_cpp_area_read(struct nfp_cpp_area *area,
		      unsigned long offset, void *kernel_vaddr,
		      size_t length)
{
	return area->cpp->op->area_read(area, kernel_vaddr, offset, length);
}

/**
 * nfp_cpp_area_write() - write data to CPP area
 * @area:	CPP area handle
 * @offset:	offset into CPP area
 * @kernel_vaddr: kernel address to read data from
 * @length:	number of bytes to write
 *
 * Write data to indicated CPP region.
 *
 * NOTE: @offset and @length must be 32-bit aligned values.
 * Area must have been locked down with an 'acquire'.
 *
 * Return: length of io, or -ERRNO
 */
int nfp_cpp_area_write(struct nfp_cpp_area *area,
		       unsigned long offset, const void *kernel_vaddr,
		       size_t length)
{
	return area->cpp->op->area_write(area, kernel_vaddr, offset, length);
}

/**
 * nfp_cpp_area_size() - return size of a CPP area
 * @cpp_area:	CPP area handle
 *
 * Return: Size of the area
 */
size_t nfp_cpp_area_size(struct nfp_cpp_area *cpp_area)
{
	return cpp_area->size;
}

/**
 * nfp_cpp_area_name() - return name of a CPP area
 * @cpp_area:	CPP area handle
 *
 * Return: Name of the area, or NULL
 */
const char *nfp_cpp_area_name(struct nfp_cpp_area *cpp_area)
{
	return cpp_area->resource.name;
}

/**
 * nfp_cpp_area_priv() - return private struct for CPP area
 * @cpp_area:	CPP area handle
 *
 * Return: Private data for the CPP area
 */
void *nfp_cpp_area_priv(struct nfp_cpp_area *cpp_area)
{
	return &cpp_area[1];
}

/**
 * nfp_cpp_area_cpp() - return CPP handle for CPP area
 * @cpp_area:	CPP area handle
 *
 * Return: NFP CPP handle
 */
struct nfp_cpp *nfp_cpp_area_cpp(struct nfp_cpp_area *cpp_area)
{
	return cpp_area->cpp;
}

/**
 * nfp_cpp_area_resource() - get resource
 * @area:	CPP area handle
 *
 * NOTE: Area must have been locked down with an 'acquire'.
 *
 * Return: struct resource pointer, or NULL
 */
struct resource *nfp_cpp_area_resource(struct nfp_cpp_area *area)
{
	struct resource *res = NULL;

	if (area->cpp->op->area_resource)
		res = area->cpp->op->area_resource(area);

	return res;
}

/**
 * nfp_cpp_area_phys() - get physical address of CPP area
 * @area:	CPP area handle
 *
 * NOTE: Area must have been locked down with an 'acquire'.
 *
 * Return: phy_addr_t of the area, or NULL
 */
phys_addr_t nfp_cpp_area_phys(struct nfp_cpp_area *area)
{
	phys_addr_t addr = ~0;

	if (area->cpp->op->area_phys)
		addr = area->cpp->op->area_phys(area);

	return addr;
}

/**
 * nfp_cpp_area_iomem() - get IOMEM region for CPP area
 * @area:	CPP area handle
 *
 * Returns an iomem pointer for use with readl()/writel() style
 * operations.
 *
 * NOTE: Area must have been locked down with an 'acquire'.
 *
 * Return: __iomem pointer to the area, or NULL
 */
void __iomem *nfp_cpp_area_iomem(struct nfp_cpp_area *area)
{
	void __iomem *iomem = NULL;

	if (area->cpp->op->area_iomem)
		iomem = area->cpp->op->area_iomem(area);

	return iomem;
}

/**
 * nfp_cpp_area_readl() - Read a u32 word from an area
 * @area:	CPP Area handle
 * @offset:	Offset into area
 * @value:	Pointer to read buffer
 *
 * Return: 0 on success, or -ERRNO
 */
int nfp_cpp_area_readl(struct nfp_cpp_area *area,
		       unsigned long offset, u32 *value)
{
	u8 tmp[4];
	int n;

	n = nfp_cpp_area_read(area, offset, &tmp, sizeof(tmp));
	if (n != sizeof(tmp))
		return n < 0 ? n : -EIO;

	*value = get_unaligned_le32(tmp);
	return 0;
}

/**
 * nfp_cpp_area_writel() - Write a u32 word to an area
 * @area:	CPP Area handle
 * @offset:	Offset into area
 * @value:	Value to write
 *
 * Return: 0 on success, or -ERRNO
 */
int nfp_cpp_area_writel(struct nfp_cpp_area *area,
			unsigned long offset, u32 value)
{
	u8 tmp[4];
	int n;

	put_unaligned_le32(value, tmp);
	n = nfp_cpp_area_write(area, offset, &tmp, sizeof(tmp));

	return n == sizeof(tmp) ? 0 : n < 0 ? n : -EIO;
}

/**
 * nfp_cpp_area_readq() - Read a u64 word from an area
 * @area:	CPP Area handle
 * @offset:	Offset into area
 * @value:	Pointer to read buffer
 *
 * Return: 0 on success, or -ERRNO
 */
int nfp_cpp_area_readq(struct nfp_cpp_area *area,
		       unsigned long offset, u64 *value)
{
	u8 tmp[8];
	int n;

	n = nfp_cpp_area_read(area, offset, &tmp, sizeof(tmp));
	if (n != sizeof(tmp))
		return n < 0 ? n : -EIO;

	*value = get_unaligned_le64(tmp);
	return 0;
}

/**
 * nfp_cpp_area_writeq() - Write a u64 word to an area
 * @area:	CPP Area handle
 * @offset:	Offset into area
 * @value:	Value to write
 *
 * Return: 0 on success, or -ERRNO
 */
int nfp_cpp_area_writeq(struct nfp_cpp_area *area,
			unsigned long offset, u64 value)
{
	u8 tmp[8];
	int n;

	put_unaligned_le64(value, tmp);
	n = nfp_cpp_area_write(area, offset, &tmp, sizeof(tmp));

	return n == sizeof(tmp) ? 0 : n < 0 ? n : -EIO;
}

/**
 * nfp_cpp_area_fill() - fill a CPP area with a value
 * @area:	CPP area
 * @offset:	offset into CPP area
 * @value:	value to fill with
 * @length:	length of area to fill
 *
 * Fill indicated area with given value.
 *
 * Return: length of io, or -ERRNO
 */
int nfp_cpp_area_fill(struct nfp_cpp_area *area,
		      unsigned long offset, u32 value, size_t length)
{
	u8 tmp[4];
	size_t i;
	int k;

	put_unaligned_le32(value, tmp);

	if (offset % sizeof(tmp) || length % sizeof(tmp))
		return -EINVAL;

	for (i = 0; i < length; i += sizeof(tmp)) {
		k = nfp_cpp_area_write(area, offset + i, &tmp, sizeof(tmp));
		if (k < 0)
			return k;
	}

	return i;
}

/**
 * nfp_cpp_area_cache_add() - Permanently reserve and area for the hot cache
 * @cpp:	NFP CPP handle
 * @size:	Size of the area - MUST BE A POWER OF 2.
 */
int nfp_cpp_area_cache_add(struct nfp_cpp *cpp, size_t size)
{
	struct nfp_cpp_area_cache *cache;
	struct nfp_cpp_area *area;

	/* Allocate an area - we use the MU target's base as a placeholder,
	 * as all supported chips have a MU.
	 */
	area = nfp_cpp_area_alloc(cpp, NFP_CPP_ID(7, NFP_CPP_ACTION_RW, 0),
				  0, size);
	if (!area)
		return -ENOMEM;

	cache = kzalloc(sizeof(*cache), GFP_KERNEL);
	if (!cache) {
		nfp_cpp_area_free(area);
		return -ENOMEM;
	}

	cache->id = 0;
	cache->addr = 0;
	cache->size = size;
	cache->area = area;
	mutex_lock(&cpp->area_cache_mutex);
	list_add_tail(&cache->entry, &cpp->area_cache_list);
	mutex_unlock(&cpp->area_cache_mutex);

	return 0;
}

static struct nfp_cpp_area_cache *
area_cache_get(struct nfp_cpp *cpp, u32 id,
	       u64 addr, unsigned long *offset, size_t length)
{
	struct nfp_cpp_area_cache *cache;
	int err;

	/* Early exit when length == 0, which prevents
	 * the need for special case code below when
	 * checking against available cache size.
	 */
	if (length == 0 || id == 0)
		return NULL;

	/* Remap from cpp_island to cpp_target */
	err = nfp_target_cpp(id, addr, &id, &addr, cpp->imb_cat_table);
	if (err < 0)
		return NULL;

	mutex_lock(&cpp->area_cache_mutex);

	if (list_empty(&cpp->area_cache_list)) {
		mutex_unlock(&cpp->area_cache_mutex);
		return NULL;
	}

	addr += *offset;

	/* See if we have a match */
	list_for_each_entry(cache, &cpp->area_cache_list, entry) {
		if (id == cache->id &&
		    addr >= cache->addr &&
		    addr + length <= cache->addr + cache->size)
			goto exit;
	}

	/* No matches - inspect the tail of the LRU */
	cache = list_entry(cpp->area_cache_list.prev,
			   struct nfp_cpp_area_cache, entry);

	/* Can we fit in the cache entry? */
	if (round_down(addr + length - 1, cache->size) !=
	    round_down(addr, cache->size)) {
		mutex_unlock(&cpp->area_cache_mutex);
		return NULL;
	}

	/* If id != 0, we will need to release it */
	if (cache->id) {
		nfp_cpp_area_release(cache->area);
		cache->id = 0;
		cache->addr = 0;
	}

	/* Adjust the start address to be cache size aligned */
	cache->id = id;
	cache->addr = addr & ~(u64)(cache->size - 1);

	/* Re-init to the new ID and address */
	if (cpp->op->area_init) {
		err = cpp->op->area_init(cache->area,
					 id, cache->addr, cache->size);
		if (err < 0) {
			mutex_unlock(&cpp->area_cache_mutex);
			return NULL;
		}
	}

	/* Attempt to acquire */
	err = nfp_cpp_area_acquire(cache->area);
	if (err < 0) {
		mutex_unlock(&cpp->area_cache_mutex);
		return NULL;
	}

exit:
	/* Adjust offset */
	*offset = addr - cache->addr;
	return cache;
}

static void
area_cache_put(struct nfp_cpp *cpp, struct nfp_cpp_area_cache *cache)
{
	if (!cache)
		return;

	/* Move to front of LRU */
	list_move(&cache->entry, &cpp->area_cache_list);

	mutex_unlock(&cpp->area_cache_mutex);
}

static int __nfp_cpp_read(struct nfp_cpp *cpp, u32 destination,
			  unsigned long long address, void *kernel_vaddr,
			  size_t length)
{
	struct nfp_cpp_area_cache *cache;
	struct nfp_cpp_area *area;
	unsigned long offset = 0;
	int err;

	cache = area_cache_get(cpp, destination, address, &offset, length);
	if (cache) {
		area = cache->area;
	} else {
		area = nfp_cpp_area_alloc(cpp, destination, address, length);
		if (!area)
			return -ENOMEM;

		err = nfp_cpp_area_acquire(area);
		if (err) {
			nfp_cpp_area_free(area);
			return err;
		}
	}

	err = nfp_cpp_area_read(area, offset, kernel_vaddr, length);

	if (cache)
		area_cache_put(cpp, cache);
	else
		nfp_cpp_area_release_free(area);

	return err;
}

/**
 * nfp_cpp_read() - read from CPP target
 * @cpp:		CPP handle
 * @destination:	CPP id
 * @address:		offset into CPP target
 * @kernel_vaddr:	kernel buffer for result
 * @length:		number of bytes to read
 *
 * Return: length of io, or -ERRNO
 */
int nfp_cpp_read(struct nfp_cpp *cpp, u32 destination,
		 unsigned long long address, void *kernel_vaddr,
		 size_t length)
{
	size_t n, offset;
	int ret;

	for (offset = 0; offset < length; offset += n) {
		unsigned long long r_addr = address + offset;

		/* make first read smaller to align to safe window */
		n = min_t(size_t, length - offset,
			  ALIGN(r_addr + 1, NFP_CPP_SAFE_AREA_SIZE) - r_addr);

		ret = __nfp_cpp_read(cpp, destination, address + offset,
				     kernel_vaddr + offset, n);
		if (ret < 0)
			return ret;
		if (ret != n)
			return offset + n;
	}

	return length;
}

static int __nfp_cpp_write(struct nfp_cpp *cpp, u32 destination,
			   unsigned long long address,
			   const void *kernel_vaddr, size_t length)
{
	struct nfp_cpp_area_cache *cache;
	struct nfp_cpp_area *area;
	unsigned long offset = 0;
	int err;

	cache = area_cache_get(cpp, destination, address, &offset, length);
	if (cache) {
		area = cache->area;
	} else {
		area = nfp_cpp_area_alloc(cpp, destination, address, length);
		if (!area)
			return -ENOMEM;

		err = nfp_cpp_area_acquire(area);
		if (err) {
			nfp_cpp_area_free(area);
			return err;
		}
	}

	err = nfp_cpp_area_write(area, offset, kernel_vaddr, length);

	if (cache)
		area_cache_put(cpp, cache);
	else
		nfp_cpp_area_release_free(area);

	return err;
}

/**
 * nfp_cpp_write() - write to CPP target
 * @cpp:		CPP handle
 * @destination:	CPP id
 * @address:		offset into CPP target
 * @kernel_vaddr:	kernel buffer to read from
 * @length:		number of bytes to write
 *
 * Return: length of io, or -ERRNO
 */
int nfp_cpp_write(struct nfp_cpp *cpp, u32 destination,
		  unsigned long long address,
		  const void *kernel_vaddr, size_t length)
{
	size_t n, offset;
	int ret;

	for (offset = 0; offset < length; offset += n) {
		unsigned long long w_addr = address + offset;

		/* make first write smaller to align to safe window */
		n = min_t(size_t, length - offset,
			  ALIGN(w_addr + 1, NFP_CPP_SAFE_AREA_SIZE) - w_addr);

		ret = __nfp_cpp_write(cpp, destination, address + offset,
				      kernel_vaddr + offset, n);
		if (ret < 0)
			return ret;
		if (ret != n)
			return offset + n;
	}

	return length;
}

/* Return the correct CPP address, and fixup xpb_addr as needed. */
static u32 nfp_xpb_to_cpp(struct nfp_cpp *cpp, u32 *xpb_addr)
{
	int island;
	u32 xpb;

	xpb = NFP_CPP_ID(14, NFP_CPP_ACTION_RW, 0);
	/* Ensure that non-local XPB accesses go
	 * out through the global XPBM bus.
	 */
	island = (*xpb_addr >> 24) & 0x3f;
	if (!island)
		return xpb;

	if (island != 1) {
		*xpb_addr |= 1 << 30;
		return xpb;
	}

	/* Accesses to the ARM Island overlay uses Island 0 / Global Bit */
	*xpb_addr &= ~0x7f000000;
	if (*xpb_addr < 0x60000) {
		*xpb_addr |= 1 << 30;
	} else {
		/* And only non-ARM interfaces use the island id = 1 */
		if (NFP_CPP_INTERFACE_TYPE_of(nfp_cpp_interface(cpp))
		    != NFP_CPP_INTERFACE_TYPE_ARM)
			*xpb_addr |= 1 << 24;
	}

	return xpb;
}

/**
 * nfp_xpb_readl() - Read a u32 word from a XPB location
 * @cpp:	CPP device handle
 * @xpb_addr:	Address for operation
 * @value:	Pointer to read buffer
 *
 * Return: 0 on success, or -ERRNO
 */
int nfp_xpb_readl(struct nfp_cpp *cpp, u32 xpb_addr, u32 *value)
{
	u32 cpp_dest = nfp_xpb_to_cpp(cpp, &xpb_addr);

	return nfp_cpp_readl(cpp, cpp_dest, xpb_addr, value);
}

/**
 * nfp_xpb_writel() - Write a u32 word to a XPB location
 * @cpp:	CPP device handle
 * @xpb_addr:	Address for operation
 * @value:	Value to write
 *
 * Return: 0 on success, or -ERRNO
 */
int nfp_xpb_writel(struct nfp_cpp *cpp, u32 xpb_addr, u32 value)
{
	u32 cpp_dest = nfp_xpb_to_cpp(cpp, &xpb_addr);

	return nfp_cpp_writel(cpp, cpp_dest, xpb_addr, value);
}

/**
 * nfp_xpb_writelm() - Modify bits of a 32-bit value from the XPB bus
 * @cpp:	NFP CPP device handle
 * @xpb_tgt:	XPB target and address
 * @mask:	mask of bits to alter
 * @value:	value to modify
 *
 * KERNEL: This operation is safe to call in interrupt or softirq context.
 *
 * Return: 0 on success, or -ERRNO
 */
int nfp_xpb_writelm(struct nfp_cpp *cpp, u32 xpb_tgt,
		    u32 mask, u32 value)
{
	int err;
	u32 tmp;

	err = nfp_xpb_readl(cpp, xpb_tgt, &tmp);
	if (err < 0)
		return err;

	tmp &= ~mask;
	tmp |= mask & value;
	return nfp_xpb_writel(cpp, xpb_tgt, tmp);
}

/**
 * nfp_cpp_event_priv() - return private struct for CPP event
 * @cpp_event:	CPP event handle
 *
 * Return: Private data of the event, or NULL
 */
void *nfp_cpp_event_priv(struct nfp_cpp_event *cpp_event)
{
	return &cpp_event[1];
}

/**
 * nfp_cpp_event_cpp() - return CPP handle for CPP event
 * @cpp_event:	CPP event handle
 *
 * Return: NFP CPP handle of the event
 */
struct nfp_cpp *nfp_cpp_event_cpp(struct nfp_cpp_event *cpp_event)
{
	return cpp_event->cpp;
}

/**
 * nfp_cpp_event_alloc() - Allocate an event monitor
 * @cpp:	CPP device handle
 * @match:	Event match bits
 * @mask:	Event match bits to compare against
 * @type:	Event filter type
 *
 * Return: NFP CPP event handle, or ERR_PTR()
 */
struct nfp_cpp_event *
nfp_cpp_event_alloc(struct nfp_cpp *cpp, u32 match, u32 mask, int type)
{
	struct nfp_cpp_event *event;
	int err;

	if (!cpp->op->event_acquire)
		return ERR_PTR(-ENODEV);

	if (type < 0)
		type = 0;

	if (type > 7)
		return ERR_PTR(-EINVAL);

	event = kzalloc(sizeof(*event) + cpp->op->event_priv_size,
			GFP_KERNEL);
	if (!event)
		return ERR_PTR(-ENOMEM);

	event->cpp = nfp_cpp_get(cpp);

	spin_lock_init(&event->callback.lock);

	err = cpp->op->event_acquire(event, mask, match, type);
	if (err < 0) {
		nfp_cpp_put(cpp);
		kfree(event);
		return ERR_PTR(err);
	}

	return event;
}

/**
 * nfp_cpp_event_as_callback() - Execute callback when event is triggered
 * @event:	Event handle
 * @func:	Function to call on trigger
 * @priv:	Private data for function
 *
 * Return: 0, or -ERRNO
 */
int nfp_cpp_event_as_callback(struct nfp_cpp_event *event,
			      void (*func)(void *), void *priv)
{
	unsigned long flags;

	spin_lock_irqsave(&event->callback.lock, flags);
	event->callback.func = func;
	event->callback.priv = priv;
	spin_unlock_irqrestore(&event->callback.lock, flags);

	return 0;
}

/**
 * nfp_cpp_event_callback() - Execute the event's callback
 * @event:	Event handle
 *
 * This function should be called by the NFP CPP implementation
 * when it's Event Monitor wants to trigger the event's action.
 */
void nfp_cpp_event_callback(struct nfp_cpp_event *event)
{
	void (*func)(void *);
	unsigned long flags;
	void *priv;

	if (!event)
		return;

	/* This is expected to be called in IRQ context */
	spin_lock_irqsave(&event->callback.lock, flags);
	func = event->callback.func;
	priv = event->callback.priv;
	spin_unlock_irqrestore(&event->callback.lock, flags);

	if (func)
		func(priv);
}

/**
 * nfp_cpp_event_free() - Free an event, releasing the event monitor
 * @event:	Event handle
 */
void nfp_cpp_event_free(struct nfp_cpp_event *event)
{
	struct nfp_cpp *cpp = nfp_cpp_event_cpp(event);

	if (cpp->op->event_release)
		cpp->op->event_release(event);

	nfp_cpp_put(cpp);
	kfree(event);
}

/* Lockdep markers */
static struct lock_class_key nfp_cpp_resource_lock_key;

static void nfp_cpp_dev_release(struct device *dev)
{
	/* Nothing to do here - it just makes the kernel happy */
}

/**
 * nfp_cpp_from_operations() - Create a NFP CPP handle
 *                             from an operations structure
 * @ops:	NFP CPP operations structure
 * @parent:	Parent device
 * @priv:	Private data of low-level implementation
 *
 * NOTE: On failure, cpp_ops->free will be called!
 *
 * Return: NFP CPP handle on success, ERR_PTR on failure
 */
struct nfp_cpp *
nfp_cpp_from_operations(const struct nfp_cpp_operations *ops,
			struct device *parent, void *priv)
{
	const u32 arm = NFP_CPP_ID(NFP_CPP_TARGET_ARM, NFP_CPP_ACTION_RW, 0);
	struct nfp_cpp *cpp;
	int id, ifc, err;
	u32 mask[2];
	u32 xpbaddr;
	size_t tgt;

	id = nfp_cpp_id_acquire();
	if (id < 0) {
		dev_err(parent, "Out of NFP CPP API slots.\n");
		return ERR_PTR(id);
	}

	cpp = kzalloc(sizeof(*cpp), GFP_KERNEL);
	if (!cpp) {
		err = -ENOMEM;
		goto err_malloc;
	}

	cpp->id = id;
	cpp->op = ops;
	cpp->priv = priv;

	ifc = ops->get_interface(parent);
	if (ifc < 0) {
		err = ifc;
		goto err_free_cpp;
	}
	cpp->interface = ifc;
	if (ops->read_serial) {
		err = ops->read_serial(parent, cpp->serial);
		if (err)
			goto err_free_cpp;
	}

	kref_init(&cpp->kref);
	rwlock_init(&cpp->resource_lock);
	init_waitqueue_head(&cpp->waitq);
	lockdep_set_class(&cpp->resource_lock, &nfp_cpp_resource_lock_key);
	INIT_LIST_HEAD(&cpp->resource_list);
	INIT_LIST_HEAD(&cpp->area_cache_list);
	mutex_init(&cpp->area_cache_mutex);
	cpp->dev.init_name = "cpp";
	cpp->dev.parent = parent;
	cpp->dev.release = nfp_cpp_dev_release;
	err = device_register(&cpp->dev);
	if (err < 0) {
		put_device(&cpp->dev);
		goto err_free_cpp;
	}

	dev_set_drvdata(&cpp->dev, cpp);

	err = device_create_file(&cpp->dev, &dev_attr_area);
	if (err < 0)
		goto err_attr;

	/* NOTE: cpp_lock is NOT locked for op->init,
	 * since it may call NFP CPP API operations
	 */
	if (cpp->op->init) {
		err = cpp->op->init(cpp);
		if (err < 0) {
			dev_err(parent,
				"NFP interface initialization failed\n");
			goto err_out;
		}
	}

	err = nfp_cpp_model_autodetect(cpp, &cpp->model);
	if (err < 0) {
		dev_err(parent, "NFP model detection failed\n");
		goto err_out;
	}

	for (tgt = 0; tgt < ARRAY_SIZE(cpp->imb_cat_table); tgt++) {
			/* Hardcoded XPB IMB Base, island 0 */
		xpbaddr = 0x000a0000 + (tgt * 4);
		err = nfp_xpb_readl(cpp, xpbaddr,
				    &cpp->imb_cat_table[tgt]);
		if (err < 0) {
			dev_err(parent,
				"Can't read CPP mapping from device\n");
			goto err_out;
		}
	}

	nfp_cpp_readl(cpp, arm, NFP_ARM_GCSR + NFP_ARM_GCSR_SOFTMODEL2,
		      &mask[0]);
	nfp_cpp_readl(cpp, arm, NFP_ARM_GCSR + NFP_ARM_GCSR_SOFTMODEL3,
		      &mask[1]);

	cpp->island_mask = (u64)mask[1] << 32 | mask[0];

	err = nfp_cpp_set_mu_locality_lsb(cpp);
	if (err < 0) {
		dev_err(parent,	"Can't calculate MU locality bit offset\n");
		goto err_out;
	}

	write_lock(&nfp_cpp_list_lock);
	list_add_tail(&cpp->list, &nfp_cpp_list);
	write_unlock(&nfp_cpp_list_lock);

	dev_info(cpp->dev.parent, "Model: 0x%08x, SN: %pM, Ifc: 0x%04x\n",
		 nfp_cpp_model(cpp), cpp->serial, nfp_cpp_interface(cpp));

	return cpp;

err_out:
	device_remove_file(&cpp->dev, &dev_attr_area);
err_attr:
	device_unregister(&cpp->dev);
err_free_cpp:
	kfree(cpp);
err_malloc:
	nfp_cpp_id_release(id);
	return ERR_PTR(err);
}

/**
 * nfp_cpp_priv() - Get the operations private data of a CPP handle
 * @cpp:	CPP handle
 *
 * Return: Private data for the NFP CPP handle
 */
void *nfp_cpp_priv(struct nfp_cpp *cpp)
{
	return cpp->priv;
}

/**
 * nfp_cpp_device() - Get the Linux device handle of a CPP handle
 * @cpp:	CPP handle
 *
 * Return: Device for the NFP CPP bus
 */
struct device *nfp_cpp_device(struct nfp_cpp *cpp)
{
	return &cpp->dev;
}

/**
 * nfp_cpp_island_mask() - Return the island mask
 * @cpp:	NFP CPP handle
 *
 * Return: 64-bit island mask
 */
u64 nfp_cpp_island_mask(struct nfp_cpp *cpp)
{
	return cpp->island_mask;
}

#define NFP_EXPL_OP(func, expl, args...)			  \
	({							  \
		struct nfp_cpp *cpp = nfp_cpp_explicit_cpp(expl); \
		int err = -ENODEV;				  \
								  \
		if (cpp->op->func) {				  \
			nfp_cpp_get(cpp);			  \
			err = cpp->op->func(expl, ##args);	  \
			nfp_cpp_put(cpp);			  \
		}						  \
		err;						  \
	})

#define NFP_EXPL_OP_NR(func, expl, args...)			  \
	({							  \
		struct nfp_cpp *cpp = nfp_cpp_explicit_cpp(expl); \
								  \
		if (cpp->op->func) {				  \
			nfp_cpp_get(cpp);			  \
			cpp->op->func(expl, ##args);		  \
			nfp_cpp_put(cpp);			  \
		}						  \
	})

/**
 * nfp_cpp_explicit_acquire() - Acquire explicit access handle
 * @cpp:	NFP CPP handle
 *
 * The 'data_ref' and 'signal_ref' values are useful when
 * constructing the NFP_EXPL_CSR1 and NFP_EXPL_POST values.
 *
 * Return: NFP CPP explicit handle
 */
struct nfp_cpp_explicit *nfp_cpp_explicit_acquire(struct nfp_cpp *cpp)
{
	struct nfp_cpp_explicit *expl;
	int err;

	expl = kzalloc(sizeof(*expl) + cpp->op->explicit_priv_size, GFP_KERNEL);
	if (!expl)
		return NULL;

	expl->cpp = cpp;
	err = NFP_EXPL_OP(explicit_acquire, expl);
	if (err < 0) {
		kfree(expl);
		return NULL;
	}

	return expl;
}

/**
 * nfp_cpp_explicit_set_target() - Set target fields for explicit
 * @expl:	Explicit handle
 * @cpp_id:	CPP ID field
 * @len:	CPP Length field
 * @mask:	CPP Mask field
 *
 * Return: 0, or -ERRNO
 */
int nfp_cpp_explicit_set_target(struct nfp_cpp_explicit *expl,
				u32 cpp_id, u8 len, u8 mask)
{
	expl->cmd.cpp_id = cpp_id;
	expl->cmd.len = len;
	expl->cmd.byte_mask = mask;

	return 0;
}

/**
 * nfp_cpp_explicit_set_data() - Set data fields for explicit
 * @expl:	Explicit handle
 * @data_master: CPP Data Master field
 * @data_ref:	CPP Data Ref field
 *
 * Return: 0, or -ERRNO
 */
int nfp_cpp_explicit_set_data(struct nfp_cpp_explicit *expl,
			      u8 data_master, u16 data_ref)
{
	expl->cmd.data_master = data_master;
	expl->cmd.data_ref = data_ref;

	return 0;
}

/**
 * nfp_cpp_explicit_set_signal() - Set signal fields for explicit
 * @expl:	Explicit handle
 * @signal_master: CPP Signal Master field
 * @signal_ref:	CPP Signal Ref field
 *
 * Return: 0, or -ERRNO
 */
int nfp_cpp_explicit_set_signal(struct nfp_cpp_explicit *expl,
				u8 signal_master, u8 signal_ref)
{
	expl->cmd.signal_master = signal_master;
	expl->cmd.signal_ref = signal_ref;

	return 0;
}

/**
 * nfp_cpp_explicit_set_posted() - Set completion fields for explicit
 * @expl:	Explicit handle
 * @posted:	True for signaled completion, false otherwise
 * @siga:	CPP Signal A field
 * @siga_mode:	CPP Signal A Mode field
 * @sigb:	CPP Signal B field
 * @sigb_mode:	CPP Signal B Mode field
 *
 * Return: 0, or -ERRNO
 */
int nfp_cpp_explicit_set_posted(struct nfp_cpp_explicit *expl, int posted,
				u8 siga,
				enum nfp_cpp_explicit_signal_mode siga_mode,
				u8 sigb,
				enum nfp_cpp_explicit_signal_mode sigb_mode)
{
	expl->cmd.posted = posted;
	expl->cmd.siga = siga;
	expl->cmd.sigb = sigb;
	expl->cmd.siga_mode = siga_mode;
	expl->cmd.sigb_mode = sigb_mode;

	return 0;
}

/**
 * nfp_cpp_explicit_put() - Set up the write (pull) data for a explicit access
 * @expl:	NFP CPP Explicit handle
 * @buff:	Data to have the target pull in the transaction
 * @len:	Length of data, in bytes
 *
 * The 'len' parameter must be less than or equal to 128 bytes.
 *
 * If this function is called before the configuration
 * registers are set, it will return -EINVAL.
 *
 * Return: 0, or -ERRNO
 */
int nfp_cpp_explicit_put(struct nfp_cpp_explicit *expl,
			 const void *buff, size_t len)
{
	return NFP_EXPL_OP(explicit_put, expl, buff, len);
}

/**
 * nfp_cpp_explicit_do() - Execute a transaction, and wait for it to complete
 * @expl:	NFP CPP Explicit handle
 * @address:	Address to send in the explicit transaction
 *
 * If this function is called before the configuration
 * registers are set, it will return -1, with an errno of EINVAL.
 *
 * Return: 0, or -ERRNO
 */
int nfp_cpp_explicit_do(struct nfp_cpp_explicit *expl, u64 address)
{
	return NFP_EXPL_OP(explicit_do, expl, &expl->cmd, address);
}

/**
 * nfp_cpp_explicit_get() - Get the 'push' (read) data from a explicit access
 * @expl:	NFP CPP Explicit handle
 * @buff:	Data that the target pushed in the transaction
 * @len:	Length of data, in bytes
 *
 * The 'len' parameter must be less than or equal to 128 bytes.
 *
 * If this function is called before all three configuration
 * registers are set, it will return -1, with an errno of EINVAL.
 *
 * If this function is called before nfp_cpp_explicit_do()
 * has completed, it will return -1, with an errno of EBUSY.
 *
 * Return: 0, or -ERRNO
 */
int nfp_cpp_explicit_get(struct nfp_cpp_explicit *expl, void *buff, size_t len)
{
	return NFP_EXPL_OP(explicit_get, expl, buff, len);
}

/**
 * nfp_cpp_explicit_release() - Release explicit access handle
 * @expl:	NFP CPP Explicit handle
 *
 */
void nfp_cpp_explicit_release(struct nfp_cpp_explicit *expl)
{
	NFP_EXPL_OP_NR(explicit_release, expl);
	kfree(expl);
}

/**
 * nfp_cpp_explicit_cpp() - return CPP handle for CPP explicit
 * @cpp_explicit:	CPP explicit handle
 *
 * Return: NFP CPP handle of the explicit
 */
struct nfp_cpp *nfp_cpp_explicit_cpp(struct nfp_cpp_explicit *cpp_explicit)
{
	return cpp_explicit->cpp;
}

/**
 * nfp_cpp_explicit_priv() - return private struct for CPP explicit
 * @cpp_explicit:	CPP explicit handle
 *
 * Return: private data of the explicit, or NULL
 */
void *nfp_cpp_explicit_priv(struct nfp_cpp_explicit *cpp_explicit)
{
	return &cpp_explicit[1];
}

/**
 * nfp_cppcore_init() - Initialize base level NFP CPP API
 *
 * Return: 0, or -ERRNO
 */
int nfp_cppcore_init(void)
{
#ifndef PCI_DEVICE_ID_NETRONOME_NFP4000
	if (!ignore_quirks) {
		pr_err("Error: this kernel does not have quirk_nfp6000\n");
		pr_err("Please contact support@netronome.com for more information\n");
		return -EINVAL;
	}
	pr_warn("Warning: this kernel does not have quirk_nfp6000\n");
	pr_warn("Please contact support@netronome.com for more information\n");
#endif
	pr_info("Netronome NFP CPP API\n");

	mutex_init(&nfp_cpp_id_lock);
	INIT_LIST_HEAD(&nfp_cpp_list);
	rwlock_init(&nfp_cpp_list_lock);

	return 0;
}

/**
 * nfp_cppcore_exit() - Cleanup base level NFP CPP API
 */
void nfp_cppcore_exit(void)
{
	BUG_ON(!list_empty(&nfp_cpp_list));
}
