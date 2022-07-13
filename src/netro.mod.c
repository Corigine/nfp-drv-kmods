#include <linux/build-salt.h>
#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

BUILD_SALT;

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

#ifdef RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0x3904ae37, "module_layout" },
	{ 0x57051bde, "alloc_pages_current" },
	{ 0x56cacb79, "device_remove_file" },
	{ 0x2e70a32f, "kmalloc_caches" },
	{ 0xd2b09ce5, "__kmalloc" },
	{ 0xdaf485b9, "pv_lock_ops" },
	{ 0x84f15016, "boot_cpu_data" },
	{ 0xc29957c3, "__x86_indirect_thunk_rcx" },
	{ 0x87b8798d, "sg_next" },
	{ 0x99198537, "param_ops_bool" },
	{ 0xa6093a32, "mutex_unlock" },
	{ 0xb5aa7165, "dma_pool_destroy" },
	{ 0x97651e6c, "vmemmap_base" },
	{ 0x922f45a6, "__bitmap_clear" },
	{ 0x15ba50a6, "jiffies" },
	{ 0x4bfe9bd7, "ib_alloc_device" },
	{ 0x80097c47, "ib_dealloc_device" },
	{ 0xd9a5ea54, "__init_waitqueue_head" },
	{ 0xb44ad4b3, "_copy_to_user" },
	{ 0x17de3d5, "nr_cpu_ids" },
	{ 0x6de13801, "wait_for_completion" },
	{ 0xa7e83e08, "_dev_warn" },
	{ 0xfb578fc5, "memset" },
	{ 0xe72a585e, "current_task" },
	{ 0x64127b67, "bitmap_find_next_zero_area_off" },
	{ 0x9a76f11f, "__mutex_init" },
	{ 0x7c32d0f0, "printk" },
	{ 0xe1537255, "__list_del_entry_valid" },
	{ 0x5a5a2271, "__cpu_online_mask" },
	{ 0x4c9d28b0, "phys_base" },
	{ 0x479c3c86, "find_next_zero_bit" },
	{ 0xa1c76e0a, "_cond_resched" },
	{ 0x5792f848, "strlcpy" },
	{ 0x41aed6e7, "mutex_lock" },
	{ 0xede3221b, "ib_umem_get" },
	{ 0x6626afca, "down" },
	{ 0x2f7754a8, "dma_pool_free" },
	{ 0xd6b8e852, "request_threaded_irq" },
	{ 0x373db350, "kstrtoint" },
	{ 0x7d79ea60, "idr_alloc" },
	{ 0x890674ef, "_dev_err" },
	{ 0x68f31cbd, "__list_add_valid" },
	{ 0x2d8183f3, "radix_tree_delete" },
	{ 0xf11543ff, "find_first_zero_bit" },
	{ 0xfe6e59fa, "idr_remove" },
	{ 0xae1c54e4, "device_create_file" },
	{ 0xa504b198, "arch_dma_alloc_attrs" },
	{ 0x615911d7, "__bitmap_set" },
	{ 0x7cd8d75e, "page_offset_base" },
	{ 0x167c5967, "print_hex_dump" },
	{ 0xe0efab6c, "_dev_info" },
	{ 0x8ff4079b, "pv_irq_ops" },
	{ 0x77a68796, "__free_pages" },
	{ 0xb601be4c, "__x86_indirect_thunk_rdx" },
	{ 0x93a219c, "ioremap_nocache" },
	{ 0x688fda14, "ib_umem_page_count" },
	{ 0xb665f56d, "__cachemode2pte_tbl" },
	{ 0xdb7305a1, "__stack_chk_fail" },
	{ 0x96838eeb, "ib_register_device" },
	{ 0xa202a8e5, "kmalloc_order_trace" },
	{ 0x47941711, "_raw_spin_lock_irq" },
	{ 0x2ea2c95c, "__x86_indirect_thunk_rax" },
	{ 0x78410556, "ib_unregister_device" },
	{ 0xcd8dd495, "dma_pool_alloc" },
	{ 0xbdfb6dbb, "__fentry__" },
	{ 0x287a375, "__radix_tree_insert" },
	{ 0x9c9c94e1, "kmem_cache_alloc_trace" },
	{ 0xdbf17652, "_raw_spin_lock" },
	{ 0x37a0cba, "kfree" },
	{ 0x5cf323a3, "remap_pfn_range" },
	{ 0xedc03953, "iounmap" },
	{ 0xcf2a6966, "up" },
	{ 0xd2938951, "ib_modify_qp_is_ok" },
	{ 0x4ca9669f, "scnprintf" },
	{ 0xb5133acf, "radix_tree_lookup" },
	{ 0x63c4d61f, "__bitmap_weight" },
	{ 0x29361773, "complete" },
	{ 0x7f02188f, "__msecs_to_jiffies" },
	{ 0x4d1ff60a, "wait_for_completion_timeout" },
	{ 0x1a75aa0f, "dma_pool_create" },
	{ 0xb20a921e, "ib_umem_release" },
	{ 0x66bd7ea3, "dma_ops" },
	{ 0x88db9f48, "__check_object_size" },
	{ 0xc1514a3b, "free_irq" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=ib_core";


MODULE_INFO(srcversion, "C942C21096FF2C9892CAF9D");
