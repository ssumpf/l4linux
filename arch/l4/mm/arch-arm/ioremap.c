#include <linux/module.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/io.h>
#include <linux/sizes.h>

#include <asm/cp15.h>
#include <asm/cputype.h>
#include <asm/cacheflush.h>
#include <asm/mmu_context.h>
#include <asm/pgalloc.h>
#include <asm/tlbflush.h>
#include <asm/system_info.h>

#include <asm/mach/map.h>
#include <asm/mach/pci.h>
#include "mm.h"


LIST_HEAD(static_vmlist);

#ifndef CONFIG_L4
static struct static_vm *find_static_vm_paddr(phys_addr_t paddr,
			size_t size, unsigned int mtype)
{
	struct static_vm *svm;
	struct vm_struct *vm;

	list_for_each_entry(svm, &static_vmlist, list) {
		vm = &svm->vm;
		if (!(vm->flags & VM_ARM_STATIC_MAPPING))
			continue;
		if ((vm->flags & VM_ARM_MTYPE_MASK) != VM_ARM_MTYPE(mtype))
			continue;

		if (vm->phys_addr > paddr ||
			paddr + size - 1 > vm->phys_addr + vm->size - 1)
			continue;

		return svm;
	}

	return NULL;
}
#endif

struct static_vm *find_static_vm_vaddr(void *vaddr)
{
	struct static_vm *svm;
	struct vm_struct *vm;

	list_for_each_entry(svm, &static_vmlist, list) {
		vm = &svm->vm;

		/* static_vmlist is ascending order */
		if (vm->addr > vaddr)
			break;

		if (vm->addr <= vaddr && vm->addr + vm->size > vaddr)
			return svm;
	}

	return NULL;
}

void __init add_static_vm_early(struct static_vm *svm)
{
	struct static_vm *curr_svm;
	struct vm_struct *vm;
	void *vaddr;

	vm = &svm->vm;
	vm_area_add_early(vm);
	vaddr = vm->addr;

	list_for_each_entry(curr_svm, &static_vmlist, list) {
		vm = &curr_svm->vm;

		if (vm->addr > vaddr)
			break;
	}
	list_add_tail(&svm->list, &curr_svm->list);
}

int ioremap_page(unsigned long virt, unsigned long phys,
		 const struct mem_type *mtype)
{
	return ioremap_page_range(virt, virt + PAGE_SIZE, phys,
				  __pgprot(mtype->prot_pte));
}
EXPORT_SYMBOL(ioremap_page);

void __check_vmalloc_seq(struct mm_struct *mm)
{
	unsigned int seq;

	do {
		seq = init_mm.context.vmalloc_seq;
		memcpy(pgd_offset(mm, VMALLOC_START),
		       pgd_offset_k(VMALLOC_START),
		       sizeof(pgd_t) * (pgd_index(VMALLOC_END) -
					pgd_index(VMALLOC_START)));
		mm->context.vmalloc_seq = seq;
	} while (seq != init_mm.context.vmalloc_seq);
}

/*
 * Used by ioremap() and iounmap() code to mark (super)section-mapped
 * I/O regions in vm_struct->flags field.
 */

#define __ARCH_IOREMAP_C_INCLUDED__
#include "../io.c"

void __check_kvm_seq(struct mm_struct *mm)
{
}

/*
 * Remap an arbitrary physical address space into the kernel virtual
 * address space. Needed when the kernel wants to access high addresses
 * directly.
 *
 * NOTE! We need to allow non-page-aligned mappings too: we will obviously
 * have to convert them into an offset in a page-aligned mapping, but the
 * caller shouldn't need to know that small detail.
 */


void __iomem *
__arm_ioremap(unsigned long phys_addr, size_t size, unsigned int flags)
{
	return __l4x_ioremap(phys_addr, size, flags);
}
EXPORT_SYMBOL(__arm_ioremap);

void __iounmap(volatile void __iomem *addr)
{
	l4x_iounmap(addr);
}
EXPORT_SYMBOL(__iounmap);

void (*arch_iounmap)(volatile void __iomem *) = __iounmap;

void __arm_iounmap(volatile void __iomem *io_addr)
{
	arch_iounmap(io_addr);
}
EXPORT_SYMBOL(__arm_iounmap);
