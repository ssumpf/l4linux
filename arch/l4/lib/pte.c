#include <linux/mm.h>
#include <linux/spinlock.h>
#include <linux/vmalloc.h>

#include <asm/segment.h>
#include <asm/pgtable.h>
#include <asm/pgalloc.h>

#include <asm/api/config.h>

#include <asm/generic/memory.h>
#include <asm/generic/task.h>
#include <asm/generic/vmalloc.h>
#include <asm/generic/ioremap.h>
#include <asm/generic/log.h>

#include <asm/l4lxapi/memory.h>

#include <l4/sys/task.h>
#include <l4/sys/kdebug.h>
#include <l4/re/consts.h>

#ifdef ARCH_arm
#include <asm/l4x/dma.h>
#endif

static void l4x_flush_page(struct mm_struct *mm,
                           unsigned long address,
                           unsigned long vaddr,
                           int size,
                           unsigned long flush_rights)
{
	l4_msgtag_t tag;

	if (mm && mm->context.l4x_unmap_mode == L4X_UNMAP_MODE_SKIP)
		return;

	/* some checks: */
	if (address > 0x80000000UL) {
		unsigned long remap;
		remap = find_ioremap_entry(address);

		/* VU: it may happen, that memory is not remapped but mapped in
		 * user space, if a task mmaps /dev/mem but never accesses it.
		 * Therefore, we fail silently...
		 */
		if (!remap)
			return;

		address = remap;

	} else if ((address & PAGE_MASK) == 0)
		address = PAGE0_PAGE_ADDRESS;

#if 0
	/* only for debugging */
	else {
		if ((address >= (unsigned long)high_memory)
		    && (address < 0x80000000UL)) {
			printk("flushing non physical page (0x%lx)\n",
				    address);
			enter_kdebug("flush_page: non physical page");
		}
	}
#endif

	/* do the real flush */
	if (mm && !l4_is_invalid_cap(mm->context.task) && mm->context.task) {
		/* Direct flush in the child, use virtual address in the
		 * child address space */
		tag = L4XV_FN(l4_msgtag_t,
		              l4_task_unmap(mm->context.task,
		                           l4_fpage(vaddr & PAGE_MASK, size,
		                                    flush_rights),
		                           L4_FP_ALL_SPACES));
	} else {
		/* Flush all pages in all childs using the 'physical'
		 * address known in the Linux server */
		tag = L4XV_FN(l4_msgtag_t,
		              l4_task_unmap(L4RE_THIS_TASK_CAP,
			                    l4_fpage(address & PAGE_MASK, size,
		                                     flush_rights),
			                    L4_FP_OTHER_SPACES));
	}
	if (l4_error(tag))
		l4x_printf("l4_task_unmap error %ld\n", l4_error(tag));
}

unsigned long l4x_set_pte(struct mm_struct *mm,
                          unsigned long addr,
                          pte_t old, pte_t pteval)
{
	/*
	 * Check if any invalidation is necessary
	 *
	 * Invalidation (flush) necessary if:
	 *   old page was present
	 *       new page is not present OR
	 *       new page has another physical address OR
	 *       new page has another protection OR
	 *       new page has other access attributes
	 */

	/* old was present && new not -> flush */
	int flush_rights = L4_FPAGE_RWX;

	if (pte_present(pteval)) {
		/* new page is present,
		 * now we have to find out what has changed */
		if (((pte_val(old) ^ pte_val(pteval)) & PAGE_MASK)
		    || (pte_young(old) && !pte_young(pteval))) {
			/* physical page frame changed
			 * || access attribute changed -> flush */
			/* flush is the default */
		} else if ((pte_write(old) && !pte_write(pteval))
		           || (pte_dirty(old) && !pte_dirty(pteval))) {
			/* Protection changed from r/w to ro
			 * or page now clean -> remap */
			flush_rights = L4_FPAGE_W;
		} else {
			/* nothing changed, simply return */
			return pte_val(pteval);
		}
	}

	/* Ok, now actually flush or remap the page */
	L4XV_FN_v(l4x_flush_page(mm, pte_val(old), addr, PAGE_SHIFT, flush_rights));
	return pte_val(pteval);
}

void l4x_pte_clear(struct mm_struct *mm, unsigned long addr, pte_t pteval)
{
	/* Invalidate page */
	L4XV_FN_v(l4x_flush_page(mm, pte_val(pteval), addr, PAGE_SHIFT, L4_FPAGE_RWX));
}





/* (Un)Mapping function for vmalloc'ed memory */

void l4x_vmalloc_map_vm_area(unsigned long address, unsigned long end)
{
	if (address & ~PAGE_MASK)
		enter_kdebug("map_vm_area: Unaligned address!");

	if (!(   (VMALLOC_START <= address && end <= VMALLOC_END)
	      || (MODULES_VADDR <= address && end <= MODULES_END))) {
		pr_err("%s: %lx-%lx outside areas: %lx-%lx, %lx-%lx\n",
		       __func__, address, end,
		       VMALLOC_START, VMALLOC_END, MODULES_VADDR, MODULES_END);
		pr_err("%s: %p\n", __func__, __builtin_return_address(0));
		enter_kdebug("KK");
		return;
	}

	for (; address < end; address += PAGE_SIZE) {
		pte_t *ptep;

#ifdef CONFIG_ARM
		unsigned long o;
		if ((o = l4x_arm_is_selfmapped_addr(address))) {
			address += o - PAGE_SIZE;
			continue;
		}
#endif

		ptep = lookup_pte(&init_mm, address);

		if (!ptep || !pte_present(*ptep)) {
			if (0)
				printk("%s: No (valid) PTE for %08lx?!"
			               " (ptep: %p, pte: %08"
#ifndef CONFIG_ARM
				       "l"
#endif
				       "x\n",
			               __func__, address,
			               ptep, pte_val(*ptep));
			continue;
		}
		l4x_virtual_mem_register(address, *ptep);
		l4lx_memory_map_virtual_page(address, *ptep);
	}
}


void l4x_vmalloc_unmap_vm_area(unsigned long address, unsigned long end)
{
	if (address & ~PAGE_MASK)
		enter_kdebug("unmap_vm_area: Unaligned address!");

	for (; address < end; address += PAGE_SIZE) {

#ifdef CONFIG_ARM
		unsigned long o;
		if ((o = l4x_arm_is_selfmapped_addr(address))) {
			address += o - PAGE_SIZE;
			continue;
		}
#endif

		/* check whether we are really flushing a vm page */
		if (address < (unsigned long)high_memory
#ifdef CONFIG_ARM
		    && !(address >= MODULES_VADDR && address < MODULES_END)
#endif
		    ) {
			printk("flushing wrong page, addr: %lx\n", address);
			enter_kdebug("l4x_vmalloc_unmap_vm_area");
			continue;
		}
		l4x_virtual_mem_unregister(address);
		l4lx_memory_unmap_virtual_page(address);
	}
}
