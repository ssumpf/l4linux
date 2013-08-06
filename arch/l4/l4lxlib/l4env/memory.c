/*
 * Implementation of include/asm-l4/l4lxapi/memory.h
 */

#include <linux/bug.h>
#include <linux/kernel.h>
#include <linux/spinlock.h>

#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/l4lxapi/memory.h>
#include <asm/api/api.h>
#include <asm/generic/memory.h>
#include <asm/generic/vcpu.h>

#include <l4/re/c/rm.h>
#include <l4/sys/err.h>

int l4lx_memory_map_virtual_page(unsigned long address, pte_t pte)
{
	l4re_ds_t ds;
	l4_addr_t offset;
	l4_addr_t addr;
	unsigned flags;
	unsigned long size;
	int r;

#ifdef CONFIG_X86_64
	pte &= ~0x8000000000000000UL;
#endif

	addr = pte_val(pte);
	size = 1;
	if (L4XV_FN_i(l4re_rm_find(&addr, &size, &offset, &flags, &ds))) {
		printk("%s: Cannot get dataspace of %08"PTE_VAL_FMTTYPE"x.\n",
		       __func__, pte_val(pte));
		WARN_ON(1);
		return -1;
	}

	offset += (pte_val(pte) & PAGE_MASK) - addr;
	addr    = address & PAGE_MASK;
	if ((r = L4XV_FN_i(l4re_rm_attach((void **)&addr, PAGE_SIZE,
	                                  L4RE_RM_IN_AREA | L4RE_RM_EAGER_MAP
	                                   | ((pte_write(pte)
	                                      ? 0 : L4RE_RM_READ_ONLY)),
	                                  ds, offset, L4_PAGESHIFT)))) {

		if (r == -L4_EADDRNOTAVAIL) {
			l4_addr_t a = addr;
			l4_addr_t q = (unsigned long)l4x_main_memory_start;
			l4re_ds_t ds2;

			size = 1;
			if (L4XV_FN_i(l4re_rm_find(&a, &size, &offset,
			                           &flags, &ds2))) {
				pr_err("%s: Failed to query address %lx\n",
				       __func__, a);
				return -1;
			}

			q += offset;

			/* Return all ok if it's the same address
			 * The cap check is not perfect but will do. */
			if (q == (pte_val(pte) & L4_PAGEMASK)
			    && (ds & L4_CAP_MASK) == (ds2 & L4_CAP_MASK))
				return 0;

			pr_err("%s: Already used, existing is %lx\n",
			       __func__, q);
		}

		pr_err("%s: cannot attach vpage (%lx, %"PTE_VAL_FMTTYPE"x): %d\n",
		       __func__, address, pte_val(pte), r);
		return -1;
	}
	return 0;
}

int l4lx_memory_map_virtual_range(unsigned long address, unsigned long size,
                                  unsigned long page, int map_rw)
{
	unsigned long end;
	l4_addr_t addr, offset;
	l4re_ds_t ds;
	unsigned flags;
	unsigned long s;
	int r;

	address = address & PAGE_MASK;
	end     = address + size;
	while (address < end) {
		addr = page;
		s = 1;

		if (L4XV_FN_i(l4re_rm_find(&addr, &s, &offset, &flags, &ds))) {
			printk("%s: Cannot get dataspace of %08lx.\n",
			       __func__, page);
			return -1;
		}

		offset += (page & PAGE_MASK) - addr;
		addr = address;
		if (s > end - address)
			s = end - address;
		r = L4XV_FN_i(l4re_rm_attach((void **)&addr, s,
		                             L4RE_RM_IN_AREA | L4RE_RM_EAGER_MAP
				             | (map_rw ? 0 : L4RE_RM_READ_ONLY),
				             ds, offset, L4_PAGESHIFT));
		if (r) {
			// FIXME wrt L4_EUSED?
			// see above...
			printk("%s: cannot attach vpage (%lx, %lx, %lx): %d\n",
			       __func__, address, page, s, r);
			return -1;
		}

		address += s;
		page    += s;
	}

	return 0;
}

int l4lx_memory_unmap_virtual_page(unsigned long address)
{
	if (L4XV_FN_i(l4re_rm_detach((void *)address)))
		// Do not complain: someone might vfree a reserved area
		// that has not been completely filled
		return -1;
	return 0;
}

/* Returns 0 if not mapped, not-0 if mapped */
int l4lx_memory_page_mapped(unsigned long address)
{
	l4re_ds_t ds;
	unsigned flags;
	unsigned long size = 1, off;

	return !L4XV_FN_i(l4re_rm_find(&address, &size, &off, &flags, &ds));
}
