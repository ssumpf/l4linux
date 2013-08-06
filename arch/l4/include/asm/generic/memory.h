#ifndef __ASM_L4__GENERIC__MEMORY_H__
#define __ASM_L4__GENERIC__MEMORY_H__

#include <linux/stddef.h>
#include <linux/mm.h>
#include <linux/sched.h>

#include <asm/l4x/exception.h>

#include <l4/sys/types.h>

//#define DEBUG_PARSE_PTABS_READ 1
//#define DEBUG_PARSE_PTABS_WRITE 1

#define PF_EUSER		4
#define PF_EKERNEL		0
#ifdef ARCH_arm
#define PF_EWRITE		(1 << 11)
#else
#define PF_EWRITE		2
#endif
#define PF_EREAD		0
#define PF_EPROTECTION		1
#define PF_ENOTPRESENT		0

#ifdef CONFIG_X86
#define PTE_VAL_FMTTYPE "l"
#endif
#ifdef CONFIG_ARM
#define PTE_VAL_FMTTYPE ""
#endif

extern void *l4x_main_memory_start;

int l4x_do_page_fault(unsigned long address, struct pt_regs *regs, unsigned long error_code);

static inline pte_t *lookup_pte_lock(struct mm_struct *mm,
                                     unsigned long address,
                                     spinlock_t **ptl)
{
	pgd_t *pgd = mm->pgd + pgd_index(address);

	if (pgd_present(*pgd)) {
		pud_t *pud = pud_offset(pgd, address);
		pmd_t *pmd = pmd_offset(pud, address);
		if (pmd_present(*pmd)) {
			if (ptl)
				*ptl = pte_lockptr(mm, pmd);
#ifdef ARCH_x86
			if (pmd_large(*pmd))
				return (pte_t *)pmd;
#endif
			return pte_offset_kernel(pmd, address);
		}
	}
	if (ptl)
		*ptl = NULL;
	return NULL;
}

static inline pte_t *lookup_pte(struct mm_struct *mm, unsigned long address)
{
	return lookup_pte_lock(mm, address, NULL);
}

static inline int l4x_pte_present_user(pte_t pte)
{
#ifdef CONFIG_X86
	return pte_present(pte) && (pte_val(pte) & _PAGE_USER);
#endif
#ifdef CONFIG_ARM
	return pte_present_user(pte);
#endif
	return 0;
}

static inline unsigned long parse_ptabs_read(unsigned long address,
                                             unsigned long *offset)
{
	spinlock_t *ptl;
	pte_t *ptep = lookup_pte_lock(current->mm, address, &ptl);

#ifdef DEBUG_PARSE_PTABS_READ
	printk("ppr: pdir: %p, address: %lx, ptep: %p pte: %lx *ptep present: %lu\n", 
	       (pgd_t *)current->active_mm->pgd, address, ptep, pte_val(*ptep), pte_present(*ptep));
#endif

	if ((ptep == NULL) || !pte_present(*ptep)) {
		struct pt_regs regs;
		l4x_make_up_kernel_regs(&regs);
		if (l4x_do_page_fault(address, &regs,
		                      PF_EKERNEL|PF_EREAD|PF_ENOTPRESENT) == -1)
			return -EFAULT;

		if (ptep == NULL)
			ptep = lookup_pte_lock(current->mm, address, &ptl);
		if (!l4x_pte_present_user(*ptep))
			panic("parse_ptabs_read: pte page still not present\n");
	}
	spin_lock(ptl);
	*ptep   = pte_mkyoung(*ptep);
	spin_unlock(ptl);
	*offset = address & ~PAGE_MASK;
	return pte_val(*ptep) & PAGE_MASK;
}

static inline unsigned long parse_ptabs_write(unsigned long address,
                                              unsigned long *offset)
{
	spinlock_t *ptl;
	pte_t *ptep = lookup_pte_lock(current->mm, address, &ptl);
	struct pt_regs regs;

	l4x_make_up_kernel_regs(&regs);

#ifdef DEBUG_PARSE_PTABS_WRITE
	printk("ppw: pdir: %p, address: %lx, ptep: %p\n",
	       (pgd_t *)current->mm->pgd, address, ptep);
#endif

	if ((ptep == NULL) || !pte_present(*ptep)) {
		if (l4x_do_page_fault(address, &regs,
		                     PF_EKERNEL|PF_EWRITE|PF_ENOTPRESENT) == -1)
			return -EFAULT;
	} else if (!pte_write(*ptep)) {
		if (l4x_do_page_fault(address, &regs,
		                     PF_EKERNEL|PF_EWRITE|PF_EPROTECTION) == -1)
			return -EFAULT;
	}

	if (ptep == NULL)
		ptep = lookup_pte_lock(current->mm, address, &ptl);

#ifdef DEBUG_PARSE_PTABS_WRITE
	if (ptep)
		printk("pte_present(*ptep) = %lx pte_write(*ptep) = %x\n",
		       pte_present(*ptep), pte_write(*ptep));
#endif

	if ((ptep == NULL) || !pte_present(*ptep) || !pte_write(*ptep))
		panic("parse_ptabs_write: pte page still not present or writable\n");

	spin_lock(ptl);
	*ptep   = pte_mkdirty(pte_mkyoung(*ptep));
	spin_unlock(ptl);
	*offset = address & ~PAGE_MASK;
	return pte_val(*ptep) & PAGE_MASK;
}

#endif /* ! __ASM_L4__GENERIC__MEMORY_H__ */
