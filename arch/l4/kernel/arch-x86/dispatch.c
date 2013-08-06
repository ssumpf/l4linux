
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/interrupt.h>
#include <linux/ptrace.h>
#include <linux/tick.h>
#include <linux/kprobes.h>

#include <asm/processor.h>
#include <asm/mmu_context.h>
#include <asm/uaccess.h>
#include <asm/io.h>
#include <asm/unistd.h>
#include <asm/i387.h>
#include <asm/traps.h>
#include <asm/fpu-internal.h>
#include <asm/switch_to.h>

#include <l4/sys/ipc.h>
#include <l4/sys/kdebug.h>
#include <l4/sys/utcb.h>
#include <l4/sys/segment.h>
#include <l4/sys/ktrace.h>
#include <l4/util/util.h>
#include <l4/log/log.h>

#include <asm/l4lxapi/task.h>
#include <asm/l4lxapi/thread.h>
#include <asm/l4lxapi/memory.h>
#include <asm/api/macros.h>

#include <asm/generic/dispatch.h>
#include <asm/generic/ferret.h>
#include <asm/generic/task.h>
#include <asm/generic/upage.h>
#include <asm/generic/memory.h>
#include <asm/generic/process.h>
#include <asm/generic/setup.h>
#include <asm/generic/ioremap.h>
#include <asm/generic/hybrid.h>
#include <asm/generic/syscall_guard.h>
#include <asm/generic/stats.h>
#include <asm/generic/smp.h>

#include <asm/l4x/exception.h>
#include <asm/l4x/fpu.h>
#include <asm/l4x/l4_syscalls.h>
#include <asm/l4x/lx_syscalls.h>
#include <asm/l4x/utcb.h>
#include <asm/l4x/signal.h>

#if 0
#define TBUF_LOG_IDLE(x)        TBUF_DO_IT(x)
#define TBUF_LOG_WAKEUP_IDLE(x)	TBUF_DO_IT(x)
#define TBUF_LOG_USER_PF(x)     TBUF_DO_IT(x)
#define TBUF_LOG_INT80(x)       TBUF_DO_IT(x)
#define TBUF_LOG_EXCP(x)        TBUF_DO_IT(x)
#define TBUF_LOG_START(x)       TBUF_DO_IT(x)
#define TBUF_LOG_SUSP_PUSH(x)   TBUF_DO_IT(x)
#define TBUF_LOG_DSP_IPC_IN(x)  TBUF_DO_IT(x)
#define TBUF_LOG_DSP_IPC_OUT(x) TBUF_DO_IT(x)
#define TBUF_LOG_SUSPEND(x)     TBUF_DO_IT(x)
#define TBUF_LOG_SWITCH(x)      TBUF_DO_IT(x)
#define TBUF_LOG_HYB_BEGIN(x)   TBUF_DO_IT(x)
#define TBUF_LOG_HYB_RETURN(x)  TBUF_DO_IT(x)

#else

#define TBUF_LOG_IDLE(x)
#define TBUF_LOG_WAKEUP_IDLE(x)
#define TBUF_LOG_USER_PF(x)
#define TBUF_LOG_INT80(x)
#define TBUF_LOG_EXCP(x)
#define TBUF_LOG_START(x)
#define TBUF_LOG_SUSP_PUSH(x)
#define TBUF_LOG_DSP_IPC_IN(x)
#define TBUF_LOG_DSP_IPC_OUT(x)
#define TBUF_LOG_SUSPEND(x)
#define TBUF_LOG_SWITCH(x)
#define TBUF_LOG_HYB_BEGIN(x)
#define TBUF_LOG_HYB_RETURN(x)

#endif

asmlinkage void __sched preempt_schedule_irq(void);

static DEFINE_PER_CPU(struct l4x_arch_cpu_fpu_state, l4x_cpu_fpu_state);

void l4x_fpu_set(int on_off)
{
	per_cpu(l4x_cpu_fpu_state, smp_processor_id()).enabled = on_off;
}

struct l4x_arch_cpu_fpu_state *l4x_fpu_get(unsigned cpu)
{
	return &per_cpu(l4x_cpu_fpu_state, cpu);
}

static inline int l4x_msgtag_fpu(unsigned cpu)
{
	return l4x_fpu_get(cpu)->enabled ? L4_MSGTAG_TRANSFER_FPU : 0;
}

static inline int l4x_msgtag_copy_ureg(l4_utcb_t *u)
{
	return 0;
}

static inline int l4x_is_triggered_exception(l4_umword_t val)
{
	return val == 0xff;
}

static inline unsigned long regs_pc(struct task_struct *p)
{
	return task_pt_regs(p)->ip;
}

static inline unsigned long regs_sp(struct task_struct *p)
{
	return task_pt_regs(p)->sp;
}

static inline void l4x_arch_task_setup(struct thread_struct *t)
{
#ifdef CONFIG_X86_32
	load_TLS(t, 0);
#endif
}

static inline void l4x_arch_do_syscall_trace(struct task_struct *p)
{
	if (unlikely(current_thread_info()->flags & _TIF_WORK_SYSCALL_EXIT))
		syscall_trace_leave(task_pt_regs(p));
}

static inline int l4x_hybrid_check_after_syscall(l4_utcb_t *utcb)
{
	l4_exc_regs_t *exc = l4_utcb_exc_u(utcb);
	return (exc->trapno == 0xd /* after L4 syscall */
	        && l4x_l4syscall_get_nr(exc->err, exc->ip) != -1
	        && (exc->err & 4))
	       || (exc->trapno == 0xff /* L4 syscall exr'd */
	           && exc->err == 0);
}

static inline void l4x_dispatch_delete_polling_flag(void)
{
	current_thread_info()->status &= ~TS_POLLING;
}

static inline void l4x_dispatch_set_polling_flag(void)
{
	current_thread_info()->status |= TS_POLLING;
}

#ifdef CONFIG_L4_VCPU
static inline void l4x_arch_task_start_setup(l4_vcpu_state_t *v,
		                             struct task_struct *p, l4_cap_idx_t task_cap)
#else
static inline void l4x_arch_task_start_setup(struct task_struct *p, l4_cap_idx_t task_cap)
#endif
{
	// - remember GS in FS so that programs can find their UTCB
	//   libl4sys-l4x.a uses %fs to get the UTCB address
	// - do not set GS because glibc does not seem to like if gs is not 0
	// - only do this if this is the first usage of the L4 thread in
	//   this task, otherwise gs will have the glibc-gs
	// - ensure this by checking if the segment is one of the user ones or
	//   another one (then it's the utcb one)
#ifdef CONFIG_X86_32
#ifdef CONFIG_L4_VCPU
	unsigned int gs = v->r.gs;
#else
	unsigned int gs = l4_utcb_exc()->gs;
#endif
	unsigned int val = (gs & 0xffff) >> 3;
	if (   val < l4x_fiasco_gdt_entry_offset
	    || val > l4x_fiasco_gdt_entry_offset + 3)
		task_pt_regs(p)->fs = gs;

	/* Setup LDTs */
	if (p->mm && p->mm->context.size) {
		unsigned i;
		L4XV_V(f);
		L4XV_L(f);
		for (i = 0; i < p->mm->context.size;
		     i += L4_TASK_LDT_X86_MAX_ENTRIES) {
			unsigned sz = p->mm->context.size - i;
			int r;
			if (sz > L4_TASK_LDT_X86_MAX_ENTRIES)
				sz = L4_TASK_LDT_X86_MAX_ENTRIES;
			r = fiasco_ldt_set(task_cap, p->mm->context.ldt,
			                   sz, i, l4_utcb());
			if (r)
				LOG_printf("fiasco_ldt_set(%d, %d): failed %d\n",
				           sz, i, r);

		}
		L4XV_U(f);
	}
#endif
}

static inline l4_umword_t l4x_l4pfa(struct thread_struct *t)
{
	return (t->cr2 & ~3) | (t->error_code & 2);
}

static inline int l4x_ispf(struct thread_struct *t)
{
	return t->trap_nr == 14;
}

static inline void l4x_print_regs(struct thread_struct *t, struct pt_regs *r)
{
	printk("ip: %08lx sp: %08lx err: %08lx trp: %08lx\n",
	       r->ip, r->sp, t->error_code, t->trap_nr);
	printk("ax: %08lx bx: %08lx  cx: %08lx  dx: %08lx\n",
	       r->ax, r->bx, r->cx, r->dx);
#ifdef CONFIG_X86_32
	printk("di: %08lx si: %08lx  bp: %08lx  gs: %08lx fs: %08lx\n",
	       r->di, r->si, r->bp, r->gs, r->fs);
#else
	printk("di: %08lx si: %08lx  bp: %08lx\n",
	       r->di, r->si, r->bp);
#endif
}

asmlinkage void ret_from_fork(void) __asm__("ret_from_fork");
#if 0
asm(
".section .text			\n"
#ifdef CONFIG_L4_VCPU
".global ret_from_fork          \n"
#endif
"ret_from_fork:			\n"
// why do we need the push/pop?
#ifdef CONFIG_X86_32
"pushl	%ebx			\n"
#endif
"call	schedule_tail		\n"
#ifdef CONFIG_X86_32
"popl	%ebx			\n"
#endif
#ifdef CONFIG_L4_VCPU
"jmp	l4x_vcpu_ret_from_fork  \n"
#else
"jmp	l4x_user_dispatcher	\n"
#endif
".previous			\n"
);
#endif

#ifndef CONFIG_L4_VCPU
void l4x_idle(void);
#endif

int  l4x_deliver_signal(int exception_nr, int error_code);

DEFINE_PER_CPU(struct thread_info *, l4x_current_ti) = &init_thread_info;
DEFINE_PER_CPU(struct thread_info *, l4x_current_proc_run);
#ifndef CONFIG_L4_VCPU
static DEFINE_PER_CPU(unsigned, utcb_snd_size);
#endif

#include <asm/generic/stack_id.h>

__notrace_funcgraph struct task_struct *
__switch_to(struct task_struct *prev, struct task_struct *next)
{
	int cpu = smp_processor_id();
	fpu_switch_t fpu;

#ifdef CONFIG_L4_VCPU
	l4_vcpu_state_t *vcpu = this_cpu_read(l4x_vcpu_ptr);
#endif
	if (0)
		LOG_printf("%s: cpu%d: %s(%d)[%ld] -> %s(%d)[%ld]\n",
		           __func__, cpu,
		           prev->comm, prev->pid, prev->state,
		           next->comm, next->pid, next->state);
#ifdef CONFIG_L4_VCPU
	TBUF_LOG_SWITCH(fiasco_tbuf_log_3val("SWITCH", (unsigned long)prev->stack, (unsigned long)next->stack, next->thread.sp0));
#else
	TBUF_LOG_SWITCH(fiasco_tbuf_log_3val("SWITCH", (prev->pid << 16) | TBUF_TID(prev->thread.user_thread_id), (next->pid << 16) | TBUF_TID(next->thread.user_thread_id), 0));
#endif

	fpu = switch_fpu_prepare(prev, next, cpu);

#ifndef CONFIG_L4_VCPU
	this_cpu_write(l4x_current_ti,
	               (struct thread_info *)((unsigned long)next->stack & ~(THREAD_SIZE - 1)));
#endif

	if (unlikely(task_thread_info(prev)->flags & _TIF_WORK_CTXSW_PREV ||
	             task_thread_info(next)->flags & _TIF_WORK_CTXSW_NEXT))
		__switch_to_xtra(prev, next, NULL);

	arch_end_context_switch(next);

	switch_fpu_finish(next, fpu);

	this_cpu_write(current_task, next);

#if defined(CONFIG_SMP) && !defined(CONFIG_L4_VCPU)
	next->thread.user_thread_id = next->thread.user_thread_ids[cpu];
	l4x_stack_struct_get(next->stack)->utcb
		= l4x_stack_struct_get(prev->stack)->utcb;
#endif

#ifdef CONFIG_L4_VCPU
	vcpu->entry_sp = (unsigned long)task_pt_regs(next);
#endif

#ifdef CONFIG_X86_32
	if (next->mm
#ifndef CONFIG_L4_VCPU
	    && !l4_is_invalid_cap(next->thread.user_thread_id)
	    && next->thread.user_thread_id
#endif
	    )
		load_TLS(&next->thread, 0);
#endif

	return prev;
}

static inline void l4x_pte_add_access_flag(pte_t *ptep)
{
	ptep->pte |= _PAGE_ACCESSED;
}

static inline void l4x_pte_add_access_and_dirty_flags(pte_t *ptep)
{
	ptep->pte |= _PAGE_ACCESSED + _PAGE_DIRTY;
}

static inline
unsigned long l4x_map_page_attr_to_l4(pte_t pte)
{
	switch (pte_val(pte) & _PAGE_CACHE_MASK) {
	case _PAGE_CACHE_WC: /* _PAGE_PWT */
		return L4_FPAGE_BUFFERABLE << 4;
	case _PAGE_CACHE_UC_MINUS: /* _PAGE_PCD */
	case _PAGE_CACHE_UC: /* _PAGE_PCD | _PAGE_PWT */
		return L4_FPAGE_UNCACHEABLE << 4;
	case _PAGE_CACHE_WB: /* 0 */
	default:
		return 0; /* same attrs as source */
	};
}

#ifdef CONFIG_L4_VCPU

static inline void
state_to_vcpu(l4_vcpu_state_t *vcpu, struct pt_regs *regs,
              struct task_struct *p)
{
	ptregs_to_vcpu(vcpu, regs);
}

static inline void vcpu_to_thread_struct(l4_vcpu_state_t *v,
                                         struct thread_struct *t)
{
#ifdef CONFIG_X86_32
	t->gs         = v->r.gs;
#endif
	t->trap_nr    = v->r.trapno;
	t->error_code = v->r.err;
	t->cr2        = v->r.pfa;
}

static inline void thread_struct_to_vcpu(l4_vcpu_state_t *v,
                                         struct thread_struct *t)
{
#ifdef CONFIG_X86_32
	v->r.gs = t->gs;
#endif
}
#else
static inline void utcb_to_thread_struct(l4_utcb_t *utcb,
                                         struct task_struct *p,
                                         struct thread_struct *t)
{
	l4_exc_regs_t *exc = l4_utcb_exc_u(utcb);
	utcb_exc_to_ptregs(exc, task_pt_regs(p));
	t->gs         = exc->gs;
	t->trap_nr    = exc->trapno;
	t->error_code = exc->err;
	t->cr2        = exc->pfa;
}
#endif

static inline void thread_struct_to_utcb(struct task_struct *p,
                                         struct thread_struct *t,
                                         l4_utcb_t *utcb,
                                         unsigned int send_size)
{
	l4_exc_regs_t *exc = l4_utcb_exc_u(utcb);
	ptregs_to_utcb_exc(task_pt_regs(p), exc);
#ifdef CONFIG_X86_32
	exc->gs   = t->gs;
#endif
#ifndef CONFIG_L4_VCPU
	per_cpu(utcb_snd_size, smp_processor_id()) = send_size;
#endif
}

#ifndef CONFIG_L4_VCPU
static int l4x_hybrid_begin(struct task_struct *p,
                            struct thread_struct *t);

static void l4x_dispatch_suspend(struct task_struct *p,
                                 struct thread_struct *t);
#endif

static inline void dispatch_system_call(struct task_struct *p,
                                        struct pt_regs *regsp)
{
	unsigned int syscall;
	syscall_t syscall_fn = NULL;
	int show_syscalls = 0;

#ifdef CONFIG_L4_VCPU
	local_irq_enable();
#endif

	regsp->orig_ax = syscall = regsp->ax;
	regsp->ax = -ENOSYS;

#ifdef CONFIG_L4_FERRET_SYSCALL_COUNTER
	ferret_histo_bin_inc(l4x_ferret_syscall_ctr, syscall);
#endif

	if (show_syscalls)
		printk("Syscall %3d for %s(%d at %p): args: %lx,%lx,%lx\n",
		       syscall, p->comm, p->pid, (void *)regsp->ip,
		       regsp->bx, regsp->cx, regsp->dx);

	if (show_syscalls && syscall == 11) {
		struct filename *fn;
		printk("execve: pid: %d(%s): ", p->pid, p->comm);
		fn = getname((char *)regsp->bx);
		printk("%s\n", IS_ERR(fn) ? "UNKNOWN" : fn->name);
		putname(fn);
	}

	if (show_syscalls && syscall == 120)
		printk("Syscall %3d for %s(%d at %p): arg1 = %lx ebp=%lx\n",
		       syscall, p->comm, p->pid, (void *)regsp->ip,
		       regsp->bx, regsp->bp);

	if (show_syscalls && syscall == 21)
		printk("Syscall %3d mount for %s(%d at %p): %lx %lx %lx %lx %lx %lx\n",
		       syscall, p->comm, p->pid, (void *)regsp->ip,
		       regsp->bx, regsp->cx, regsp->dx, regsp->si,
		       regsp->di, regsp->bp);
	if (show_syscalls && syscall == 5) {
		struct filename *fn = getname((char *)regsp->bx);
		printk("open: pid: %d(%s): %s (%lx)\n",
		       current->pid, current->comm,
		       IS_ERR(fn) ? "UNKNOWN" : fn->name, regsp->bx);
		putname(fn);
	}

	if (unlikely(!is_lx_syscall(syscall))) {
		printk("Syscall %3d for %s(%d at %p): arg1 = %lx\n",
		       syscall, p->comm, p->pid, (void *)regsp->ip,
		       regsp->bx);
		l4x_print_regs(&p->thread, regsp);
	}

	if (likely((is_lx_syscall(syscall))
		   && ((syscall_fn = (syscall_t)sys_call_table[syscall])))) {

		if (unlikely(current_thread_info()->flags & _TIF_WORK_SYSCALL_ENTRY))
			syscall_trace_enter(regsp);

		regsp->ax = syscall_fn(regsp->bx, regsp->cx,
		                       regsp->dx, regsp->si,
		                       regsp->di, regsp->bp);

		if (unlikely(current_thread_info()->flags & _TIF_WORK_SYSCALL_EXIT))
			syscall_trace_leave(regsp);
	}

	if (show_syscalls)
		printk("Syscall %3d for %s(%d at %p): return %lx/%ld\n",
		       syscall, p->comm, p->pid, (void *)regsp->ip,
		       regsp->ax, regsp->ax);
#ifdef CONFIG_L4_VCPU
	local_irq_disable();
#endif
}

static void
l4x_pre_iret_work(struct pt_regs *regs, struct task_struct *p,
                  unsigned long scno, void *dummy)
{
	unsigned long tifl;

resume_userspace:
	local_irq_disable();

	tifl = current_thread_info()->flags;
	if (tifl & _TIF_WORK_MASK)
		goto work_pending;

	goto restore_all;

work_pending:
	if (!(current_thread_info()->flags & _TIF_NEED_RESCHED))
		goto work_notifysig;

work_resched:
	schedule();

	local_irq_disable();

	tifl = current_thread_info()->flags;
	if (!(tifl & _TIF_WORK_MASK))
		goto restore_all;
	if (tifl & _TIF_NEED_RESCHED)
		goto work_resched;

work_notifysig:
	local_irq_enable();

	if ((regs->cs & SEGMENT_RPL_MASK) < USER_RPL)
#ifdef CONFIG_PREEMPT
		goto resume_kernel;
#else
		goto restore_all;
#endif

	do_notify_resume(regs, 0, tifl);
	goto resume_userspace;

restore_all:

	return;

#ifdef CONFIG_PREEMPT
resume_kernel:
	local_irq_disable();

	if (current_thread_info()->preempt_count == 0)
		goto restore_all;

need_resched:
	tifl = current_thread_info()->flags;
	if (!(tifl & _TIF_NEED_RESCHED))
		goto restore_all;

	if (regs->flags & X86_EFLAGS_IF)
		goto restore_all;

	preempt_schedule_irq();

	goto need_resched;
#endif
}

/*
 * A primitive emulation.
 *
 * Returns 1 if something could be handled, 0 if not.
 */
static inline int l4x_port_emulation(struct pt_regs *regs)
{
	u8 op;

	if (get_user(op, (char *)regs->ip))
		return 0; /* User memory could not be accessed */

	//printf("OP: %x (ip: %08x) dx = 0x%x\n", op, regs->ip, regs->edx & 0xffff);

	switch (op) {
		case 0xed: /* in dx, eax */
		case 0xec: /* in dx, al */
			switch (regs->dx & 0xffff) {
				case 0xcf8:
				case 0x3da:
				case 0x3cc:
				case 0x3c1:
					regs->ax = -1;
					regs->ip++;
					return 1;
			};
		case 0xee: /* out al, dx */
			switch (regs->dx & 0xffff) {
				case 0x3c0:
					regs->ip++;
					return 1;
			};
	};

	return 0; /* Not handled here */
}

/*
 * Emulation of (some) jdb commands. The user program may not
 * be allowed to issue jdb commands, they trap in here. Nevertheless
 * hybrid programs may want to use some of them. Emulate them here.
 * Note:  When there's a failure reading the string from user we
 *        nevertheless return true.
 * Note2: More commands to be emulated can be added on request.
 */
static int l4x_kdebug_emulation(struct pt_regs *regs)
{
	u8 op = 0, val;
	char *addr = (char *)regs->ip - 1;
	int i, len;

	if (get_user(op, addr))
		return 0; /* User memory could not be accessed */

	if (op != 0xcc) /* Check for int3 */
		return 0; /* Not for us */

	/* jdb command group */
	if (get_user(op, addr + 1))
		return 0; /* User memory could not be accessed */

	if (op == 0xeb) { /* enter_kdebug */
		if (get_user(len, addr + 2))
			return 0; /* Access failure */
		regs->ip += len + 2;
		outstring("User enter_kdebug text: ");
		for (i = 3; len; len--) {
			if (get_user(val, addr + i++))
				break;
			outchar(val);
		}
		outchar('\n');
		enter_kdebug("User program enter_kdebug");

		return 1; /* handled */

	} else if (op == 0x3c) {
		if (get_user(op, addr + 2))
			return 0; /* Access failure */
		switch (op) {
			case 0: /* outchar */
				outchar(regs->ax & 0xff);
				break;
			case 1: /* outnstring */
				len = regs->bx;
				for (i = 0;
				     !get_user(val, (char *)(regs->ax + i++))
				     && len;
				     len--)
					outchar(val);
				break;
			case 2: /* outstring */
				for (i = 0;
				     !get_user(val, (char *)(regs->ax + i++))
				     && val;)
					outchar(val);
				break;
			case 5: /* outhex32 */
				outhex32(regs->ax);
				break;
			case 6: /* outhex20 */
				outhex20(regs->ax);
				break;
			case 7: /* outhex16 */
				outhex16(regs->ax);
				break;
			case 8: /* outhex12 */
				outhex12(regs->ax);
				break;
			case 9: /* outhex8 */
				outhex8(regs->ax);
				break;
			case 11: /* outdec */
				outdec(regs->ax);
				break;
			default:
				return 0; /* Did not understand */
		};
		regs->ip += 2;
		return 1; /* handled */
	}

	return 0; /* Not handled here */
}

static inline unsigned r_trapno(struct thread_struct *t, l4_vcpu_state_t *v)
{
#ifdef CONFIG_L4_VCPU
	return v->r.trapno;
#else
	return t->trap_nr;
#endif
}

static inline unsigned r_err(struct thread_struct *t, l4_vcpu_state_t *v)
{
#ifdef CONFIG_L4_VCPU
	return v->r.err;
#else
	return t->error_code;
#endif
}

/*
 * Return values: 0 -> do send a reply
 *                1 -> don't send a reply
 */
static inline int l4x_dispatch_exception(struct task_struct *p,
                                         struct thread_struct *t,
                                         l4_vcpu_state_t *v,
                                         struct pt_regs *regs)
{
#ifndef CONFIG_L4_VCPU
	l4x_hybrid_do_regular_work();
#endif
	l4x_debug_stats_exceptions_hit();

	if (0) {
#ifndef CONFIG_L4_VCPU
	} else if (t->trap_nr == 0xff) {
		/* we come here for suspend events */
		TBUF_LOG_SUSPEND(fiasco_tbuf_log_3val("dsp susp", TBUF_TID(t->user_thread_id), regs->ip, 0));
		l4x_dispatch_suspend(p, t);

		return 0;
#endif
	} else if (likely(r_trapno(t, v) == 0xd && r_err(t, v) == 0x402)) {
		/* int 0x80 is trap 0xd and err 0x402 (0x80 << 3 | 2) */

		TBUF_LOG_INT80(fiasco_tbuf_log_3val("int80  ", TBUF_TID(t->user_thread_id), regs->ip, regs->ax));

		/* set after int 0x80, before syscall so the forked childs
		 * get the increase too */
		regs->ip += 2;

		dispatch_system_call(p, regs);
		l4x_pre_iret_work(regs, p, 0, 0);

		BUG_ON(p != current);

		return 0;
	} else if (r_trapno(t, v) == 7) {
		do_device_not_available(regs, -1);
		l4x_pre_iret_work(regs, p, 0, 0);
		return 0;
	} else if (unlikely(r_trapno(t, v) == 1)) {
		do_debug(regs, 0);
		l4x_pre_iret_work(regs, p, 0, 0);
		return 0;
	} else if (r_trapno(t, v) == 0xd) {
#ifndef CONFIG_L4_VCPU
		if (l4x_hybrid_begin(p, t))
			return 0;
#endif
		/* Fall through otherwise */
	}

	if (r_trapno(t, v) == 3) {
		if (l4x_kdebug_emulation(regs))
			return 0; /* known and handled */
		do_int3(regs, r_err(t, v));
		l4x_pre_iret_work(regs, p, 0, 0);
		return 0;
	}

	if (l4x_port_emulation(regs))
		return 0; /* known and handled */

	TBUF_LOG_EXCP(fiasco_tbuf_log_3val("except ", TBUF_TID(t->user_thread_id), t->trap_nr, t->error_code));

	if (l4x_deliver_signal(r_trapno(t, v), r_err(t, v)))
		return 0; /* handled signal, reply */

	/* This path should never be reached... */

	printk("(Unknown) EXCEPTION\n");
	l4x_print_regs(t, regs);

	enter_kdebug("check");

	/* The task somehow misbehaved, so it has to die */
	do_exit(SIGKILL);

	return 1; /* no reply -- no come back */
}

static inline int l4x_handle_page_fault_with_exception(struct thread_struct *t,
                                                       struct pt_regs *regs)
{
	return 0; // not for us
}

#ifdef CONFIG_L4_VCPU
static inline void l4x_vcpu_entry_user_arch(void)
{
#ifdef CONFIG_X86_32
	asm ("cld          \n"
	     "mov %0, %%gs \n"
	     "mov %1, %%fs \n"
	     : : "r" (l4x_x86_utcb_get_orig_segment()),
#ifdef CONFIG_SMP
	     "r" ((l4x_fiasco_gdt_entry_offset + 2) * 8 + 3)
#else
	     "r" (l4x_x86_utcb_get_orig_segment())
#endif
	     : "memory");
#else
	asm ("cld" : : : "memory");
#endif
}

static inline bool l4x_vcpu_is_wr_pf(l4_vcpu_state_t *v)
{
	return v->r.err & 2;
}
#endif

#define __INCLUDED_FROM_L4LINUX_DISPATCH
#include "../dispatch.c"
