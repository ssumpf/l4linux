#include <linux/slab.h>
#include <linux/interrupt.h>
#include <linux/irq.h>

#include <l4/sys/irq.h>
#include <l4/sys/icu.h>
#include <l4/io/io.h>

#include <asm/l4lxapi/generic/irq_gen.h>

int l4x_alloc_irq_desc_data(int irq)
{
	struct l4x_irq_desc_private *p;

	p = kzalloc(sizeof(*p), GFP_KERNEL);
	if (!p)
		return -ENOMEM;

	p->irq_cap = L4_INVALID_CAP;

	return irq_set_chip_data(irq, p);
}

void l4x_irq_set_type_at_icu(unsigned irq, unsigned type)
{
	l4_msgtag_t t;

	if (irq >= NR_IRQS_HW)
		return;

	t = L4XV_FN(l4_msgtag_t, l4_icu_set_mode(l4io_request_icu(), irq, type));
	if (l4_error(t))
		printk("irq: l4-set-mode(%d) failed for irq %d\n", type, irq);
}

int l4lx_irq_set_type(struct irq_data *data, unsigned int type)
{
	unsigned int irq = data->irq;
	struct l4x_irq_desc_private *p;
	struct irq_desc *desc = irq_to_desc(data->irq);

	if (unlikely(irq >= NR_IRQS))
		return -1;

	p = irq_get_chip_data(irq);
	if (!p)
		return -1;

	printk("L4IRQ: set irq type of %u to %x\n", irq, type);
	switch (type & IRQF_TRIGGER_MASK) {
		case IRQ_TYPE_EDGE_BOTH:
			p->trigger = L4_IRQ_F_BOTH_EDGE;
			desc->handle_irq = handle_edge_eoi_irq;
			break;
		case IRQ_TYPE_EDGE_RISING:
			p->trigger = L4_IRQ_F_POS_EDGE;
			desc->handle_irq = handle_edge_eoi_irq;
			break;
		case IRQ_TYPE_EDGE_FALLING:
			p->trigger = L4_IRQ_F_NEG_EDGE;
			desc->handle_irq = handle_edge_eoi_irq;
			break;
		case IRQ_TYPE_LEVEL_HIGH:
			p->trigger = L4_IRQ_F_LEVEL_HIGH;
			desc->handle_irq = handle_level_irq;
			break;
		case IRQ_TYPE_LEVEL_LOW:
			p->trigger = L4_IRQ_F_LEVEL_LOW;
			desc->handle_irq = handle_level_irq;
			break;
		default:
			p->trigger = L4_IRQ_F_NONE;
			break;
	};

	if (!l4_is_invalid_cap(p->irq_cap))
		l4x_irq_set_type_at_icu(irq, p->trigger);

	return 0;
}

