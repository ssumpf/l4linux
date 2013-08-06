#ifndef __ASM_L4__L4X_X86__INIT_H__
#define __ASM_L4__L4X_X86__INIT_H__

char *l4x_x86_memory_setup(void);

static void __init l4x_io_apic_init_mappings(void)
{}

static unsigned int l4x_io_apic_read(unsigned int apic, unsigned int reg)
{
        return ~0;
}

static void l4x_io_apic_write(unsigned int apic, unsigned int reg,
                              unsigned int val)
{}

static void l4x_io_apic_modify(unsigned int apic, unsigned int reg,
                               unsigned int val)
{}

static void l4x_io_apic_print_entries(unsigned int apic,
                                      unsigned int nr_entries)
{}

static int l4x_ioapic_set_affinity(struct irq_data *data,
                                   const struct cpumask *mask,
                                   bool force)
{
	return -ENODEV;
}

static int l4x_setup_ioapic_entry(int irq, struct IO_APIC_route_entry *entry,
                                  unsigned int destination, int vector,
                                  struct io_apic_irq_attr *attr)
{
	return -ENODEV;
}

static void l4x_eoi_ioapic_pin(int apic, int pin, int vector)
{}

static void l4x_disable_io_apic(void)
{}

#endif /* __ASM_L4__L4X_X86__INIT_H__ */
