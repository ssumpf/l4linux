#include <linux/gpio.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/slab.h>

#include <l4/vbus/vbus_gpio.h>
#include <l4/io/io.h>

#include <asm/generic/l4lib.h>
#include <asm/generic/util.h>
#include <asm/generic/l4gpio.h>

#include <mach/l4gpio.h>

MODULE_AUTHOR("Adam Lackorzynski <adam@os.inf.tu-dresden.de>");
MODULE_DESCRIPTION("L4 GPIO driver");
MODULE_LICENSE("GPL");

L4_EXTERNAL_FUNC(l4vbus_gpio_config_pad);
L4_EXTERNAL_FUNC(l4vbus_gpio_multi_config_pad);
L4_EXTERNAL_FUNC(l4vbus_gpio_setup);
L4_EXTERNAL_FUNC(l4vbus_gpio_set);
L4_EXTERNAL_FUNC(l4vbus_gpio_get);
L4_EXTERNAL_FUNC(l4vbus_gpio_to_irq);

struct l4gpio_gpio {
	l4io_device_handle_t dh;
	struct gpio_chip     gc;
};

static l4io_device_handle_t *dhandles;
static struct platform_device platform_device;
static l4_cap_idx_t vbus;

static inline struct l4gpio_gpio *gc_to_l4gpio(struct gpio_chip *gc)
{
	return container_of(gc, struct l4gpio_gpio, gc);;
}

/* Public function */
int l4gpio_config_pin(unsigned globalpin, unsigned func, unsigned value)
{
	int r;
	unsigned gpiopin = globalpin % L4GPIO_GROUP_SIZE;
	unsigned gpiochip = globalpin / L4GPIO_GROUP_SIZE;

	if (gpiochip >= L4GPIO_MAX)
		return -EINVAL;

	if (!dhandles || !dhandles[gpiochip])
		return -EINVAL;

	r = L4XV_FN_i(l4vbus_gpio_config_pad(vbus, dhandles[gpiochip],
	                                     gpiopin, func, value));
	if (r < 0)
		pr_warn("l4gpio: Config-pin GPIO(%d/%d) failed\n",
		        globalpin, gpiochip);
	return r;
}
EXPORT_SYMBOL(l4gpio_config_pin);

/* Public function */
int l4gpio_multi_config_pin(unsigned gpiochip, unsigned pinmask,
                            unsigned func, unsigned value)
{
	int r;

	if (gpiochip >= L4GPIO_MAX)
		return -EINVAL;

	if (!dhandles || !dhandles[gpiochip])
		return -EINVAL;

	r = L4XV_FN_i(l4vbus_gpio_multi_config_pad(vbus, dhandles[gpiochip],
	                                           pinmask, func, value));
	if (r < 0)
		pr_warn("l4gpio: Multi-config-pin GPIO(%d*%d) failed\n",
		        gpiochip, L4GPIO_GROUP_SIZE);
	return r;
}
EXPORT_SYMBOL(l4gpio_multi_config_pin);

static int l4gpio_direction_input(struct gpio_chip *gc, unsigned offset)
{
	struct l4gpio_gpio *chip = gc_to_l4gpio(gc);
	int r;

	if (offset >= gc->ngpio)
		return -EINVAL;

	r = L4XV_FN_i(l4vbus_gpio_setup(vbus, chip->dh, offset,
	                                L4VBUS_GPIO_SETUP_INPUT, 0));
	if (r < 0)
		pr_warn("l4gpio: Config-input GPIO(%d) failed\n", offset);
	return r;
}

static int l4gpio_direction_output(struct gpio_chip *gc, unsigned offset,
		                   int value)
{
	struct l4gpio_gpio *chip = gc_to_l4gpio(gc);
	int r;

	if (offset >= gc->ngpio)
		return -EINVAL;

	r = L4XV_FN_i(l4vbus_gpio_setup(vbus, chip->dh, offset,
	                                L4VBUS_GPIO_SETUP_OUTPUT, value));
	if (r < 0)
		pr_warn("l4gpio: Config-output GPIO(%d) failed\n", offset);
	return r;
}

static int l4gpio_get_value(struct gpio_chip *gc, unsigned offset)
{
	struct l4gpio_gpio *chip = gc_to_l4gpio(gc);
	int r;

	if (offset >= gc->ngpio)
		return -EINVAL;

	r = L4XV_FN_i(l4vbus_gpio_get(vbus, chip->dh, offset));
	if (r < 0)
		pr_warn("l4gpio: Getting GPIO(%d) failed\n", offset);
	return r;
}

static void l4gpio_set_value(struct gpio_chip *gc, unsigned offset, int value)
{
	struct l4gpio_gpio *chip = gc_to_l4gpio(gc);
	int r;

	if (offset >= gc->ngpio)
		return;

	r = L4XV_FN_i(l4vbus_gpio_set(vbus, chip->dh, offset, value));
	if (r < 0)
		pr_warn("l4gpio: Setting GPIO(%d) failed\n", offset);
}

static int l4gpio_to_irq(struct gpio_chip *gc, unsigned offset)
{
	struct l4gpio_gpio *chip = gc_to_l4gpio(gc);

	if (offset >= gc->ngpio)
		return -EINVAL;

	return L4XV_FN_i(l4vbus_gpio_to_irq(vbus, chip->dh, offset));
}

static int add_chip(unsigned gpio, l4io_device_handle_t dh,
                    struct platform_device *pdev)
{
	int ret;
	struct l4gpio_gpio *chip;

	chip = kzalloc(sizeof(*chip), GFP_KERNEL);
	if (!chip)
		return -ENOMEM;

	dhandles[gpio] = dh;
	chip->dh = dh;
	chip->gc.direction_input  = l4gpio_direction_input;
	chip->gc.direction_output = l4gpio_direction_output;
        chip->gc.get              = l4gpio_get_value;
        chip->gc.set              = l4gpio_set_value;
        chip->gc.to_irq           = l4gpio_to_irq;
        chip->gc.base             = L4GPIO_OFFSET(gpio),
        chip->gc.ngpio            = L4GPIO_GROUP_SIZE;
        chip->gc.label            = l4gpio_dev_name(gpio);
        chip->gc.dev              = pdev ? &pdev->dev : NULL;
        chip->gc.owner            = THIS_MODULE;

	ret = gpiochip_add(&chip->gc);
	if (ret) {
		pr_err("l4gpio: Failed to add chip '%s' (%d)\n",
		       l4gpio_dev_name(gpio), ret);
		goto free_chip;
	}

	return 0;

free_chip:
	kfree(chip);
	return ret;
}

static int l4gpio_probe(struct platform_device *pdev)
{
	l4io_device_handle_t dh;
	l4io_device_t dev;
	l4io_resource_handle_t reshandle;
	unsigned found = 0, i, r;
	L4XV_V(f);

	BUILD_BUG_ON(ARCH_NR_GPIOS < L4GPIO_MAX * L4GPIO_GROUP_SIZE);

	if (!dhandles)
		dhandles = kzalloc(L4GPIO_MAX * sizeof(*dhandles),
		                   GFP_KERNEL);
	if (!dhandles)
		return -ENOMEM;

	r = -EINVAL;
	if (l4x_re_resolve_name("vbus", &vbus))
		goto out;

	L4XV_L(f);
	dh = l4io_get_root_device();
	L4XV_U(f);
	while (1) {
		L4XV_L(f);
		r = l4io_iterate_devices(&dh, &dev, &reshandle);
		L4XV_U(f);
		if (r)
			break;

		if (!strstr(dev.name, "gpio_"))
			continue;

		for (i = 0; i < L4GPIO_MAX; ++i) {
			if (!strcasecmp(dev.name + 5, l4gpio_dev_name(i))) {
				r = add_chip(i, dh, pdev);
				if (r == 0)
					found++;
				break;
			}
		}
	}

	if (!found)
		pr_info("l4gpio: No GPIOs found.\n");
	else
		pr_info("l4gpio: Registered %d GPIOs\n", found);

	r = 0;

out:
	/* fill up non-found gpio-group slots */
	for (i = 0; i < L4GPIO_MAX; ++i)
		if (!dhandles[i])
			add_chip(i, 0, NULL);

	if (r)
		kfree(dhandles);
	return r;
}

static int __exit l4gpio_remove(struct platform_device *pdev)
{
	return 0;
}

static struct platform_driver l4gpio_driver = {
	.probe  = l4gpio_probe,
	.remove = __exit_p(l4gpio_remove),
	.driver = {
		.name = "l4gpio",
	},
};

static __init int l4gpio_init(void)
{
	int r;

	r = platform_driver_register(&l4gpio_driver);
	if (r)
		return r;

	platform_device.id   = 0;
	platform_device.name = "l4gpio";
	return platform_device_register(&platform_device);
}

static void __exit l4gpio_exit(void)
{
	platform_device_unregister(&platform_device);
	platform_driver_unregister(&l4gpio_driver);
}

subsys_initcall(l4gpio_init);
module_exit(l4gpio_exit);
