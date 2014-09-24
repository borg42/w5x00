/****************************************************************************
 *
 * driver/module.c
 */

/*********************************************
 * Module support
 *********************************************/

#include <linux/gpio.h>
#include <linux/spi/spi.h>
#include "w5x00.h"

static wiz_t gDrvInfo;

static unsigned char defmac[] = { 0x00, 0x08, 0xDC, 0x91, 0x97, 0x98 };

struct spi_device *spi_device = NULL;

static int w5x00_probe(struct spi_device *spi)
{
	printk("w5x00 probe\n");
	spi_device = spi;

	/* Initial field */
	gDrvInfo.base = 0;
	gDrvInfo.irq  = gpio_to_irq(W5X00_NINT);

	/* mac address */
	memcpy(gDrvInfo.macaddr, defmac, 6);
	
	/* initialize device */
	if (wiz_dev_init(&gDrvInfo) < 0) {
		return -EFAULT;
	}

	/* create network interface */
	gDrvInfo.dev = wiznet_drv_create(&gDrvInfo);

	return 0;
}

static int w5x00_remove(struct spi_device *spi)
{
	printk("w5x00 remove\n");

	/* de-initialize device */
	if (gDrvInfo.dev) {
		wiznet_drv_delete(gDrvInfo.dev);
		gDrvInfo.dev = NULL;
	}

	/* free irq */
	wiz_dev_exit(&gDrvInfo);

	spi_device = NULL;
	return 0;
}

static struct spi_driver w5x00_driver = {
	.driver = {
		.name = "w5x00",
		.bus = &spi_bus_type,
		.owner = THIS_MODULE,
	},
	.probe = w5x00_probe,
	.remove = __devexit_p(w5x00_remove),
};


static int __init
wiz_module_init(void)
{
	int ret;

	printk(KERN_INFO "%s: %s\n", DRV_NAME, DRV_VERSION);

	ret = spi_register_driver(&w5x00_driver);
	if(ret < 0)
	{
		printk("w5x00 spi_register_driver failed\n");
		return ret;
	}
	else
		printk("w5x00 spi register succeed\n");

	return 0;
}

static void __exit 
wiz_module_exit(void)
{
	spi_unregister_driver(&w5x00_driver);
}

module_init(wiz_module_init);
module_exit(wiz_module_exit);

MODULE_AUTHOR("WIZnet");
MODULE_AUTHOR("Olaf Lüke <olaf@tinkerforge.com>");
MODULE_DESCRIPTION("Support for WIZnet w5x00-based MACRAW Mode.");
MODULE_SUPPORTED_DEVICE("WIZnet W5X00 Chip");
MODULE_LICENSE("GPL");

