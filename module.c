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

static int param_mac_size = 6;

struct spi_device *spi_device = NULL;

static int param_pin_interrupt = W5X00_DEFAULT_PIN_INTERRUPT;
static int param_pin_reset = W5X00_DEFAULT_PIN_RESET;
static int param_select = W5X00_DEFAULT_SELECT;
static unsigned char param_mac[6] = W5X00_DEFAULT_MAC;

module_param(param_pin_interrupt, int, 0);
MODULE_PARM_DESC(param_pin_interrupt, "Interrupt pin number");

module_param(param_pin_reset, int, 0);
MODULE_PARM_DESC(param_pin_reset, "Reset pin number");

module_param(param_select, int, 0);
MODULE_PARM_DESC(param_select, "SPI select number");

module_param_array(param_mac, byte, &param_mac_size, 0);
MODULE_PARM_DESC(param_mac, "MAC Address");

static int w5x00_probe(struct spi_device *spi)
{
	printk("w5x00 probe [int %d, rst %d, sel %d, mac %x:%x:%x:%x:%x:%x]\n",
	       param_pin_interrupt,
		   param_pin_reset,
		   param_select,
		   param_mac[0], param_mac[1], param_mac[2], 
		   param_mac[3], param_mac[4], param_mac[5]);

	printk("chip select before: %d\n", spi->chip_select);

	spi->chip_select = param_select;
	spi_device = spi;

	/* Initial field */
	gDrvInfo.base = 0;
	gDrvInfo.pin_interrupt = param_pin_interrupt;
	gDrvInfo.pin_reset = param_pin_reset;
	gDrvInfo.irq = gpio_to_irq(param_pin_interrupt);

	/* mac address */
	memcpy(gDrvInfo.macaddr, param_mac, 6);
	
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

