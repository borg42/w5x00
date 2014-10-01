/****************************************************************************
 *
 * driver/w5x00.h
 */

#ifndef _WIZNET_W5X00_H_
#define _WIZNET_W5X00_H_

#define DRV_NAME	"w5x00"
#define DRV_VERSION	"2.0.0"


/* Linux OS macros and functions related */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/interrupt.h>
#include <asm/io.h>
#include <asm/irq.h>
#include <asm/atomic.h>
#include <asm/uaccess.h>

#include "regs.h"

#define W5X00_DEFAULT_PIN_RESET      15
#define W5X00_DEFAULT_PIN_INTERRUPT  17
#define W5X00_DEFAULT_SELECT         0
#define W5X00_DEFAULT_MAC            {0x00, 0x08, 0xDC, 0x91, 0x97, 0x98}

#define SPI_BURST_SIZE	28			// Read/Write Burst Size (For spi_write_then_read)

/* driver information */
typedef struct _wiz_t {
	u32 base;
	int irq;
	int pin_interrupt;
	int pin_reset;
	int sock[MAX_SOCK_NUM];
	int nof_socks;
	u8  macaddr[8];
	u16 local_port;

#if 1	// 2014.03.12 sskim
	struct sk_buff *tx_skb;
	struct work_struct tx_work;
	struct work_struct rx_work;
#endif
	spinlock_t lock;
	struct net_device *dev;
} wiz_t;


/* 
 * Information that need to be kept for each board.
 */
struct wiz_private {
	struct net_device_stats stats;
	wiz_t *wiz;
	int s;
	/* tasklet */

	/* Tx control lock.  This protects the transmit buffer ring
	 * state along with the "tx full" state of the driver.  This
	 * means all netif_queue flow control actions are protected
	 * by this lock as well.
	 */
	spinlock_t lock;
};


/* hwtcpip driver information */
typedef struct _hwtcpip_t {
	int sock_use[MAX_SOCK_NUM];
	int sock_opmode[MAX_SOCK_NUM];
	int sock_status[MAX_SOCK_NUM];
} hwtcpip_t;


typedef union un_l2cval {
	unsigned long	lVal;
	unsigned char	cVal[4];
}un_l2cval;

typedef union un_i2cval {
	unsigned int	iVal;
	unsigned char	cVal[2];
}un_i2cval;


/* 
 * wiznet ioctl interface.
 */
 
#define WIZNETIOCTL     SIOCDEVPRIVATE
#define WZIOC_GETOID    1
#define WZIOC_SETOID    2
#define WZIOC_TEST      3

struct s_wiznet_ioctl {
	unsigned long cmd;
	unsigned long oid;
	unsigned long len;
	char *data;
};

/* base.c */
void wiz_mac_update(wiz_t *wz, u8 *mac);
void wiz_srcip_update(wiz_t *wz, u32 addr);
void wiz_subnet_update(wiz_t *wz, u32 addr);
void wiz_gateway_update(wiz_t *wz, u32 addr);
int wiz_dev_init(wiz_t *wz);
int wiz_dev_exit(wiz_t *wz);
int wiz_socket_open(wiz_t *wz, int s, int protocol, int port, int flag);
int wiz_socket_close(wiz_t *wz, int s);

/* netdrv.c */
struct net_device *wiznet_drv_create(wiz_t *wz);
void wiznet_drv_delete(struct net_device *dev);

/* dev.c */
int iinchip_netif_create(struct net_device *dev);
int iinchip_open(int s, int type, int ipproto);
int iinchip_close(int s);
int iinchip_netif_delete(struct net_device *dev);
int iinchip_send_buf(int s, unsigned char *buf, int len);
void iinchip_socket_sethwaddr(char *addr);
void iinchip_copy_to(u32 adr, const u8 *buf, ssize_t len);
void iinchip_copy_from(u32 adr, u8 *buf, ssize_t len);
int iinchip_socket_tasklet_init(int s, void (*func)(unsigned long), unsigned long data);
int iinchip_socket_interrupt_enable(int s);
int iinchip_socket_interrupt_disable(int s);
int iinchip_socket_tasklet_kill(int s);

/* debug */
#define DBFENTER
#define DBFEXIT

#endif 
