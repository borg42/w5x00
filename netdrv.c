/****************************************************************************
 *
 * driver/netdrv.c
 */

/*********************************************
 * network interface driver support
 *********************************************/

#include <linux/spi/spi.h>
#include "w5x00.h"
#include "queue.h"

extern struct spi_device *spi_device;
extern struct workqueue_struct *w5x00_wq;

//#define DEBUG_PKT
#if 0
#define DPRINTK(format,args...) printk(format,##args)
#else
#define DPRINTK(format,args...)
#endif

/*
 * Open/initialize the board. This is called (in the current kernel)
 * sometime after booting when the 'ifconfig' program is run.
 *
 * This routine should set everything up anew at each open, even
 * registers that "should" only need to be set once at boot, so that
 * there is non-reboot way to recover if something goes wrong.
 */
static int 
wiznet_open(struct net_device *dev)
{
	struct wiz_private *wp = netdev_priv(dev);
	int r;

	/* create socket */
	r = iinchip_netif_create(dev);
	if (r < 0) {
		printk("%s: can't create socket\n", dev->name);
		return -EFAULT;
	}

	/* open socket */
	r = iinchip_open(wp->s, WSOCK_MACL_RAWM, 0);
	if (r < 0) {
		printk("%s: can't open socket\n", dev->name);
		return -EFAULT;
	}

	/*
	 * start driver.
	 */
	netif_start_queue(dev);
	
	return 0;
}


/*
 * The inverse routine to net_open().
 */
static int
wiznet_close(struct net_device *dev)
{
	struct wiz_private *wp = netdev_priv(dev);

	/* 
	 * stop driver.
	 */
	netif_stop_queue(dev);

	// close socket
	iinchip_close(wp->s);

	// delete interface
	iinchip_netif_delete(dev);
	
	return 0;
}

/* This will only be invoked if the driver is _not_ in XOFF state.
 * What this means is that we need not check it, and that this
 * invariant will hold if we make sure that the netif_*_queue()
 * calls are done at the proper times.
 */
static int 
wiznet_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct wiz_private *wp = netdev_priv(dev);
	SKB_NODE *p;

	p = alloc_skb_node();
	if(p == NULL) {
		printk("skb alloc failed\n");
		return 0;
	}

	p->skb = skb;
	push_skb(p);

	queue_work(w5x00_wq, &(wp->wiz->tx_work));
	return 0;
}

/*
 * Get the current statistics.
 * This may be called with the card open or closed.
 */
static struct net_device_stats *
wiznet_get_stats(struct net_device *dev)
{
	struct wiz_private *wp = netdev_priv(dev);

	return (&wp->stats);
}

/* 
 * set MAC address of the interface. called from the core after a
 * SIOCSIFADDR ioctl, and from the bootup above.
 */
static int 
wiznet_set_address(struct net_device *dev, void *p)
{
	struct sockaddr *addr = p;

	/* update */
	iinchip_socket_sethwaddr(addr->sa_data);

	/* remember it */
	memcpy(dev->dev_addr, addr->sa_data, dev->addr_len);

	return 0;
}

/*
 * Set or clear the multicast filter for this adaptor.
 * num_addrs == -1	Promiscuous mode, receive all packets
 * num_addrs == 0	Normal mode, clear multicast list
 * num_addrs > 0	Multicast mode, receive normal and MC packets,
 *			and do best-effort filtering.
 */
static void 
wiznet_set_multicast(struct net_device *dev)
{
	if (dev->flags & IFF_PROMISC) {
		/* promiscuous mode */

	} else if (dev->flags & IFF_ALLMULTI) {
		/* MC mode, receive normal and MC packets */

	} else {
		/* Normal, clear the mc list */

	}
}

static void
wiznet_tx_timeout(struct net_device *dev)
{
	struct wiz_private *wp = netdev_priv(dev);

	wp->stats.tx_errors++;
}

/* ioctl service */
static int
wiznet_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd)
{
	struct s_wiznet_ioctl req;
	int err = 0;
	
	if (!capable (CAP_NET_ADMIN))
		return -EPERM;

	if (dev == NULL)
		return -ENODEV;

	if (cmd != WIZNETIOCTL)
		return -ENOTTY;

	err = copy_from_user(&req, ifr->ifr_data, sizeof(struct s_wiznet_ioctl));
	if (err)
		return -EFAULT;

	switch (req.cmd) {
	
	case WZIOC_SETOID:
		DPRINTK("ioctl: Set REG 0x%x: data %p, len %d\n", req.oid, req.data, req.len);
		if (!access_ok(VERIFY_READ, req.data, req.len))
			return -EFAULT;
		iinchip_copy_to(req.oid, req.data, req.len);
		if (copy_to_user(ifr->ifr_data, &req, sizeof(struct s_wiznet_ioctl)))
			err = -EFAULT;
		break;
		
	case WZIOC_GETOID:
		DPRINTK("ioctl: Get REG 0x%x, len %d\n", req.oid, req.len);
		if (!access_ok(VERIFY_WRITE, req.data, req.len))
			return -EFAULT;
		iinchip_copy_from(req.oid, req.data, req.len);
		if (copy_to_user(ifr->ifr_data, &req, sizeof(struct s_wiznet_ioctl)))
			err = -EFAULT;
		break;
		
	default:
		err = -EOPNOTSUPP;
	}

	return err;
}

/* create network device driver */
static const struct net_device_ops netdev_ops = {
	.ndo_open		= wiznet_open,
	.ndo_stop		= wiznet_close,
	.ndo_get_stats		= wiznet_get_stats,
	.ndo_start_xmit		= wiznet_start_xmit,
	.ndo_tx_timeout		= wiznet_tx_timeout,
	.ndo_set_mac_address	= wiznet_set_address,
	.ndo_do_ioctl		= wiznet_ioctl,
	.ndo_set_rx_mode 	= wiznet_set_multicast,
	.ndo_change_mtu		= eth_change_mtu,
	.ndo_validate_addr	= eth_validate_addr,
};

struct net_device *
wiznet_drv_create(wiz_t *wz)
{
	struct net_device *dev;
	struct wiz_private *wp;

	/* create ethernet device */
	dev = alloc_etherdev(sizeof(struct wiz_private));
	if (dev == NULL) {
		printk("%s: can't create device\n", DRV_NAME);
		return NULL;
	}

	/* initialize private device structure */

	/* initialize network device structure */
	wp = netdev_priv(dev);

	dev_set_drvdata(&spi_device->dev, wp);
	SET_NETDEV_DEV(dev, &spi_device->dev);

	wp->s = 0;
	wp->wiz = wz;
	memcpy(dev->dev_addr, wz->macaddr, 6);
	dev->base_addr = wz->base;
	dev->irq = wz->irq;
	dev->netdev_ops = &netdev_ops;
	dev->watchdog_timeo	= 2 * HZ;
	
	/* override Name */
	strcpy(dev->name, "wiz%d");

	/* register driver */
	if (register_netdev(dev)) {
		printk("%s: register_netdev() failed\n", DRV_NAME);
		kfree(dev);
		return NULL;
	}
	
	return dev;
}

void wiznet_drv_delete(struct net_device *dev)
{
	/* unregister driver */
	unregister_netdev(dev);
}
