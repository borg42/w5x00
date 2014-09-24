/****************************************************************************
 *
 * driver/regs.h
 * tabsize = 8
 */

#ifndef _WIZNET_REGS_H_
#define _WIZNET_REGS_H_

#define BUS8			1
#define BUS16			2
#define BUS32			4

#define BUSWIDTH BUS8

#define W5X00_VERSION_W5200 3
#define W5X00_VERSION_W5500 4

#define REG_BASE			0x0
#define	MAX_SOCK_NUM		8						// Maxmium number of socket 

#define	SEND_DATA_BUF		0x0
#define	RECV_DATA_BUF		0x0

#define MAX_SEGMENT_SIZE	1460		// 최대 송신 사이즈(MSS)
#define MAX_BUF_SIZE1		0


/* TMODE register values */
#define TMODE_NOSIZECHK_RAW	0x04		// Not availailable in w5200
#define TMODE_PPPOE			0x08
#define TMODE_PINGBLOCK		0x10
#define TMODE_WOL			0x20		// WOL (Not availailable in w5200)
#define TMODE_SWRESET		0x80
#define TMODE_UDP_FARP		0x02		// New enable force ARP (Not availailable in w5200)

/* INT_REG register values */
#define INT_MAGIC			0x10		// New magic packet interrupt (Not availailable in w5200)
#define INT_PPPTERM			0x20
#define INT_UNREACH			0x40		// Not availailable in w5200
#define INT_IPCONFLICT		0x80

/* OPT_PROTOCOL values */
#define	WSOCK_CLOSEDM		0x00		// unused socket
#define	WSOCK_STREAM		0x01		// TCP
#define	WSOCK_DGRAM			0x02		// UDP
#define	WSOCK_IPL_RAWM		0x03		// IP LAYER RAW SOCK
#define	WSOCK_MACL_RAWM		0x04		// MAC LAYER RAW SOCK
#define	WSOCK_PPPOEM		0x05		// PPPoE
#define WSOCKOPT_UCASTB		0x10		// Not availailable in w5200
#define WSOCKOPT_NDACK		0x20		// No Delayed Ack(TCP) flag
#define WSOCKOPT_BCASTB		0x40		// New Broadcast block in UDP Multicasting
#define WSOCKOPT_MULTI		0x80		// support multicating

/* COMMAND values */
#define CSOCKINIT		0x01		// initialize or open socket
#define CLISTEN			0x02		// wait connection request in tcp mode(Server mode)
#define CCONNECT		0x04		// send connection request in tcp mode(Client mode)
#define CDISCONNECT		0x08		// send closing reqeuset in tcp mode
#define CCLOSE			0x10		// close socket
#define CSEND			0x20		// updata txbuf pointer, send data
#define CSENDMAC		0x21		// send data with MAC address
#define CSENDKEEPALIVE	0x22		// send keep alive message

#define CPPPCON			0x23		// updata txbuf pointer, send data (Not availailable in w5200)
#define CPPPDISCON		0x24		// updata txbuf pointer, send data (Not availailable in w5200)
#define CPPPCR			0x25		// updata txbuf pointer, send data (Not availailable in w5200) 
#define CPPPCN			0x26		// updata txbuf pointer, send data (Not availailable in w5200)
#define CPPPCJ			0x27		// updata txbuf pointer, send data (Not availailable in w5200)
#define CRECV			0x40		// update rxbuf pointer, recv data

/* INT_STATUS values */
#define ISR_CON			0x01		// established connection
#define ISR_DISCON		0x02		// closed socket
#define ISR_RECV		0x04		// receiving data
#define ISR_TIMEOUT		0x08		// assert timeout
#define ISR_SEND_OK		0x10		// New complete sending..
#define ISR_PPP_NXT		0x20		// receiving data
#define ISR_PPP_FAIL	0x40		// receiving data
#define ISR_PPP_RECV	0x80		// receiving data
                            	
/* SOCK_STATUS values */
#define SOCK_CLOSED			0x00		// closed
#define SOCK_INIT			0x13		// init state
#define SOCK_LISTEN			0x14		// listen state
#define SOCK_SYNSENT		0x15		// connection state
#define SOCK_SYNRECV		0x16		// connection state
#define SOCK_ESTABLISHED	0x17		// success to connect

#define SOCK_FIN_WAIT1		0x18		// closing state (Not availailable in w5200)
#define SOCK_FIN_WAIT2		0x19		// closing state (Not availailable in w5200)
#define SOCK_CLOSING		0x1A		// closing state (Not availailable in w5200)
#define SOCK_TIME_WAIT		0x1B		// closing state (Not availailable in w5200)
#define SOCK_CLOSE_WAIT		0x1C		// closing state
#define SOCK_LAST_ACK		0x1D		// closing state (Not availailable in w5200)

#define SOCK_UDP			0x22		// udp socket
#define SOCK_IPL_RAW		0x32		// ip raw mode socket
#define SOCK_MACL_RAW		0x42		// mac raw mode socket
#define SOCK_PPPOE			0x5F		// pppoe socket

/* IP PROTOCOL */
#define IPPROTO_IP		0           /* Dummy for IP */
#define IPPROTO_ICMP	1           /* Control message protocol */
#define IPPROTO_IGMP	2           /* Internet group management protocol */
#define IPPROTO_GGP		3           /* Gateway^2 (deprecated) */
#define IPPROTO_TCP		6           /* TCP */
#define IPPROTO_PUP		12          /* PUP */
#define IPPROTO_UDP		17          /* UDP */
#define IPPROTO_IDP		22          /* XNS idp */
#define IPPROTO_ND		77          /* UNOFFICIAL net disk protocol */
#define IPPROTO_RAW		255         /* Raw IP packet */

/* 
 * socket registers.
 */
#define CH_SIZE			0x010000	// 0x0100->0x010000 
#define CH_OFFSET(c)	((iinchip_local_p.regs.CH_BASE) + (c << (iinchip_local_p.regs.CH_OFFSET_SHIFT)))

#define RX_BASE 0xC000
#define TX_BASE 0x8000

/**
 * \brief socket option register -> Socket Mode Register
 */
	#define OPT_PROTOCOL(c)		(CH_OFFSET(c) + 0x000000)
/**
 * \brief channel command register
 */
	#define COMMAND(c)			(CH_OFFSET(c) + 0x000100)
/**
 * \brief channel interrupt register
 */
	#define INT_STATUS(c)		(CH_OFFSET(c) + 0x000200)
/**
 * \brief channel status register
 */
	#define SOCK_STATUS(c)		(CH_OFFSET(c) + 0x000300)
/**
 * \brief source port register
 */
	#define SRC_PORT_PTR(c)		(CH_OFFSET(c) + 0x000400)
/**
 * \brief Peer MAC register address
 */
	#define DST_HA_PTR(c)		(CH_OFFSET(c) + 0x000600)
/**
 * \brief Peer IP register address
 */
	#define DST_IP_PTR(c)		(CH_OFFSET(c) + 0x000C00)
/**
 * \brief Peer port register address
 */
	#define DST_PORT_PTR(c)		(CH_OFFSET(c) + 0x001000)
/**
 * \brief Maximum Segment Size(MSS) register address
 */
	#define MSS(c)			(CH_OFFSET(c) + 0x001200)
/**
 * \brief IP Type of Service(TOS) Register 
 */
	#define IP_WTOS(c)		(CH_OFFSET(c) + 0x001500)
/**
 * \brief TTL Field
 */
	#define IP_WTTL(c)		(CH_OFFSET(c) + 0x001600)
/**
 * \brief Socket n Receive Buffer Size register
 */
	#define RX_BUF_SIZE_PTR(c)	(CH_OFFSET(c) + 0x001E00)
/**
 * \brief Socket n Receive Buffer Size register
 */
	#define TX_BUF_SIZE_PTR(c)	(CH_OFFSET(c) + 0x001F00)	
/**
 * \brief Transmit free memory size register
 */
	#define TX_FREE_SIZE_PTR(c)	(CH_OFFSET(c) + 0x002000)
/**
 * \brief Transmit memory read pointer register address
 */
	#define TX_RD_PTR(c)		(CH_OFFSET(c) + 0x002200)
/**
 * \brief Transmit memory write pointer register address
 */
	#define TX_WR_PTR(c)		(CH_OFFSET(c) + 0x002400)
/**
 * \brief Received data size register
 */
	#define RX_RECV_SIZE_PTR(c)	(CH_OFFSET(c) + 0x002600)
/**
 * \brief Read point of Receive memory
 */
	#define RX_RD_PTR(c)		(CH_OFFSET(c) + 0x002800)
/**
 * \brief Write point of Receive memory
 */
	#define RX_WR_PTR(c)		(CH_OFFSET(c) + 0x002A00)
/**
 * \brief Interrupt Mask register
 */
	#define INT_MASK(c)			(CH_OFFSET(c) + 0x002C00)
/**
 * \brief Fragment Offset in IP header
 */
	#define FRAG				(CH_OFFSET(c) + 0x002D00)

/**
 * \brief Keep Alive Timer (Not availailable in w5200)
 */
	#define KEEP_AL_TIMER		(CH_OFFSET(c) + 0x002F00)



struct w5x00_regs {
	int REG_TMODE;      // (REG_BASE+0x000)
	int REG_IP_GATEWAY; // (REG_BASE+0x001)	// 0x001 - 0x004
	int REG_IP_SUBNET;  // (REG_BASE+0x005)	// 0x005 - 0x008
	int REG_MAC_SRC;    // (REG_BASE+0x009)	// 0x009 - 0x00E
	int REG_IP_SRC;     // (REG_BASE+0x00F)	// 0x00F - 0x012

	int REG_INT_LL_TIMER0; // REG_IP_TOS -> REG_INT_LL_TIMER0
	int REG_INT_LL_TIMER1; // REG_IP_TTL -> REG_INT_LL_TIMER1
	int REG_INT_ST;        // (REG_BASE+0x015)
	int REG_INT_MASK;      // (REG_BASE+0x016)

	int REG_SIR;           // New Socket Interrupt
	int REG_SIMR;          // New Socket Interrupt Mask
	int REG_RTRY_TIMEOUT;  // (REG_BASE+0x017) -> 0x001900 
	int REG_RTRY_COUNT;    // (REG_BASE+0x019) -> 0x001B00

	int REG_PTIMER;        // New PPP LCP Request Timer register
	int REG_PMAGIC;        // New PPP LCP Magic number register
	int REG_PPP_MAC_DST;   // New PPP Destination MAC Address 	// 0x0x001E00 - 0x002300

	int REG_PSID;          // New PPP Session Identification register
	int REG_PMR;           // New PPP Maximum Segment Size register
	int REG_UIPR;          // New Unreachable IP register
	int REG_UPORT;         // New Unreachable Port register
	int REG_PHYCFGR;       // New PHY Configuration register
	int REG_VERSIONR;      // New Chip version register

	int CH_BASE;
	int CH_OFFSET_SHIFT;
};


#endif /* _WIZNET_REGS_H_ */
