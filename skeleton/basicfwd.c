/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2015 Intel Corporation
 */

#include <stdint.h>
#include <inttypes.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <arpa/inet.h>
#include <stdbool.h>
#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

#define logprintf(...) if (enable_log) { fprintf(logfile, __VA_ARGS__); }
static bool enable_log = true;
static FILE *logfile;

static const struct rte_eth_conf port_conf_default = {
	.rxmode = {
		   .max_rx_pkt_len = ETHER_MAX_LEN,
		   .ignore_offload_bitfield = 1,
		   },
};

/* basicfwd.c: Basic DPDK skeleton forwarding example. */

/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */
static inline int port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
	struct rte_eth_conf port_conf = port_conf_default;
	const uint16_t rx_rings = 1, tx_rings = 1;
	uint16_t nb_rxd = RX_RING_SIZE;
	uint16_t nb_txd = TX_RING_SIZE;
	int retval;
	uint16_t q;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf txconf;

	if (!rte_eth_dev_is_valid_port(port))
		return -1;

	rte_eth_dev_info_get(port, &dev_info);
	if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
		port_conf.txmode.offloads |= DEV_TX_OFFLOAD_MBUF_FAST_FREE;

	/* Configure the Ethernet device. */
	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;

	retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
	if (retval != 0)
		return retval;

	/* Allocate and set up 1 RX queue per Ethernet port. */
	for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
						rte_eth_dev_socket_id(port),
						NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	txconf = dev_info.default_txconf;
	txconf.txq_flags = ETH_TXQ_FLAGS_IGNORE;
	txconf.offloads = port_conf.txmode.offloads;
	/* Allocate and set up 1 TX queue per Ethernet port. */
	for (q = 0; q < tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(port, q, nb_txd,
						rte_eth_dev_socket_id(port),
						&txconf);
		if (retval < 0)
			return retval;
	}

	/* Start the Ethernet port. */
	retval = rte_eth_dev_start(port);
	if (retval < 0)
		return retval;

	/* Display the port MAC address. */
	struct ether_addr addr;
	rte_eth_macaddr_get(port, &addr);
	printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
	       " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
	       port,
	       addr.addr_bytes[0], addr.addr_bytes[1],
	       addr.addr_bytes[2], addr.addr_bytes[3],
	       addr.addr_bytes[4], addr.addr_bytes[5]);

	/* Enable RX in promiscuous mode for the Ethernet device. */
	rte_eth_promiscuous_enable(port);

	return 0;
}

#define  RULE_COUNT 1
static struct in_addr filter_source_ip[RULE_COUNT];
static struct in_addr filter_dest_ip[RULE_COUNT];
static uint16_t filter_dest_port[RULE_COUNT];
static uint16_t filter_source_port[RULE_COUNT];
static uint8_t filter_protocol[RULE_COUNT];

static char *mac_address_int_to_str(uint8_t * hwaddr, char *buff, size_t size)
{
	snprintf(buff, size, "%02x:%02x:%02x:%02x:%02x:%02x",
		 hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3], hwaddr[4],
		 hwaddr[5]);
	return (buff);
}

static char *IP_address_int_to_IP_address_str(u_int32_t ip, char *buff,
					      socklen_t size)
{
	struct in_addr *addr;
	addr = (struct in_addr *)&ip;
	inet_ntop(AF_INET, addr, buff, size);
	return (buff);
}

static const char *get_ip_protocol(const struct ipv4_hdr *iphdr)
{
	const char *protocol[] = {
		"undifined",
		"ICMP",
		"IGMP",
		"undifined",
		"IP",
		"undifined",
		"TCP",
		"CBT",
		"EGP",
		"IGP",
		"undifined",
		"undifined",
		"undifined",
		"undifined",
		"undifined",
		"undifined",
		"undifined",
		"UDP",
	};

	// logprintf("protocol : %u ",iphdr->protocol);

	if ((iphdr->next_proto_id) <= 17) {
		return protocol[iphdr->next_proto_id];
	} else {
		return "undifined";
	}
}

static int input_filter_info(int count)
{
	unsigned long int dest_port_ul;
	unsigned long int src_port_ul;
	char dest_port_str[256];
	char src_port_str[256];
	char dest_ip[256];
	char src_ip[256];
	char protocol[256];
	int res;

	printf("\n[filter:%d]\n", count);
	//ip dest
	printf("input filter dest ip:");
	errno = 0;
	res = scanf("%s", dest_ip);
	if (errno != 0) {
		perror("scanf");
		return -1;
	} else if (res != 1) {
		fprintf(stderr, "scanf failed\n");
		return -1;
	}
	res = inet_pton(AF_INET, dest_ip, &filter_dest_ip[count]);
	if (res == -1) {
		perror("inet_pton");
		return -1;
	} else if (res == 0) {
		fprintf(stderr, "invalid address\n");
		return -1;
	}
	//ip src
	printf("input filter source ip:");
	errno = 0;
	res = scanf("%s", src_ip);
	if (errno != 0) {
		perror("scanf");
		return -1;
	} else if (res != 1) {
		fprintf(stderr, "scanf failed\n");
	}
	res = inet_pton(AF_INET, src_ip, &filter_source_ip[count]);
	if (res == -1) {
		perror("inet_pton");
		return -1;
	} else if (res == 0) {
		fprintf(stderr, "invalid address\n");
		return -1;
	}
	//ip proto
	printf("input filter protocol:");
	errno = 0;
	res = scanf("%s", protocol);
	if (errno != 0) {
		perror("scanf");
		return -1;
	} else if (res != 1) {
		fprintf(stderr, "scanf failed\n");
		return -1;
	}

	if (strcmp(protocol, "TCP") == 0) {
		filter_protocol[count] = IPPROTO_TCP;
	} else if (strcmp(protocol, "UDP") == 0) {
		filter_protocol[count] = IPPROTO_UDP;
	} else {
		fprintf(stderr, "invalid protocol\n");
		return -1;
	}

	//port dest
	printf("input filter dest port:");
	errno = 0;
	res = scanf("%s", dest_port_str);
	if (errno != 0) {
		perror("scanf");
		return -1;
	} else if (res != 1) {
		fprintf(stderr, "scanf failed\n");
		return -1;
	}
	errno = 0;
	dest_port_ul = strtoul(dest_port_str, NULL, 10);
	if (errno != 0) {
		perror("strtoul");
		return -1;
	} else if (dest_port_ul > UINT16_MAX) {
		fprintf(stderr, "port number too large\n");
		return -1;
	} else if (dest_port_ul == 0) {
		fprintf(stderr, "invalid port number\n");
		return -1;
	}
	filter_dest_port[count] = htons((uint16_t) dest_port_ul);

	//port src
	printf("input filter source port:");
	errno = 0;
	res = scanf("%s", src_port_str);

	if (errno != 0) {
		perror("scanf");
		return -1;
	} else if (res != 1) {
		fprintf(stderr, "scanf failed\n");
		return -1;
	}
	errno = 0;
	src_port_ul = strtoul(src_port_str, NULL, 10);
	if (errno != 0) {
		perror("strtoul");
		return -1;
	} else if (src_port_ul > UINT16_MAX) {
		fprintf(stderr, "port number too large\n");
		return -1;
	} else if (src_port_ul == 0) {
		fprintf(stderr, "invalid port number\n");
		return -1;
	}
	filter_source_port[count] = htons((uint16_t) src_port_ul);
	return 0;

}

static bool check_packet(struct ipv4_hdr *ih, void *l4hdr, int count)
{
	if (ih->src_addr != filter_source_ip[count].s_addr) {
		return false;
	}
	if (ih->dst_addr != filter_dest_ip[count].s_addr) {
		return false;
	}
	if (ih->next_proto_id != filter_protocol[count]) {
		return false;
	}

	if (filter_protocol[count] == IPPROTO_TCP) {
		struct tcp_hdr *th = (struct tcp_hdr *)l4hdr;
		if (th->src_port != filter_source_port[count]) {
			return false;
		}
		if (th->dst_port != filter_dest_port[count]) {
			return false;
		}
	} else if (filter_protocol[count] == IPPROTO_UDP) {
		struct udp_hdr *uh = (struct udp_hdr *)l4hdr;
		if (uh->src_port != filter_source_port[count]) {
			return false;
		}
		if (uh->dst_port != filter_dest_port[count]) {
			return false;
		}
	}
	return true;
}

static bool filter(struct rte_mbuf *m)
{
	struct ether_hdr *eh;
	struct ipv4_hdr *ih;
	char buf[256];
	uint16_t ether_type;
	uint32_t packet_length = rte_pktmbuf_pkt_len(m);
	int lest = (int)packet_length;
	//unsigned int oplen;

	if (lest < (int)sizeof(struct ether_hdr)) {
		return true;
	}

	lest -= (int)sizeof(struct ether_hdr);
	eh = rte_pktmbuf_mtod(m, struct ether_hdr *);
	ether_type = ntohs(eh->ether_type);

	logprintf("\n==== ether info ====\n");
	logprintf("ether dest host:%s\n",
		  mac_address_int_to_str(eh->d_addr.addr_bytes, buf,
					 sizeof(buf)));
	logprintf("ether src  host:%s\n",
		  mac_address_int_to_str(eh->s_addr.addr_bytes, buf,
					 sizeof(buf)));
	logprintf("ether type:0x%02X:", ether_type);

	switch (ether_type) {
	case ETHER_TYPE_IPv4:
		logprintf("[IP]\n");
		break;
	case ETHER_TYPE_ARP:
		logprintf("[ARP]\n");
		return false;
	default:
		logprintf("\n");
		return false;
	}

	if (lest < (int)sizeof(struct ipv4_hdr)) {
		return true;
	}
	lest -= sizeof(struct ipv4_hdr);
	ih = rte_pktmbuf_mtod_offset(m, struct ipv4_hdr *,
				     sizeof(struct ether_hdr));

	int version_mask = 240;	// 0x11110000
	int oplen =
	    ((ih->version_ihl) & IPV4_HDR_IHL_MASK) * 4 - sizeof(struct ipv4_hdr);

	logprintf("==== IP info ====\n");
	logprintf("ip header version:%d\n",
		  (ih->version_ihl & version_mask) >> 4)
	    logprintf("ip header length:%d\n", ih->version_ihl & IPV4_HDR_IHL_MASK)
	    logprintf("src ip:%s\n",
		      IP_address_int_to_IP_address_str(ih->src_addr, buf,
						       sizeof(buf)));
	logprintf("dest ip:%s\n",
		  IP_address_int_to_IP_address_str(ih->dst_addr, buf,
						   sizeof(buf)));
	logprintf("ip protocol:[%s]\n", get_ip_protocol(ih));
	logprintf("tol:%u\n", ih->total_length);
	logprintf("oplen:%u\n", oplen);
	lest -= oplen;
	if (ih->next_proto_id == IPPROTO_TCP) {

		if (lest < (int)sizeof(struct tcp_hdr)) {
			return true;
		}
		lest -= sizeof(struct tcp_hdr);

		struct tcp_hdr *th =
		    rte_pktmbuf_mtod_offset(m, struct tcp_hdr *,
					    sizeof(struct ether_hdr) +
					    sizeof(struct ipv4_hdr) + oplen);
		logprintf("==== TCP info ====\n");
		logprintf("src port:%u\n", ntohs(th->src_port));
		logprintf("dest port:%u\n", ntohs(th->dst_port));
		logprintf("seq:%u\n", ntohl(th->sent_seq));
		logprintf("ack:%u\n", ntohl(th->recv_ack));
		for (int i = 0; i < RULE_COUNT; i++) {
			bool res = check_packet(ih, (void *)th, i);
			if (res) {
				return true;
			}
		}
		return false;

	} else if (ih->next_proto_id == IPPROTO_UDP) {

		if (lest < (int)sizeof(struct udp_hdr)) {
			return true;
		}
		lest -= sizeof(struct udp_hdr);

		struct udp_hdr *uh =
		    rte_pktmbuf_mtod_offset(m, struct udp_hdr *,
					    sizeof(struct ether_hdr) +
					    sizeof(struct ipv4_hdr) + oplen);
		logprintf("==== UDP info ====\n");
		logprintf("src port:%u\n", ntohs(uh->src_port));
		logprintf("dest port:%u\n", ntohs(uh->dst_port));
		for (int i = 0; i < RULE_COUNT; i++) {
			bool res = check_packet(ih, (void *)uh, i);
			if (res) {
				return true;
			}
		}
		return false;
	} else {
		return false;
	}
}

/*
 * The lcore main. This is the main thread that does the work, reading from
 * an input port and writing to an output port.
 */

static __attribute__ ((noreturn))
void lcore_main(void)
{
	uint16_t port;

	/*
	 * Check that the port is on the same NUMA node as the polling thread
	 * for best performance.
	 */
	RTE_ETH_FOREACH_DEV(port)
	    if (rte_eth_dev_socket_id(port) > 0 &&
		rte_eth_dev_socket_id(port) != (int)rte_socket_id())
		printf("WARNING, port %u is on remote NUMA node to "
		       "polling thread.\n\tPerformance will "
		       "not be optimal.\n", port);

	printf("\nCore %u forwarding packets. [Ctrl+C to quit]\n",
	       rte_lcore_id());

	/* Run until the application is quit or killed. */
	for (;;) {
		/*
		 * Receive packets on a port and forward them on the paired
		 * port. The mapping is 0 -> 1, 1 -> 0, 2 -> 3, 3 -> 2, etc.
		 */
		RTE_ETH_FOREACH_DEV(port) {

			/* Get burst of RX packets, from first port of pair. */
			struct rte_mbuf *bufs[BURST_SIZE];
			struct rte_mbuf *tx_bufs[BURST_SIZE];
			const uint16_t nb_rx = rte_eth_rx_burst(port, 0,
								bufs,
								BURST_SIZE);
			uint16_t packet_count = 0;

			if (unlikely(nb_rx == 0))
				continue;

			for (int i = 0; i < nb_rx; i++) {
				struct rte_mbuf *m = bufs[i];
				bool res = filter(m);
				logprintf("size:%d\n", rte_pktmbuf_pkt_len(m));
				logprintf("result:%d\n", res);

				if (!res) {
					tx_bufs[packet_count] = m;
					packet_count++;
				} else {
					rte_pktmbuf_free(m);
				}
			}

			//send
			const uint16_t nb_tx =
			    rte_eth_tx_burst(port ^ 1, 0, tx_bufs,
					     packet_count);

			/* Free any unsent packets. */
			if (unlikely(nb_tx < packet_count)) {
				uint16_t buf;
				for (buf = nb_tx; buf < nb_rx; buf++)
					rte_pktmbuf_free(tx_bufs[buf]);
			}
		}
	}
}

/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int main(int argc, char *argv[])
{
	struct rte_mempool *mbuf_pool;
	unsigned nb_ports;
	uint16_t portid;

	/* Initialize the Environment Abstraction Layer (EAL). */
	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

	argc -= ret;
	argv += ret;

	/* Check that there is an even number of ports to send/receive on. */
	nb_ports = rte_eth_dev_count();
	if (nb_ports < 2 || (nb_ports & 1))
		rte_exit(EXIT_FAILURE, "Error: number of ports must be even\n");

	/* Creates a new mempool in memory to hold the mbufs. */
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
					    MBUF_CACHE_SIZE, 0,
					    RTE_MBUF_DEFAULT_BUF_SIZE,
					    rte_socket_id());

	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	/* Initialize all ports. */
	RTE_ETH_FOREACH_DEV(portid)
	    if (port_init(portid, mbuf_pool) != 0)
		rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n",
			 portid);

	if (rte_lcore_count() > 1)
		printf("\nWARNING: Too many lcores enabled. Only 1 used.\n");

	for (int i = 0; i < RULE_COUNT; i++) {
		while (1) {
			int res = input_filter_info(i);
			if (res == 0)
				break;
		}
	}

	if (enable_log) {
		logfile = fopen("output.log", "w");
		if (logfile == NULL) {
			fprintf(stderr, "err cant open file");
			return (-1);
		}
	}

	/* Call lcore_main on the master core only. */
	lcore_main();

	if (enable_log) {
		fclose(logfile);
	}
	return 0;
}
