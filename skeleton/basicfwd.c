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
static inline int
port_init(uint16_t port, struct rte_mempool *mbuf_pool)
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
		port_conf.txmode.offloads |=
			DEV_TX_OFFLOAD_MBUF_FAST_FREE;

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
				rte_eth_dev_socket_id(port), NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	txconf = dev_info.default_txconf;
	txconf.txq_flags = ETH_TXQ_FLAGS_IGNORE;
	txconf.offloads = port_conf.txmode.offloads;
	/* Allocate and set up 1 TX queue per Ethernet port. */
	for (q = 0; q < tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(port, q, nb_txd,
				rte_eth_dev_socket_id(port), &txconf);
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

static char *mac_address_int_to_str(uint8_t * hwaddr, char *buff, size_t size)
{
        snprintf(buff, size, "%02x:%02x:%02x:%02x:%02x:%02x",
                 hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3], hwaddr[4],
                 hwaddr[5]);
        return (buff);
}

static char *IP_address_int_to_IP_address_str(u_int32_t ip, char *buff, socklen_t size)
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

#define logprintf printf

static void filter(struct rte_mbuf **bufs, const uint16_t nb_rx){
	for(int i=0;i<nb_rx;i++){
		struct rte_mbuf *m = bufs[i];
		struct ether_hdr *eh;
		struct tcp_hdr *th;
		struct udp_hdr *uh;
		struct ipv4_hdr *ih;
		char buf[256];
		uint16_t ether_type;
		//unsigned int oplen;

		eh = rte_pktmbuf_mtod(m, struct ether_hdr*);
		ether_type = ntohs(eh->ether_type);

		logprintf("\n==== ether info ====\n");
        	logprintf("ether dest host:%s\n",mac_address_int_to_str(eh->d_addr.addr_bytes,buf,sizeof(buf)));
        	logprintf("ether src  host:%s\n",mac_address_int_to_str(eh->s_addr.addr_bytes,buf,sizeof(buf)));
        	logprintf("ether type:0x%02X:",ether_type);

		switch(ether_type){
                	case ETHER_TYPE_IPv4:
                        	logprintf("[IP]\n");
                        	break;
                	case ETHER_TYPE_ARP:
                        	logprintf("[ARP]\n");
                        	continue;
                	default:
                        	logprintf("\n");
                        	continue;
        	}

		ih = rte_pktmbuf_mtod_offset(m, struct ipv4_hdr*, sizeof(struct ether_hdr));
		//oplen = ih->ihl * 4 - sizeof(struct iphdr);

        	logprintf("==== IP info ====\n");
        	logprintf("src ip:%s\n", IP_address_int_to_IP_address_str(ih->src_addr, buf, sizeof(buf)));
        	logprintf("dest ip:%s\n", IP_address_int_to_IP_address_str(ih->dst_addr, buf, sizeof(buf)));
        	logprintf("ip protocol:[%s]\n", get_ip_protocol(ih));
        	//logprintf("oplen:%u\n", oplen);

		if (ih->next_proto_id == IPPROTO_TCP) {
                th = rte_pktmbuf_mtod_offset(m, struct tcp_hdr*, sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr));
		logprintf("==== TCP info ====\n");
                logprintf("src port:%u\n", ntohs(th->src_port));
                logprintf("dest port:%u\n", ntohs(th->dst_port));
                logprintf("seq:%u\n", ntohl(th->sent_seq));
                logprintf("ack:%u\n", ntohl(th->recv_ack));

                //bool res = check_packet(ih, (const void*)th);

                //return res;
        } else if (ih->next_proto_id == IPPROTO_UDP) {
                uh = rte_pktmbuf_mtod_offset(m, struct udp_hdr*, sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr));
                logprintf("==== UDP info ====\n");
                logprintf("src port:%u\n", ntohs(uh->src_port));
                logprintf("dest port:%u\n", ntohs(uh->dst_port));

                //bool res = check_packet(ih, (const void*)uh);
                //return res;
	        }
	}
}

/*
 * The lcore main. This is the main thread that does the work, reading from
 * an input port and writing to an output port.
 */
static __attribute__((noreturn)) void
lcore_main(void)
{
	uint16_t port;

	/*
	 * Check that the port is on the same NUMA node as the polling thread
	 * for best performance.
	 */
	RTE_ETH_FOREACH_DEV(port)
		if (rte_eth_dev_socket_id(port) > 0 &&
				rte_eth_dev_socket_id(port) !=
						(int)rte_socket_id())
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
			const uint16_t nb_rx = rte_eth_rx_burst(port, 0,
					bufs, BURST_SIZE);

			if (unlikely(nb_rx == 0))
				continue;

			filter(bufs, nb_rx); 
			/* Send burst of TX packets, to second port of pair. */
			const uint16_t nb_tx = rte_eth_tx_burst(port ^ 1, 0,
					bufs, nb_rx);

			/* Free any unsent packets. */
			if (unlikely(nb_tx < nb_rx)) {
				uint16_t buf;
				for (buf = nb_tx; buf < nb_rx; buf++)
					rte_pktmbuf_free(bufs[buf]);
			}
		}
	}
}

/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int
main(int argc, char *argv[])
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
		MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	/* Initialize all ports. */
	RTE_ETH_FOREACH_DEV(portid)
		if (port_init(portid, mbuf_pool) != 0)
			rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n",
					portid);

	if (rte_lcore_count() > 1)
		printf("\nWARNING: Too many lcores enabled. Only 1 used.\n");

	/* Call lcore_main on the master core only. */
	lcore_main();

	return 0;
}
