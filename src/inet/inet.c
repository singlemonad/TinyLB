//
// Created by tedqu on 24-9-12.
//

#include <linux/if_ether.h>
#include <rte_arp.h>
#include "../common/util.h"
#include "../common/log.h"
#include "../common/lcore.h"
#include "inet.h"
#include "ipv4.h"
#include "tcp.h"
#include "udp.h"
#include "gre.h"
#include "icmp.h"

static struct l3_handler* l3_handlers[L3_HANDLER_MAX];

void inet_register_l3_handler(struct l3_handler *handler, uint16_t pkt_type) {
    if (pkt_type == ETH_P_ARP) {
        l3_handlers[L3_HANDLER_ARP] = handler;
    } else if (pkt_type == ETH_P_IP) {
        l3_handlers[L3_HANDLER_IPV4] = handler;
    } else {
        rte_exit(EXIT_FAILURE, "%s: l3 type %s not support", __func__, pkt_type);
    }
}

int deliver_l3_skb(sk_buff_t *skb) {
    struct rte_ether_hdr *eth;
    struct lcore_rxtx_stats *stats = get_lcore_stats(rte_lcore_id());

    eth = (struct rte_ether_hdr*)(skb->eth);
    switch (rte_be_to_cpu_16(eth->ether_type)) {
        case ETH_P_IP:
            ++stats->rx_ip;
            l3_handlers[L3_HANDLER_IPV4]->rcv(skb);
            break;
        case ETH_P_ARP:
            ++stats->rx_arp;
            l3_handlers[L3_HANDLER_ARP]->rcv(skb);
            break;
        default:
            RTE_LOG(ERR, NAT_LB, "%s: no l3 handler for proto %d, drop it\n", __func__, rte_be_to_cpu_16(eth->ether_type));
            ++stats->drop.invalid_l3_proto;
            rte_pktmbuf_free((struct rte_mbuf*)skb);
    }
    return NAT_LB_OK;
}

void inet_module_init(void) {
    ipv4_init();
    icmp_init();
    tcp_init();
    udp_init();
    gre_init();
}