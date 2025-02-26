//
// Created by tedqu on 24-9-12.
//

#include <linux/if_ether.h>
#include "../include/inet.h"
#include "../include/common.h"
#include "../include/log.h"

enum l3_handler_type {
    L3_HANDLER_ARP = 0,
    L3_HANDLER_IPV4 = 1,
    L3_HANDLER_MAX = 2
};

static struct l3_handler* l3_handlers[L3_HANDLER_MAX];

void inet_register_l3_handler(struct l3_handler *handler, uint16_t pkt_type) {
    if (pkt_type == ETH_P_ARP) {
        l3_handlers[L3_HANDLER_ARP] = handler;
    } else if (pkt_type == ETH_P_IP) {
        l3_handlers[L3_HANDLER_IPV4] = handler;
    } else {
        rte_exit(EXIT_FAILURE, "l3 type %s not support.", pkt_type);
    }
}


static bool is_valid_pkt(sk_buff_t *skb) {
    if (NULL == skb || skb->mbuf.data_len == 0 || skb->mbuf.pkt_len == 0) {
        return false;
    }
    return true;
}

static int l3_deliver_skb(sk_buff_t *skb) {
    struct rte_ether_hdr *eth_hdr;
    int l3_handler_idx;

    eth_hdr = rte_pktmbuf_mtod((struct rte_mbuf*)skb, struct rte_ether_hdr *);
    skb->mbuf.l2_len = sizeof(struct rte_ether_hdr);

    // remove eth hdr before deliver to l3
    if (NULL == rte_pktmbuf_adj((struct rte_mbuf*)skb, sizeof(struct rte_ether_hdr))) {
        goto drop;
    }

    if (likely(eth_hdr->ether_type == rte_cpu_to_be_16(ETH_P_IP))) {
        l3_handler_idx = L3_HANDLER_IPV4;
    } else if (eth_hdr->ether_type == rte_cpu_to_be_16(ETH_P_ARP)) {
        l3_handler_idx = L3_HANDLER_ARP;
    } else {
        RTE_LOG(ERR, DEV, "No l3 rcv for pkt type %d.\n", rte_be_to_cpu_16(eth_hdr->ether_type));
        goto drop;
    }

    return l3_handlers[l3_handler_idx]->rcv(skb);

drop:
    rte_pktmbuf_free((struct rte_mbuf*)skb);
    return NAT_LB_OK;
}

int inet_pkt_rcv(sk_buff_t *skb) {
    struct dev_port *port;

    if (!is_valid_pkt(skb)) {
        if (NULL != skb) {
            rte_pktmbuf_free((struct rte_mbuf*)skb);
        }
        return NAT_LB_OK;
    }

    return l3_deliver_skb(skb);
}
