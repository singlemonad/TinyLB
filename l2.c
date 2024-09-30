//
// Created by tedqu on 24-9-8.
//

#include <rte_mbuf.h>
#include <rte_mbuf_core.h>
#include "common.h"
#include "l2.h"
#include "log.h"

static struct list_head g_pkt_types;

static struct pkt_type* get_pkt_type(uint16_t l3_proto) {
    struct pkt_type *pkt_type;

    list_for_each_entry(pkt_type, &g_pkt_types, pkt_type_node) {
        if (pkt_type->type == l3_proto) {
            return pkt_type;
        }
    }
    return NULL;
}

int pkt_type_register(struct pkt_type *pkt_type) {
    struct pkt_type *curr;

    list_for_each_entry(curr, &g_pkt_types, pkt_type_node) {
        if (curr->type == pkt_type->type) {
            return NAT_LB_EXIST;
        }
    }
    list_add(&pkt_type->pkt_type_node, &g_pkt_types);
    return NAT_LB_OK;
}

static int l2_deliver_mbuf(sk_buff_t *skb) {
    struct rte_ether_hdr *eth_hdr;
    struct pkt_type *l3_handler;

    eth_hdr = rte_pktmbuf_mtod((struct rte_mbuf*)skb, struct rte_ether_hdr *);
    skb->mbuf.l2_len = sizeof(struct rte_ether_hdr);

    // remove eth hdr before deliver to l3
    if (NULL == rte_pktmbuf_adj((struct rte_mbuf*)skb, sizeof(struct rte_ether_hdr))) {
        goto drop;
    }

    l3_handler = get_pkt_type(rte_be_to_cpu_16(eth_hdr->ether_type));
    if (NULL == l3_handler) {
        RTE_LOG(ERR, L3, "No l3 handler for %d.\n", rte_be_to_cpu_16(eth_hdr->ether_type));
        goto drop;
    }
    return l3_handler->func(skb);

drop:
    rte_pktmbuf_free((struct rte_mbuf*)skb);
    return NAT_LB_OK;
}

int l2_rcv(sk_buff_t *skb) {
    struct dev_port *port;

    if (NULL == skb || skb->mbuf.data_len == 0 || skb->mbuf.pkt_len == 0) {
        RTE_LOG(ERR, L2, "Rcv empty pkt.\n");
        return NAT_LB_OK;
    }

    port = get_port_by_id(skb->mbuf.port);
    if (NULL == port) {
        RTE_LOG(ERR, L2, "No dev_port found %d.", skb->mbuf.port);
        rte_pktmbuf_free((struct rte_mbuf*)skb);
        return NAT_LB_OK;
    }

    return l2_deliver_mbuf(skb);
}

void l2_init(void) {
    INIT_LIST_HEAD(&g_pkt_types);
}