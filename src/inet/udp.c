//
// Created by tedqu on 25-3-7.
//

#include <rte_mbuf.h>
#include <rte_mbuf_core.h>
#include <rte_udp.h>
#include "../common/log.h"
#include "../common/util.h"
#include "ipv4.h"
#include "udp.h"

static struct list_head udp_pkt_handlers;

void udp_pkt_handler_register(struct udp_pkt_handler *handler) {
    list_add(&handler->node, &udp_pkt_handlers);
}

int udp_out(struct sk_buff *skb, struct udp_out_args *args) {
    struct rte_udp_hdr *udp;
    struct flow4 fl4;

    udp = (struct rte_udp_hdr*)(rte_pktmbuf_prepend(&skb->mbuf, sizeof(struct rte_udp_hdr)));
    udp->src_port = args->src_port;
    udp->dst_port = args->dst_port;
    udp->dgram_len = htons(skb->mbuf.data_len);
    skb->calc_l4_checksum = true;

    fl4.src_addr = args->src_ip;
    fl4.dst_addr = args->dst_ip;
    fl4.flc.proto = IPPROTO_UDP;
    return ipv4_local_out(skb, &fl4);
}

static int udp_in(struct sk_buff *skb, struct rte_ipv4_hdr *hdr) {
    struct rte_udp_hdr *udp;
    struct udp_pkt_handler *handler;
    struct lcore_rxtx_stats *stats = get_lcore_stats(rte_lcore_id());

    udp = rte_pktmbuf_mtod(&skb->mbuf, struct rte_udp_hdr*);
    list_for_each_entry(handler, &udp_pkt_handlers, node) {
        if (handler->port == udp->dst_port) {
            skb->mbuf.l4_len = sizeof(struct rte_udp_hdr);
            rte_pktmbuf_adj((struct rte_mbuf*)skb, skb->mbuf.l4_len);
            return handler->rcv(skb);
        }
    }

    RTE_LOG(ERR, NAT_LB, "%s: no handle for dst port %s, drop it\n", __func__, rte_be_to_cpu_16(udp->dst_port));
    rte_pktmbuf_free(&skb->mbuf);
    ++stats->drop.invalid_l4_port;
    return NAT_LB_OK;
}

static struct l4_handler udp_proto = {
        .rcv = udp_in,
};

void udp_init(void) {
    INIT_LIST_HEAD(&udp_pkt_handlers);
    inet_register_l4_handler(&udp_proto, IPPROTO_UDP);
}