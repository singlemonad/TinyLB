//
// Created by tedqu on 25-3-12.
//

#include <rte_mbuf.h>
#include "../common/list.h"
#include "../common/skb.h"
#include "../common/util.h"
#include "../common/log.h"
#include "ipv4.h"
#include "tcp.h"

#define TCP_RCV_SIZE 1500

static uint32_t seq;
static struct list_head tcp_pkt_handlers;

void tcp_pkt_handler_register(struct tcp_pkt_handler *handler) {
    list_add(&handler->node, &tcp_pkt_handlers);
}

static int tcp_in(struct sk_buff *skb, struct rte_ipv4_hdr *hdr) {
    struct tcp_hdr *tcp;
    struct tcp_pkt_handler *handler;
    struct lcore_rxtx_stats *stats = get_lcore_stats(rte_lcore_id());

    tcp = rte_pktmbuf_mtod(&skb->mbuf, struct tcp_hdr*);
    list_for_each_entry(handler, &tcp_pkt_handlers, node) {
        if (handler->port == tcp->dest) {
            skb->mbuf.l4_len = sizeof(struct rte_tcp_hdr);
            rte_pktmbuf_adj((struct rte_mbuf*)skb, skb->mbuf.l4_len);
            return handler->rcv(tcp, skb);
        }
    }

    // no handler, drop it
    RTE_LOG(ERR, NAT_LB, "%s: no handle for dst port %d, drop it\n", __func__, rte_be_to_cpu_16(tcp->dest));
    rte_pktmbuf_free(&skb->mbuf);
    ++stats->drop.invalid_l4_port;
    return NAT_LB_OK;
}

static struct l4_handler tcp_proto = {
        .rcv = tcp_in,
};

void tcp_init(void) {
    INIT_LIST_HEAD(&tcp_pkt_handlers);
    inet_register_l4_handler(&tcp_proto, IPPROTO_TCP);
}