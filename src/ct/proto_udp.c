//
// Created by tedqu on 25-2-27.
//

#include <linux/udp.h>
#include "../common/util.h"
#include "ct.h"

enum ct_udp_state {
    UDP_CT_NONE = CT_NEW,
    UDP_CT_ESTABLISHED = CT_ESTABLISHED,
    UDP_CT_MAX,
};

static unsigned int udp_timeouts[UDP_CT_MAX] = {
        [UDP_CT_NONE]		= 30 SECS,
        [UDP_CT_ESTABLISHED]		= 180 SECS,
};

static struct ct_tuple udp_gen_tuple(struct sk_buff *skb, bool reverse) {
    struct rte_ipv4_hdr *iph;
    struct ct_tuple tuple;
    uint16_t *ports;

    iph = rte_pktmbuf_mtod((struct rte_mbuf*)skb, struct rte_ipv4_hdr*);
    tuple.proto = IPPROTO_UDP;
    if (!reverse) {
        tuple.src_addr = iph->src_addr;
        tuple.dst_addr = iph->dst_addr;
        ports = (uint16_t *) &iph[1];
        tuple.ports.src_port = ports[0];
        tuple.ports.dst_port = ports[1];
    } else {
        tuple.src_addr = iph->dst_addr;
        tuple.dst_addr = iph->src_addr;
        ports = (uint16_t *)&iph[1];
        tuple.ports.src_port = ports[1];
        tuple.ports.dst_port = ports[0];
    }
    return tuple;
}

static bool is_udp_tuple_equal(struct ct_tuple_hash *lhs, struct ct_tuple *rhs) {
    if (lhs->tuple.ports.src_port == rhs->ports.src_port &&
        lhs->tuple.ports.dst_port == rhs->ports.dst_port) {
        return true;
    }
    return false;
}

static int udp_pkt_in(struct sk_buff *skb, struct per_lcore_ct_ctx *ctx) {
    if (ctx->tuple_hash->tuple.dir == CT_DRI_REPLY) {
        ctx->ct->state = UDP_CT_ESTABLISHED;
    }
    ctx->ct->timeout = udp_timeouts[ctx->ct->state];
    return NAT_LB_OK;
}

static int udp_pkt_new(struct sk_buff *skb, struct per_lcore_ct_ctx *ctx) {
    if (ctx->ct->state == CT_NEW) {
        ctx->ct->state = UDP_CT_ESTABLISHED;
    }
    return NAT_LB_OK;
}

struct ct_l4_proto udp_l4_proto = {
        .gen_tuple = udp_gen_tuple,
        .is_tuple_equal = is_udp_tuple_equal,
        .pkt_in = udp_pkt_in,
        .pkt_new = udp_pkt_new,
};
