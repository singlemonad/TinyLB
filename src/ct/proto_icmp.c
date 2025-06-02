//
// Created by tedqu on 25-2-27.
//
#include "../common/util.h"
#include "ct.h"

enum ct_icmp_state {
    ICMP_CT_NONE = CT_NEW,
    ICMP_CT_ESTABLISHED = CT_ESTABLISHED,
    ICMP_CT_MAX,
};

static unsigned int icmp_timeouts[ICMP_CT_MAX] = {
        [ICMP_CT_NONE]		= 30 SECS,
        [ICMP_CT_ESTABLISHED]		= 30 SECS,
};

static inline struct ct_tuple icmp_gen_tuple(struct sk_buff *skb, bool reverse) {
    struct rte_ipv4_hdr *iph;
    struct rte_icmp_hdr *icmp;
    struct ct_tuple tuple;

    iph = rte_pktmbuf_mtod((struct rte_mbuf*)skb, struct rte_ipv4_hdr*);
    tuple.proto = IPPROTO_ICMP;
    if (!reverse) {
        tuple.src_addr = iph->src_addr;
        tuple.dst_addr = iph->dst_addr;
        icmp = (struct rte_icmp_hdr *) &iph[1];
        tuple.icmp.type = icmp->icmp_type;
        tuple.icmp.code = icmp->icmp_code;
    } else {
        tuple.src_addr = iph->dst_addr;
        tuple.dst_addr = iph->src_addr;
        icmp = (struct rte_icmp_hdr *) &iph[1];
        tuple.icmp.type = icmp->icmp_type;
        tuple.icmp.code = icmp->icmp_code;
    }
    return tuple;
}

static inline bool is_icmp_tuple_equal(struct ct_tuple_hash *lhs, struct ct_tuple *rhs) {
    if (lhs->tuple.icmp.type == rhs->icmp.type &&
        lhs->tuple.icmp.code == rhs->icmp.code) {
        return true;
    }
    return false;
}

static inline int icmp_pkt_in(struct sk_buff *skb, struct per_lcore_ct_ctx *ctx) {
    return NAT_LB_OK;
}

static inline int icmp_pkt_new(struct sk_buff *skb, struct per_lcore_ct_ctx *ctx) {
    if (ctx->ct->state == CT_NEW) {
        ctx->ct->state = ICMP_CT_ESTABLISHED;
        ctx->ct->timeout = icmp_timeouts[ICMP_CT_ESTABLISHED];
    }
    return NAT_LB_OK;
}

struct ct_l4_proto icmp_l4_proto = {
        .gen_tuple = icmp_gen_tuple,
        .is_tuple_equal = is_icmp_tuple_equal,
        .pkt_in = icmp_pkt_in,
        .pkt_new = icmp_pkt_new,
};
