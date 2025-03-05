//
// Created by tedqu on 24-11-19.
//

#include <rte_malloc.h>
#include "../common/util.h"
#include "../common/log.h"
#include "../common/skb.h"
#include "svc.h"
#include "sa_pool.h"
#include "../common/pipeline.h"
#include "../common/thread.h"
#include "lb.h"
#include "nat.h"

extern __thread struct per_lcore_ct_ctx per_lcore_ctx;
extern struct rewrite dnat_rewrite;
extern struct rewrite snat_rewrite;

static struct rewrite rewrite_actions[INVALID_REWRITE];

static void set_dnat_ext(struct ct_session *ct, uint32_t dst_ip, uint16_t dst_port) {
    struct dnat_rewrite_data *data = (struct dnat_rewrite_data*)(ct_ext_data_get(CT_EXT_DNAT, ct));
    data->dst_ip = dst_ip;
    data->port = dst_port;
}

static void set_snat_ext(struct ct_session *ct, uint32_t src_ip, uint16_t src_port) {
    struct snat_rewrite_data *data = (struct snat_rewrite_data*)(ct_ext_data_get(CT_EXT_SNAT, ct));
    data->src_ip = src_ip;
    data->port = src_port;
}

static void rewrite_reply_tuple_after_nat(struct sk_buff *skb, struct per_lcore_ct_ctx *ctx) {
    struct rte_ipv4_hdr *iph;
    struct rte_tcp_hdr *tcp;
    struct rte_udp_hdr *udp;

    iph = rte_pktmbuf_mtod((struct rte_mbuf*)skb, struct rte_ipv4_hdr*);
    ctx->ct->tuple_hash[CT_DRI_REPLY].tuple.src_addr = iph->dst_addr;
    ctx->ct->tuple_hash[CT_DRI_REPLY].tuple.dst_addr = iph->src_addr;
    if (ctx->l4_proto == IPPROTO_TCP) {
        tcp = (struct rte_tcp_hdr*)&iph[1];
        ctx->ct->tuple_hash[CT_DRI_REPLY].tuple.ports.src_port = tcp->dst_port;
        ctx->ct->tuple_hash[CT_DRI_REPLY].tuple.ports.dst_port= tcp->src_port;
    } else {
        udp = (struct rte_udp_hdr*)&iph[1];
        ctx->ct->tuple_hash[CT_DRI_REPLY].tuple.ports.src_port = udp->dst_port;
        ctx->ct->tuple_hash[CT_DRI_REPLY].tuple.ports.dst_port= udp->src_port;
    }
}

static int schedule(sk_buff_t *skb, struct per_lcore_ct_ctx *ctx) {
    int ret;
    struct rte_ipv4_hdr *iph;
    struct rte_tcp_hdr *tcp;
    struct svc *svc;
    struct rs *rs;
    uint32_t snat_ip;
    uint16_t snat_port;

    iph = rte_pktmbuf_mtod((struct rte_mbuf*)skb, struct rte_ipv4_hdr*);
    tcp = (struct rte_tcp_hdr*)&iph[1];

    svc = svc_find(iph->dst_addr, tcp->dst_port);
    if (NULL == svc) {
        RTE_LOG(ERR, LB, "%s: No svc found for dst<%s:%d>\n", __func__, be_ip_to_str(iph->dst_addr), ntohs(tcp->dst_port));
        return NAT_LB_NOT_EXIST;
    }

    rs = rs_schedule(iph->dst_addr, tcp->dst_port);
    if (NULL == rs) {
        RTE_LOG(ERR, LB, "%s: No rs found\n", __func__);
        return NAT_LB_NOT_EXIST;
    }

    ret = snat_addr_get(iph->dst_addr, tcp->dst_port, &snat_ip, &snat_port);
    if (NAT_LB_OK != ret) {
        RTE_LOG(ERR, LB, "Get original_snat addr failed\n");
        return NAT_LB_NO_SNAT_PORT;
    }

    set_dnat_ext(per_lcore_ctx.ct, rs->rs_ip, rs->rs_port);
    set_snat_ext(per_lcore_ctx.ct, snat_ip, snat_port);

    return NAT_LB_OK;
}

static void do_dnat(struct sk_buff *skb, struct per_lcore_ct_ctx *ctx) {
    rewrite_actions[DNAT_REWRITE].func(skb, ct_ext_data_get(CT_EXT_DNAT, ctx->ct));
}

static void do_snat(struct sk_buff *skb, struct per_lcore_ct_ctx *ctx) {
    rewrite_actions[SNAT_REWRITE].func(skb, ct_ext_data_get(CT_EXT_SNAT, ctx->ct));
}

static void do_reply_dnat(struct sk_buff *skb, struct per_lcore_ct_ctx *ctx) {
    struct dnat_rewrite_data data = {
            .dst_ip = ctx->ct->tuple_hash[CT_DRI_ORIGINAL].tuple.src_addr,
            .port = ctx->ct->tuple_hash[CT_DRI_ORIGINAL].tuple.ports.src_port
    };
    rewrite_actions[DNAT_REWRITE].func(skb, &data);
}

static void do_reply_snat(struct sk_buff *skb, struct per_lcore_ct_ctx *ctx) {
    struct snat_rewrite_data data = {
            .src_ip = ctx->ct->tuple_hash[CT_DRI_ORIGINAL].tuple.dst_addr,
            .port = ctx->ct->tuple_hash[CT_DRI_ORIGINAL].tuple.ports.dst_port
    };
    rewrite_actions[SNAT_REWRITE].func(skb, &data);
}

static pipeline_actions lb_in(sk_buff_t *skb) {
    int ret;
    struct per_lcore_ct_ctx *ctx;

    ctx = &per_lcore_ctx;
    assert(NULL != ctx && NULL != ctx->ct);

    if (ctx->l4_proto != IPPROTO_TCP && ctx->l4_proto != IPPROTO_UDP) {
        return PIPELINE_ACTION_NEXT;
    }

    if (ctx->ct->state == CT_NEW) {
        ret = schedule(skb, ctx);
        if (NAT_LB_OK != ret) {
            return PIPELINE_ACTION_DROP;
        }
    }

    if (ctx->tuple_hash->tuple.dir == CT_DRI_ORIGINAL) {
        do_dnat(skb, ctx);
        do_snat(skb, ctx);
    } else {
        do_reply_snat(skb, ctx);
        do_reply_dnat(skb, ctx);
    }

    if (ctx->ct->state == CT_NEW) {
        rewrite_reply_tuple_after_nat(skb, ctx);
    }

    return PIPELINE_ACTION_NEXT;
}

void lb_module_init(void) {
    ct_ext_register(CT_EXT_DNAT, sizeof(struct dnat_rewrite_data));
    ct_ext_register(CT_EXT_SNAT, sizeof(struct snat_rewrite_data));

    rewrite_actions[DNAT_REWRITE] = dnat_rewrite;
    rewrite_actions[SNAT_REWRITE] = snat_rewrite;

    pipeline_register("lb_in", lb_in, PIPELINE_PRIORITY_LB, NULL);
}