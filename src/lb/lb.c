//
// Created by tedqu on 24-11-19.
//

#include <rte_malloc.h>
#include "../common/util.h"
#include "../common/log.h"
#include "../common/pipeline.h"
#include "svc.h"
#include "sa_pool.h"
#include "lb.h"
#include "nat.h"

extern __thread struct per_lcore_ct_ctx per_lcore_ctx;
extern struct rewrite dnat_rewrite;
extern struct rewrite snat_rewrite;

static struct rewrite rewrite_actions[MAX_REWRITE];

static inline void set_dnat_ext(struct ct_session *ct, uint32_t dst_ip, uint16_t dst_port) {
    struct dnat_rewrite_data *data = (struct dnat_rewrite_data*)(ct_ext_data_get(CT_EXT_DNAT, ct));
    data->dst_ip = dst_ip;
    data->port = dst_port;
    ct->ext_flags |= (1 << CT_EXT_DNAT);
}

static inline void set_snat_ext(struct ct_session *ct, uint32_t src_ip, uint16_t src_port) {
    struct snat_rewrite_data *data = (struct snat_rewrite_data*)(ct_ext_data_get(CT_EXT_SNAT, ct));
    data->src_ip = src_ip;
    data->port = src_port;
    ct->ext_flags |= (1 << CT_EXT_SNAT);
}

static inline void rewrite_reply_tuple_after_nat(struct sk_buff *skb, struct per_lcore_ct_ctx *ctx) {
    struct rte_ipv4_hdr *iph = (struct rte_ipv4_hdr*)skb->iph;

    ctx->ct->tuple_hash[CT_DRI_REPLY].tuple.src_addr = iph->dst_addr;
    ctx->ct->tuple_hash[CT_DRI_REPLY].tuple.dst_addr = iph->src_addr;
    if (ctx->l4_proto == IPPROTO_TCP) {
        struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr*)&iph[1];
        ctx->ct->tuple_hash[CT_DRI_REPLY].tuple.ports.src_port = tcp->dst_port;
        ctx->ct->tuple_hash[CT_DRI_REPLY].tuple.ports.dst_port= tcp->src_port;
    } else {
        struct rte_udp_hdr *udp = (struct rte_udp_hdr*)&iph[1];
        ctx->ct->tuple_hash[CT_DRI_REPLY].tuple.ports.src_port = udp->dst_port;
        ctx->ct->tuple_hash[CT_DRI_REPLY].tuple.ports.dst_port= udp->src_port;
    }
}

static int schedule(sk_buff_t *skb, struct per_lcore_ct_ctx *ctx) {
    struct rte_ipv4_hdr *iph = (struct rte_ipv4_hdr*)skb->iph;
    uint16_t *ports = (uint16_t*)&iph[1];

    struct svc *svc = svc_find(iph->next_proto_id, iph->dst_addr, ports[1]);
    if (NULL == svc) {
        RTE_LOG(ERR, NAT_LB, "%s: no svc found, vip=%s,vport=%u\n", __func__, be_ip_to_str(iph->dst_addr), ntohs(ports[1]));
        return NAT_LB_NOT_EXIST;
    }

    struct rs *rs = rs_schedule(svc, skb, iph->next_proto_id, iph->dst_addr, ports[1]);
    if (NULL == rs) {
        RTE_LOG(ERR, NAT_LB, "%s: no rs found, vip=%s,vport=%u\n", __func__, be_ip_to_str(iph->dst_addr), ntohs(ports[1]));
        return NAT_LB_NOT_EXIST;
    }

    per_lcore_ctx.ct->flags |= CT_FLAG_DNAT;
    if (svc->type == SVC_UNDERLAY) {
        per_lcore_ctx.ct->flags |= CT_FLAG_SNAT;
    }
    set_dnat_ext(per_lcore_ctx.ct, rs->rs_ip, rs->rs_port);
    if (per_lcore_ctx.ct->flags & CT_FLAG_SNAT) {
        uint32_t snat_ip;
        uint16_t snat_port;

        int ret = snat_addr_get(per_lcore_ctx.l4_proto, rs->rs_ip, rs->rs_port, &rs->snat_ips[rte_lcore_id()], &snat_ip, &snat_port);
        if (NAT_LB_OK != ret) {
            RTE_LOG(ERR, NAT_LB, "%s: get snat addr failed, lcore_id=%d\n", __func__, rte_lcore_id());
            return NAT_LB_NO_SNAT_PORT;
        }
        set_snat_ext(per_lcore_ctx.ct, snat_ip, snat_port);
    }

    return NAT_LB_OK;
}

static inline void do_dnat(struct sk_buff *skb, struct per_lcore_ct_ctx *ctx) {
    rewrite_actions[DNAT_REWRITE].func(skb, ct_ext_data_get(CT_EXT_DNAT, ctx->ct));
}

static inline void do_snat(struct sk_buff *skb, struct per_lcore_ct_ctx *ctx) {
    rewrite_actions[SNAT_REWRITE].func(skb, ct_ext_data_get(CT_EXT_SNAT, ctx->ct));
}

static inline void do_reply_dnat(struct sk_buff *skb, struct per_lcore_ct_ctx *ctx) {
    struct dnat_rewrite_data data = {
            .dst_ip = ctx->ct->tuple_hash[CT_DRI_ORIGINAL].tuple.src_addr,
            .port = ctx->ct->tuple_hash[CT_DRI_ORIGINAL].tuple.ports.src_port
    };
    rewrite_actions[DNAT_REWRITE].func(skb, &data);
}

static inline void do_reply_snat(struct sk_buff *skb, struct per_lcore_ct_ctx *ctx) {
    struct snat_rewrite_data data = {
            .src_ip = ctx->ct->tuple_hash[CT_DRI_ORIGINAL].tuple.dst_addr,
            .port = ctx->ct->tuple_hash[CT_DRI_ORIGINAL].tuple.ports.dst_port
    };
    rewrite_actions[SNAT_REWRITE].func(skb, &data);
}

static inline pipeline_actions lb_in(sk_buff_t *skb) {
    struct per_lcore_ct_ctx *ctx = &per_lcore_ctx;
    assert(NULL != ctx && NULL != ctx->ct);

    if (unlikely(ctx->l4_proto != IPPROTO_TCP && ctx->l4_proto != IPPROTO_UDP)) {
        return PIPELINE_ACTION_NEXT;
    }

    if (unlikely(ctx->ct->state == CT_NEW)) {
        int ret = schedule(skb, ctx);
        if (NAT_LB_OK != ret) {
            return PIPELINE_ACTION_DROP;
        }
    }

    // do nat
    if (ctx->tuple_hash->tuple.dir == CT_DRI_ORIGINAL) {
        do_dnat(skb, ctx);
        if (ctx->ct->flags & CT_FLAG_SNAT) {
            do_snat(skb, ctx);
        }
    } else {
        do_reply_snat(skb, ctx);
        if (ctx->ct->flags & CT_FLAG_SNAT) {
            do_reply_dnat(skb, ctx);
        }
    }

    // 重写反向连接tuple信息
    if (unlikely(ctx->ct->state == CT_NEW)) {
        rewrite_reply_tuple_after_nat(skb, ctx);
    }
    return PIPELINE_ACTION_NEXT;
}

static void snat_sync_ext_push(struct sk_buff *skb, struct ct_session *ct) {
    struct snat_rewrite_data *data;

    data = (struct snat_rewrite_data*)rte_pktmbuf_append(&skb->mbuf, sizeof(struct snat_rewrite_data));
    memcpy(data, ct_ext_data_get(CT_EXT_SNAT, ct), sizeof(struct snat_rewrite_data));
}

static void snat_sync_ext_pop(struct sk_buff *skb, uint32_t length, struct ct_session *ct) {
    struct snat_rewrite_data *data;

    data = rte_pktmbuf_mtod(&skb->mbuf, struct snat_rewrite_data*);
    memcpy(ct_ext_data_get(CT_EXT_SNAT, ct), data, sizeof(struct snat_rewrite_data));
    ct->ext_flags |= (1 << CT_EXT_SNAT);
    rte_pktmbuf_adj(&skb->mbuf, length);
}

static uint32_t snat_ext_dump(char *buff, struct ct_session *ct) {
    struct snat_rewrite_data *data = ct_ext_data_get(CT_EXT_SNAT, ct);
    return sprintf(buff, "<SNAT_EXT,SRC_IP=%s,SRC_PORT=%d>", be_ip_to_str(data->src_ip), ntohs(data->port));
}

struct ct_ext snat_ct_ext = {
        .type = CT_EXT_SNAT,
        .need_sync = true,
        .length = sizeof(struct snat_rewrite_data),
        .offset = 0,
        .sync_ext_push_func = snat_sync_ext_push,
        .sync_ext_pop_func = snat_sync_ext_pop,
        .dump_func = snat_ext_dump,
};

static void dnat_sync_ext_push(struct sk_buff *skb, struct ct_session *ct) {
    struct dnat_rewrite_data *data;

    data = (struct dnat_rewrite_data*)rte_pktmbuf_append(&skb->mbuf, sizeof(struct dnat_rewrite_data));
    memcpy(data, ct_ext_data_get(CT_EXT_DNAT, ct), sizeof(struct dnat_rewrite_data));
}

static void dnat_sync_ext_pop(struct sk_buff *skb, uint32_t length, struct ct_session *ct) {
    struct dnat_rewrite_data *data;

    data = rte_pktmbuf_mtod(&skb->mbuf, struct dnat_rewrite_data*);
    memcpy(ct_ext_data_get(CT_EXT_DNAT, ct), data, sizeof(struct dnat_rewrite_data));
    ct->ext_flags |= (1 << CT_EXT_DNAT);
    rte_pktmbuf_adj(&skb->mbuf, length);
}

static uint32_t dnat_ext_dump(char *buff, struct ct_session *ct) {
    struct dnat_rewrite_data *data = ct_ext_data_get(CT_EXT_DNAT, ct);
    return sprintf(buff, "<DNAT_EXT,DST_IP=%s,DST_PORT=%d>", be_ip_to_str(data->dst_ip), ntohs(data->port));
}

struct ct_ext dnat_ct_ext = {
        .type = CT_EXT_DNAT,
        .need_sync = true,
        .length = sizeof(struct dnat_rewrite_data),
        .offset = 0,
        .sync_ext_push_func = dnat_sync_ext_push,
        .sync_ext_pop_func = dnat_sync_ext_pop,
        .dump_func = dnat_ext_dump,
};

void lb_module_init(void) {
    svc_init();
    sa_pool_init();

    ct_ext_register(&dnat_ct_ext);
    ct_ext_register(&snat_ct_ext);

    rewrite_actions[DNAT_REWRITE] = dnat_rewrite;
    rewrite_actions[SNAT_REWRITE] = snat_rewrite;

    pipeline_register("lb_in", lb_in, PIPELINE_PRIORITY_LB, NULL);

    wrr_init();
}