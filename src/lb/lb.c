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
#include "lb.h"

static uint16_t gen_ipv4_nat_checksum(uint32_t old_rev_val, uint32_t new_val, uint16_t old_check)
{
    uint32_t check_sum = old_check ^ 0xFFFF;

    check_sum += old_rev_val >> 16;
    check_sum += old_rev_val & 0xFFFF;
    check_sum += new_val >> 16;
    check_sum += new_val & 0xFFFF;

    check_sum = (check_sum & 0xFFFFUL) + (check_sum >> 16);
    check_sum = (check_sum & 0xFFFFUL) + (check_sum >> 16);

    return ~((uint16_t)check_sum);
}

static void do_dnat(sk_buff_t *skb, per_cpu_ctx_t *ctx) {
    struct rte_ipv4_hdr *iph;
    dnat_action_data_t *arg;
    struct rte_tcp_hdr *tcp;
    struct rte_udp_hdr *udp;
    uint32_t old_dst_ip;
    uint32_t new_port, old_port;

    assert(NULL != ctx && NULL != ctx->ct);

    arg = (dnat_action_data_t *)(ct_ext_data_get(CT_EXT_DNAT, ctx->ct));
    iph = rte_pktmbuf_mtod((struct rte_mbuf*)skb, struct rte_ipv4_hdr*);
    old_dst_ip = iph->dst_addr;

    iph->dst_addr = arg->dst_ip;
    iph->hdr_checksum = 0;
    iph->hdr_checksum = rte_ipv4_cksum(iph);

    if (iph->next_proto_id == IPPROTO_TCP) {
        tcp = (struct rte_tcp_hdr*)&iph[1];
        old_port = (tcp->src_port << 16) | tcp->dst_port;
        tcp->dst_port = arg->port;
        new_port = (tcp->src_port << 16) | tcp->dst_port;

        tcp->cksum = gen_ipv4_nat_checksum(~old_dst_ip, iph->dst_addr, tcp->cksum);
        tcp->cksum = gen_ipv4_nat_checksum(~old_port, new_port, tcp->cksum);
    } else if (iph->next_proto_id == IPPROTO_UDP) {
        udp = (struct rte_udp_hdr*)&iph[1];
        old_port = (udp->src_port << 16) | udp->dst_port;
        udp->dst_port = arg->port;
        new_port = (udp->src_port << 16) | udp->dst_port;

        udp->dgram_cksum = gen_ipv4_nat_checksum(~old_dst_ip, iph->dst_addr, udp->dgram_cksum);
        udp->dgram_cksum = gen_ipv4_nat_checksum(~old_port, new_port, udp->dgram_cksum);
    }
}

static void do_snat(sk_buff_t *skb, per_cpu_ctx_t *ctx) {
    struct rte_ipv4_hdr *iph;
    struct rte_tcp_hdr *tcp;
    struct rte_udp_hdr *udp;
    snat_action_data_t *arg;
    uint32_t old_sip;
    uint32_t new_port, old_port;

    assert(NULL != ctx && NULL != ctx->ct);

    arg = (snat_action_data_t *)(ct_ext_data_get(CT_EXT_SNAT, ctx->ct));
    iph = rte_pktmbuf_mtod((struct rte_mbuf*)skb, struct rte_ipv4_hdr*);
    old_sip = iph->src_addr;

    iph->src_addr = arg->src_ip;
    iph->hdr_checksum = 0;
    iph->hdr_checksum = rte_ipv4_cksum(iph);

    if (IPPROTO_TCP == iph->next_proto_id) {
        tcp = (struct rte_tcp_hdr*)&iph[1];
        old_port = (tcp->src_port << 16) | tcp->dst_port;
        tcp->src_port = arg->port;
        new_port = (tcp->src_port << 16) | tcp->dst_port;

        tcp->cksum = gen_ipv4_nat_checksum(~old_sip, iph->src_addr, tcp->cksum);
        tcp->cksum = gen_ipv4_nat_checksum(~old_port, new_port, tcp->cksum);
    } else if (IPPROTO_UDP == iph->next_proto_id) {
        udp = (struct rte_udp_hdr*)&iph[1];
        old_port = (udp->src_port << 16) | udp->dst_port;
        udp->src_port = arg->port;
        new_port = (udp->src_port << 16) | udp->dst_port;

        udp->dgram_cksum = gen_ipv4_nat_checksum(~old_sip, iph->src_addr, udp->dgram_cksum);
        udp->dgram_cksum = gen_ipv4_nat_checksum(~old_port, new_port, udp->dgram_cksum);
    }
}

static void do_reply_nat(struct sk_buff *skb, struct per_cpu_ctx *ctx) {
    struct rte_ipv4_hdr *iph;
    struct rte_tcp_hdr *tcp;
    struct rte_udp_hdr *udp;
    uint32_t old_sip, old_dip;
    uint32_t old_sport, new_sport;
    uint32_t old_dport, new_dport;

    iph = rte_pktmbuf_mtod((struct rte_mbuf*)skb, struct rte_ipv4_hdr*);
    old_sip = iph->src_addr;
    old_dip = iph->dst_addr;

    iph->src_addr = ctx->ct->tuple_hash[CT_DRI_ORIGINAL].tuple.dst_addr;
    iph->dst_addr = ctx->ct->tuple_hash[CT_DRI_ORIGINAL].tuple.src_addr;
    iph->hdr_checksum = 0;
    iph->hdr_checksum = rte_ipv4_cksum(iph);

    if (IPPROTO_TCP == iph->next_proto_id) {
        tcp = (struct rte_tcp_hdr*)&iph[1];

        old_sport = (tcp->src_port << 16) | tcp->dst_port;
        tcp->src_port = ctx->ct->tuple_hash[CT_DRI_ORIGINAL].tuple.ports.dst_port;
        new_sport = (tcp->src_port << 16) | tcp->dst_port;
        tcp->cksum = gen_ipv4_nat_checksum(~old_sip, iph->src_addr, tcp->cksum);
        tcp->cksum = gen_ipv4_nat_checksum(~old_dip, iph->dst_addr, tcp->cksum);
        tcp->cksum = gen_ipv4_nat_checksum(~old_sport, new_sport, tcp->cksum);

        old_dport = (tcp->src_port << 16) | tcp->dst_port;
        tcp->dst_port = ctx->ct->tuple_hash[CT_DRI_ORIGINAL].tuple.ports.src_port;
        new_dport = (tcp->src_port << 16) | tcp->dst_port;
        tcp->cksum = gen_ipv4_nat_checksum(~old_dport, new_dport, tcp->cksum);
    } else if (IPPROTO_UDP == iph->next_proto_id) {
        udp = (struct rte_udp_hdr*)&iph[1];

        old_sport = (udp->src_port << 16) | udp->dst_port;
        udp->src_port = ctx->ct->tuple_hash[CT_DRI_ORIGINAL].tuple.ports.dst_port;
        new_sport = (udp->src_port << 16) | udp->dst_port;
        udp->dgram_cksum = gen_ipv4_nat_checksum(~old_sip, iph->src_addr, udp->dgram_cksum);
        udp->dgram_cksum = gen_ipv4_nat_checksum(~old_dip, iph->dst_addr, udp->dgram_cksum);
        udp->dgram_cksum = gen_ipv4_nat_checksum(~old_sport, new_sport, udp->dgram_cksum);

        old_dport = (udp->src_port << 16) | udp->dst_port;
        udp->dst_port = ctx->ct->tuple_hash[CT_DRI_ORIGINAL].tuple.ports.src_port;
        new_dport = (udp->src_port << 16) | udp->dst_port;
        udp->dgram_cksum = gen_ipv4_nat_checksum(~old_dport, new_dport, udp->dgram_cksum);
    }
}

static int schedule(sk_buff_t *skb, per_cpu_ctx_t *ctx) {
    int ret;
    struct rte_ipv4_hdr *iph;
    struct rte_tcp_hdr *tcp;
    svc_t *svc;
    rs_t *rs;
    dnat_action_data_t *dnat_ext;
    snat_action_data_t *snat_ext;
    uint32_t snat_ip;
    uint16_t snat_port;

    iph = rte_pktmbuf_mtod((struct rte_mbuf*)skb, struct rte_ipv4_hdr*);
    tcp = (struct rte_tcp_hdr*)&iph[1];

    svc = svc_find(iph->dst_addr, tcp->dst_port);
    if (NULL == svc) {
        RTE_LOG(ERR, LB, "No svc found, dst_port=%d\n", ntohs(tcp->dst_port));
        return NAT_LB_NOT_EXIST;
    }

    rs = rs_schedule(iph->dst_addr, tcp->dst_port);
    if (NULL == rs) {
        RTE_LOG(ERR, LB, "No rs found\n");
        return NAT_LB_NOT_EXIST;
    }

    dnat_ext = (dnat_action_data_t *)ct_ext_data_get(CT_EXT_DNAT, ctx->ct);
    dnat_ext->dst_ip = rs->rs_ip;
    dnat_ext->port = rs->rs_port;

    ret = snat_addr_get(iph->dst_addr, tcp->dst_port, &snat_ip, &snat_port);
    if (NAT_LB_OK != ret) {
        RTE_LOG(ERR, LB, "Get snat addr failed\n");
        return NAT_LB_NO_SNAT_PORT;
    }
    snat_ext = (snat_action_data_t *) ct_ext_data_get(CT_EXT_SNAT, ctx->ct);
    snat_ext->src_ip = snat_ip;
    snat_ext->port = snat_port;

    // update reply ct tuple
    ctx->ct->tuple_hash[CT_DRI_REPLY].tuple.src_addr = rs->rs_ip;
    ctx->ct->tuple_hash[CT_DRI_REPLY].tuple.ports.src_port = rs->rs_port;
    ctx->ct->tuple_hash[CT_DRI_REPLY].tuple.dst_addr = snat_ip;
    ctx->ct->tuple_hash[CT_DRI_REPLY].tuple.ports.dst_port = snat_port;

    return NAT_LB_OK;
}

static pipeline_actions lb_in(sk_buff_t *skb) {
    int ret;
    struct per_cpu_ctx *ctx;

    ctx = get_per_cpu_ctx();
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
        do_snat(skb, ctx);
        do_dnat(skb, ctx);
    } else if (ctx->tuple_hash->tuple.dir == CT_DRI_REPLY) {
        do_reply_nat(skb, ctx);
    } else {
        return PIPELINE_ACTION_DROP;
    }

    return PIPELINE_ACTION_NEXT;
}

void lb_module_init(void) {
    ct_ext_register(CT_EXT_DNAT, sizeof(dnat_action_data_t));
    ct_ext_register(CT_EXT_SNAT, sizeof(snat_action_data_t));
    pipeline_register("lb_in", lb_in, PIPELINE_PRIORITY_LB, NULL);
}