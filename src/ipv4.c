//
// Created by tedqu on 24-9-9.
//

#include <rte_mbuf_core.h>
#include <linux/if_ether.h>
#include "../include/common.h"
#include "../include/log.h"
#include "../include/ipv4.h"
#include "../include/inet.h"
#include "../include/acl.h"
#include "../include/svc.h"
#include "../include/sa_pool.h"
#include "../include/neigh.h"
#include "../include/pipeline.h"
#include "../include/inet.h"

static struct l4_handler* l4_handlers[IPPROTO_MAX];

static int ipv4_hdr_len(struct rte_ipv4_hdr *iph) {
    return (iph->version_ihl & 0xf) << 2;
}

static int ipv4_local_in(sk_buff_t *skb) {
    struct rte_ipv4_hdr *iph;
    unsigned char next_proto;
    struct l4_handler* proto;

    iph = rte_pktmbuf_mtod((struct rte_mbuf*)skb, struct rte_ipv4_hdr*);

    next_proto = iph->next_proto_id;
    proto = l4_handlers[next_proto];
    if (NULL == proto) {
        goto drop;
    }

    // remove network header
    rte_pktmbuf_adj((struct rte_mbuf*)skb, skb->mbuf.l3_len);
    return proto->rcv(skb, iph);

drop:
    rte_pktmbuf_free((struct rte_mbuf*)skb);

    return NAT_LB_OK;
}

static int ipv4_rcv_finish(sk_buff_t *skb) {
    struct rte_ipv4_hdr *iph;
    pipeline_actions action;
    struct per_cpu_ctx *ctx;
    struct rt_cache *rt;

    action = run_pipeline_for_skb(skb);
    if (PIPELINE_ACTION_DROP == action) {
        goto drop;
    } else if (PIPELINE_ACTION_OUTPUT == action) {
        ctx = get_per_cpu_ctx();
        rt = ct_ext_data_get(CT_EXT_ROUTE, ctx->ct);
        if (rt->flags & RTF_LOCAL) {
            ipv4_local_in(skb);
        } else if (rt->flags & RTF_FORWARD) {
            ipv4_output(skb, rt);
        }
        put_per_cpu_ctx();
    }
    return NAT_LB_OK;

drop:
    rte_pktmbuf_free((struct rte_mbuf*)skb);
    return NAT_LB_OK;
}

static int ipv4_rcv(sk_buff_t *skb) {
    int ret;
    uint16_t iph_len, len;
    struct rte_ipv4_hdr *iph;
    per_cpu_ctx_t *ctx;
    struct ct_session *ct;

    iph = rte_pktmbuf_mtod((struct rte_mbuf*)skb, struct rte_ipv4_hdr*);

    if (iph->next_proto_id == IPPROTO_ICMP) {
        goto drop;
    }

    iph_len = ipv4_hdr_len(iph);
    if (((iph->version_ihl) >> 4 ) != 4 || iph_len < sizeof(struct rte_ipv4_hdr)) {
        goto drop;
    }

    if (rte_raw_cksum(iph, iph_len) != 0xFFFF) {
        goto drop;
    }

    len = ntohs(iph->total_length);
    if (skb->mbuf.pkt_len < len || len < iph_len) {
        goto drop;
    }

    if (skb->mbuf.pkt_len > len) {
        if(rte_pktmbuf_trim((struct rte_mbuf*)skb, skb->mbuf.pkt_len - len) != 0) {
            goto drop;
        }
    }

    skb->mbuf.l3_len = iph_len;

    ctx = get_per_cpu_ctx();
    ctx->l4_proto = iph->next_proto_id;

    ret = ipv4_rcv_finish(skb);
    if (NAT_LB_OK != ret) {
        goto drop;
    }
    return NAT_LB_OK;

drop:
    rte_pktmbuf_free((struct rte_mbuf*)skb);

    return NAT_LB_OK;
}

int ipv4_output(sk_buff_t *skb, struct rt_cache *rt) {
    uint32_t next_hop;
    struct rte_ipv4_hdr *iph;

    if (NULL == rt) {
        fprintf(stderr, "No route.\n");
        goto drop;
    }

    iph = rte_pktmbuf_mtod((struct rte_mbuf*)skb, struct rte_ipv4_hdr*);
    if (rt->gw != 0) {
        next_hop = rt->gw;
    } else {
        next_hop = iph->dst_addr;
    }
    next_hop = rte_be_to_cpu_32(next_hop);
    iph->hdr_checksum = 0;
    iph->hdr_checksum = rte_ipv4_cksum(iph);

    skb->mbuf.packet_type = RTE_ETHER_TYPE_IPV4;
    skb->mbuf.port = rt->port->port_id;

    return neigh_output(next_hop, skb, rt->port);

drop:
    rte_pktmbuf_free((struct rte_mbuf*)skb);
    return NAT_LB_OK;
}

int ipv4_local_out(sk_buff_t *skb, struct flow4 *fl4) {
    struct rte_ipv4_hdr *iph;
    struct route_entry *rt_entry;

    fl4->dst_addr = rte_be_to_cpu_32(fl4->dst_addr);
    rt_entry = route_egress_lockup(fl4);
    if (NULL == rt_entry) {
        goto no_route;
    }
    fl4->dst_addr = rte_cpu_to_be_32(fl4->dst_addr);

    iph = (struct rte_ipv4_hdr*)rte_pktmbuf_prepend((struct rte_mbuf*)skb, sizeof(struct rte_ipv4_hdr));
    iph->version_ihl = ((4 << 4) | 5);
    iph->fragment_offset = 0;
    iph->time_to_live = DEFAULT_TIME_LIVE_TTL;
    iph->next_proto_id = fl4->flc.proto;
    iph->src_addr = fl4->src_addr;
    iph->dst_addr = fl4->dst_addr;
    iph->hdr_checksum = 0;
    iph->hdr_checksum = rte_ipv4_cksum(iph);

    // next hop
    uint32_t next_hop = iph->dst_addr;
    if (rt_entry->gw != 0) {
        next_hop = rt_entry->gw;
    }

    skb->mbuf.packet_type = RTE_ETHER_TYPE_IPV4;
    skb->mbuf.port = rt_entry->port->port_id;

    return neigh_output(next_hop, skb, rt_entry->port);

no_route:
    fprintf(stderr, "No route, %s, dst %u.%u.%u.%u.\n",
            __func__, fl4->dst_addr & 0xff, ( fl4->dst_addr>>8) & 0xff, ( fl4->dst_addr>>16) & 0xff, (fl4->dst_addr>>24) & 0xff);
drop:
    rte_pktmbuf_free((struct rte_mbuf*)skb);

    return NAT_LB_OK;
}

int inet_register_l4_handler(struct l4_handler *proto, unsigned char protocol) {
    if (NULL != l4_handlers[protocol]) {
        return NAT_LB_EXIST;
    }

    l4_handlers[protocol] = proto;

    return NAT_LB_OK;
}

static struct l3_handler ipv4_handler = {
        .rcv= ipv4_rcv,
};

void ipv4_init(void) {
    inet_register_l3_handler(&ipv4_handler, ETH_P_IP);
}

