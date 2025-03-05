//
// Created by tedqu on 24-9-9.
//

#include <rte_mbuf_core.h>
#include <linux/if_ether.h>
#include "../common/util.h"
#include "../common/log.h"
#include "../common/inet.h"
#include "../lb/svc.h"
#include "../neigh/neigh.h"
#include "../common/pipeline.h"
#include "../common/thread.h"
#include "ipv4.h"

extern __thread struct per_lcore_ct_ctx per_lcore_ctx;
static struct l4_handler* l4_handlers[IPPROTO_MAX];

static int ipv4_hdr_len(struct rte_ipv4_hdr *iph) {
    return (iph->version_ihl & 0xf) << 2;
}

static int ipv4_local_in(sk_buff_t *skb) {
    struct rte_ipv4_hdr *iph;
    struct l4_handler* proto;

    iph = rte_pktmbuf_mtod((struct rte_mbuf*)skb, struct rte_ipv4_hdr*);

    proto = l4_handlers[iph->next_proto_id];
    if (NULL == proto) {
        RTE_LOG(ERR, IP, "No l4 handler for protocol %d(%s).\n", iph->next_proto_id, protocol_to_str(iph->next_proto_id));
        goto drop;
    }

    // remove network header
    rte_pktmbuf_adj((struct rte_mbuf*)skb, skb->mbuf.l3_len);
    return proto->rcv(skb, iph);

drop:
    rte_pktmbuf_free((struct rte_mbuf*)skb);

    return NAT_LB_OK;
}

static int ipv4_pipeline(sk_buff_t *skb) {
    int ret;
    struct rt_cache *rt;
    pipeline_actions action;
    struct per_lcore_ct_ctx *ctx;

    ctx = &per_lcore_ctx;
    action = run_pipeline_for_skb(skb);
    switch (action) {
        case PIPELINE_ACTION_FORWARD:
            rt = ct_ext_data_get(CT_EXT_ROUTE, ctx->ct);
            ret = ipv4_output(skb, rt);
            break;
        case PIPELINE_ACTION_LOCAL_IN:
            ret = ipv4_local_in(skb);
            break;
        default:
            goto drop;
    }

    return ret;

    drop:
    rte_pktmbuf_free((struct rte_mbuf*)skb);
    return NAT_LB_OK;
}

static int ipv4_forward(sk_buff_t *skb) {
    struct flow4 fl4;
    struct rte_ipv4_hdr *iph = rte_pktmbuf_mtod((struct rte_mbuf*)skb, struct rte_ipv4_hdr*);

    memset(&fl4, 0, sizeof(struct flow4));
    fl4.src_addr = iph->dst_addr;
    fl4.dst_addr = iph->src_addr;
    fl4.flc.proto = iph->next_proto_id;

    struct route_entry *rt_entry = route_egress_lockup(&fl4);
    if (NULL == rt_entry) {
        RTE_LOG(ERR, IP, "No route to dst %s, drop it.\n", be_ip_to_str(fl4.dst_addr));
        goto drop;
    }

    iph->time_to_live -= 1;
    iph->hdr_checksum = 0;
    iph->hdr_checksum = rte_ipv4_cksum(iph);

    uint32_t next_hop = iph->dst_addr;
    if (rt_entry->gw != 0) {
        next_hop = rt_entry->gw;
    }

    skb->mbuf.packet_type = RTE_ETHER_TYPE_IPV4;
    skb->mbuf.port = rt_entry->port->port_id;

    return neigh_output(next_hop, skb, rt_entry->port);

drop:
    rte_pktmbuf_free((struct rte_mbuf*)skb);
    return NAT_LB_OK;
}

static int ipv4_rcv_finish(sk_buff_t *skb) {
    struct per_lcore_ct_ctx *ctx;
    struct flow4 fl4;
    struct rte_ipv4_hdr *iph;

    ctx = &per_lcore_ctx;
    if (ctx->l4_proto == IPPROTO_TCP || ctx->l4_proto == IPPROTO_UDP || ctx->l4_proto == IPPROTO_ICMP) {
        return ipv4_pipeline(skb);
    } else {
        iph = rte_pktmbuf_mtod((struct rte_mbuf*)skb, struct rte_ipv4_hdr*);
        fl4.dst_addr = iph->dst_addr;

        struct route_entry* rt_entry = route_ingress_lockup(&fl4);
        if (NULL == rt_entry) {
            RTE_LOG(ERR, IP, "No route to dst %s, drop it.\n", be_ip_to_str(fl4.dst_addr));
            goto drop;
        }
        if (rt_entry->flags & RTF_LOCAL) {
            return ipv4_local_in(skb);
        } else if (rt_entry->flags & RTF_FORWARD) {
            return ipv4_forward(skb);
        }
    }

drop:
    rte_pktmbuf_free((struct rte_mbuf*)skb);
    return NAT_LB_OK;
}

static int ipv4_rcv(sk_buff_t *skb) {
    uint16_t iph_len, len;
    struct rte_ipv4_hdr *iph;
    struct per_lcore_ct_ctx *ctx;

    iph = rte_pktmbuf_mtod((struct rte_mbuf*)skb, struct rte_ipv4_hdr*);
    iph_len = ipv4_hdr_len(iph);
    if ((iph->version_ihl >> 4) != 4) {
        RTE_LOG(ERR, IP, "Not IPv4 pkt, drop it.\n");
        goto drop;
    }
    if (iph_len < sizeof(struct rte_ipv4_hdr)) {
        RTE_LOG(ERR, IP, "IPv4 pkt header not complete, drop it.\n");
    }
    if (rte_raw_cksum(iph, iph_len) != 0xFFFF) {
        RTE_LOG(ERR, IP, "IPv4 pkt Checksum error, drop it.\n");
        goto drop;
    }

    len = ntohs(iph->total_length);
    if (skb->mbuf.pkt_len < len || len < iph_len) {
        RTE_LOG(ERR, IP, "IPv4 pkt body not complete, drop it.\n");
        goto drop;
    }
    if (skb->mbuf.pkt_len > len) {
        if(rte_pktmbuf_trim((struct rte_mbuf*)skb, skb->mbuf.pkt_len - len) != 0) {
            goto drop;
        }
    }

    if (iph->next_proto_id == IPPROTO_ICMP) {
        goto drop;
    }

    ctx = &per_lcore_ctx;
    skb->mbuf.l3_len = iph_len;
    ctx->l4_proto = iph->next_proto_id;

    return ipv4_rcv_finish(skb);

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

    rt_entry = route_egress_lockup(fl4);
    if (NULL == rt_entry) {
        RTE_LOG(ERR, IP, "No route to dst %s, drop it.\n", be_ip_to_str(fl4->dst_addr));
        goto drop;
    }

    iph = (struct rte_ipv4_hdr*)rte_pktmbuf_prepend((struct rte_mbuf*)skb, sizeof(struct rte_ipv4_hdr));
    iph->version_ihl = ((4 << 4) | 5);
    iph->fragment_offset = 0;
    iph->time_to_live = DEFAULT_TIME_LIVE_TTL;
    iph->next_proto_id = fl4->flc.proto;
    iph->src_addr = fl4->src_addr;
    iph->dst_addr = fl4->dst_addr;
    iph->hdr_checksum = 0;
    iph->hdr_checksum = rte_ipv4_cksum(iph);

    uint32_t next_hop = iph->dst_addr;
    if (rt_entry->gw != 0) {
        next_hop = rt_entry->gw;
    }

    skb->mbuf.packet_type = RTE_ETHER_TYPE_IPV4;
    skb->mbuf.port = rt_entry->port->port_id;

    return neigh_output(next_hop, skb, rt_entry->port);

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

