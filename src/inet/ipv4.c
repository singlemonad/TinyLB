//
// Created by tedqu on 24-9-9.
//

#include <rte_mbuf_core.h>
#include <rte_tcp.h>
#include <linux/if_ether.h>
#include "../common/util.h"
#include "../common/log.h"
#include "inet.h"
#include "../lb/svc.h"
#include "../neigh/neigh.h"
#include "../common/pipeline.h"
#include "ipv4.h"
#include "../ct/ct.h"

extern __thread struct per_lcore_ct_ctx per_lcore_ctx;
static struct l4_handler* l4_handlers[IPPROTO_MAX];
static struct route_entry static_rt; // 会话同步和健康检查默认都从port 0出

static int ipv4_hdr_len(struct rte_ipv4_hdr *iph) {
    return (iph->version_ihl & 0xf) << 2;
}

static int ipv4_local_in(sk_buff_t *skb) {
    struct l4_handler* proto;
    struct lcore_rxtx_stats *stats = get_lcore_stats(rte_lcore_id());
    struct rte_ipv4_hdr* iph = rte_pktmbuf_mtod((struct rte_mbuf*)skb, struct rte_ipv4_hdr*);

    proto = l4_handlers[iph->next_proto_id];
    if (NULL == proto) {
        RTE_LOG(ERR, NAT_LB, "%s: no l4 handler for protocol %d(%s)\n", __func__, iph->next_proto_id, protocol_to_str(iph->next_proto_id));
        rte_pktmbuf_free((struct rte_mbuf*)skb);
        ++stats->drop.invalid_l4_proto;
        return NAT_LB_OK;
    }

    // remove network header
    skb->iph = iph;
    rte_pktmbuf_adj((struct rte_mbuf*)skb, skb->mbuf.l3_len);
    return proto->rcv(skb, iph);
}

static int ipv4_pipeline(sk_buff_t *skb) {
    int ret;
    struct rt_cache *rt;
    pipeline_actions action;
    struct per_lcore_ct_ctx* ctx = &per_lcore_ctx;
    struct lcore_rxtx_stats *stats = get_lcore_stats(rte_lcore_id());

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

    // 进入pipeline查找/创建ct后，会引用ct，退出pipeline时，需要解引用ct
    ct_deref(ctx->ct);
    return ret;

drop:
    ct_deref(ctx->ct);
    ++stats->drop.pipeline;
    rte_pktmbuf_free((struct rte_mbuf*)skb);
    return NAT_LB_OK;
}

static int ipv4_forward(sk_buff_t *skb) {
    struct flow4 fl4;
    struct lcore_rxtx_stats *stats = get_lcore_stats(rte_lcore_id());
    struct rte_ipv4_hdr *iph = rte_pktmbuf_mtod((struct rte_mbuf*)skb, struct rte_ipv4_hdr*);

    memset(&fl4, 0, sizeof(struct flow4));
    fl4.src_addr = iph->dst_addr;
    fl4.dst_addr = iph->src_addr;
    fl4.flc.proto = iph->next_proto_id;

    struct route_entry *rt_entry = route_egress_lockup(&fl4);
    if (NULL == rt_entry) {
        RTE_LOG(ERR, NAT_LB, "%s: no route to dst %s, drop it\n", be_ip_to_str(fl4.dst_addr));
        rte_pktmbuf_free((struct rte_mbuf*)skb);
        ++stats->drop.no_route;
        return NAT_LB_OK;
    }

    iph->time_to_live -= 1;
    iph->hdr_checksum = 0;
    iph->hdr_checksum = rte_ipv4_cksum(iph);
    skb->mbuf.packet_type = RTE_ETHER_TYPE_IPV4;
    skb->mbuf.port = rt_entry->port->port_id;

    uint32_t next_hop = iph->dst_addr;
    if (rt_entry->gw != 0) {
        next_hop = rt_entry->gw;
    }
    return neigh_output(next_hop, skb, rt_entry->port);
}

static int ipv4_rcv_finish(sk_buff_t *skb) {
    struct per_lcore_ct_ctx *ctx;
    struct flow4 fl4;
    struct rte_ipv4_hdr *iph;
    struct lcore_rxtx_stats *stats = get_lcore_stats(rte_lcore_id());

    iph = rte_pktmbuf_mtod((struct rte_mbuf*)skb, struct rte_ipv4_hdr*);
    ctx = &per_lcore_ctx;

    // 会话同步报文或健康检查报文，上送到本地协议栈
    if (skb->flags & (SKB_SESSION_SYNC|SKB_KEEPALIVE)) {
        return ipv4_local_in(skb);
    }

    if (ctx->l4_proto == IPPROTO_TCP ||
        ctx->l4_proto == IPPROTO_UDP ||
        ctx->l4_proto == IPPROTO_ICMP) {
        return ipv4_pipeline(skb);
    }

    fl4.dst_addr = iph->dst_addr;
    struct route_entry* rt_entry = route_ingress_lockup(&fl4);

    if (NULL == rt_entry) {
        RTE_LOG(ERR, NAT_LB, "%s: no route to dst %s, drop it\n", __func__, be_ip_to_str(fl4.dst_addr));
        rte_pktmbuf_free((struct rte_mbuf*)skb);
        ++stats->drop.no_route;
        return NAT_LB_OK;
    }
    if (rt_entry->flags & RTF_LOCAL) {
        return ipv4_local_in(skb);
    }
    return ipv4_forward(skb);
}

int ipv4_rcv(sk_buff_t *skb) {
    uint16_t iph_len, len;
    struct rte_ipv4_hdr *iph;
    struct per_lcore_ct_ctx *ctx;
    struct lcore_rxtx_stats *stats = get_lcore_stats(rte_lcore_id());

    iph = rte_pktmbuf_mtod((struct rte_mbuf*)skb, struct rte_ipv4_hdr*);
    iph_len = ipv4_hdr_len(iph);
    if ((iph->version_ihl >> 4) != 4) {
        RTE_LOG(ERR, NAT_LB, "%s: not IPv4 pkt, drop it\n", __func__);
        goto drop;
    }
    if (iph_len < sizeof(struct rte_ipv4_hdr)) {
        RTE_LOG(ERR, NAT_LB, "%s: IPv4 pkt header not complete, drop it\n", __func__);
        goto drop;
    }
    if (rte_raw_cksum(iph, iph_len) != 0xFFFF) {
        RTE_LOG(ERR, NAT_LB, "IPv4 pkt Checksum error, drop it\n", __func__);
        goto drop;
    }

    len = ntohs(iph->total_length);
    if (skb->mbuf.pkt_len < len || len < iph_len) {
        RTE_LOG(ERR, NAT_LB, "IPv4 pkt body not complete, drop it\n", __func__);
        goto drop;
    }
    if (skb->mbuf.pkt_len > len) {
        if(rte_pktmbuf_trim((struct rte_mbuf*)skb, skb->mbuf.pkt_len - len) != 0) {
            goto drop;
        }
    }

    if (iph->next_proto_id == IPPROTO_ICMP) {
        ++stats->drop.icmp;
        rte_pktmbuf_free((struct rte_mbuf*)skb);
        return NAT_LB_OK;
    }

    // RTE_LOG(INFO, NAT_LB, "%s: rcv pkt,src_ip=%s,l4_proto=%d\n", __func__, be_ip_to_str(iph->src_addr), iph->next_proto_id);

    ctx = &per_lcore_ctx;
    skb->mbuf.l3_len = iph_len;
    skb->iph = iph;
    ctx->l4_proto = iph->next_proto_id;
    return ipv4_rcv_finish(skb);

drop:
    ++stats->drop.invalid_pkt;
    rte_pktmbuf_free((struct rte_mbuf*)skb);
    return NAT_LB_OK;
}

static void calc_l4_checksum(struct rte_ipv4_hdr *iph) {
    struct rte_tcp_hdr *tcp;
    struct rte_udp_hdr *udp;

    if (iph->next_proto_id == IPPROTO_UDP) {
        udp = (struct rte_udp_hdr*)&iph[1];
        udp->dgram_cksum = 0;
        udp->dgram_cksum = rte_ipv4_udptcp_cksum(iph, udp);
    } else {
        tcp = (struct rte_tcp_hdr*)&iph[1];
        tcp->cksum = 0;
        tcp->cksum = rte_ipv4_udptcp_cksum(iph, tcp);
    }
}

int ipv4_output(sk_buff_t *skb, struct rt_cache *rt) {
    uint32_t next_hop;
    struct rte_ipv4_hdr *iph;
    struct lcore_rxtx_stats *stats = get_lcore_stats(rte_lcore_id());

    if (NULL == rt) {
        RTE_LOG(ERR, NAT_LB, "%s: no route\n", __func__);
        rte_pktmbuf_free((struct rte_mbuf*)skb);
        ++stats->drop.no_route;
        return NAT_LB_OK;
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
}

int ipv4_local_out(sk_buff_t *skb, struct flow4 *fl4) {
    struct rte_ipv4_hdr *iph;
    struct route_entry *rt_entry;
    struct lcore_rxtx_stats *stats = get_lcore_stats(rte_lcore_id());

    if (skb->flags & (SKB_KEEPALIVE | SKB_SESSION_SYNC)) {
        rt_entry = &static_rt;
    } else {
        rt_entry = route_egress_lockup(fl4);
        if (NULL == rt_entry) {
            RTE_LOG(ERR, NAT_LB, "%s: no route to dst %s, drop it\n", __func__, be_ip_to_str(fl4->dst_addr));
            rte_pktmbuf_free((struct rte_mbuf*)skb);
            ++stats->drop.no_route;
            return NAT_LB_OK;
        }
    }

    iph = (struct rte_ipv4_hdr*)rte_pktmbuf_prepend((struct rte_mbuf*)skb, sizeof(struct rte_ipv4_hdr));
    iph->version_ihl = ((4 << 4) | 5);
    iph->fragment_offset = 0;
    iph->time_to_live = DEFAULT_TIME_LIVE_TTL;
    iph->next_proto_id = fl4->flc.proto;
    if (fl4->src_addr == 0) {
        iph->src_addr = rt_entry->port->local_ip;
    } else {
        iph->src_addr = fl4->src_addr;
    }
    iph->dst_addr = fl4->dst_addr;
    iph->total_length = htons(skb->mbuf.data_len);
    iph->hdr_checksum = 0;
    iph->hdr_checksum = rte_ipv4_cksum(iph);

    uint32_t next_hop = rte_be_to_cpu_32(iph->dst_addr);
    if (rt_entry->gw != 0) {
        next_hop = rt_entry->gw;
    }

    calc_l4_checksum(iph);

    skb->mbuf.packet_type = RTE_ETHER_TYPE_IPV4;
    skb->mbuf.port = rt_entry->port->port_id;
    return neigh_output(next_hop, skb, rt_entry->port);
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

void ipv4_init_static_route(void) {
    static_rt.port = get_port_by_id(0);
    static_rt.dst_addr = static_rt.port->local_ip;
}
