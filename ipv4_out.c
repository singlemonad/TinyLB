//
// Created by tedqu on 24-9-10.
//

#include <rte_mbuf_core.h>
#include "common.h"
#include "ipv4_out.h"
#include "inet.h"
#include "neigh.h"

int ipv4_output(sk_buff_t *skb) {
    uint32_t next_hop;
    struct rte_ipv4_hdr *iph;

    if (NULL == skb->rt_entry) {
        fprintf(stderr, "No route.\n");
        goto drop;
    }

    iph = rte_pktmbuf_mtod((struct rte_mbuf*)skb, struct rte_ipv4_hdr*);
    if (skb->rt_entry->gw != 0) {
        next_hop = skb->rt_entry->gw;
    } else {
        next_hop = iph->dst_addr;
    }
    next_hop = rte_be_to_cpu_32(next_hop);
    iph->hdr_checksum = 0;
    iph->hdr_checksum = rte_ipv4_cksum(iph);

    skb->mbuf.packet_type = RTE_ETHER_TYPE_IPV4;
    skb->mbuf.port = skb->rt_entry->port->port_id;

    return neigh_output(next_hop, skb, skb->rt_entry->port);

drop:
    rte_pktmbuf_free((struct rte_mbuf*)skb);
    return NAT_LB_OK;
}

int ipv4_xmit(sk_buff_t *skb, struct flow4 *fl4) {
    struct rte_ipv4_hdr *iph;
    struct route_entry *rt_entry;

    fl4->dst_addr = rte_be_to_cpu_32(fl4->dst_addr);
    rt_entry = route_egress_lockup(fl4);
    if (NULL == rt_entry) {
        goto no_route;
    }
    skb->rt_entry = rt_entry;
    fl4->dst_addr = rte_cpu_to_be_32(fl4->dst_addr);

    iph = (struct rte_ipv4_hdr*)rte_pktmbuf_prepend((struct rte_mbuf*)skb, sizeof(struct rte_ipv4_hdr));
    iph->version_ihl = ((4 << 4) | 5);
    iph->fragment_offset = 0;
    iph->time_to_live = DEFAULT_TIME_LIVE_TTL;
    iph->next_proto_id = fl4->flc.proto;
    iph->src_addr = fl4->src_addr;
    iph->dst_addr = fl4->dst_addr;

    if (iph->src_addr == INADDR_ANY) {
        // TODO select src addr
    }

    return ipv4_output(skb);

no_route:
    fprintf(stderr, "No route, %s, dst %u.%u.%u.%u.\n",
            __func__, fl4->dst_addr & 0xff, ( fl4->dst_addr>>8) & 0xff, ( fl4->dst_addr>>16) & 0xff, (fl4->dst_addr>>24) & 0xff);
drop:
    rte_pktmbuf_free((struct rte_mbuf*)skb);

    return NAT_LB_OK;
}