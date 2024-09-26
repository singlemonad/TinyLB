//
// Created by tedqu on 24-9-9.
//

#include <rte_mbuf_core.h>
#include "common.h"
#include "l2.h"
#include "ipv4_in.h"
#include "ipv4_forward.h"
#include "route.h"
#include "inet.h"
#include "acl.h"
#include "ct.h"

static int ipv4_hdr_len(struct rte_ipv4_hdr *iph) {
    return (iph->version_ihl & 0xf) << 2;
}

static int ipv4_local_in_finish(sk_buff_t *skb) {
    struct rte_ipv4_hdr *iph;
    unsigned char next_proto;
    struct inet_protocol* proto;

    iph = rte_pktmbuf_mtod((struct rte_mbuf*)skb, struct rte_ipv4_hdr*);

    next_proto = iph->next_proto_id;
    proto = get_protocol(next_proto);
    if (NULL == proto) {
        goto drop;
    }

    // remove network header
    rte_pktmbuf_adj((struct rte_mbuf*)skb, skb->mbuf.l3_len);
    return proto->handler(skb, iph);

drop:
    rte_pktmbuf_free((struct rte_mbuf*)skb);

    return NAT_LB_OK;
}

static int ipv4_local_in(sk_buff_t *skb) {
    return ipv4_local_in_finish(skb);
}

static int ipv4_rcv_finish(sk_buff_t *skb) {
    struct route_entry *rt_entry;
    struct flow4 fl4;
    struct rte_ipv4_hdr *iph;
    struct ct_session *ct;

    ct = ct_find(skb);
    if (NULL == ct ) {
        rte_exit(EXIT_FAILURE, "ct not found, unexpected.\n");
    }

    if (NULL != ct->rt_entry) {
        rt_entry = ct->rt_entry;
    } else {
        iph = rte_pktmbuf_mtod((struct rte_mbuf*)skb, struct rte_ipv4_hdr*);

        fl4.dst_addr = rte_be_to_cpu_32(iph->dst_addr);
        rt_entry = route_ingress_lockup(&fl4);
        if (NULL == rt_entry) {
            fprintf(stderr, "No route found for dst %u.%u.%u.%u.\n",
                    fl4.dst_addr & 0xff, (fl4.dst_addr >> 8) & 0xff, (fl4.dst_addr >> 16) & 0xff,
                    (fl4.dst_addr >> 24) & 0xff);
            goto drop;
        }
        ct->rt_entry = rt_entry;
    }
    skb->rt_entry = rt_entry;

    if (rt_entry->flags & RTF_LOCAL) {
        return ipv4_local_in(skb);
    } else if (rt_entry->flags & RTF_FORWARD) {
        return ipv4_forward(skb);
    } else {
        goto drop;
    }

drop:
    rte_pktmbuf_free((struct rte_mbuf*)skb);
    return NAT_LB_OK;
}

static int ingress_acl(sk_buff_t *skb) {
    struct rte_ipv4_hdr *iph;
    struct ipv4_3tuple match;
    int ret;

    iph = rte_pktmbuf_mtod((struct rte_mbuf*)skb, struct rte_ipv4_hdr*);
    match.proto = iph->next_proto_id;
    match.ip_src = iph->src_addr;
    match.ip_dst = iph->dst_addr;

    ret = ingress_acl_match(&match);
    if (ret < 0) {
        fprintf(stderr, "Ingress acl match failed, %s.", rte_strerror(rte_errno));
        return ACL_ACCEPT;
    }
    return ret;
}

static int ipv4_rcv(sk_buff_t *skb) {
    uint16_t iph_len, len;
    struct rte_ipv4_hdr *iph;
    int acl_res;
    struct ct_session *ct;

    iph = rte_pktmbuf_mtod((struct rte_mbuf*)skb, struct rte_ipv4_hdr*);

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

    ct = ct_find(skb);
    if (NULL == ct) {
        fprintf(stdout, "ct miss.\n");

        ct = ct_new(skb);
        if (NULL == ct) {
            fprintf(stderr, "ct new failed.\n");
            goto drop;
        }
    } else {
        // fprintf(stdout, "ct hint.\n");
    }


    acl_res = ingress_acl(skb);
    if (ACL_DROP == acl_res) {
        goto drop;
    }

    skb->mbuf.l3_len = iph_len;

    return ipv4_rcv_finish(skb);

drop:
    rte_pktmbuf_free((struct rte_mbuf*)skb);

    return NAT_LB_OK;
}

static struct pkt_type ipv4_handler = {
        .type = RTE_ETHER_TYPE_IPV4,
        .func = ipv4_rcv,
};

void ipv4_in_init(void) {
    pkt_type_register(&ipv4_handler);
}

