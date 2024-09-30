//
// Created by tedqu on 24-9-9.
//

#include <rte_mbuf_core.h>
#include "common.h"
#include "log.h"
#include "l2.h"
#include "ipv4_in.h"
#include "ipv4_forward.h"
#include "ipv4_out.h"
#include "route.h"
#include "inet.h"
#include "acl.h"
#include "ct.h"
#include "svc.h"
#include "sa_pool.h"

static int ipv4_hdr_len(struct rte_ipv4_hdr *iph) {
    return (iph->version_ihl & 0xf) << 2;
}

static int ipv4_local_in_finish(sk_buff_t *skb, sk_ext_info_t *ext) {
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

static int ipv4_local_in(sk_buff_t *skb, sk_ext_info_t *ext) {
    return ipv4_local_in_finish(skb, ext);
}

static int do_ingress_acl(sk_buff_t *skb) {
    struct rte_ipv4_hdr *iph;
    struct ipv4_3tuple match;
    int ret;

    iph = rte_pktmbuf_mtod((struct rte_mbuf*)skb, struct rte_ipv4_hdr*);
    match.proto = iph->next_proto_id;
    match.ip_src = iph->src_addr;
    match.ip_dst = iph->dst_addr;

    ret = ingress_acl_match(&match);
    if (ret < 0) {
        RTE_LOG(ERR, L3, "Ingress acl match failed, %s.", rte_strerror(rte_errno));
        return ACL_ACCEPT;
    }
    return ret;
}

static int ipv4_schedule(sk_buff_t *skb, sk_ext_info_t *ext) {
    int ret;
    struct rte_ipv4_hdr *iph;
    struct rte_tcp_hdr *tcp;
    svc_t *svc;
    rs_t *rs;
    dnat_action_data_t *dnat_data;
    snat_action_data_t *snat_data;
    uint32_t snat_ip;
    uint16_t snat_port;

    iph = rte_pktmbuf_mtod((struct rte_mbuf*)skb, struct rte_ipv4_hdr*);
    tcp = (struct rte_tcp_hdr*)&iph[1];

    // show_ip(iph->dst_addr);
    RTE_LOG(INFO, L3, "dir=%d,dst_port=%d\n", ext->tuple_hash->tuple.dir, ntohs(tcp->dst_port));

    svc = svc_find(iph->dst_addr, tcp->dst_port);
    if (NULL == svc) {
        // RTE_LOG(ERR, L3, "no svc found, dst_port=%d.\n", ntohs(tcp->dst_port));
        return NAT_LB_NOT_EXIST;
    }

    rs = rs_schedule(iph->dst_addr, tcp->dst_port);
    if (NULL == rs) {
        RTE_LOG(ERR, L3, "no rs found.");
        return NAT_LB_NOT_EXIST;
    }

    dnat_data = rte_malloc("dnat data", sizeof(dnat_action_data_t), RTE_CACHE_LINE_SIZE);
    if (NULL == dnat_data) {
        RTE_LOG(ERR, L3, "no memory.");
        return NAT_LB_NOMEM;
    }
    dnat_data->dst_ip = rs->rs_ip;
    dnat_data->port = rs->rs_port;
    ext->ct->action_data[CT_ACTION_DNAT] = dnat_data;

    ret = snat_addr_get(iph->dst_addr, tcp->dst_port, &snat_ip, &snat_port);
    if (NAT_LB_OK != ret) {
        RTE_LOG(ERR, L3, "get snat addr failed.");
        return NAT_LB_NO_SNAT_PORT;
    }

    snat_data = rte_malloc("snat data", sizeof(snat_action_data_t), RTE_CACHE_LINE_SIZE);
    if (NULL == snat_data) {
        RTE_LOG(ERR, L3, "no memory.");
        return NAT_LB_NOMEM;
    }
    snat_data->src_ip = snat_ip;
    snat_data->port = snat_port;
    ext->ct->action_data[CT_ACTION_SNAT] = snat_data;

    ext->ct->orig_src_ip = iph->src_addr;
    ext->ct->orig_src_port = tcp->src_port;
    ext->ct->vip = iph->dst_addr;
    ext->ct->vport = tcp->dst_port;

    do_dnat(skb, ext);
    do_snat(skb, ext);
    reinsert_ct(skb, ext);

    return NAT_LB_OK;
}

static int ipv4_rcv_finish(sk_buff_t *skb, sk_ext_info_t *ext) {
    struct route_entry *rt_entry;
    struct flow4 fl4;
    struct rte_ipv4_hdr *iph;
    int ret;

    if (NULL == ext->ct) {
        rte_exit(EXIT_FAILURE, "ct not found, unexpected.\n");
    }

    ext->ct->acl_action = do_ingress_acl(skb);
    if (ext->ct->acl_action == ACL_DROP) {
        goto drop;
    }

    iph = rte_pktmbuf_mtod((struct rte_mbuf*)skb, struct rte_ipv4_hdr*);

    if (likely(NULL == ext->ct->rt_entry)) {

        fl4.dst_addr = rte_be_to_cpu_32(iph->dst_addr);
        rt_entry = route_ingress_lockup(&fl4);
        if (NULL == rt_entry) {
            fprintf(stderr, "No route found for dst %u.%u.%u.%u.\n",
                    fl4.dst_addr & 0xff, (fl4.dst_addr >> 8) & 0xff, (fl4.dst_addr >> 16) & 0xff,
                    (fl4.dst_addr >> 24) & 0xff);
            goto drop;
        }
        ext->ct->rt_entry = rt_entry;
    }

    if (IPPROTO_TCP == iph->next_proto_id) {
        ret = ipv4_schedule(skb, ext);
        if (NAT_LB_OK != ret) {
            ct_delete(ext->ct);
            goto drop;
        }
        return ipv4_forward(skb, ext);
    }

    if (ext->ct->rt_entry->flags & RTF_LOCAL) {
        return ipv4_local_in(skb, ext);
    } else if (rt_entry->flags & RTF_FORWARD) {
        return ipv4_forward(skb, ext);
    } else {
        goto drop;
    }

drop:
    rte_pktmbuf_free((struct rte_mbuf*)skb);
    return NAT_LB_OK;
}

static int init_ext_ct(sk_buff_t *skb, sk_ext_info_t *ext) {
    struct ct_session *ct;

    ct = ct_new(skb);
    if (NULL == ct) {
        return NAT_LB_NOMEM;
    }

    ext->ct = ct;
    return NAT_LB_OK;
}

static int ipv4_fast_path(sk_buff_t *skb, sk_ext_info_t *ext) {
    if (ext->ct->acl_action == ACL_DROP) {
        goto drop;
    }

    if (IPPROTO_TCP == ext->l4_proto) {
        if (ext->tuple_hash->tuple.dir == CT_DRI_ORIGINAL) {
            do_dnat(skb, ext);
            do_snat(skb, ext);
            return ipv4_output(skb, ext);
        } else if (ext->tuple_hash->tuple.dir == CT_DRI_REPLY) {
            RTE_LOG(INFO, L3, "reply ct hit.\n");
            do_reply_nat(skb, ext);
            return ipv4_output(skb, ext);
        }
    }

    if (NULL != ext->ct && NULL != ext->ct->rt_entry) {
        if (ext->ct->rt_entry->flags & RTF_LOCAL) {
            return ipv4_local_in(skb, ext);
        }
        return ipv4_output(skb, ext);
    }

drop:
    rte_pktmbuf_free((struct rte_mbuf*)skb);
    return NAT_LB_OK;
}

static int ipv4_rcv(sk_buff_t *skb) {
    int ret;
    uint16_t iph_len, len;
    struct rte_ipv4_hdr *iph;
    sk_ext_info_t ext;
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

    skb->mbuf.l3_len = iph_len;
    ext.l4_proto = iph->next_proto_id;

    ct = ct_find(skb, &ext);
    if (likely(NULL != ct)) {
        ext.ct = ct;
        goto fast_path;
    }

    ret = init_ext_ct(skb, &ext);
    if (NAT_LB_OK != ret) {
        goto drop;
    }

    return ipv4_rcv_finish(skb, &ext);

fast_path:
    return ipv4_fast_path(skb, &ext);

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

