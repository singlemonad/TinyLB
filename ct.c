//
// Created by tedqu on 24-9-15.
//

#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <rte_ip.h>
#include <rte_hash_crc.h>
#include "common.h"
#include "ct.h"

#define MAX_CT_BUCKETS 512

static const uint8_t tcp_ct_state_transfer_map[CT_DRI_COUNT][TCP_BIT_MAX][TCP_CT_MAX] = {
/* original */
        {
                /* sNO、sSS、sSR、sES、sFW、sCW、sLA、sTM、sCL、sS2 */
/* SYN */       {sSS, sSS, sSR, sES, sFW, sCW, sLA, sSS, sSS, sS2},
/* SYNACK */    {sNO, },
/* FIN */       {},
/* ACK */       {},
/* RST */       {},
/* NONE*/       {}
        },

/* reply */
        {
/* SYN */       {},
/* SYNACK */    {},
/* FIN */       {},
/* ACK */       {},
/* RST*/        {},
/* none */      {}
        }
};

static struct list_head g_ct_table[MAX_CT_BUCKETS];

static uint16_t gen_ipv4_nat_check(uint32_t old_rev_val, uint32_t new_val, uint16_t old_check)
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

int do_dnat(sk_buff_t *skb, sk_ext_info_t *ext) {
    struct rte_ipv4_hdr *iph;
    dnat_action_data_t *arg;
    struct rte_tcp_hdr *tcp;
    struct rte_udp_hdr *udp;
    uint32_t old_dst_ip;
    uint32_t new_port, old_port;

    if (NULL == ext || NULL == ext->ct) {
        rte_exit(EXIT_FAILURE, "ct not init.");
    }

    arg = (dnat_action_data_t *)(ext->ct->action_data[CT_ACTION_DNAT]);
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

        tcp->cksum = gen_ipv4_nat_check(~old_dst_ip, iph->dst_addr, tcp->cksum);
        tcp->cksum = gen_ipv4_nat_check(~old_port, new_port, tcp->cksum);
    } else if (iph->next_proto_id == IPPROTO_UDP) {
        udp = (struct rte_udp_hdr*)&iph[1];
        old_port = (udp->src_port << 16) | udp->dst_port;
        udp->dst_port = arg->port;
        new_port = (udp->src_port << 16) | udp->dst_port;

        udp->dgram_cksum = gen_ipv4_nat_check(~old_dst_ip, iph->dst_addr, udp->dgram_cksum);
        udp->dgram_cksum = gen_ipv4_nat_check(~old_port, new_port, udp->dgram_cksum);
    }

    return NAT_LB_OK;
}

int do_snat(sk_buff_t *skb, sk_ext_info_t *ext) {
    struct rte_ipv4_hdr *iph;
    struct rte_tcp_hdr *tcp;
    struct rte_udp_hdr *udp;
    snat_action_data_t *arg;
    uint32_t old_sip;
    uint32_t new_port, old_port;

    if (NULL == ext || NULL == ext->ct) {
        rte_exit(EXIT_FAILURE, "ct not init.");
    }

    arg = (snat_action_data_t *)(ext->ct->action_data[CT_ACTION_SNAT]);
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

        tcp->cksum = gen_ipv4_nat_check(~old_sip, iph->src_addr, tcp->cksum);
        tcp->cksum = gen_ipv4_nat_check(~old_port, new_port, tcp->cksum);
    } else if (IPPROTO_UDP == iph->next_proto_id) {
        udp = (struct rte_udp_hdr*)&iph[1];
        old_port = (udp->src_port << 16) | udp->dst_port;
        udp->src_port = arg->port;
        new_port = (udp->src_port << 16) | udp->dst_port;

        udp->dgram_cksum = gen_ipv4_nat_check(~old_sip, iph->src_addr, udp->dgram_cksum);
        udp->dgram_cksum = gen_ipv4_nat_check(~old_port, new_port, udp->dgram_cksum);
    }

    return NAT_LB_OK;
}

int do_reply_nat(struct sk_buff *skb, struct sk_ext_info *ext) {
    struct rte_ipv4_hdr *iph;
    struct rte_tcp_hdr *tcp;
    struct rte_udp_hdr *upd;
    uint32_t old_sip, old_dip;
    uint32_t old_sport, new_sport;
    uint32_t old_dport, new_dport;

    iph = rte_pktmbuf_mtod((struct rte_mbuf*)skb, struct rte_ipv4_hdr*);
    old_sip = iph->src_addr;
    old_dip = iph->dst_addr;

    iph->src_addr = ext->ct->vip;
    iph->dst_addr = ext->ct->orig_src_ip;
    iph->hdr_checksum = 0;
    iph->hdr_checksum = rte_ipv4_cksum(iph);

    if (IPPROTO_TCP == iph->next_proto_id) {
        tcp = (struct rte_tcp_hdr*)&iph[1];

        old_sport = (tcp->src_port << 16) | tcp->dst_port;
        tcp->src_port = ext->ct->vport;
        new_sport = (tcp->src_port << 16) | tcp->dst_port;
        tcp->cksum = gen_ipv4_nat_check(~old_sip, iph->src_addr, tcp->cksum);
        tcp->cksum = gen_ipv4_nat_check(~old_dip, iph->dst_addr, tcp->cksum);
        tcp->cksum = gen_ipv4_nat_check(~old_sport, new_sport, tcp->cksum);

        old_dport = (tcp->src_port << 16) | tcp->dst_port;
        tcp->dst_port = ext->ct->orig_src_port;
        new_dport = (tcp->src_port << 16) | tcp->dst_port;
        tcp->cksum = gen_ipv4_nat_check(~old_dport, new_dport, tcp->cksum);
    } else if (IPPROTO_UDP == iph->next_proto_id) {
        // TODO
    }

    return NAT_LB_OK;
}

static struct ct_session* ct_alloc(void) {
    struct ct_session *ct;

    ct = rte_zmalloc("ct", sizeof(struct ct_session), RTE_CACHE_LINE_SIZE);
    if (NULL == ct) {
        fprintf(stderr, "No memory, %s.", __func__ );
        return NULL;
    }
    return ct;
}

static struct ct_tuple ct_pkt_to_tuple(sk_buff_t *skb, bool reverse) {
    struct rte_ipv4_hdr *iph;
    struct rte_icmp_hdr *icmp;
    struct ct_tuple tuple;
    uint16_t *ports;

    iph = rte_pktmbuf_mtod((struct rte_mbuf*)skb, struct rte_ipv4_hdr*);

    if (!reverse) {
        tuple.src_addr = iph->src_addr;
        tuple.dst_addr = iph->dst_addr;
        if (IPPROTO_ICMP == iph->next_proto_id) {
            icmp = (struct rte_icmp_hdr *) &iph[1];
            tuple.icmp.type = icmp->icmp_type;
            tuple.icmp.code = icmp->icmp_code;
        } else {
            ports = (uint16_t *) &iph[1];
            tuple.ports.src_port = ports[0];
            tuple.ports.dst_port = ports[1];
        }
    } else {
        tuple.src_addr = iph->dst_addr;
        tuple.dst_addr = iph->src_addr;
        if (IPPROTO_ICMP == ntohs(iph->next_proto_id)) {
            icmp = (struct rte_icmp_hdr *) &iph[1];
            tuple.icmp.type = icmp->icmp_type;
            tuple.icmp.code = icmp->icmp_code;
        } else {
            ports = (uint16_t *) &iph[1];
            tuple.ports.src_port = ports[1];
            tuple.ports.dst_port = ports[0];
        }
    }

    return tuple;
}

static void ct_fill_tuple(sk_buff_t *skb, struct ct_session *ct) {
    ct->tuple_hash[CT_DRI_ORIGINAL].tuple = ct_pkt_to_tuple(skb, false);
    ct->tuple_hash[CT_DRI_ORIGINAL].tuple.dir = CT_DRI_ORIGINAL;

    ct->tuple_hash[CT_DRI_REPLY].tuple = ct_pkt_to_tuple(skb, true);
    ct->tuple_hash[CT_DRI_REPLY].tuple.dir = CT_DRI_REPLY;
}

static uint32_t ct_get_tuple_hash(struct ct_tuple tuple) {
    return rte_hash_crc_4byte(tuple.src_addr, tuple.dst_addr) % MAX_CT_BUCKETS;
}

static void ct_insert(struct ct_session *ct) {
    uint32_t orig_hash, reply_hash;

    orig_hash = ct_get_tuple_hash(ct->tuple_hash[CT_DRI_ORIGINAL].tuple);
    reply_hash = ct_get_tuple_hash(ct->tuple_hash[CT_DRI_REPLY].tuple);

    list_add(&ct->tuple_hash[CT_DRI_ORIGINAL].tuple_node, &g_ct_table[orig_hash]);
    list_add(&ct->tuple_hash[CT_DRI_REPLY].tuple_node, &g_ct_table[reply_hash]);
}

int reinsert_ct(struct sk_buff *skb, struct sk_ext_info *ext) {
    uint32_t hash;
    struct ct_tuple tuple;
    snat_action_data_t *snat_arg;
    dnat_action_data_t *dnat_arg;

    snat_arg = (snat_action_data_t *)ext->ct->action_data[CT_ACTION_SNAT];
    dnat_arg = (dnat_action_data_t *)ext->ct->action_data[CT_ACTION_DNAT];

    tuple.dir = CT_DRI_REPLY;
    tuple.dst_addr = snat_arg->src_ip;
    tuple.ports.dst_port = snat_arg->port;
    tuple.src_addr = dnat_arg->dst_ip;
    tuple.ports.src_port = dnat_arg->port;

    list_del(&ext->ct->tuple_hash[CT_DRI_REPLY].tuple_node);
    ext->ct->tuple_hash[CT_DRI_REPLY].tuple = tuple;

    hash = ct_get_tuple_hash(tuple);
    list_add(&ext->ct->tuple_hash[CT_DRI_REPLY].tuple_node, &g_ct_table[hash]);

    return NAT_LB_OK;
}

struct ct_session* ct_new(sk_buff_t *skb) {
    struct ct_session *ct;

    ct = ct_alloc();
    if (NULL == ct) {
        return NULL;
    }

    ct_fill_tuple(skb, ct);
    ct->state = TCP_CT_NONE;
    ct->rt_entry = NULL;
    ct_insert(ct);

    return ct;
}

struct ct_session* ct_find(sk_buff_t *skb, sk_ext_info_t *ext) {
    struct ct_tuple tuple;
    uint32_t hash;
    struct ct_tuple_hash *tuple_hash;
    struct ct_session *ct;
    struct rte_ipv4_hdr *iph;

    tuple = ct_pkt_to_tuple(skb, false);
    hash = ct_get_tuple_hash(tuple);
    list_for_each_entry(tuple_hash, &g_ct_table[hash], tuple_node) {
        if (tuple_hash->tuple.src_addr == tuple.src_addr &&
        tuple_hash->tuple.dst_addr == tuple.dst_addr) {
            iph = rte_pktmbuf_mtod((struct rte_mbuf*)skb, struct rte_ipv4_hdr*);
            if (IPPROTO_ICMP == iph->next_proto_id) {
                if (tuple_hash->tuple.icmp.type == tuple.icmp.type &&
                tuple_hash->tuple.icmp.code == tuple.icmp.code) {
                    ext->tuple_hash = tuple_hash;
                    return TUPLE_TO_CT(tuple_hash);
                }
            } else {
                if (tuple_hash->tuple.ports.src_port == tuple.ports.src_port &&
                tuple_hash->tuple.ports.dst_port == tuple.ports.dst_port) {
                    ext->tuple_hash = tuple_hash;
                    return TUPLE_TO_CT(tuple_hash);
                }
            }
        }
    }

    return NULL;
}

int ct_delete(struct ct_session *ct) {
    list_del(&ct->tuple_hash[CT_DRI_ORIGINAL].tuple_node);
    list_del(&ct->tuple_hash[CT_DRI_REPLY].tuple_node);
    return NAT_LB_OK;
}

void ct_init(void) {
    int i;

    for (i = 0; i < MAX_CT_BUCKETS; i++) {
        INIT_LIST_HEAD(&g_ct_table[i]);
    }
}
