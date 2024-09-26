//
// Created by tedqu on 24-9-15.
//

#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <rte_ip.h>
#include <rte_hash_crc.h>
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
        if (IPPROTO_ICMP == ntohs(iph->next_proto_id)) {
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
    ct->tuple_hash[CT_DRI_REPLY].tuple = ct_pkt_to_tuple(skb, true);
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

struct ct_session* ct_new(sk_buff_t *skb) {
    struct ct_session *ct;

    ct = ct_alloc();
    if (NULL == ct) {
        return NULL;
    }

    ct_fill_tuple(skb, ct);
    ct->rt_entry = NULL;
    ct_insert(ct);

    return ct;
}

struct ct_session* ct_find(sk_buff_t *skb) {
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
                    return TUPLE_TO_CT(tuple_hash);
                }
            } else {
                if (tuple_hash->tuple.ports.src_port == tuple.ports.src_port &&
                tuple_hash->tuple.ports.dst_port == tuple.ports.dst_port) {
                    return TUPLE_TO_CT(tuple_hash);
                }
            }
        }
    }

    return NULL;
}

void ct_init(void) {
    int i;

    for (i = 0; i < MAX_CT_BUCKETS; i++) {
        INIT_LIST_HEAD(&g_ct_table[i]);
    }
}
