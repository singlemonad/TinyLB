//
// Created by tedqu on 25-4-8.
//

#include <rte_hash_crc.h>
#include <rte_jhash.h>
#include <rte_malloc.h>
#include "../common/util.h"
#include "../lb/sa_pool.h"
#include "ip_group.h"
#include "log.h"

#define IP_GROUP_BUCKET_SIZE 64

extern struct rte_mempool *socket_pkt_mbuf_pool[2];
static dispatch_func dispatch_array[IP_TYPE_MAX];
static struct list_head ip_group_bucket[IP_GROUP_BUCKET_SIZE];

static inline uint32_t hash_skb_by_5tuple(struct rte_ipv4_hdr *iph) {
    return rte_jhash_3words(iph->src_addr, iph->dst_addr, *((uint32_t*)(&iph[1])), iph->next_proto_id);
}

static inline uint32_t hash_icmp_skb(struct rte_ipv4_hdr *iph, struct rte_icmp_hdr *icmp) {
    uint32_t hash1, hash2;

    hash1 = rte_hash_crc_4byte(iph->src_addr, iph->dst_addr);
    hash2 = rte_hash_crc_2byte(icmp->icmp_code, icmp->icmp_type);
    return rte_hash_crc_4byte(hash1, hash2);
}

static inline uint16_t dispatch_original_skb(struct sk_buff* skb, void* arg) {
    uint32_t skb_hash;

    struct rte_ipv4_hdr* iph = rte_pktmbuf_mtod(&skb->mbuf, struct rte_ipv4_hdr*);
    if (likely(iph->next_proto_id == IPPROTO_TCP|| iph->next_proto_id == IPPROTO_UDP)) {
        skb_hash = hash_skb_by_5tuple(iph);
    } else if(iph->next_proto_id == IPPROTO_ICMP) {
        skb_hash = hash_icmp_skb(iph, (struct rte_icmp_hdr*)&iph[1]);
    } else {
        skb_hash = rte_hash_crc_4byte(iph->src_addr, iph->dst_addr);
    }

    struct original_skb_dis_arg* dis_arg = (struct original_skb_dis_arg*)arg;
    return dis_arg->work_lcores[skb_hash % dis_arg->work_lcore_n];
}

static inline uint16_t dispatch_reply_skb(struct sk_buff* skb, void* arg) {
    struct rte_ipv4_hdr* iph = rte_pktmbuf_mtod(&skb->mbuf, struct rte_ipv4_hdr*);
    return snat_addr_lcore(iph->dst_addr);
}

static inline uint16_t dispatch_session_sync_skb(struct sk_buff* skb, void* arg) {
    return *((uint16_t *)arg);
}

static inline uint16_t dispatch_keepalive_skb(struct sk_buff* skb, void* arg) {
    return *((uint16_t *)arg);
}

static uint32_t get_ip_group_hash(uint32_t addr) {
    return rte_jhash_1word(addr, 0) % IP_GROUP_BUCKET_SIZE;
}

int add_ip_group(enum ip_type type, uint32_t ip) {
    struct ip_group *group;
    uint32_t hash = get_ip_group_hash(ip);

    list_for_each_entry(group, &ip_group_bucket[hash], node) {
        if (group->ip == ip) {
            return NAT_LB_EXIST;
        }
    }

    group = rte_zmalloc("ip_group", sizeof(struct ip_group), RTE_CACHE_LINE_SIZE);
    if (group == NULL) {
        RTE_LOG(ERR, NAT_LB, "%s: no memory\n", __func__);
        return NAT_LB_NOMEM;
    }
    group->type = type;
    group->ip = ip;
    list_add(&group->node, &ip_group_bucket[hash]);
    return NAT_LB_OK;
}

enum ip_type get_ip_group_type(uint32_t ip) {
    struct ip_group *group;
    uint32_t hash = get_ip_group_hash(ip);

    list_for_each_entry(group, &ip_group_bucket[hash], node) {
        if (group->ip == ip) {
            return group->type;
        }
    }
    return IP_TYPE_INVALID;
}

int get_rcv_lcore_id(struct sk_buff* skb, void* arg) {
    assert(dispatch_array[skb->ip_type] != NULL);
    return dispatch_array[skb->ip_type](skb, arg);
}

void ip_group_module_init(void) {
    for (int i = 0; i < IP_GROUP_BUCKET_SIZE; i++) {
        INIT_LIST_HEAD(&ip_group_bucket[i]);
    }
    dispatch_array[IP_TYPE_SVC] = dispatch_original_skb;
    dispatch_array[IP_TYPE_SNAT] = dispatch_reply_skb;
    dispatch_array[IP_TYPE_SESSION_SYNC] = dispatch_session_sync_skb;
    dispatch_array[IP_TYPE_KEEPALIVE] = dispatch_keepalive_skb;
}