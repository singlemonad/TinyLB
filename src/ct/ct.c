//
// Created by tedqu on 24-9-15.
//

#include <pthread.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <rte_ip.h>
#include <rte_hash_crc.h>
#include "../common/util.h"
#include "../common/pipeline.h"
#include "../common/log.h"
#include "../common/jiffies.h"
#include "ct.h"

#define MAX_CT_BUCKETS 512

extern __thread struct per_lcore_ct_ctx per_lcore_ctx;

extern struct ct_l4_proto tcp_l4_proto;
extern struct ct_l4_proto udp_l4_proto;
extern struct ct_l4_proto icmp_l4_proto;

static struct ct_ext ct_extensions[MAX_CT_ACTION];

static struct ct_l4_proto ct_l4_handlers[IPPROTO_MAX];

static RTE_DEFINE_PER_LCORE(struct list_head, ct_table[MAX_CT_BUCKETS]);
#define local_ct_tbl (RTE_PER_LCORE(ct_table))

void ct_ext_register(uint8_t index, uint32_t length) {
    uint32_t offset = 0;
    int i = 0;

    for ( ; i < index; i++) {
        offset += ct_extensions[i].length;
    }
    ct_extensions[i].offset = offset;
    ct_extensions[i].length = length;
}

void* ct_ext_data_get(uint8_t index, struct ct_session *ct) {
    struct ct_ext ext;

    ext = ct_extensions[index];
    return (void *)(ct->extension + ext.offset);
}

static uint32_t ct_ext_get_total_length(void) {
    int i;
    uint32_t length = 0;

    for (i = 0; i < MAX_CT_ACTION; i++) {
        if (ct_extensions[i].length != 0) {
            length += ct_extensions[i].length;
        }
    }
    return length;
}

static void ct_fill_tuple(sk_buff_t *skb, struct ct_session *ct) {
    struct rte_ipv4_hdr *iph;
    struct ct_l4_proto *handler;

    iph = rte_pktmbuf_mtod((struct rte_mbuf*)skb, struct rte_ipv4_hdr*);
    handler = &ct_l4_handlers[iph->next_proto_id];
    ct->tuple_hash[CT_DRI_ORIGINAL].tuple = handler->gen_tuple(skb, false);
    ct->tuple_hash[CT_DRI_ORIGINAL].tuple.dir = CT_DRI_ORIGINAL;
    ct->tuple_hash[CT_DRI_REPLY].tuple = handler->gen_tuple(skb, true);
    ct->tuple_hash[CT_DRI_REPLY].tuple.dir = CT_DRI_REPLY;
}

static uint32_t ct_get_tuple_hash(struct ct_tuple tuple) {
    uint32_t hash1 = rte_hash_crc_4byte(tuple.src_addr, tuple.dst_addr);
    uint32_t hash2 = rte_hash_crc_4byte(tuple.proto, tuple.ports.src_port | tuple.ports.dst_port);
    return rte_hash_crc_4byte(hash1, hash2) % MAX_CT_BUCKETS;
}

static char* ct_tuple_to_str(struct ct_tuple *tuple, char *buff) {
    if (tuple->proto == IPPROTO_TCP || tuple->proto == IPPROTO_UDP) {
        sprintf(buff, "proto:%s,src_ip:%s", protocol_to_str(tuple->proto), be_ip_to_str(tuple->src_addr));
        sprintf(buff, "%s,dst_ip:%s,src_port:%d,dst_port:%d", buff, be_ip_to_str(tuple->dst_addr), rte_be_to_cpu_16(tuple->ports.src_port), rte_be_to_cpu_16(tuple->ports.dst_port));
    } else if (tuple->proto == IPPROTO_ICMP) {
        sprintf(buff, "proto:%s,src_ip:%s", protocol_to_str(tuple->proto), be_ip_to_str(tuple->src_addr));
        sprintf(buff, "%s,dst_ip:%s,type:%d,code:%d", buff, be_ip_to_str(tuple->dst_addr), tuple->icmp.type, tuple->icmp.code);
    }
    return buff;
}

char* ct_to_str(struct ct_session* ct, char *buff) {
    LOG_BUFF(orig_buf);
    LOG_BUFF(reply_buf);
    sprintf(buff, "original<%s>,reply<%s>",
            ct_tuple_to_str(&ct->tuple_hash[CT_DRI_ORIGINAL].tuple, orig_buf),
            ct_tuple_to_str(&ct->tuple_hash[CT_DRI_REPLY].tuple, reply_buf));
    return buff;
}

static struct ct_session* ct_alloc(void) {
    struct ct_session *ct;

    ct = rte_zmalloc("ct", sizeof(struct ct_session) + ct_ext_get_total_length(), RTE_CACHE_LINE_SIZE);
    if (NULL == ct) {
        RTE_LOG(ERR, CT, "No memory, %s\n", __func__ );
        return NULL;
    }
    return ct;
}

static void ct_free(struct ct_session *ct) {
    rte_free(ct);
}

static struct ct_session* ct_new(sk_buff_t *skb) {
    struct ct_session *ct;

    ct = ct_alloc();
    if (NULL == ct) {
        return NULL;
    }

    ct_fill_tuple(skb, ct);
    ct->state = CT_NEW;
    rte_timer_init(&ct->timer);

    return ct;
}

static void ct_ref(struct ct_session *ct) {
    assert(NULL != ct);
    ct->ref += 1;
}

static void ct_deref(struct ct_session *ct) {
    assert(NULL != ct);
    ct->ref -= 1;
    if (0 == ct->ref) {
        ct_free(ct);
    }
}

static void ct_insert_original(struct ct_session *ct) {
    uint32_t hash = ct_get_tuple_hash(ct->tuple_hash[CT_DRI_ORIGINAL].tuple);
    list_add(&ct->tuple_hash[CT_DRI_ORIGINAL].tuple_node, &local_ct_tbl[hash]);
}

static void ct_insert_reply(struct ct_session *ct) {
    uint32_t hash = ct_get_tuple_hash(ct->tuple_hash[CT_DRI_REPLY].tuple);
    list_add(&ct->tuple_hash[CT_DRI_REPLY].tuple_node, &local_ct_tbl[hash]);
}

static void ct_delete(struct ct_session *ct) {
    list_del(&ct->tuple_hash[CT_DRI_ORIGINAL].tuple_node);
    list_del(&ct->tuple_hash[CT_DRI_REPLY].tuple_node);
    ct_deref(ct);
}

static void ct_timeout(struct rte_timer *timer, void *arg) {
    struct ct_session *ct;

    ct = container_of(timer, struct ct_session, timer);
    rte_timer_stop(timer);
    ct_delete(ct);
    ct_deref(ct);
}

static void ct_mod_timer(struct ct_session *ct) {
    int ret;

    ret = rte_timer_reset(&ct->timer, ct->real_timeout, SINGLE, rte_lcore_id(), ct_timeout, NULL);
    if (NAT_LB_OK != ret) {
        RTE_LOG(ERR, CT, "Reset ct timer failed, %s", rte_strerror(rte_errno));
    }
}

static struct ct_session* ct_find(sk_buff_t *skb, struct per_lcore_ct_ctx *ctx) {
    struct rte_ipv4_hdr *iph = rte_pktmbuf_mtod((struct rte_mbuf*)skb, struct rte_ipv4_hdr*);
    struct ct_tuple tuple = ct_l4_handlers[iph->next_proto_id].gen_tuple(skb, false);

    struct ct_tuple_hash *tuple_hash;
    list_for_each_entry(tuple_hash, &local_ct_tbl[ct_get_tuple_hash(tuple)], tuple_node) {
        if (tuple_hash->tuple.src_addr == tuple.src_addr &&
        tuple_hash->tuple.dst_addr == tuple.dst_addr) {
            if (tuple.proto == iph->next_proto_id &&
            ct_l4_handlers[iph->next_proto_id].is_tuple_equal(tuple_hash, &tuple)) {
                    ctx->tuple_hash = tuple_hash;
                    return TUPLE_TO_CT(tuple_hash);
            }
       }
    }

    // not found
    return NULL;
}

static pipeline_actions ct_in(sk_buff_t *skb) {
    struct per_lcore_ct_ctx *ctx;
    struct ct_l4_proto *l4_handler;

    struct ct_session *ct = ct_find(skb, &per_lcore_ctx);
    if (unlikely(NULL == ct)) {
        ct = ct_new(skb);
        if (NULL == ct) {
            RTE_LOG(ERR, CT, "%s: No memory.\n", __func__ );
            return PIPELINE_ACTION_DROP;
        } else {
            ct_ref(ct);
            per_lcore_ctx.ct = ct;
            per_lcore_ctx.tuple_hash = &ct->tuple_hash[CT_DRI_ORIGINAL];

            // insert original ct
            ct_ref(ct);
            ct_insert_original(ct);

            return PIPELINE_ACTION_NEXT;
        }
    }

    // ct found
    ct_ref(ct);
    per_lcore_ctx.ct = ct;
    ct_l4_handlers[per_lcore_ctx.l4_proto].pkt_in(skb, &per_lcore_ctx);

    return PIPELINE_ACTION_NEXT;
}

static pipeline_actions ct_confirm(sk_buff_t *skb) {
    if (per_lcore_ctx.ct->state == CT_NEW) {
        ct_l4_handlers[per_lcore_ctx.l4_proto].pkt_new(skb, &per_lcore_ctx);

        // insert reply
        ct_insert_reply(per_lcore_ctx.ct);

        LOG_BUFF(buff);
        RTE_LOG(INFO, CT, "Confirm CT(%s).\n", ct_to_str(per_lcore_ctx.ct, buff));
    }
    per_lcore_ctx.ct->real_timeout = get_jiffies() + per_lcore_ctx.ct->timeout;
    ct_mod_timer(per_lcore_ctx.ct);

    return PIPELINE_ACTION_NEXT;
}

static int ct_table_init_lcore(void *arg) {
    for (int i = 0; i < MAX_CT_BUCKETS; i++) {
        INIT_LIST_HEAD(&local_ct_tbl[i]);
    }
    return NAT_LB_OK;
}

void ct_module_init(void) {
    uint16_t lcore_id;

    rte_eal_mp_remote_launch(ct_table_init_lcore, NULL, SKIP_MAIN);
    RTE_LCORE_FOREACH_WORKER(lcore_id) {
        if (rte_eal_wait_lcore(lcore_id) < 0) {
            RTE_LOG(ERR, CT, "Init lcore %d ct table failed, %s.\n", lcore_id, rte_strerror(rte_errno));
        }
    }

    ct_l4_handlers[IPPROTO_TCP] = tcp_l4_proto;
    ct_l4_handlers[IPPROTO_UDP] = udp_l4_proto;
    ct_l4_handlers[IPPROTO_ICMP] = icmp_l4_proto;

    pipeline_register("ct_in", ct_in, PIPELINE_PRIORITY_CT, NULL);
    pipeline_register("ct_confirm", ct_confirm, PIPELINE_PRIORITY_CONFIRM, NULL);
}
