//
// Created by tedqu on 24-9-15.
//

#include <netinet/tcp.h>
#include <pthread.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <rte_ip.h>
#include <rte_hash_crc.h>
#include "../include/common.h"
#include "../include/ct.h"
#include "../include/pipeline.h"
#include "../include/log.h"
#include "../include/jiffies.h"

#define MAX_CT_BUCKETS 512

static const uint8_t tcp_ct_state_transfer_map[CT_DRI_COUNT][TCP_BIT_MAX][TCP_CT_MAX] = {
/* original */
        {
                /* sNO、sSS、sSR、sES、sFW、sCW、sLA、sTM、sCL、sS2 */
/* SYN */       {sSS, sSS, sSR, sES, sFW, sCW, sLA, sSS, sSS, sS2},
/* SYNACK */    { sNO, sSS, sSR, sES, sFW, sCW, sLA, sTW, sCL, sSR},
/* FIN */      { sNO, sSS, sFW, sFW, sLA, sLA, sLA, sTW, sCL, sS2 },
/* ACK */       { sES, sS2, sES, sES, sCW, sCW, sTW, sTW, sCL, sS2 },
/* RST */        { sNO, sCL, sCL, sCL, sCL, sCL, sCL, sCL, sCL, sCL },
/* NONE*/    { sNO, sCL, sCL, sCL, sCL, sCL, sCL, sCL, sCL, sCL }
        },

/* reply */
        {
/* SYN */     { sNO, sS2, sSR, sES, sFW, sCW, sLA, sTW, sCL, sS2 },
/* SYNACK */   { sNO, sSR, sSR, sES, sFW, sCW, sLA, sTW, sCL, sSR },
/* FIN */      { sNO, sSS, sFW, sFW, sLA, sLA, sLA, sTW, sCL, sS2 },
/* ACK */      { sNO, sSS, sSR, sES, sCW, sCW, sTW, sTW, sCL, sS2 },
/* RST*/       { sNO, sCL, sCL, sCL, sCL, sCL, sCL, sCL, sCL, sCL },
/* none */    { sNO, sSS, sSR, sES, sFW, sCW, sLA, sTW, sCL, sS2 }
        }
};

static const char *tcp_state_name[] = {
        [sNO] = "NONE",
        [sSS] = "SYN_SENT",
        [sSR] = "SYN_RCV",
        [sES] = "ESTABLISHED",
        [sFW] = "FIN_WAIT",
        [sCW] = "CLOSE_WAIT",
        [sLA] = "LAST_ACK",
        [sTW] = "TIME_WAIT",
        [sCL] = "CLOSE",
        [sS2] = "SYN_SENT2",
};

#define HZ	1000
#define SECS * HZ
#define MINUTES * 60 SECS
#define HOURS * 60 MINUTES

static unsigned int tcp_timeouts[TCP_CT_MAX] = {
        [TCP_CT_NONE]		= 0 SECS,
        [TCP_CT_SYN_SEND]	= 60 SECS,
        [TCP_CT_SYN_RCV]	= 60 SECS,
        [TCP_CT_ESTABLISHED]	= 3 HOURS,
        [TCP_CT_FIN_WAIT]	= 2 MINUTES,
        [TCP_CT_CLOSE_WAIT]	= 60 SECS,
        [TCP_CT_LAST_ACK]	= 30 SECS,
        [TCP_CT_TIME_WAIT]	= 2 MINUTES,
        [TCP_CT_CLOSE]		= 10 SECS,
        [TCP_CT_SYN_SEND2]	= 60 SECS,
};

static unsigned int udp_timeouts[UDP_CT_MAX] = {
        [UDP_CT_NONE]		= 0 SECS,
        [UDP_CT_NORMAL]		= 3 MINUTES,
};

static struct list_head ct_table[MAX_CT_BUCKETS];

__thread per_cpu_ctx_t g_per_cpu_ctx = {
        .ct = NULL,
        .tuple_hash = NULL,
        .l4_proto = 0,
};

static struct ct_ext ct_extensions[MAX_CT_ACTION];

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

static unsigned int ct_get_tcp_index(struct tcphdr *tcp) {
    if (tcp->rst) {
        return TCP_RST_SET;
    }
    if (tcp->syn) {
        if (tcp->ack) {
            return TCP_SYNACK_SET;
        }
        return TCP_SYN_SET;
    }
    if (tcp->fin) {
        return TCP_FIN_SET;
    }
    if (tcp->ack) {
        return TCP_ACK_SET;
    }
    return TCP_NONE_SET;
}

static struct ct_tuple ct_skb_to_tuple(sk_buff_t *skb, bool reverse) {
    struct rte_ipv4_hdr *iph;
    struct rte_icmp_hdr *icmp;
    struct ct_tuple tuple;
    uint16_t *ports;

    iph = rte_pktmbuf_mtod((struct rte_mbuf*)skb, struct rte_ipv4_hdr*);
    tuple.proto = iph->next_proto_id;
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
            ports = (uint16_t *)&iph[1];
            tuple.ports.src_port = ports[1];
            tuple.ports.dst_port = ports[0];
        }
    }
    return tuple;
}

static void ct_fill_tuple(sk_buff_t *skb, struct ct_session *ct) {
    ct->tuple_hash[CT_DRI_ORIGINAL].tuple = ct_skb_to_tuple(skb, false);
    ct->tuple_hash[CT_DRI_ORIGINAL].tuple.dir = CT_DRI_ORIGINAL;
    ct->tuple_hash[CT_DRI_REPLY].tuple = ct_skb_to_tuple(skb, true);
    ct->tuple_hash[CT_DRI_REPLY].tuple.dir = CT_DRI_REPLY;
}

static uint32_t ct_get_tuple_hash(struct ct_tuple tuple) {
    uint32_t hash1 = rte_hash_crc_4byte(tuple.src_addr, tuple.dst_addr);
    uint32_t hash2 = rte_hash_crc_4byte(tuple.proto, tuple.ports.src_port | tuple.ports.dst_port);
    return rte_hash_crc_4byte(hash1, hash2) % MAX_CT_BUCKETS;
}

static struct ct_session* ct_alloc(void) {
    struct ct_session *ct;

    ct = rte_zmalloc("ct", sizeof(struct ct_session) + ct_ext_get_total_length(), RTE_CACHE_LINE_SIZE);
    if (NULL == ct) {
        RTE_LOG(ERR, LB, "No memory, %s\n", __func__ );
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

struct per_cpu_ctx *get_per_cpu_ctx(void) {
    return &g_per_cpu_ctx;
}

void put_per_cpu_ctx(void) {
    struct per_cpu_ctx *ctx;

    ctx = get_per_cpu_ctx();
    assert(NULL != ctx->ct);
    ct_deref(ctx->ct);
    ctx->ct = NULL;
    ctx->tuple_hash = NULL;
    ctx->l4_proto = 0;
}

static void ct_insert(struct ct_session *ct) {
    uint32_t orig_hash, reply_hash;

    ct_ref(ct);
    orig_hash = ct_get_tuple_hash(ct->tuple_hash[CT_DRI_ORIGINAL].tuple);
    list_add(&ct->tuple_hash[CT_DRI_ORIGINAL].tuple_node, &ct_table[orig_hash]);
    reply_hash = ct_get_tuple_hash(ct->tuple_hash[CT_DRI_REPLY].tuple);
    list_add(&ct->tuple_hash[CT_DRI_REPLY].tuple_node, &ct_table[reply_hash]);
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
}

static void ct_mod_timer(struct ct_session *ct) {
    int ret;

    ret = rte_timer_reset(&ct->timer, ct->real_timeout, SINGLE, rte_lcore_id(), ct_timeout, NULL);
    if (NAT_LB_OK != ret) {
        RTE_LOG(ERR, CT, "Reset ct timer failed, %s", rte_strerror(rte_errno));
    }
}

static struct ct_session* ct_find(sk_buff_t *skb, per_cpu_ctx_t *ctx) {
    struct ct_tuple tuple;
    uint32_t hash;
    struct ct_tuple_hash *tuple_hash;
    struct ct_session *ct;
    struct rte_ipv4_hdr *iph;

    tuple = ct_skb_to_tuple(skb, false);
    hash = ct_get_tuple_hash(tuple);
    list_for_each_entry(tuple_hash, &ct_table[hash], tuple_node) {
        if (tuple_hash->tuple.src_addr == tuple.src_addr &&
        tuple_hash->tuple.dst_addr == tuple.dst_addr) {
            iph = rte_pktmbuf_mtod((struct rte_mbuf*)skb, struct rte_ipv4_hdr*);
            if (tuple.proto != iph->next_proto_id) {
                continue;
            }
            if (IPPROTO_ICMP == iph->next_proto_id) {
                if (tuple_hash->tuple.icmp.type == tuple.icmp.type &&
                tuple_hash->tuple.icmp.code == tuple.icmp.code) {
                    ctx->tuple_hash = tuple_hash;
                    return TUPLE_TO_CT(tuple_hash);
                }
            } else {
                if (tuple_hash->tuple.ports.src_port == tuple.ports.src_port &&
                tuple_hash->tuple.ports.dst_port == tuple.ports.dst_port) {
                    ctx->tuple_hash = tuple_hash;
                    return TUPLE_TO_CT(tuple_hash);
                }
            }
        }
    }

    return NULL;
}

static pipeline_actions ct_in(sk_buff_t *skb) {
    struct per_cpu_ctx *ctx;
    struct ct_session* ct;
    struct rte_ipv4_hdr *iph;
    struct tcphdr *tcp;
    unsigned int direction, index, old_state, new_state;

    ctx = get_per_cpu_ctx();
    ct = ct_find(skb, ctx);
    if (NULL == ct) {
        ct = ct_new(skb);
        if (NULL == ct) {
            RTE_LOG(ERR, EAL, "No memory, %s\n", __func__ );
            return PIPELINE_ACTION_DROP;
        }
        ctx->tuple_hash = &ct->tuple_hash[CT_DRI_ORIGINAL];
        ct_ref(ct);
        ctx->ct = ct;
        return PIPELINE_ACTION_NEXT;
    }

    ct_ref(ct);
    ctx->ct = ct;

    iph = rte_pktmbuf_mtod((struct rte_mbuf*)skb, struct rte_ipv4_hdr*);
    if (ctx->l4_proto == IPPROTO_TCP) {
        direction = ctx->tuple_hash->tuple.dir;
        if (direction == CT_DRI_REPLY) {
            RTE_LOG(INFO, CT, "Reply ct hit\n");
        }
        tcp = (struct tcphdr*)&iph[1];
        index = ct_get_tcp_index(tcp);
        old_state = ct->state;
        new_state = tcp_ct_state_transfer_map[direction][index][old_state];
        if (old_state != new_state) {
            RTE_LOG(INFO, CT, "CT state transfer, %s->%s\n", tcp_state_name[old_state], tcp_state_name[new_state]);
        }
        ct->state = new_state;
        ct->timeout = tcp_timeouts[ct->state];
        ct->real_timeout = get_jiffies() + ct->timeout;
        ct_mod_timer(ct);
    }

    return PIPELINE_ACTION_NEXT;
}

static pipeline_actions ct_confirm(sk_buff_t *skb) {
    struct per_cpu_ctx *ctx;

    ctx = get_per_cpu_ctx();
    if (ctx->ct->state != CT_NEW) {
        return PIPELINE_ACTION_NEXT;
    }

    ct_insert(ctx->ct);
    if (ctx->l4_proto == IPPROTO_TCP) {
        ctx->ct->state = TCP_CT_SYN_SEND;
        ctx->ct->timeout = tcp_timeouts[ctx->ct->state];
    } else if (ctx->l4_proto == IPPROTO_UDP) {
        ctx->ct->state = UDP_CT_NORMAL;
        ctx->ct->timeout = udp_timeouts[ctx->ct->state];
    }
    ctx->ct->real_timeout = get_jiffies() + ctx->ct->timeout;
    ct_mod_timer(ctx->ct);
    RTE_LOG(INFO, CT, "Confirm ct\n");

    return PIPELINE_ACTION_NEXT;
}

void ct_module_init(void) {
    int i;

    for (i = 0; i < MAX_CT_BUCKETS; i++) {
        INIT_LIST_HEAD(&ct_table[i]);
    }

    pipeline_register("ct_in", ct_in, PIPELINE_PRIORITY_CT, NULL);
    pipeline_register("ct_confirm", ct_confirm, PIPELINE_PRIORITY_CONFIRM, NULL);
}
