//
// Created by tedqu on 24-9-15.
//

#include <pthread.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <rte_ip.h>
#include <rte_jhash.h>
#include "../common/util.h"
#include "../common/pipeline.h"
#include "../common/log.h"
#include "../common/const.h"
#include "../sync/sync.h"
#include "../lb/sa_pool.h"
#include "../inet/tcp.h"
#include "ct.h"

#define MAX_CT_BUCKETS 512

extern __thread struct per_lcore_ct_ctx per_lcore_ctx;


extern struct ct_l4_proto tcp_l4_proto;
extern struct ct_l4_proto udp_l4_proto;
extern struct ct_l4_proto icmp_l4_proto;

struct ct_ext* ct_extensions[MAX_CT_ACTION];
static struct ct_l4_proto ct_l4_handlers[IPPROTO_MAX];

static RTE_DEFINE_PER_LCORE(struct list_head, ct_table[MAX_CT_BUCKETS]);
#define local_ct_tbl (RTE_PER_LCORE(ct_table))

void ct_ext_register(struct ct_ext* ext) {
    uint32_t offset = 0;
    enum ct_ext_type i = 0;

    for ( ; i < ext->type; i++) {
        offset += ct_extensions[i]->length;
    }
    ext->offset = offset;
    ct_extensions[i] = ext;
}

inline void* ct_ext_data_get(uint8_t index, struct ct_session *ct) {
    return (void *)(ct->extension + ct_extensions[index]->offset);
}

static uint32_t ct_ext_get_total_length(void) {
    uint32_t length = 0;

    for (int i = 0; i < CT_EXT_MAX; i++) {
        if (ct_extensions[i]->length != 0) {
            length += ct_extensions[i]->length;
        }
    }
    return length;
}

static inline void ct_fill_tuple(sk_buff_t *skb, struct ct_session *ct) {
    struct rte_ipv4_hdr *iph = (struct rte_ipv4_hdr*)skb->iph;
    struct ct_l4_proto *handler = &ct_l4_handlers[iph->next_proto_id];

    ct->tuple_hash[CT_DRI_ORIGINAL].tuple = handler->gen_tuple(skb, false);
    ct->tuple_hash[CT_DRI_ORIGINAL].tuple.dir = CT_DRI_ORIGINAL;
    ct->tuple_hash[CT_DRI_REPLY].tuple = handler->gen_tuple(skb, true);
    ct->tuple_hash[CT_DRI_REPLY].tuple.dir = CT_DRI_REPLY;
}

static inline uint32_t ct_get_tuple_hash(struct ct_tuple tuple) {
    if (unlikely(tuple.proto == IPPROTO_ICMP)) {
        return rte_jhash_3words(tuple.src_addr, tuple.dst_addr, tuple.proto, tuple.icmp.code | tuple.icmp.type) % MAX_CT_BUCKETS;
    } else {
        return rte_jhash_3words(tuple.src_addr, tuple.dst_addr, tuple.proto, tuple.ports.src_port | tuple.ports.dst_port) % MAX_CT_BUCKETS;
    }
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

static char* ct_ext_to_str(struct ct_session* ct, char *buff) {
    uint32_t offset = 0;
    uint32_t ext_len = 0;

    for (int idx = 0; idx < CT_EXT_MAX; idx++) {
        if(ct->ext_flags & (1 << idx) && ct_extensions[idx]->dump_func) {
            ext_len = ct_extensions[idx]->dump_func(buff+offset, ct);
            offset += ext_len;
        }
    }
    return buff;
}

char* ct_to_str(struct ct_session* ct, char *buff) {
    LOG_BUFF(orig_buf);
    LOG_BUFF(reply_buf);
    LOG_BUFF(ext_buff);

    sprintf(buff, "original<%s>,reply<%s>,ext{%s}",
            ct_tuple_to_str(&ct->tuple_hash[CT_DRI_ORIGINAL].tuple, orig_buf),
            ct_tuple_to_str(&ct->tuple_hash[CT_DRI_REPLY].tuple, reply_buf),
            ct_ext_to_str(ct, ext_buff));
    return buff;
}

static void dump_ct(void) {
    struct ct_session *ct;

    for (int idx = 0; idx < MAX_CT_BUCKETS; idx++) {
        struct ct_tuple_hash *tuple_hash;
        list_for_each_entry(tuple_hash, &local_ct_tbl[idx], tuple_node) {
            LOG_BUFF(buff);

            ct = TUPLE_TO_CT(tuple_hash);
            RTE_LOG(DEBUG, NAT_LB, "ct %d info, %s\n", idx, ct_to_str(ct, buff));
        }
    }
}

struct ct_session* ct_alloc(void) {
    struct ct_session *ct = rte_zmalloc("ct", sizeof(struct ct_session) + ct_ext_get_total_length(), RTE_CACHE_LINE_SIZE);
    return ct;
}

static void ct_free(struct ct_session *ct) {
    assert(NULL != ct);

    LOG_BUFF(buff);
    RTE_LOG(DEBUG, NAT_LB, "%s: free ct(%s)", __func__, ct_to_str(ct, buff));

    rte_free(ct);
}

static struct ct_session* ct_new(sk_buff_t *skb) {
    struct ct_session *ct = ct_alloc();
    if (NULL == ct) {
        return NULL;
    }

    ct_fill_tuple(skb, ct);
    ct->state = CT_NEW;
    ct->real_timeout = 0;
    rte_timer_init(&ct->timer);
    return ct;
}

static inline void ct_ref(struct ct_session *ct) {
    assert(NULL != ct);
    ++ct->ref;
}

// 返回true说明ct已被释放
bool ct_deref(struct ct_session *ct) {
    assert(NULL != ct);
    --ct->ref;
    if (0 == ct->ref) {
        ct_free(ct);
        return true;
    }
    return false;
}

static inline void ct_insert_original(struct ct_session *ct) {
    ct_ref(ct); // ct插入正向连接哈希表
    uint32_t hash = ct_get_tuple_hash(ct->tuple_hash[CT_DRI_ORIGINAL].tuple);
    list_add(&ct->tuple_hash[CT_DRI_ORIGINAL].tuple_node, &local_ct_tbl[hash]);
}

static inline void ct_insert_reply(struct ct_session *ct) {
    ct_ref(ct); // ct插入反向连接哈希表
    uint32_t hash = ct_get_tuple_hash(ct->tuple_hash[CT_DRI_REPLY].tuple);
    list_add(&ct->tuple_hash[CT_DRI_REPLY].tuple_node, &local_ct_tbl[hash]);
}

static inline void ct_delete(struct ct_session *ct) {
    assert(ct != NULL);

    // 从正向连接哈希表中删除
    list_del(&ct->tuple_hash[CT_DRI_ORIGINAL].tuple_node);
    bool released = ct_deref(ct);
    if (!released) {
        // 从反向连哈希表中删除
        list_del(&ct->tuple_hash[CT_DRI_REPLY].tuple_node);
        ct_deref(ct);
    }
}

static void ct_timeout(struct rte_timer *timer, void *arg) {
    struct ct_session *ct = container_of(timer, struct ct_session, timer);

    LOG_BUFF(buff);
    RTE_LOG(DEBUG, NAT_LB, "%s: ct(%s) timeout, delete it\n", __func__, ct_to_str(ct, buff));

    rte_timer_stop(timer);
    ct_delete(ct);
}

static inline void ct_mod_timer(struct ct_session *ct) {
    uint64_t next_timeout = rte_rdtsc() + (rte_get_timer_hz() * ct->timeout);
    if ((next_timeout - ct->real_timeout) > 20000000ULL) {
        ct->real_timeout = next_timeout;

        int ret = rte_timer_reset(&ct->timer, ct->real_timeout, SINGLE, rte_lcore_id(), ct_timeout, NULL);
        if (NAT_LB_OK != ret) {
            RTE_LOG(ERR, NAT_LB, "%s: reset ct timer failed, %s", __func__, rte_strerror(rte_errno));
        }
        // 定时器发生变化时需要进行会话同步
        ct->flags |= CT_FLAG_NEED_SYNC;
    }
}

static struct ct_session* ct_find(sk_buff_t *skb, struct per_lcore_ct_ctx *ctx) {
    struct rte_ipv4_hdr *iph = (struct rte_ipv4_hdr*)skb->iph;
    struct ct_tuple tuple = ct_l4_handlers[iph->next_proto_id].gen_tuple(skb, false);

    struct ct_tuple_hash *tuple_hash;
    uint32_t hash_val = ct_get_tuple_hash(tuple);
    list_for_each_entry(tuple_hash, &local_ct_tbl[hash_val], tuple_node) {
        if (tuple_hash->tuple.src_addr == tuple.src_addr &&
        tuple_hash->tuple.dst_addr == tuple.dst_addr) {
            if (tuple_hash->tuple.proto == tuple.proto &&
            ct_l4_handlers[iph->next_proto_id].is_tuple_equal(tuple_hash, &tuple)) {
                    ctx->tuple_hash = tuple_hash;
                    return TUPLE_TO_CT(tuple_hash);
            }
        }
    }
    return NULL;
}

bool ct_tuple_in_use(uint8_t proto, uint32_t src_ip, uint16_t src_port, uint32_t dst_port, uint32_t dst_ip) {
    struct ct_tuple tuple;
    struct ct_tuple_hash *tuple_hash;

    tuple.proto = proto;
    tuple.src_addr = src_ip;
    tuple.dst_addr = dst_ip;
    tuple.ports.src_port = src_port;
    tuple.ports.dst_port = dst_port;

    uint32_t hash_val = ct_get_tuple_hash(tuple);
    list_for_each_entry(tuple_hash, &local_ct_tbl[hash_val], tuple_node) {
        if (tuple_hash->tuple.src_addr == tuple.src_addr &&
            tuple_hash->tuple.dst_addr == tuple.dst_addr) {
            if (tuple_hash->tuple.proto == tuple.proto &&
                ct_l4_handlers[proto].is_tuple_equal(tuple_hash, &tuple)) {
                return true;
            }
        }
    }
    return false;
}

static void push_sync_to_ring(struct ct_session *ct) {
    return;
    struct work_lcore_conf* conf = lcore_array[rte_lcore_id()]->lcore_cfg;
    int ret = rte_ring_enqueue(conf->sync_ct_out_ring, ct);
    if (ret != 0) {
        LOG_BUFF(buff);
        RTE_LOG(ERR, NAT_LB, "%s: enqueue sync ct failed, ct(%s)\n", __func__, ct_to_str(ct, buff));
    }
}

void process_sync_in_ct(struct ct_session* ct) {
    // TODO check ct status
    ct_insert_original(ct);
    ct_insert_reply(ct);
}

static inline bool is_valid_first_skb(sk_buff_t *skb) {
    // 1. 只有original方向的包才允许建立ct
    // 2. tcp只有syn首包才允许建立ct
    // 3. udp、icmp不做首包校验
    struct rte_ipv4_hdr *iph = (struct rte_ipv4_hdr*)skb->iph;
    if (skb->ip_type != IP_TYPE_SVC) {
        RTE_LOG(ERR, NAT_LB, "%s: only original direction pkt can create ct\n", __func__);
        return false;
    }
    if (iph->next_proto_id == IPPROTO_TCP) {
        struct tcp_hdr* tcp = rte_pktmbuf_mtod(&skb->mbuf, struct tcp_hdr*);
        if (!tcp->syn || tcp->ack || tcp->syn || tcp->rst) {
            RTE_LOG(ERR, NAT_LB, "%s: only tcp first pkt can create ct\n", __func__);
            return false;
        }
    }
    return true;
}

static inline bool need_reuse_ct(sk_buff_t* skb, struct ct_session* ct) {
    struct rte_ipv4_hdr *iph = (struct rte_ipv4_hdr*)skb->iph;
    if (iph->next_proto_id == IPPROTO_TCP && ct->state >= TCP_CT_TIME_WAIT) {
        ct_delete(ct);
        return true;
    }
    return false;
}

static inline pipeline_actions ct_in(sk_buff_t *skb) {
    struct ct_session* ct = ct_find(skb, &per_lcore_ctx);
    if (unlikely(NULL == ct)) {
reuse_ct:
        if (!is_valid_first_skb(skb)) {
            RTE_LOG(ERR, NAT_LB, "%s: not valid first pkt\n", __func__);
            return PIPELINE_ACTION_DROP;
        }

        ct = ct_new(skb);
        if (unlikely(NULL == ct)) {
            RTE_LOG(ERR, NAT_LB, "%s: no memory\n", __func__);
            return PIPELINE_ACTION_DROP;
        }

        // insert original ct
        ct_insert_original(ct);

        // LOG_BUFF(buff);
        // RTE_LOG(INFO, NAT_LB, "%s: insert ct(%s)\n", __func__, ct_to_str(ct, buff));

        per_lcore_ctx.tuple_hash = &ct->tuple_hash[CT_DRI_ORIGINAL];
    }

    if (need_reuse_ct(skb, ct)) {
        goto reuse_ct;
    }

    ct_ref(ct);
    per_lcore_ctx.ct = ct; // per_lcore_ctx引用ct
    enum ct_state old_state = ct->state;
    ct_l4_handlers[per_lcore_ctx.l4_proto].pkt_in(skb, &per_lcore_ctx);

    // modify timeout
    ct_mod_timer(per_lcore_ctx.ct);

    // 只同步状态大于等于CT_ESTABLISHED的包
    if (ct->state >= CT_ESTABLISHED && (old_state != ct->state || ct->flags & CT_FLAG_NEED_SYNC)) {
        push_sync_to_ring(ct);
        ct->flags &= ~CT_FLAG_NEED_SYNC;
    }

    return PIPELINE_ACTION_NEXT;
}

static inline pipeline_actions ct_confirm(sk_buff_t *skb) {
    if (unlikely(per_lcore_ctx.ct->state == CT_NEW)) {
        // insert reply
        ct_insert_reply(per_lcore_ctx.ct);

        // update state machine
        ct_l4_handlers[per_lcore_ctx.l4_proto].pkt_new(skb, &per_lcore_ctx);

        // modify timer
        ct_mod_timer(per_lcore_ctx.ct);

        // LOG_BUFF(buff);
        // RTE_LOG(INFO, NAT_LB, "%s: confirm ct(%s)\n", __func__, ct_to_str(per_lcore_ctx.ct, buff));

        // UDP、ICMP连接在正向会话建立后立即同步
        if (per_lcore_ctx.ct->state == CT_ESTABLISHED) {
            push_sync_to_ring(per_lcore_ctx.ct);
        }
    }
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
            RTE_LOG(ERR, NAT_LB, "%s: init lcore %d ct table failed, %s.\n", __func__, lcore_id, rte_strerror(rte_errno));
        }
    }

    ct_l4_handlers[IPPROTO_TCP] = tcp_l4_proto;
    ct_l4_handlers[IPPROTO_UDP] = udp_l4_proto;
    ct_l4_handlers[IPPROTO_ICMP] = icmp_l4_proto;

    pipeline_register("ct_in", ct_in, PIPELINE_PRIORITY_CT, NULL);
    pipeline_register("ct_confirm", ct_confirm, PIPELINE_PRIORITY_CONFIRM, NULL);
}
