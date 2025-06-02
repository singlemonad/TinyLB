//
// Created by tedqu on 25-3-7.
//

#include <rte_mbuf.h>
#include <toml.h>
#include "../common/skb.h"
#include "../common/log.h"
#include "../common/util.h"
#include "../common/conf.h"
#include "../inet/udp.h"
#include "sync.h"

#define MAX_CT_NUM_PER_PKT 1
#define MAX_DATA_LEN_PER_PKT 1400u
#define MAX_SYNC_DELAY 9000000000ULL

extern struct rte_mempool *socket_pkt_mbuf_pool[2];
extern struct ct_ext* ct_extensions[CT_EXT_MAX];

static struct sync_ct_ctx sync_ctx;
static struct conf_item sync_conf_parser;

struct sync_pkt_hdr {
    uint8_t version;
    uint8_t num;
    uint16_t padding;
    uint32_t seq;
};

static void sync_fill_upd_out_args(struct udp_out_args *args) {
    args->src_ip = sync_ctx.src_ip;
    args->src_port = sync_ctx.src_port;
    args->dst_port = sync_ctx.dst_port;
    args->dst_ip = sync_ctx.dst_ip;
}

static void send_sync_skb(struct sk_buff* skb) {
    struct udp_out_args udp_args;

    sync_fill_upd_out_args(&udp_args);

    int ret = udp_out(skb, &udp_args);
    if (ret != NAT_LB_OK) {
        RTE_LOG(ERR, NAT_LB, "%s: send sync pkt failed\n", __func__);
    }
}

static bool is_sync_skb_full(uint32_t len) {
    assert(sync_ctx.sync_skb != NULL);

    struct sync_pkt_hdr* hdr = (struct sync_pkt_hdr*)sync_ctx.sync_skb->data_hdr;
    if (hdr->num >= MAX_CT_NUM_PER_PKT || sync_ctx.sync_skb->mbuf.data_len + len > MAX_DATA_LEN_PER_PKT) {
        return true;
    }
    return false;
}

static struct sk_buff* sync_get_skb(uint32_t len) {
    assert(len <= MAX_DATA_LEN_PER_PKT);

    struct sync_pkt_hdr *hdr;
    struct sk_buff* skb = sync_ctx.sync_skb;
    if (NULL == skb) { // 当前skb已满，新建一个skb
        skb = (struct sk_buff*) rte_pktmbuf_alloc(sync_ctx.sync_skb_pool);
        if (NULL == skb) {
            RTE_LOG(ERR, NAT_LB, "%s: alloc sync pkt mbuf failed, %s\n", __func__, rte_strerror(rte_errno));
            return NULL;
        } else {
            hdr = (struct sync_pkt_hdr*) rte_pktmbuf_append(&skb->mbuf, sizeof(struct sync_pkt_hdr));
            hdr->num = 0;
            hdr->version = sync_ctx.version;
            hdr->seq = sync_ctx.seq;
            skb->data_hdr = hdr;
            sync_ctx.sync_skb = skb;
            sync_ctx.pending_ct_n = 0;
            skb->flags |= SKB_SESSION_SYNC;
        }
    } else {
        hdr = (struct sync_pkt_hdr*)skb->data_hdr;
    }

    hdr->num += 1;
    sync_ctx.sync_skb = skb;
    return skb;
}

static uint32_t sync_get_total_len(struct ct_session *ct) {
    int idx;
    uint32_t tot_len = 0;

    tot_len += sizeof(struct sync_ct);
    for (idx = 0; idx < CT_EXT_MAX; idx++) {
        if (ct_extensions[idx]->length != 0) {
            if (ct_extensions[idx]->need_sync && (ct->ext_flags & (1 << idx))) {
                tot_len += ct_extensions[idx]->length;
            }
        }
    }
    return tot_len;
}

static void sync_fill_ct_meta(struct sync_ct *sync_ct, struct ct_session *ct) {
    sync_ct->tuples[CT_DRI_ORIGINAL] =  ct->tuple_hash[CT_DRI_ORIGINAL].tuple;
    sync_ct->tuples[CT_DRI_REPLY] = ct->tuple_hash[CT_DRI_REPLY].tuple;
    sync_ct->flags = ct->flags;
    sync_ct->state = ct->state;
    sync_ct->timeout = ct->timeout;
}

static void sync_fill_ct_ext(struct sk_buff *skb, struct sync_ct *sync_ct, struct ct_session *ct) {
    int idx;

    for (idx = 0; idx < CT_EXT_MAX; idx++) {
        if (ct_extensions[idx]->need_sync && (ct->ext_flags & (1 << idx))) {
            sync_ct->ext_lengths[idx] = ct_extensions[idx]->length;
            ct_extensions[idx]->sync_ext_push_func(skb, ct);
        } else {
            sync_ct->ext_lengths[idx] = 0;
        }
    }
}

void flush_sync_skb(void* arg) {
    if (sync_ctx.sync_skb != NULL && rte_rdtsc() - sync_ctx.last_sync_time > MAX_SYNC_DELAY) {
        send_sync_skb(sync_ctx.sync_skb); // 发送会话同步报文
        sync_ctx.sync_skb = NULL;
        sync_ctx.last_sync_time = rte_rdtsc(); // 更新最后发送会话同步报文时间戳
    }
}

int sync_one_ct(struct ct_session *ct) {
    struct sk_buff *skb;
    uint32_t tot_len;
    struct sync_ct *sync_ct;

    LOG_BUFF(buff);
    RTE_LOG(DEBUG, NAT_LB, "%s: rcv need sync out ct(%s)\n", __func__, ct_to_str(ct, buff));

    tot_len = sync_get_total_len(ct);
    if (sync_ctx.sync_skb != NULL && is_sync_skb_full(tot_len)) {
        RTE_LOG(DEBUG, NAT_LB, "%s: send out sync skb\n", __func__);
        send_sync_skb(sync_ctx.sync_skb); // 发送会话同步报文
        sync_ctx.sync_skb = NULL;
        sync_ctx.last_sync_time = rte_rdtsc(); // 更新最后发送会话同步报文时间戳
    }

    skb = sync_get_skb(tot_len);

    sync_ct = (struct sync_ct*) rte_pktmbuf_append(&skb->mbuf, sizeof(struct sync_ct));
    sync_ct->worker = ct->worker;
    sync_fill_ct_meta(sync_ct, ct);
    sync_fill_ct_ext(skb, sync_ct, ct);
    ++sync_ctx.pending_ct_n;
    return NAT_LB_OK;
}

static void sync_rcv_one_ct(struct sk_buff *skb) {
    int idx;
    struct sync_ct *sync_ct;
    struct ct_session *ct;

    if (NULL == (ct = ct_alloc())) {
        RTE_LOG(ERR, NAT_LB, "%s: alloc ct failed\n", __func__);
        goto drop;
    }

    sync_ct = rte_pktmbuf_mtod(&skb->mbuf, struct sync_ct*);
    memcpy(&ct->tuple_hash[CT_DRI_ORIGINAL].tuple, &sync_ct->tuples[CT_DRI_ORIGINAL], sizeof(struct ct_tuple));
    memcpy(&ct->tuple_hash[CT_DRI_REPLY].tuple, &sync_ct->tuples[CT_DRI_REPLY], sizeof(struct ct_tuple));
    ct->state = sync_ct->state;
    ct->flags = sync_ct->flags;
    ct->timeout = sync_ct->timeout;
    ct->worker = sync_ct->worker;
    rte_pktmbuf_adj(&skb->mbuf, sizeof(struct sync_ct));

    for (idx = 0; idx < CT_EXT_MAX; idx++) {
        if (ct_extensions[idx]->need_sync && (sync_ct->ext_lengths[idx] != 0)) {
            ct_extensions[idx]->sync_ext_pop_func(skb, sync_ct->ext_lengths[idx], ct);
        }
    }

    LOG_BUFF(buff);
    RTE_LOG(DEBUG, NAT_LB, "%s: rcv sync ct(%s)\n", __func__, ct_to_str(ct, buff));

    struct session_sync_lcore_conf* conf = lcore_array[rte_lcore_id()]->lcore_cfg;
    int ret = rte_ring_enqueue(conf->ct_in_rings[ct->worker], ct);
    if (ret != 0) {
        memset(buff, 0, sizeof(buff));
        RTE_LOG(ERR, NAT_LB, "%s: enqueue ct(%s) to lcore %d failed\n", ct_to_str(ct, buff), ct->worker);
    }

drop:
    rte_pktmbuf_free((struct rte_mbuf*)skb);
}

int sync_rcv(struct sk_buff *skb) {
    int idx;
    struct sync_pkt_hdr *hdr;

    hdr = rte_pktmbuf_mtod(&skb->mbuf, struct sync_pkt_hdr*);
    rte_pktmbuf_adj(&skb->mbuf, sizeof(struct sync_pkt_hdr));
    for (idx = 0; idx < hdr->num; idx++) {
        sync_rcv_one_ct(skb);
    }

    return NAT_LB_OK;
}

static struct udp_pkt_handler sync_pkt_handler;

static const char* sync_item_name[4] = {
        "src_ip",
        "src_port",
        "dst_ip",
        "dst_port",
};

static void sync_parse_func(struct conf_item *item, toml_table_t *table) {
    toml_datum_t src_ip = toml_string_in(table, sync_item_name[0]);
    toml_datum_t src_port = toml_int_in(table, sync_item_name[1]);
    toml_datum_t dst_ip = toml_string_in(table, sync_item_name[2]);
    toml_datum_t dst_port = toml_int_in(table, sync_item_name[3]);
    RTE_LOG(INFO, NAT_LB, "%s: add backup, src_ip=%s,src_port=%d,dst_ip=%s,dst_port=%d\n", __func__, src_ip.u.s, src_port.u.i, dst_ip.u.s, dst_port.u.i);

    uint32_t src_ip_be = ip_to_int_be(src_ip.u.s);
    uint16_t src_port_be = htons(src_port.u.i);
    uint32_t dst_ip_be = ip_to_int_be(dst_ip.u.s);
    uint16_t dst_port_be = htons(dst_port.u.i);

    sync_ctx.src_ip = src_ip_be;
    sync_ctx.src_port = src_port_be;
    sync_ctx.dst_ip = dst_ip_be;
    sync_ctx.dst_port = dst_port_be;
    add_ip_group(IP_TYPE_SESSION_SYNC, sync_ctx.dst_ip); // 用于分流会话同步报文

    // 注册会话同步包udp处理函数
    sync_pkt_handler.port = rte_cpu_to_be_16(sync_ctx.dst_port);
    sync_pkt_handler.rcv = sync_rcv;
    udp_pkt_handler_register(&sync_pkt_handler);
}

static void init_session_sync_parser(void) {
    char conf_name[] = "session_sync";
    bzero(&sync_conf_parser, sizeof(sync_conf_parser));

    memcpy(sync_conf_parser.name, conf_name, strlen(conf_name));
    sync_conf_parser.parse_func = sync_parse_func;
    add_conf_item_parser(&sync_conf_parser);
}

void sync_module_init(void) {

    init_session_sync_parser();
    sync_ctx.sync_skb_pool = socket_pkt_mbuf_pool[0];
}
