//
// Created by tedqu on 25-2-25.
//

#ifndef NAT_LB_LCORE_H
#define NAT_LB_LCORE_H

#include <inttypes.h>
#include <rte_ring.h>
#include <rte_mbuf.h>
#include "skb.h"

#define MAX_SLOW_FUNC_PER_LCORE 16

enum lcore_type {
    LCORE_TYPE_INVALID = 0,
    LCORE_TYPE_CTRL = 0,
    LCORE_TYPE_RX = 1,
    LCORE_TYPE_WORK = 2,
    LCORE_TYPE_SESSION_SYNC = 3,
    LCORE_TYPE_KEEPALIVE = 4,
};

extern enum lcore_type lcore_type_array[MAX_LCORE];
extern struct lcore* lcore_array[MAX_LCORE];

struct lcore_drop_stats {
    uint64_t invalid_pkt;
    uint64_t invalid_l3_proto;
    uint64_t invalid_l4_proto;
    uint64_t invalid_l4_port;
    uint64_t no_ip_group;
    uint64_t no_svc;
    uint64_t no_snat_addr;
    uint64_t enqueue_failed;
    uint64_t icmp;
    uint64_t no_route;
    uint64_t pipeline;
};

struct lcore_rxtx_stats {
    uint64_t rx;
    uint64_t tx;
    uint64_t rx_arp;
    uint64_t rx_ip;
    struct lcore_drop_stats drop;
};

struct rx_port_conf {
    uint16_t port_id;
    uint16_t rxq_n;
    struct sk_buff *mbufs[MAX_RX_BURST];
};

struct rx_lcore_conf {
    struct lcore_rxtx_stats rxtx_stats;
    uint8_t port_n;
    struct rx_port_conf ports[MAX_PORT_SIZE_PER_RX_LCORE];
    struct rte_ring* pkt_out_rings[MAX_LCORE];
};

struct work_lcore_conf {
    struct lcore_rxtx_stats rxtx_stats;
    struct rte_ring* pkt_in_ring; // 收包的队列，由rx_lcore分流后投递skb到该队列
    struct rte_eth_dev_tx_buffer* tx_buffers[MAX_PORT_SIZE]; // work lcore处理完后，将需要发送的包缓存到tx_buffers进行批量发送
    struct rte_ring* sync_ct_out_ring; // 用于对外发送需要同步的会话
    struct rte_ring* sync_ct_in_ring; // 用于接受同步的会话
};

struct session_sync_lcore_conf {
    struct lcore_rxtx_stats rxtx_stats;
    struct rte_ring* pkt_in_ring; // 接受会话同步报文
    struct rte_ring* pending_ring; // 等待发送出去的会话
    struct rte_ring* ct_in_rings[MAX_LCORE]; //  worker用于接受同步过来的会话
};

struct keepalive_lcore_conf {
    struct lcore_rxtx_stats rxtx_stats;
    struct rte_ring* pkt_in_ring; // 接收健康检查报文
};

typedef void(*lcore_main_func)(void* cfg);
typedef void(*lcore_slow_func)(void* cfg);

struct lcore{
    enum lcore_type type;
    void* lcore_cfg;
    lcore_main_func main_func;
    int slow_func_n;
    lcore_slow_func slow_funcs[MAX_SLOW_FUNC_PER_LCORE];
};

struct per_lcore_ct_ctx{
    uint16_t l4_proto;
    struct ct_session *ct;
    struct ct_tuple_hash *tuple_hash;
}__rte_cache_aligned;

static inline void* get_lcore_conf(uint16_t lcore_id) {
    return lcore_array[lcore_id]->lcore_cfg;
}

static inline struct lcore_rxtx_stats* get_lcore_stats(uint16_t lcore_id) {
    void* conf = lcore_array[lcore_id]->lcore_cfg;
    if (lcore_type_array[lcore_id] == LCORE_TYPE_RX) {
        return &((struct rx_lcore_conf*)(conf))->rxtx_stats;
    } else if (lcore_type_array[lcore_id] == LCORE_TYPE_WORK) {
        return &((struct work_lcore_conf*)(conf))->rxtx_stats;
    } else if (lcore_type_array[lcore_id] == LCORE_TYPE_SESSION_SYNC) {
        return &((struct session_sync_lcore_conf*)(conf))->rxtx_stats;
    } else if (lcore_type_array[lcore_id] == LCORE_TYPE_KEEPALIVE) {
        return &((struct keepalive_lcore_conf*)(conf))->rxtx_stats;
    } else {
        rte_exit(EXIT_FAILURE, "%s: unexpected\n");
    }
}

void conf_lcores(void);
void start_lcores(void);
void lcore_module_init(void);

#endif //NAT_LB_LCORE_H
