//
// Created by tedqu on 25-2-25.
//

#ifndef NAT_LB_THREAD_H
#define NAT_LB_THREAD_H

#include <inttypes.h>
#include <rte_ring.h>
#include <rte_mbuf.h>
#include "skb.h"

#define RX_THREAD_MAX_QUEUE 16
#define RX_BURST_MAX 32

enum thread_type {
    CTRL_THREAD = 0,
    RX_THREAD = 1,
    WORK_THREAD = 2,
    TX_THREAD = 3,
    SESSION_SYNC_THREAD = 4
};

enum thread_mode {
    RTC = 0,
    PIPELINE = 1,
};

struct thread_cfg {
    uint16_t thread_id;
};

struct ctrl_thread_cfg {
    struct thread_cfg cfg;
    char listen_ip[24];
    uint16_t listen_port;
};

struct thread_rx_queue_cfg {
    uint16_t port_id;
    uint16_t queue_id;
    struct sk_buff *mbufs[RX_BURST_MAX];
};

struct rx_thread_cfg {
    struct thread_cfg cfg;
    uint16_t n_queue;
    struct thread_rx_queue_cfg queues[RX_THREAD_MAX_QUEUE];
};

struct work_thread_cfg {
    struct thread_cfg cfg;
    struct rte_ring *in;
    struct rte_ring *out;
};

struct tx_thread_cfg {
    struct thread_cfg cfg;
    struct rte_ring *in;
};

struct ct_sync_cfg {
    struct thread_cfg cfg;
};

typedef void(*thread_work_func)(struct thread_cfg* cfg);

struct thread {
    enum thread_type type;
    struct thread_cfg *cfg;
    thread_work_func work_func;
};

struct per_lcore_ct_ctx{
    uint16_t l4_proto;
    struct ct_session *ct;
    struct ct_tuple_hash *tuple_hash;
};

struct thread* create_rx_thread(struct rx_thread_cfg* cfg);
void lcore_add_thread(uint16_t lcore_id, struct thread* thread);
void start_lcore(uint16_t lcore_id);

#endif //NAT_LB_THREAD_H
