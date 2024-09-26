//
// Created by tedqu on 24-9-7.
//

#include <inttypes.h>
#include <rte_mbuf.h>
#include "skb.h"

#ifndef NAT_LB_LCORE_H
#define NAT_LB_LCORE_H

#define MAX_QUEUES_PRE_PORT 16
#define MAX_PORT_PRE_LCORE 64
#define MAX_LCORE 64

#define MAX_PKT_BURST 32

enum lcore_type {
    LCORE_TYPE_MASTER,
    LCORE_TYPE_FWD_WORKER,
    LCORE_TYPE_MAX
};

struct lcore_queue_conf {
    uint16_t queue_id;
    uint16_t len;
    sk_buff_t *mbufs[MAX_PKT_BURST];
};

struct lcore_port_conf {
    uint16_t port_id;
    int rxq_n;
    int txq_n;
    struct lcore_queue_conf rxq[MAX_QUEUES_PRE_PORT];
    struct lcore_queue_conf txq[MAX_QUEUES_PRE_PORT];
};

struct lcore_conf {
    uint16_t lcore_id;
    enum lcore_type type;
    int ports_n;
    struct lcore_port_conf ports[MAX_PORT_PRE_LCORE];
};

void add_lcore_configure(struct lcore_conf lcore_conf);
struct lcore_port_conf* get_lcore_port_conf(uint16_t cid, uint16_t port_id);
struct lcore_queue_conf* get_lcore_tx_queue_conf(uint16_t cid, uint16_t port_id, uint16_t qid);
struct lcore_queue_conf* get_lcore_rx_queue_conf(uint16_t cid, uint16_t port_id, uint16_t qid);
enum lcore_type get_lcore_type(uint16_t cid);
void lcore_init(void);

#endif //NAT_LB_LCORE_H
