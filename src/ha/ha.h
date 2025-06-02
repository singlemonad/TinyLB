//
// Created by tedqu on 25-3-11.
//

#ifndef NAT_LB_HA_H
#define NAT_LB_HA_H

#include <inttypes.h>
#include <rte_timer.h>
#include "../common/list.h"

enum rs_status {
    UNKNOWN = 0,
    HEALTHY,
    FAILED,
};

enum detect_stage {
    TO_DETECT = 0,
    DETECTING,
};

struct detect_rs {
    struct list_head node;
    uint8_t proto;
    uint32_t rs_ip;
    uint16_t rs_port;
    enum rs_status rs_status;
    enum detect_stage detect_stage;
    struct rte_timer timer;
};

struct ha_ctx {
    uint16_t lcore_id;
    struct rte_mempool *ha_mbuf_pool;
    uint32_t src_ip;
    uint16_t src_port;
    uint32_t seq;
    uint16_t rcv_size;
};

int add_detect_rs(uint8_t proto, uint32_t rs_ip, uint16_t rs_port);
int remove_detect_rs(uint8_t proto, uint32_t rs_ip, uint16_t rs_port);
void ha_module_init(uint32_t src_port);

#endif //NAT_LB_HA_H
