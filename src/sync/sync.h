//
// Created by tedqu on 25-3-7.
//

#ifndef NAT_LB_SYNC_H
#define NAT_LB_SYNC_H

#include <inttypes.h>
#include "../common/skb.h"
#include "../ct/ct.h"

struct sync_ct_ctx {
    uint32_t src_ip;
    uint16_t src_port;
    uint32_t dst_ip;
    uint16_t dst_port;
    struct rte_mempool *sync_skb_pool;
    struct sk_buff *sync_skb;
    uint8_t version;
    uint32_t seq;
    uint32_t pending_ct_n; // 待发送的ct数量
    uint64_t last_sync_time; // 上一次同步ct的时间
};

struct sync_ct {
    struct ct_tuple tuples[CT_DRI_COUNT];
    uint32_t timeout;
    uint32_t ext_lengths[CT_EXT_MAX];
    uint8_t state;
    uint8_t flags;
    uint16_t worker;
};

void sync_module_init(void);
int sync_one_ct(struct ct_session *ct);
void flush_sync_skb(void* arg);
int sync_rcv(struct sk_buff *skb);

#endif //NAT_LB_SYNC_H
