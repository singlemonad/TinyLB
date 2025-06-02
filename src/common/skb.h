//
// Created by tedqu on 24-9-25.
//

#ifndef NAT_LB_SKB_H
#define NAT_LB_SKB_H

#include <rte_mbuf.h>
#include "../common/ip_group.h"
#include "../route/route.h"
#include "../ct/ct.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SKB_SESSION_SYNC  1 << 0
#define SKB_KEEPALIVE 1 << 1

typedef struct sk_buff {
    struct rte_mbuf mbuf;
    void* eth;
    void* iph;
    void* data_hdr;
    uint32_t vpc_id;
    bool calc_l4_checksum;
    enum ip_type ip_type;
    uint16_t rcv_port;
    uint64_t rcv_timestamp;
    uint64_t last_timestamp;
    uint8_t flags;
}sk_buff_t;

#define PKT_HEADROOM \
    (int)(RTE_PKTMBUF_HEADROOM - (sizeof(struct sk_buff) - sizeof(struct rte_mbuf)))

#define MAX_PKT_SIZE 2000

#define MBUF_SIZE	\
	(MAX_PKT_SIZE + PKT_HEADROOM + sizeof(sk_buff_t))

#endif //NAT_LB_SKB_H
