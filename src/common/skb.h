//
// Created by tedqu on 24-9-25.
//

#ifndef NAT_LB_SKB_H
#define NAT_LB_SKB_H

#include <rte_mbuf.h>
#include "../route/route.h"
#include "../ct/ct.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct sk_buff {
    struct rte_mbuf mbuf;
}sk_buff_t;

#define PKT_HEADROOM \
    (int)(RTE_PKTMBUF_HEADROOM - (sizeof(struct sk_buff) - sizeof(struct rte_mbuf)))

#define MAX_PKT_SIZE 2000

#define MBUF_SIZE	\
	(MAX_PKT_SIZE + PKT_HEADROOM + sizeof(sk_buff_t))

#endif //NAT_LB_SKB_H
