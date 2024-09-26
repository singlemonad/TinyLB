//
// Created by tedqu on 24-9-8.
//

#ifndef NAT_LB_L2_H
#define NAT_LB_L2_H

#include <rte_mbuf.h>
#include "list.h"
#include "dev.h"
#include "skb.h"

struct pkt_type {
    uint16_t type;
    int (*func) (sk_buff_t *skb);
    struct list_head pkt_type_node;
} __rte_cache_aligned;

void l2_init(void);
int pkt_type_register(struct pkt_type *pkt_type);
int l2_rcv(sk_buff_t *skb);

#endif //NAT_LB_L2_H
