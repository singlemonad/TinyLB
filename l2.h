//
// Created by tedqu on 24-9-8.
//

#ifndef NAT_LB_L2_H
#define NAT_LB_L2_H

#include <rte_mbuf.h>
#include "list.h"
#include "dev.h"

struct pkt_type {
    uint16_t type;
    int (*func) (struct rte_mbuf *mbuf, struct dev_port *port);
    struct list_head pkt_type_node;
} __rte_cache_aligned;

void l2_init(void);
int pkt_type_register(struct pkt_type *pkt_type);
int l2_rcv(uint16_t lcore_id, struct rte_mbuf *mbuf);

#endif //NAT_LB_L2_H
