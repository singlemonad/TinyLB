//
// Created by tedqu on 24-9-10.
//

#ifndef NAT_LB_NEIGH_H
#define NAT_LB_NEIGH_H

#include "list.h"
#include "dev.h"
#include "skb.h"

struct neigh_mbuf {
    sk_buff_t *skb;
    struct list_head neigh_mbuf_node;
};

struct neighbor {
    uint32_t next_hop;
    struct rte_ether_addr mac;
    struct list_head neighbor_list_node;
    struct list_head wait_pkt;
};

void neigh_init(void);
int neighbor_add(uint32_t next_hop, struct rte_ether_addr *mac);
int neighbor_del(uint32_t next_hop);
int neigh_output(uint32_t next_hop, sk_buff_t *skb, struct dev_port *port);
struct neighbor* neighbor_lookup(uint32_t next_hop);

#endif //NAT_LB_NEIGH_H
