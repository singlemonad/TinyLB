//
// Created by tedqu on 24-9-10.
//

#ifndef NAT_LB_NEIGH_H
#define NAT_LB_NEIGH_H

#include "../common/list.h"
#include "../dev/dev.h"
#include "../common/skb.h"

#ifdef __cplusplus
extern "C" {
#endif

enum neighbor_state {
    NEIGHBOR_INIT = 0,
    NEIGHBOR_VALID = 1,
};

struct neigh_mbuf {
    sk_buff_t *skb;
    struct list_head neigh_mbuf_node;
};

struct neighbor {
    uint32_t next_hop;
    struct rte_ether_addr mac;
    struct list_head neighbor_list_node;
    int wait_pkt_count;
    struct list_head wait_pkt;
    enum neighbor_state state;
};

void neigh_init(void);
int neighbor_add(uint32_t next_hop, struct rte_ether_addr *mac);
int neighbor_del(uint32_t next_hop);
int neigh_output(uint32_t next_hop, sk_buff_t *skb, struct dev_port *port);
struct neighbor* neighbor_lookup(uint32_t next_hop);
void neigh_fill_mac(sk_buff_t *skb, struct neighbor *neighbor, struct dev_port *port);

#endif //NAT_LB_NEIGH_H
