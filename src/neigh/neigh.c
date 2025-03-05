//
// Created by tedqu on 24-9-10.
//

#include <rte_malloc.h>
#include "../common/util.h"
#include "neigh.h"
#include "arp.h"
#include "../common/log.h"

#define NEIGH_BUCKETS 64

static struct list_head g_neigh_table[NEIGH_BUCKETS];

static uint get_neigh_hash(uint32_t next_hop) {
    return next_hop % NEIGH_BUCKETS;
}

int neighbor_add(uint32_t next_hop, struct rte_ether_addr *mac) {
    uint hash;
    struct neighbor *neighbor;

    hash = get_neigh_hash(next_hop);
    list_for_each_entry(neighbor, &g_neigh_table[hash], neighbor_list_node) {
        if (neighbor->next_hop == next_hop) {
            return NAT_LB_EXIST;
        }
    }

    neighbor = rte_zmalloc("neighbor", sizeof(struct neighbor), RTE_CACHE_LINE_SIZE);
    if (NULL == neighbor) {
        fprintf(stderr, "No memory, %s.", __func__ );
        return NAT_LB_NOMEM;
    }
    neighbor->next_hop = next_hop;
    rte_ether_addr_copy(mac, &neighbor->mac);
    INIT_LIST_HEAD(&neighbor->wait_pkt);
    neighbor->state = NEIGHBOR_VALID;
    list_add(&neighbor->neighbor_list_node, &g_neigh_table[hash]);

    return NAT_LB_OK;
}

int neighbor_del(uint32_t next_hop) {
    int hash;
    bool found = false;
    struct neighbor *neighbor;

    hash = get_neigh_hash(next_hop);
    list_for_each_entry(neighbor, &g_neigh_table[hash], neighbor_list_node) {
        if (neighbor->next_hop == next_hop) {
            found = true;
            break;
        }
    }

    if (!found) {
        return NAT_LB_NOT_EXIST;
    }

    list_del(&neighbor->neighbor_list_node);
    rte_free(neighbor);

    return NAT_LB_OK;
}

struct neighbor* neighbor_lookup(uint32_t next_hop) {
    int hash;
    struct neighbor *neighbor;

    hash = get_neigh_hash(next_hop);
    list_for_each_entry(neighbor, &g_neigh_table[hash], neighbor_list_node) {
        if (neighbor->next_hop == next_hop) {
            return neighbor;
        }
    }
    return NULL;
}

void neigh_fill_mac(sk_buff_t *skb, struct neighbor *neighbor, struct dev_port *port) {
    struct rte_ether_hdr *eth_hdr;
    uint16_t pkt_type;

    skb->mbuf.l2_len = sizeof(struct rte_ether_hdr);
    eth_hdr = (struct rte_ether_hdr*)rte_pktmbuf_prepend((struct rte_mbuf*)skb, (uint16_t)sizeof(struct rte_ether_hdr));
    rte_ether_addr_copy(&neighbor->mac, &eth_hdr->dst_addr);
    rte_ether_addr_copy(&port->mac, &eth_hdr->src_addr);
    pkt_type = (uint16_t)skb->mbuf.packet_type;
    eth_hdr->ether_type = rte_cpu_to_be_16(pkt_type);
}

static int neigh_solicit(struct neighbor *neighbor, sk_buff_t *skb, struct dev_port *port) {
    struct neigh_mbuf *neigh_mbuf;

    neigh_mbuf = rte_zmalloc("neigh mbuf", sizeof(struct neigh_mbuf), RTE_CACHE_LINE_SIZE);
    if (NULL == neigh_mbuf) {
        RTE_LOG(ERR, IP, "No memory: %s\n", __func__ );
        return NAT_LB_NOMEM;
    }

    neigh_mbuf->skb= skb;
    list_add(&neigh_mbuf->neigh_mbuf_node, &neighbor->wait_pkt);
    neighbor->wait_pkt_count += 1;

    return arp_send(port, port->local_ip, neighbor->next_hop);
}

int neigh_output(uint32_t next_hop, sk_buff_t *skb, struct dev_port *port) {
    struct neighbor *neighbor;
    uint hash;

    neighbor = neighbor_lookup(next_hop);
    if (NULL == neighbor) {
        RTE_LOG(INFO, IP, "No neighbor to %s, solicit it.\n", ip_to_str(next_hop));

        neighbor = rte_zmalloc("neigh", sizeof(struct neighbor), RTE_CACHE_LINE_SIZE);
        if (NULL == neighbor) {
            RTE_LOG(ERR, IP, "No memory: %s\n", __func__ );
            return NAT_LB_NOMEM;
        }
        neighbor->state = NEIGHBOR_INIT;
        neighbor->next_hop = next_hop;
        INIT_LIST_HEAD(&neighbor->wait_pkt);
        hash = get_neigh_hash(next_hop);
        list_add(&neighbor->neighbor_list_node, &g_neigh_table[hash]);
    }

    if (neighbor->state != NEIGHBOR_VALID) {
        return neigh_solicit(neighbor, skb, port);
    } else {
        neigh_fill_mac(skb, neighbor, port);
        dev_port_xmit(port, skb);

        return NAT_LB_OK;
    }
}

void neigh_init(void) {
    int i;

    for (i = 0; i< NEIGH_BUCKETS; i++) {
        INIT_LIST_HEAD(&g_neigh_table[i]);
    }
}