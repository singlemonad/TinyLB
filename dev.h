//
// Created by tedqu on 24-9-5.
//

#ifndef NAT_LB_DEV_H
#define NAT_LB_DEV_H

#include <net/if.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_common.h>
#include "list.h"
#include "skb.h"

struct dev_port;

struct sk_buff;

struct port_conf {
    uint16_t port_id;
    int rxq_n;
    int rx_desc_n;
    int txq_n;
    int tx_desc_n;
    int mtu;
    uint32_t local_ip;
    struct list_head port_conf_list_node;
};

struct port_ops {
    int (*op_xmit) (struct sk_buff *mbuf, struct dev_port *port);
};

struct dev_port {
    char name[IFNAMSIZ];
    u_int16_t port_id;
    int rxq_n;
    int txq_n;
    int rx_desc_n;
    int tx_desc_n;
    unsigned int socket_id;
    struct rte_ether_addr mac;
    unsigned short mtu;
    struct rte_mempool *mbuf_pool;
    struct rte_eth_dev_info dev_info;
    struct rte_eth_conf dev_conf;
    struct rte_eth_stats stats;
    struct port_ops* ops;
    struct list_head list_node;
    struct list_head id_list_node; /* device list node hash by id */
    struct list_head name_list_node; /* device list node hash by name */
    uint32_t local_ip;
} __rte_cache_aligned;

int add_port_configure(struct port_conf *conf);

void port_init(void);
void port_start_all(void);
uint16_t port_rx_burst(uint16_t port_id, uint16_t queue_id);
int port_xmit(struct sk_buff *skb, struct dev_port *port);
struct dev_port* get_port_by_id(unsigned int port_id);

#endif //NAT_LB_DEV_H
