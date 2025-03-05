//
// Created by tedqu on 24-9-5.
//

#include <rte_ethdev.h>
#include <rte_malloc.h>
#include "../common/util.h"
#include "../common/log.h"
#include "dev.h"

#define PORT_TABLE_BUCKETS 16
#define MAX_SOCKETS 2
#define PKT_MBUF_POOL_NB 4096
#define PKT_MBUF_POOL_CACHE_SIZE 256
#define MAX_PKT_BURST 32

#define SHOW_RX_PKT 0
#define SHOW_TX_PKT 0

static struct rte_eth_conf dev_port_default_conf = {};

static struct list_head port_conf_list = {
        .next = &port_conf_list,
        .prev = &port_conf_list,
};

static struct list_head port_id_hash_table[PORT_TABLE_BUCKETS];
static struct list_head port_name_hash_table[PORT_TABLE_BUCKETS];

static struct rte_mempool *socket_pkt_mbuf_pool[MAX_SOCKETS];

static void dev_pkt_mbuf_pool_init(void) {
    unsigned int i, socket_n;
    char name[64];

    socket_n = rte_socket_count();
    for (i = 0; i < socket_n; i++) {
        snprintf(name, 64, "pkt_mbuf_pool_%d", i);
        socket_pkt_mbuf_pool[i] = rte_mempool_create(name,
                                                     PKT_MBUF_POOL_NB,
                                                     MBUF_SIZE,
                                                     PKT_MBUF_POOL_CACHE_SIZE,
                                                     sizeof(struct rte_pktmbuf_pool_private),
                                                     rte_pktmbuf_pool_init,
                                                     NULL,
                                                     rte_pktmbuf_init,
                                                     NULL,
                                                     (int)i,
                                                     0);
        if (NULL == socket_pkt_mbuf_pool[i]) {
            rte_exit(EXIT_FAILURE, "Create pkt mbuf pool on socket %d failed, %s.",
                     i, rte_strerror(rte_errno));
        }
    }
}

static struct port_conf* dev_get_port_cfg(uint16_t port_id) {
    struct port_conf *cfg;
    list_for_each_entry(cfg, &port_conf_list, port_conf_list_node) {
        if (cfg->port_id == port_id) {
            return cfg;
        }
    }
    return NULL;
}

static void dev_port_table_init(void) {
    int i;

    for (i = 0; i < PORT_TABLE_BUCKETS; i++) {
        INIT_LIST_HEAD(&port_id_hash_table[i]);
    }

    for (i = 0; i < PORT_TABLE_BUCKETS; i++) {
        INIT_LIST_HEAD(&port_name_hash_table[i]);
    }
}

static int dev_get_port_hash(uint16_t port_id) {
    return port_id % PORT_TABLE_BUCKETS;
}

static unsigned int dev_get_port_name_hash(const char *name, size_t len) {
    size_t i;
    unsigned int hash=1315423911;
    for (i = 0; i < len; i++)
    {
        if (name[i] == '\0')
            break;
        hash^=((hash<<5)+name[i]+(hash>>2));
    }
    return hash % PORT_TABLE_BUCKETS;
}

int dev_add_port_configure(struct port_conf *conf) {
    list_add(&conf->port_conf_list_node, &port_conf_list);
    return NAT_LB_OK;
}

struct dev_port* get_port_by_id(unsigned int port_id) {
    int hash;
    struct dev_port *curr;

    hash = dev_get_port_hash(port_id);
    list_for_each_entry(curr, &port_id_hash_table[hash], id_list_node) {
        if (curr->port_id == port_id) {
            return curr;
        }
    }
    return NULL;
}

static int dev_port_register(struct dev_port* port) {
    int hash;
    struct dev_port *curr;

    if (port == NULL) {
        return NAT_LB_INVALID;
    }

    hash = dev_get_port_hash(port->port_id);
    list_for_each_entry(curr, &port_id_hash_table[hash], id_list_node) {
        if (curr->port_id == port->port_id) {
            return NAT_LB_EXIST;
        }
    }

    unsigned int name_hash = dev_get_port_name_hash(port->name, sizeof(port->name));
    list_for_each_entry(curr, &port_name_hash_table[name_hash], name_list_node) {
        if (strcmp(curr->name, port->name) == 0) {
            return NAT_LB_EXIST;
        }
    }

    list_add(&port->id_list_node, &port_id_hash_table[hash]);
    list_add(&port->name_list_node, &port_name_hash_table[name_hash]);

    return NAT_LB_OK;
}

static struct dev_port* dev_port_alloc(void) {
    struct dev_port *port;

    port = rte_zmalloc("dev_port", sizeof(struct dev_port), RTE_CACHE_LINE_SIZE);
    if (port == NULL) {
        RTE_LOG(ERR, DEV, "No memory: %s\n", __func__);
        return port;
    }
    return port;
}

static void dev_port_configure(struct dev_port *port, uint16_t port_id, struct rte_eth_conf *conf) {
    struct port_conf *cfg;

    cfg = dev_get_port_cfg(port->port_id);
    if (cfg == NULL) {
        rte_exit(EXIT_FAILURE, "Port %d not have dev_port config.", port->port_id);
    }

    port->port_id = port_id;
    port->socket_id = rte_socket_id();
    rte_eth_macaddr_get(port_id, &port->mac);
    rte_eth_dev_get_mtu(port_id, &port->mtu);
    rte_eth_dev_info_get(port_id, &port->dev_info);
    port->dev_conf = *conf;
    port->mbuf_pool = socket_pkt_mbuf_pool[port->socket_id];
    snprintf(port->name, sizeof (port->name), "dev_port-%d", port_id);
    port->mtu = cfg->mtu;
    port->rxq_n = cfg->rxq_n;
    port->rx_desc_n = cfg->rx_desc_n;
    port->txq_n = cfg->txq_n;
    port->tx_desc_n = cfg->tx_desc_n;
    port->local_ip = cfg->local_ip;
}

void dev_port_init(void) {
    int ret;
    uint16_t port_n, port_cfg_n, port_id;
    struct dev_port *port;

    port_n = rte_eth_dev_count_avail();
    if (port_n <= 0) {
        rte_exit(EXIT_FAILURE, "No dpdk ports found.\n");
    }

    port_cfg_n = list_elems(&port_conf_list);
    if (port_n < port_cfg_n) {
        rte_exit(EXIT_FAILURE, "Port amount %d less than port cfg amount %d.", port_cfg_n, port_n);
    }

    dev_pkt_mbuf_pool_init();
    dev_port_table_init();

    for (port_id = 0; port_id < port_n; port_id++) {
        port = dev_port_alloc();
        if (port == NULL) {
            rte_exit(EXIT_FAILURE, "Port alloc failed %d.", port_id);
        }

        dev_port_configure(port, port_id, &dev_port_default_conf);

        ret = dev_port_register(port);
        if (ret != NAT_LB_OK) {
            rte_exit(EXIT_FAILURE, "Port register failed.", port_id);
        }
    }
}

static uint16_t get_tx_queue_id(struct dev_port *port, sk_buff_t *skb) {
    return (((uint32_t)skb->mbuf.buf_iova) >> 8 ) % port->txq_n;
}

static int dev_port_hard_xmit(struct dev_port *port, sk_buff_t *skb) {
    struct port_ops *ops;
    int tx_n, qid;

    if (NULL == skb || NULL == port) {
        if (skb == NULL) {
            rte_pktmbuf_free((struct rte_mbuf*)skb);
        }
        return NAT_LB_INVALID;
    }

#ifdef SHOW_TX_PKT
    RTE_LOG(INFO, DEV, "Tx one pkt, dev_port %d.\n", port->port_id);
    print_pkt(skb);
#endif

    ops = port->ops;
    if (NULL != ops && NULL != ops->op_xmit) {
        return ops->op_xmit(skb, port);
    }

    qid = get_tx_queue_id(port, skb);
    tx_n = rte_eth_tx_burst(port->port_id, qid, (struct rte_mbuf**)&skb, 1);
    if (tx_n != 1) {
        rte_pktmbuf_free((struct rte_mbuf*)skb);
    }
    return NAT_LB_OK;
}

int dev_port_xmit(struct dev_port *port, sk_buff_t *skb) {
    if (NULL == skb || NULL == port) {
        if (skb == NULL) {
            rte_pktmbuf_free((struct rte_mbuf*)skb);
        }
        return NAT_LB_INVALID;
    }

    if (skb->mbuf.port != port->port_id) {
        skb->mbuf.port = port->port_id;
    }

    return dev_port_hard_xmit(port, skb);
}

uint16_t dev_port_rx_burst(uint16_t port_id, uint16_t queue_id, sk_buff_t **mbufs) {
    int rx_n;

    rx_n = rte_eth_rx_burst(port_id, queue_id, (struct rte_mbuf**)mbufs, MAX_PKT_BURST);

#ifdef SHOW_RX_PKT
    int idx;
    for (idx = 0; idx < rx_n; idx++) {
        RTE_LOG(INFO, PORT, "Rcv one pkt\n");
        print_pkt(mbufs[idx]);
    }
#endif

    return rx_n;
}

void dev_port_start(uint16_t port_id) {
    int ret;
    struct dev_port *port;

    port = get_port_by_id(port_id);
    if (NULL == port) {
        rte_exit(EXIT_FAILURE, "Port %d not exist.", port_id);
    }

    ret = rte_eth_dev_configure(port->port_id, port->rxq_n, port->txq_n, &port->dev_conf);
    if (ret != NAT_LB_OK) {
        rte_exit(EXIT_FAILURE, "Configure dev_port %d failed, %s.", port->port_id, rte_strerror(rte_errno));
    }

    ret = rte_eth_dev_set_mtu(port->port_id, port->mtu);
    if (ret != NAT_LB_OK) {
        rte_exit(EXIT_FAILURE, "Set dev_port %d's mtu failed, %s.", port->port_id, rte_strerror(rte_errno));
    }

    int qid;
    for (qid = 0; qid < port->rxq_n; qid++) {
        ret = rte_eth_rx_queue_setup(port->port_id, qid, port->rx_desc_n, port->socket_id, NULL, port->mbuf_pool);
        if (ret != NAT_LB_OK) {
            rte_exit(EXIT_FAILURE, "Set dev_port %d rxq %d failed, %s.", port->port_id, qid, rte_strerror(rte_errno));
        }
    }
    for (qid = 0; qid < port->txq_n; qid++) {
        ret = rte_eth_tx_queue_setup(port->port_id, qid, port->tx_desc_n, port->socket_id, NULL);
        if (ret != NAT_LB_OK) {
            rte_exit(EXIT_FAILURE, "Set dev_port %d txq %d failed, %s", port->port_id, qid, rte_strerror(rte_errno));
        }
    }

    ret = rte_eth_dev_start(port->port_id);
    if (ret != NAT_LB_OK) {
        rte_exit(EXIT_FAILURE, "Start dev_port %d failed, %s.", port->port_id, rte_strerror(rte_errno));
    }

    ret = rte_eth_promiscuous_enable(port->port_id);
    if (ret != NAT_LB_OK) {
        rte_exit(EXIT_FAILURE, "Enable promiscuous dev_port %d failed, %s.", port->port_id, rte_strerror(rte_errno));
    }

    RTE_LOG(INFO, DEV, "Start dev_port %d success.\n", port->port_id);
}
