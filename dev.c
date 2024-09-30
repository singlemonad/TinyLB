//
// Created by tedqu on 24-9-5.
//

#include <rte_ethdev.h>
#include <rte_malloc.h>
#include "common.h"
#include "lcore.h"
#include "list.h"
#include "dev.h"

#define PORT_TABLE_BUCKETS 16
#define MAX_SOCKETS 2
#define PKT_MBUF_POOL_NB 4096
#define PKT_MBUF_POOL_CACHE_SIZE 256

// #define SHOW_RX_PKT 0
// #define SHOW_TX_PKT 0

static struct rte_eth_conf default_conf = {};

static struct list_head g_port_conf_list = {
        .next = &g_port_conf_list,
        .prev = &g_port_conf_list,
};

static int g_port_amount;
static struct list_head g_ports;
static struct list_head g_port_table[PORT_TABLE_BUCKETS];
static struct list_head g_port_name_table[PORT_TABLE_BUCKETS];

static struct rte_mempool *g_pkt_mbuf_pool[MAX_SOCKETS];

static void pkt_mbuf_pool_init(void) {
    unsigned int i, socket_n;
    char name[64];

    socket_n = rte_socket_count();
    for (i = 0; i < socket_n; i++) {
        snprintf(name, 64, "pkt_mbuf_pool_%d", i);
        g_pkt_mbuf_pool[i] = rte_mempool_create(name,
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
        if (NULL == g_pkt_mbuf_pool[i]) {
            rte_exit(EXIT_FAILURE, "Create pkt mbuf pool on socket %d failed, %s.",
                     i, rte_strerror(rte_errno));
        }
    }
}

static void port_table_init(void) {
    int i;

    for (i = 0; i < PORT_TABLE_BUCKETS; i++) {
        INIT_LIST_HEAD(&g_port_table[i]);
    }

    for (i = 0; i < PORT_TABLE_BUCKETS; i++) {
        INIT_LIST_HEAD(&g_port_name_table[i]);
    }
}

static int port_hash(uint16_t port_id) {
    return port_id % PORT_TABLE_BUCKETS;
}

static unsigned int port_name_hash(const char *name, size_t len) {
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

static int port_register(struct dev_port* port) {
    int hash;
    struct dev_port *curr;

    if (port == NULL) {
        return NAT_LB_INVALID;
    }

    hash = port_hash(port->port_id);
    list_for_each_entry(curr, &g_port_table[hash], id_list_node) {
        if (curr->port_id == port->port_id) {
            return NAT_LB_EXIST;
        }
    }

    unsigned int name_hash = port_name_hash(port->name, sizeof(port->name));
    list_for_each_entry(curr, &g_port_name_table[name_hash], name_list_node) {
        if (strcmp(curr->name, port->name) == 0) {
            return NAT_LB_EXIST;
        }
    }

    list_add(&port->list_node, &g_ports);
    list_add(&port->id_list_node, &g_port_table[hash]);
    list_add(&port->name_list_node, &g_port_name_table[name_hash]);
    g_port_amount++;

    return NAT_LB_OK;
}

static struct dev_port* port_alloc(uint16_t port_id, struct rte_eth_conf *conf) {
    struct dev_port *port;

    port = rte_zmalloc("dev_port", sizeof(struct dev_port), RTE_CACHE_LINE_SIZE);
    if (port == NULL) {
        RTE_LOG(ERR, PORT, "No memory: %s", __func__);
        return port;
    }

    port->port_id = port_id;
    port->socket_id = rte_socket_id();
    rte_eth_macaddr_get(port_id, &port->mac);
    rte_eth_dev_get_mtu(port_id, &port->mtu);
    rte_eth_dev_info_get(port_id, &port->dev_info);
    port->dev_conf = *conf;
    port->mbuf_pool = g_pkt_mbuf_pool[port->socket_id];
    snprintf(port->name, sizeof (port->name), "dev_port-%d", port_id);
    return port;
}

static struct port_conf* get_port_cfg(uint16_t port_id) {
    struct port_conf *cfg;
    list_for_each_entry(cfg, &g_port_conf_list, port_conf_list_node) {
        if (cfg->port_id == port_id) {
            return cfg;
        }
    }
    return NULL;
}

static void port_configure(struct dev_port *port) {
    struct port_conf *cfg;

    cfg = get_port_cfg(port->port_id);
    if (cfg == NULL) {
        rte_exit(EXIT_FAILURE, "Port %d not have dev_port config.", port->port_id);
    }

    port->mtu = cfg->mtu;
    port->rxq_n = cfg->rxq_n;
    port->rx_desc_n = cfg->rx_desc_n;
    port->txq_n = cfg->txq_n;
    port->tx_desc_n = cfg->tx_desc_n;
    port->local_ip = cfg->local_ip;
}

static void port_tx_burst(uint16_t cid, uint16_t port_id, uint16_t qid) {
    int tx_n;
    struct lcore_queue_conf *tx_queue_conf;

    tx_queue_conf = get_lcore_tx_queue_conf(cid, port_id, qid);

#ifdef SHOW_TX_PKT
    int idx;
    for (idx = 0; idx < tx_queue_conf->len; idx++) {
         RTE_LOG(INFO, PORT, "Tx one pkt, dev_port %d.\n", port_id);
         show_pkt(tx_queue_conf->mbufs[idx]);
    }
#endif

    tx_n = rte_eth_tx_burst(port_id, qid, (struct rte_mbuf**)tx_queue_conf->mbufs, tx_queue_conf->len);
    if (tx_n < tx_queue_conf->len) {
        do {
            rte_pktmbuf_free((struct rte_mbuf*)tx_queue_conf->mbufs[tx_n]);
        } while (++tx_n < tx_queue_conf->len);
    }
    tx_queue_conf->len = 0;
}

static uint16_t get_tx_queue_id(sk_buff_t *skb, struct lcore_port_conf* port_conf) {
    return (((uint32_t)skb->mbuf.buf_iova) >> 8 ) % port_conf->txq_n;
}

static int port_hard_xmit(sk_buff_t *skb, struct dev_port *port) {
    struct port_ops *ops;

    if (NULL == skb || NULL == port) {
        if (skb == NULL) {
            rte_pktmbuf_free((struct rte_mbuf*)skb);
        }
        return NAT_LB_INVALID;
    }

    ops = port->ops;
    if (NULL != ops && NULL != ops->op_xmit) {
        return ops->op_xmit(skb, port);
    }

    uint16_t  cid, qid;
    struct lcore_port_conf *lcore_port_conf;
    struct lcore_queue_conf *tx_queue_conf;

    cid = rte_lcore_id();
    lcore_port_conf = get_lcore_port_conf(cid, port->port_id);
    qid = get_tx_queue_id(skb, lcore_port_conf);

    tx_queue_conf = get_lcore_tx_queue_conf(cid, port->port_id, qid);
    tx_queue_conf->mbufs[tx_queue_conf->len] = skb;
    tx_queue_conf->len += 1;
    port_tx_burst(cid, port->port_id, qid);

    return NAT_LB_OK;
}

int add_port_configure(struct port_conf *conf) {
    list_add(&conf->port_conf_list_node, &g_port_conf_list);
    return NAT_LB_OK;
}

struct dev_port* get_port_by_id(unsigned int port_id) {
    int hash;
    struct dev_port *curr;

    hash = port_hash(port_id);
    list_for_each_entry(curr, &g_port_table[hash], id_list_node) {
        if (curr->port_id == port_id) {
            return curr;
        }
    }
    return NULL;
}

void port_init(void) {
    int port_n, port_cfg_n;

    port_n = rte_eth_dev_count_avail();
    if (port_n <= 0) {
        rte_exit(EXIT_FAILURE, "No dpdk ports found.\n");
    }

    pkt_mbuf_pool_init();

    port_cfg_n = list_elems(&g_port_conf_list);
    if (port_cfg_n < port_n) {
        rte_exit(EXIT_FAILURE, "Port cfg amount %d less than dev_port amount %d.", port_cfg_n, port_n);
    }

    INIT_LIST_HEAD(&g_ports);
    port_table_init();

    int ret;
    int port_id;
    struct dev_port *port;
    for (port_id = 0; port_id < port_n; port_id++) {
        port = port_alloc(port_id, &default_conf);
        if (port == NULL) {
            rte_exit(EXIT_FAILURE, "Port alloc failed %d.", port_id);
        }

        ret = port_register(port);
        if (ret != NAT_LB_OK) {
            rte_exit(EXIT_FAILURE, "Port register failed.", port_id);
        }
    }
}

static void port_start(struct dev_port *port) {
    int ret;

    port_configure(port);

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

    RTE_LOG(INFO, PORT, "Start dev_port %d success.\n", port->port_id);
}

void port_start_all(void) {
    struct dev_port *port;

    list_for_each_entry(port, &g_ports, list_node) {
        port_start(port);
    }
}

int port_xmit(sk_buff_t *skb, struct dev_port *port) {
    if (NULL == skb || NULL == port) {
        if (skb == NULL) {
            rte_pktmbuf_free((struct rte_mbuf*)skb);
        }
        return NAT_LB_INVALID;
    }

    if (skb->mbuf.port != port->port_id) {
        skb->mbuf.port = port->port_id;
    }

    return port_hard_xmit(skb, port);
}

uint16_t port_rx_burst(uint16_t port_id, uint16_t queue_id) {
    uint16_t cid;
    int rx_n;
    struct lcore_queue_conf *rx_queue_conf;

    cid = rte_lcore_id();
    rx_queue_conf = get_lcore_rx_queue_conf(cid, port_id, queue_id);
    rx_n = rte_eth_rx_burst(port_id, queue_id, (struct rte_mbuf**)rx_queue_conf->mbufs, MAX_PKT_BURST);
    rx_queue_conf->len = rx_n;

#ifdef SHOW_RX_PKT
    int idx;
    for (idx = 0; idx < rx_queue_conf->len; idx++) {
        RTE_LOG(INFO, PORT, "Rcv on pkt\n");
        show_pkt(rx_queue_conf->mbufs[idx]);
    }
#endif

    return rx_n;
}

