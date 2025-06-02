//
// Created by tedqu on 24-9-5.
//

#include <toml.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>
#include "../common/util.h"
#include "../common/log.h"
#include "../common/conf.h"
#include "../common/const.h"
#include "dev.h"

#define PORT_TABLE_BUCKET_SIZE 16
#define MAX_SOCKETS 2
#define PKT_MBUF_POOL_NB (8192 * 4)
#define PKT_MBUF_POOL_CACHE_SIZE (256 * 2)

// #define SHOW_RX_PKT 0
// #define SHOW_TX_PKT 0

__thread int64_t send_pkt_count = 0;
int64_t total_latency_record_interval = 10000;

static struct conf_item port_conf_parser;

static struct rte_eth_conf dev_port_default_conf = {};

static int port_conf_n = 0;
static struct list_head port_conf_list = {
        .next = &port_conf_list,
        .prev = &port_conf_list,
};

static struct list_head port_id_hash_table[PORT_TABLE_BUCKET_SIZE];
static struct list_head port_name_hash_table[PORT_TABLE_BUCKET_SIZE];

struct rte_mempool *socket_pkt_mbuf_pool[MAX_SOCKETS];

static void dev_pkt_mbuf_pool_init(void) {
    char name[64];
    int socket_n = (int)rte_socket_count();
    for (int i = 0; i < socket_n; i++) {
        RTE_LOG(INFO, NAT_LB, "%s: create pkt mbuf pool for socket %d\n", __func__, i);

        snprintf(name, 64, "pkt_mbuf_pool_%d", i);
        socket_pkt_mbuf_pool[i] = rte_pktmbuf_pool_create(name,
                                                          PKT_MBUF_POOL_NB,
                                                          PKT_MBUF_POOL_CACHE_SIZE,
                                                          0,
                                                          RTE_MBUF_DEFAULT_BUF_SIZE,
                                                          i);
        if (NULL == socket_pkt_mbuf_pool[i]) {
            rte_exit(EXIT_FAILURE, "%s: create pkt mbuf pool on socket %d failed, %s\n",
                     __func__, i, rte_strerror(rte_errno));
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

    for (i = 0; i < PORT_TABLE_BUCKET_SIZE; i++) {
        INIT_LIST_HEAD(&port_id_hash_table[i]);
    }

    for (i = 0; i < PORT_TABLE_BUCKET_SIZE; i++) {
        INIT_LIST_HEAD(&port_name_hash_table[i]);
    }
}

static int dev_get_port_hash(uint16_t port_id) {
    return port_id % PORT_TABLE_BUCKET_SIZE;
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
    return hash % PORT_TABLE_BUCKET_SIZE;
}

int dev_add_port_configure(struct port_conf *conf) {
    list_add(&conf->port_conf_list_node, &port_conf_list);
    ++port_conf_n;
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
        RTE_LOG(ERR, NAT_LB, "%s: no memory\n", __func__);
        return port;
    }
    return port;
}

static void dev_port_configure(struct dev_port *port, uint16_t port_id, struct rte_eth_conf *conf) {
    struct port_conf *cfg;

    cfg = dev_get_port_cfg(port->port_id);
    if (cfg == NULL) {
        rte_exit(EXIT_FAILURE, "%s: port %d not have dev_port config\n", __func__, port->port_id);
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

static const char* port_item_name[6] = {
    "local_ip",
    "rxq_n",
    "rx_desc_n",
    "txq_n",
    "tx_desc_n",
    "mtu",
};

static void port_parse_func(struct conf_item *item, toml_table_t *table) {
    toml_datum_t local_ip = toml_string_in(table, port_item_name[0]);
    toml_datum_t rxq_n = toml_int_in(table, port_item_name[1]);
    toml_datum_t rx_desc_n = toml_int_in(table, port_item_name[2]);
    toml_datum_t txq_n = toml_int_in(table, port_item_name[3]);
    toml_datum_t tx_desc_n = toml_int_in(table, port_item_name[4]);
    toml_datum_t mtu = toml_int_in(table, port_item_name[5]);
    RTE_LOG(INFO, NAT_LB, "%s: add port, local_ip=%s,rxq_n=%ld,rx_desc_n=%ld,txq_n=%ld,tx_desc_n=%ld,mtu=%ld\n",
            __func__, local_ip.u.s, rxq_n.u.i, rx_desc_n.u.i, txq_n.u.i, tx_desc_n.u.i, mtu.u.i);

    struct port_conf *port_conf = (struct port_conf*)rte_zmalloc("dev_port conf", sizeof (struct port_conf), RTE_CACHE_LINE_SIZE);
    if (NULL == port_conf) {
        rte_exit(EXIT_FAILURE, "%s: no memory\n", __func__ );
    }

    port_conf->port_id = port_conf_n;
    port_conf->rxq_n = (int)rxq_n.u.i;
    port_conf->rx_desc_n = (int)rx_desc_n.u.i;
    port_conf->txq_n = (int)txq_n.u.i;
    port_conf->tx_desc_n = (int)tx_desc_n.u.i;
    port_conf->mtu = (int)mtu.u.i;
    port_conf->local_ip = ip_to_int_be(local_ip.u.s);
    dev_add_port_configure(port_conf);
}

static void init_port_parser(void) {
    char conf_name[] = "port";
    bzero(&port_conf_parser, sizeof(port_conf_parser));

    memcpy(port_conf_parser.name, conf_name, strlen(conf_name));
    port_conf_parser.parse_func = port_parse_func;
    add_conf_item_parser(&port_conf_parser);
}

void dev_port_configure_port(uint16_t avail_port_n) {
    int ret;
    struct dev_port *port;

    for (uint16_t port_id = 0; port_id < avail_port_n; port_id++) {
        port = dev_port_alloc();
        if (port == NULL) {
            rte_exit(EXIT_FAILURE, "%s: port alloc failed %d\n", __func__, port_id);
        }

        dev_port_configure(port, port_id, &dev_port_default_conf);

        ret = dev_port_register(port);
        if (ret != NAT_LB_OK) {
            rte_exit(EXIT_FAILURE, "%s: port %d register failed\n", __func__, port_id);
        }
    }
}

void dev_port_module_init(uint16_t port_n) {
    uint16_t port_cfg_n;

    init_port_parser();

    port_cfg_n = list_elems(&port_conf_list);
    if (port_n < port_cfg_n) {
        rte_exit(EXIT_FAILURE, "%s port amount %d less than port cfg amount %d\n", __func__, port_cfg_n, port_n);
    }

    dev_pkt_mbuf_pool_init();
    dev_port_table_init();
}

static uint16_t get_tx_queue_id(struct dev_port *port, sk_buff_t *skb) {
    return (((uint32_t)skb->mbuf.buf_iova) >> 8 ) % port->txq_n;
}

static int dev_port_hard_xmit(struct dev_port *port, sk_buff_t *skb) {
    struct port_ops *ops;
    int tx_n, qid;

    if (NULL == skb || NULL == port) {
        if (skb != NULL) {
            rte_pktmbuf_free((struct rte_mbuf*)skb);
        }
        return NAT_LB_INVALID;
    }

#ifdef SHOW_TX_PKT
    RTE_LOG(INFO, NAT_LB, "Tx one pkt, dev_port %d.\n", port->port_id);
    print_pkt(skb);
#endif

    qid = get_tx_queue_id(port, skb);
    tx_n = rte_eth_tx_burst(port->port_id, qid, (struct rte_mbuf**)&skb, 1);
    if (tx_n != 1) {
        rte_pktmbuf_free((struct rte_mbuf*)skb);
    }
    send_pkt_count += 1;
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

    rx_n = rte_eth_rx_burst(port_id, queue_id, (struct rte_mbuf**)mbufs, MAX_RX_BURST);

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
        rte_exit(EXIT_FAILURE, "%s: port %d not exist\n", __func__, port_id);
    }

    ret = rte_eth_dev_configure(port->port_id, port->rxq_n, port->txq_n, &port->dev_conf);
    if (ret != NAT_LB_OK) {
        rte_exit(EXIT_FAILURE, "%s: configure dev_port %d failed, %s\n", __func__, port->port_id, rte_strerror(rte_errno));
    }

    ret = rte_eth_dev_set_mtu(port->port_id, port->mtu);
    if (ret != NAT_LB_OK) {
        rte_exit(EXIT_FAILURE, "%s: set dev_port %d's mtu failed, %s\n", __func__, port->port_id, rte_strerror(rte_errno));
    }

    int qid;
    for (qid = 0; qid < port->rxq_n; qid++) {
        ret = rte_eth_rx_queue_setup(port->port_id, qid, port->rx_desc_n, port->socket_id, NULL, port->mbuf_pool);
        if (ret != NAT_LB_OK) {
            rte_exit(EXIT_FAILURE, "%s: set dev_port %d rxq %d failed, %s\n", __func__, port->port_id, qid, rte_strerror(rte_errno));
        }
    }
    for (qid = 0; qid < port->txq_n; qid++) {
        ret = rte_eth_tx_queue_setup(port->port_id, qid, port->tx_desc_n, port->socket_id, NULL);
        if (ret != NAT_LB_OK) {
            rte_exit(EXIT_FAILURE, "%s: set dev_port %d txq %d failed, %s\n", __func__, port->port_id, qid, rte_strerror(rte_errno));
        }
    }

    ret = rte_eth_dev_start(port->port_id);
    if (ret != NAT_LB_OK) {
        rte_exit(EXIT_FAILURE, "%s: start dev_port %d failed, %s\n", __func__, port->port_id, rte_strerror(rte_errno));
    }

    ret = rte_eth_promiscuous_enable(port->port_id);
    if (ret != NAT_LB_OK) {
        rte_exit(EXIT_FAILURE, "%s: enable promiscuous dev_port %d failed, %s\n", __func__, port->port_id, rte_strerror(rte_errno));
    }

    RTE_LOG(INFO, NAT_LB, "%s: start dev_port %d success\n", __func__, port->port_id);
}
