//
// Created by tedqu on 25-2-25.
//

#include <toml.h>
#include <rte_malloc.h>
#include <rte_log.h>
#include <rte_rcu_qsbr.h>
#include "../common/util.h"
#include "../inet/inet.h"
#include "../sync/sync.h"
#include "lcore.h"
#include "ip_group.h"
#include "conf.h"
#include "const.h"
#include "log.h"

struct rte_rcu_qsbr* rcu_lock;

static uint16_t ETHER_TYPE_ARP_BE;
static uint16_t ETHER_TYPE_IPV4_BE;

extern struct rte_mempool *socket_pkt_mbuf_pool[2];

static struct conf_item lcore_parser;
enum lcore_type lcore_type_array[MAX_LCORE];
struct lcore* lcore_array[MAX_LCORE];
static struct original_skb_dis_arg orig_dis_arg;
static uint16_t session_sync_lcore_id;
static uint16_t keepalive_lcore_id;

__thread struct per_lcore_ct_ctx per_lcore_ctx = {
        .l4_proto = 0,
        .ct = NULL,
        .tuple_hash = NULL,
};

static void create_rcu_lock(void) {
    int ret;
    size_t mem_size = rte_rcu_qsbr_get_memsize(MAX_LCORE);

    rcu_lock = rte_zmalloc("rcu", mem_size, RTE_CACHE_LINE_SIZE);
    if (rcu_lock == NULL) {
        rte_exit(EXIT_FAILURE, "%s: no memory\n", __func__);
    }

    ret = rte_rcu_qsbr_init(rcu_lock, MAX_LCORE);
    if (ret != 0) {
        rte_exit(EXIT_FAILURE, "%s: init rcu lock failed\n", __func__);
    }
}

static inline bool is_valid_pkt(sk_buff_t *skb) {
    if (NULL == skb || skb->mbuf.data_len == 0 || skb->mbuf.pkt_len == 0) {
        return false;
    }
    return true;
}

static struct sk_buff* clone_arp_skb(struct sk_buff *skb) {
    struct sk_buff* clone_skb;

    clone_skb = (struct sk_buff*)rte_pktmbuf_clone(&skb->mbuf, socket_pkt_mbuf_pool[rte_socket_id()]);
    if (NULL == clone_skb) {
        return NULL;
    }
    clone_skb->eth = skb->eth;
    clone_skb->data_hdr = skb->data_hdr;
    return clone_skb;
}

static void dispatch_arp_skb(struct sk_buff *skb) {
    struct rte_ring *rcv_ring;
    struct sk_buff* clone_skb;

    uint16_t lcore_id = rte_lcore_id();
    struct rx_lcore_conf *conf = lcore_array[lcore_id]->lcore_cfg;
    ++conf->rxtx_stats.tx;
    for (int i = 0; i < MAX_LCORE; i++) {
        if (lcore_type_array[i] == LCORE_TYPE_WORK ||
        lcore_type_array[i] == LCORE_TYPE_KEEPALIVE ||
        lcore_type_array[i] == LCORE_TYPE_SESSION_SYNC) {
            rcv_ring = conf->pkt_out_rings[i];
            if (NULL != rcv_ring) {
                clone_skb = clone_arp_skb(skb);
                if (NULL == clone_skb) {
                    RTE_LOG(ERR, NAT_LB, "%s: clone arp skb failed", __func__ );
                }

                int ret = rte_ring_enqueue(rcv_ring, clone_skb);
                if (ret != 0) {
                    RTE_LOG(ERR, NAT_LB, "%s: enqueue arp skb failed", __func__);
                }
            }
        }
    }
    rte_pktmbuf_free((struct rte_mbuf*)skb);
}

static void dispatch_ip_skb(struct sk_buff* skb) {
    uint16_t work_lcore_id;
    uint16_t lcore_id = rte_lcore_id();
    struct rx_lcore_conf *conf = lcore_array[lcore_id]->lcore_cfg;

    struct rte_ipv4_hdr *iph = rte_pktmbuf_mtod(&skb->mbuf, struct rte_ipv4_hdr*);
    if (iph->next_proto_id == IPPROTO_GRE) {
        // TODO 处理GRE协议
    }

    skb->ip_type = get_ip_group_type(iph->dst_addr);
    switch (skb->ip_type) {
        case IP_TYPE_SVC:
            work_lcore_id = get_rcv_lcore_id(skb, &orig_dis_arg);
            break;
        case IP_TYPE_SNAT:
            work_lcore_id = get_rcv_lcore_id(skb, NULL);
            break;
        case IP_TYPE_SESSION_SYNC:
            skb->flags |= SKB_SESSION_SYNC;
            work_lcore_id = get_rcv_lcore_id(skb, &session_sync_lcore_id);
            break;
        case IP_TYPE_KEEPALIVE:
            skb->flags |= SKB_KEEPALIVE;
            work_lcore_id = get_rcv_lcore_id(skb, &keepalive_lcore_id);
            break;
        default:
            rte_pktmbuf_free((struct rte_mbuf*)skb);
            ++conf->rxtx_stats.drop.no_ip_group;
            return;
    }

    assert(conf->pkt_out_rings[work_lcore_id] != NULL);
    int en = rte_ring_enqueue(conf->pkt_out_rings[work_lcore_id], skb);
    if (unlikely(en != 0)) {
        RTE_LOG(DEBUG, NAT_LB, "%s: enqueue skb to lcore %d failed\n", __func__, work_lcore_id);
        rte_pktmbuf_free((struct rte_mbuf*)skb);
        ++conf->rxtx_stats.drop.enqueue_failed;
    } else {
        ++conf->rxtx_stats.tx;
    }
}

static void dispatch_pkt(struct sk_buff* skb) {
    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(&skb->mbuf, struct rte_ether_hdr*);
    skb->eth = eth;
    rte_pktmbuf_adj(&skb->mbuf, sizeof(struct rte_ether_hdr));

    uint16_t lcore_id = rte_lcore_id();
    struct rx_lcore_conf *conf = lcore_array[lcore_id]->lcore_cfg;
    if (unlikely(eth->ether_type == ETHER_TYPE_ARP_BE)) {
        ++conf->rxtx_stats.rx_arp;
        return dispatch_arp_skb(skb);
    } else if (likely(eth->ether_type == ETHER_TYPE_IPV4_BE)) {
        ++conf->rxtx_stats.rx_ip;
        return dispatch_ip_skb(skb);
    } else {
        rte_pktmbuf_free((struct rte_mbuf*)skb);
        ++conf->rxtx_stats.drop.invalid_l3_proto;
    }
}

static void rx_lcore_main_func(void *lcore_cfg) {
    uint16_t port_id;
    struct sk_buff *skb;

    struct rx_lcore_conf *rx_cfg = (struct rx_lcore_conf*)lcore_cfg;
    for (int i = 0; i < rx_cfg->port_n; i++) {
        port_id = rx_cfg->ports[i].port_id;
        for (int j = 0; j < rx_cfg->ports[i].rxq_n; j++) {
            int rx_n = dev_port_rx_burst(port_id, j, (struct sk_buff **) &rx_cfg->ports[i].mbufs);
            if (rx_n == 0) {
                continue;
            }

            rx_cfg->rxtx_stats.rx += rx_n;
            for (int k = 0; k < rx_n; k++) {
                skb = rx_cfg->ports[i].mbufs[k];
                if (!is_valid_pkt(skb)) {
                    ++rx_cfg->rxtx_stats.drop.invalid_pkt;
                    rte_pktmbuf_free((struct rte_mbuf*)skb);
                    continue;
                } else {
                    skb->flags = 0;
                    dispatch_pkt(skb);
                }
            }
        }
    }
}

static void process_in_pkt(struct rte_ring *ring, struct lcore_rxtx_stats *stats) {
    unsigned int i = 0, n_rx;
    struct sk_buff *skb_burst[MAX_RX_BURST];

    while (true) {
        n_rx = rte_ring_dequeue_burst(ring, (void **) skb_burst, MAX_RX_BURST, NULL);
        if (n_rx == 0) {
            return;
        }
        stats->rx += n_rx;
        for (i = 0; i < n_rx; i++) {
            deliver_l3_skb(skb_burst[i]);
        }
    }
}

static void work_lcore_main_func(void *lcore_cfg) {
    unsigned int i, ct_n;
    struct ct_session* ct;
    struct ct_session* ct_burst[MAX_RX_BURST];
    struct work_lcore_conf *conf = (struct work_lcore_conf*)lcore_cfg;

    process_in_pkt(conf->pkt_in_ring, &conf->rxtx_stats);

    while (true) {
        ct_n = rte_ring_dequeue_burst(conf->sync_ct_in_ring, (void **)ct_burst, MAX_RX_BURST, NULL);
        if (ct_n == 0) {
            return;
        }
        for (i = 0; i < ct_n; i++) {
            process_sync_in_ct(ct_burst[i]);
        }
    }
}

static void session_sync_lcore_main_func(void *lcore_cfg) {
    unsigned int i, n = 0;
    struct ct_session *ct_burst[MAX_RX_BURST];
    struct session_sync_lcore_conf* conf = (struct session_sync_lcore_conf*)lcore_cfg;

    process_in_pkt(conf->pkt_in_ring, &conf->rxtx_stats);

    while (true) { // process out ct
        n = rte_ring_dequeue_burst(conf->pending_ring, (void **)ct_burst, MAX_RX_BURST, NULL);
        if (n == 0) {
            break;
        }
        for (i = 0; i < n; i++) {
            sync_one_ct(ct_burst[i]);
        }
    }
}

static void keepalive_lcore_main_func(void *lcore_cfg) {
    struct keepalive_lcore_conf* conf = (struct keepalive_lcore_conf*)lcore_cfg;
    process_in_pkt(conf->pkt_in_ring, &conf->rxtx_stats);
}

static void rxtx_stats_dump(void *lcore_cfg) {
    uint16_t lcore_id = rte_lcore_id();
    if (lcore_type_array[lcore_id] == LCORE_TYPE_RX) {
        struct rx_lcore_conf *rx_conf = lcore_cfg;
        RTE_LOG(INFO, NAT_LB, "lcore %d, rx=%d,tx=%d,enqueue_field=%d\n",
                lcore_id, rx_conf->rxtx_stats.rx, rx_conf->rxtx_stats.tx, rx_conf->rxtx_stats.drop.enqueue_failed);
    } /*else if (lcore_type_array[lcore_id] == LCORE_TYPE_WORK) {
        struct work_lcore_conf *work_conf = lcore_cfg;
        RTE_LOG(INFO, NAT_LB, "lcore %d, rx=%d,tx=%d,drop=%d,rx_arp=%d,rx_ip=%d\n",
                lcore_id, work_conf->rxtx_stats.rx, work_conf->rxtx_stats.tx, work_conf->rxtx_stats.drop,
                work_conf->rxtx_stats.rx_arp, work_conf->rxtx_stats.rx_ip);
    } else if (lcore_type_array[lcore_id] == LCORE_TYPE_SESSION_SYNC) {
        struct session_sync_lcore_conf* sync_conf = lcore_cfg;
        RTE_LOG(INFO, NAT_LB, "lcore %d, rx=%d,tx=%d,drop=%d,rx_arp=%d,rx_ip=%d\n",
                lcore_id, sync_conf->rxtx_stats.rx, sync_conf->rxtx_stats.tx, sync_conf->rxtx_stats.drop,
                sync_conf->rxtx_stats.rx_arp, sync_conf->rxtx_stats.rx_ip);
    } else if (lcore_type_array[lcore_id] == LCORE_TYPE_KEEPALIVE) {
        struct keepalive_lcore_conf* keepalive_conf = lcore_cfg;
        RTE_LOG(INFO, NAT_LB, "lcore %d, rx=%d,tx=%d,drop=%d,rx_arp=%d,rx_ip=%d\n",
                lcore_id, keepalive_conf->rxtx_stats.rx, keepalive_conf->rxtx_stats.tx, keepalive_conf->rxtx_stats.drop,
                keepalive_conf->rxtx_stats.rx_arp, keepalive_conf->rxtx_stats.rx_ip);
    }*/
}

static void port_stats_dump(void* args) {
    int ret;
    struct rte_eth_stats stats;

    unsigned avail_port_n = rte_eth_dev_count_avail();
    if (avail_port_n <= 0) {
        RTE_LOG(ERR, NAT_LB, "%s: no available port\n", avail_port_n);
        return;
    }
    for (unsigned port_id = 0; port_id < avail_port_n; port_id++) {
        bzero(&stats, sizeof(struct rte_eth_stats));
        ret = rte_eth_stats_get(port_id, &stats);
        if (ret != 0) {
            RTE_LOG(ERR, NAT_LB, "%s: get port %d stats failed\n", __func__, port_id);
            continue;
        }
        RTE_LOG(INFO, NAT_LB, "%s: port %d stat, in_packets=%ld,out_packets=%ld,in_bytes=%ld,out_bytes=%ld,in_missed=%ld,in_errors=%ld,out_errors=%ld,rx_no_mbuf=%ld\n",
                           __func__, port_id, stats.ipackets, stats.opackets, stats.ibytes, stats.obytes, stats.imissed, stats.ierrors, stats.oerrors, stats.rx_nombuf);
    }
}

static void setup_lcore(enum lcore_type type, uint16_t lcore_id, lcore_main_func func, void *cfg, int slow_func_n, lcore_slow_func slow_funcs[]) {
    assert(lcore_array[lcore_id] == NULL);

    struct lcore* lcore = rte_malloc("lcore", sizeof(struct lcore), RTE_CACHE_LINE_SIZE);
    if (NULL == lcore) {
        rte_exit(EXIT_FAILURE, "%s: no memory\n", __func__);
        return;
    }

    lcore->type = type;
    lcore->lcore_cfg = cfg;
    lcore->main_func = func;
    lcore->slow_func_n = slow_func_n;
    for (int i = 0; i < lcore->slow_func_n; i++) {
        lcore->slow_funcs[i] = slow_funcs[i];
    }
    lcore_array[lcore_id] = lcore;
}

static int lcore_loop(void* arg) {
    uint16_t lcore_id = rte_lcore_id();

    if (lcore_type_array[lcore_id] == LCORE_TYPE_INVALID) {
        RTE_LOG(INFO, NAT_LB, "%s: lcore %d not config, exit lcore loop\n", __func__, lcore_id);
        return NAT_LB_OK;
    }

    assert(lcore_array[lcore_id] != NULL);
    RTE_LOG(INFO, NAT_LB, "%s: start lcore %d, type %d\n", __func__, lcore_id, lcore_array[lcore_id]->type);

    // worker线程需要注册rcu lock
    if (lcore_type_array[lcore_id] == LCORE_TYPE_WORK) {
        rte_rcu_qsbr_thread_register(rcu_lock, lcore_id);
        rte_rcu_qsbr_thread_online(rcu_lock, lcore_id);
    }

    uint64_t prev_tsc = 0, slow_pre_tsc = 0, cur_tsc, diff_tsc;
    uint64_t timer_resolution_cycles = rte_get_tsc_hz() / 10;
    uint64_t slow_func_resolution_cycles = rte_get_tsc_hz() * 5;
    struct lcore* lcore = lcore_array[lcore_id];
    for (; true; )
    {
        cur_tsc = rte_rdtsc();

        // run lcore main func
        lcore->main_func(lcore->lcore_cfg);

        // run timer
        diff_tsc = cur_tsc - prev_tsc;
        if (diff_tsc > timer_resolution_cycles) {
            rte_timer_manage();
            prev_tsc = cur_tsc;
        }

        // run lcore slow func
        diff_tsc = cur_tsc - slow_pre_tsc;
        if (diff_tsc > slow_func_resolution_cycles) {
            for (int i = 0; i < lcore->slow_func_n; i++) {
                lcore->slow_funcs[i](lcore->lcore_cfg);
            }
            slow_pre_tsc = cur_tsc;
        }

        // worker线程需要报告rcu qs状态
        if (lcore_type_array[lcore_id] == LCORE_TYPE_WORK) {
            rte_rcu_qsbr_quiescent(rcu_lock, lcore_id);
        }
    }

    // worker线程需要取消注册rcu lock
    if (lcore_type_array[lcore_id] == LCORE_TYPE_WORK) {
        rte_rcu_qsbr_thread_offline(rcu_lock, lcore_id);
        rte_rcu_qsbr_thread_unregister(rcu_lock, lcore_id);
    }
}

static const char* lcore_item_name[4] = {
    "lcore_id",
    "lcore_type",
};

static void lcore_parse_func(struct conf_item *item, toml_table_t *table) {
    toml_datum_t lcore_id = toml_int_in(table, lcore_item_name[0]);
    toml_datum_t lcore_type = toml_int_in(table, lcore_item_name[1]);
    RTE_LOG(INFO, EAL, "%s: add lcore, lcore_id=%ld,lcore_type=%ld\n", __func__, lcore_id.u.i, lcore_type.u.i);

    assert(lcore_type_array[lcore_id.u.i] == 0);
    lcore_type_array[lcore_id.u.i] = lcore_type.u.i;
}

static void init_lcore_parser(void) {
    char conf_name[] = "lcore";
    bzero(&lcore_parser, sizeof(lcore_parser));

    memcpy(lcore_parser.name, conf_name, strlen(conf_name));
    lcore_parser.parse_func = lcore_parse_func;
    add_conf_item_parser(&lcore_parser);
}

static void conf_rx_lcore(void) {
    int rx_lcore_n = 0;
    uint16_t rx_lcore_ids[MAX_LCORE];
    struct rx_lcore_conf* confs[MAX_LCORE];

    memset(confs, 0, sizeof(confs));
    for (int i = 0; i < MAX_LCORE; i++) {
        if (lcore_type_array[i] == LCORE_TYPE_RX) {
            confs[i] = rte_zmalloc("lcore_conf", sizeof(struct rx_lcore_conf), RTE_CACHE_LINE_SIZE);
            if (confs[i] == NULL) {
                rte_exit(EXIT_FAILURE, "%s: no memory\n", __func__);
            }
            rx_lcore_ids[rx_lcore_n] = i;
            ++rx_lcore_n;
        }
    }

    int next_lcore_idx = 0;
    int avail_port = rte_eth_dev_count_avail();
    for (int port_id = 0; port_id < avail_port; port_id++) {
        struct dev_port *port = get_port_by_id(port_id);
        uint16_t lcore_id = rx_lcore_ids[next_lcore_idx];
        struct rx_lcore_conf *lcore_conf = confs[lcore_id];
        lcore_conf->ports[lcore_conf->port_n].port_id = port_id;
        lcore_conf->ports[lcore_conf->port_n].rxq_n = port->rxq_n;
        ++lcore_conf->port_n;

        ++next_lcore_idx;
        if (next_lcore_idx >= rx_lcore_n) {
            next_lcore_idx = 0;
        }
    }

    int slow_func_n = 2;
    lcore_slow_func slow_funcs[] = {
            rxtx_stats_dump,
            port_stats_dump,
    };
    next_lcore_idx = 0;
    for ( ; next_lcore_idx < rx_lcore_n; next_lcore_idx++) {
        uint16_t lcore_id = rx_lcore_ids[next_lcore_idx];
        setup_lcore(LCORE_TYPE_RX, lcore_id, rx_lcore_main_func, confs[lcore_id], slow_func_n, slow_funcs);
    }
}

static void setup_lcore_pkt_in_ring(uint16_t lcore_id, struct rte_ring *work_ring) {
    for (int i = 0; i < MAX_LCORE; i++) {
        if (lcore_type_array[i] == LCORE_TYPE_RX) {
            struct rx_lcore_conf *cfg = (struct rx_lcore_conf*)lcore_array[i]->lcore_cfg;
            cfg->pkt_out_rings[lcore_id] = work_ring;
        }
    }
}

static void conf_work_lcore(void) {
    int work_lcore_n = 0;
    uint16_t work_lcore_ids[MAX_LCORE];
    struct work_lcore_conf* confs[MAX_LCORE];

    memset(confs, 0, sizeof(confs));
    for (int i = 0; i < MAX_LCORE; i++) {
        if (lcore_type_array[i] == LCORE_TYPE_WORK) {
            confs[i] = rte_zmalloc("lcore_conf", sizeof(struct work_lcore_conf), RTE_CACHE_LINE_SIZE);
            if (confs[i] == NULL) {
                rte_exit(EXIT_FAILURE, "%s: no memory\n", __func__);
            }
            work_lcore_ids[work_lcore_n] = i;
            orig_dis_arg.work_lcores[work_lcore_n] = i;
            ++work_lcore_n;
        }
    }
    orig_dis_arg.work_lcore_n = work_lcore_n;

    char ring_name[64];
    struct rte_ring *work_ring;
    int avail_port = rte_eth_dev_count_avail();
    for(int i = 0; i < work_lcore_n; i++) {
        // setup pkt rcv ring
        bzero(ring_name, sizeof(ring_name));
        uint16_t lcore_id = work_lcore_ids[i];
        sprintf(ring_name, "rcv_ring_%d", lcore_id);
        work_ring =  rte_ring_create(ring_name, MAX_RING_SIZE, 0, RING_F_SP_ENQ | RING_F_SC_DEQ);
        if (NULL == work_ring) {
            rte_exit(EXIT_FAILURE, "%s: create work ring for lcore %d failed\n", lcore_id, __func__);
        }
        confs[lcore_id]->pkt_in_ring = work_ring;
        setup_lcore_pkt_in_ring(lcore_id, work_ring);

        // setup tx buffer
        for (int port_id = 0; port_id < avail_port; port_id++) {
            struct rte_eth_dev_tx_buffer *tx_buffer =
                    rte_zmalloc_socket("tx_buffer", RTE_ETH_TX_BUFFER_SIZE(MAX_RX_BURST), 0, rte_eth_dev_socket_id(port_id));
            if (tx_buffer == NULL) {
                rte_exit(EXIT_FAILURE, "%s: create tx buffer for lcore %d port %d failed\n", lcore_id, port_id);
            }
            confs[lcore_id]->tx_buffers[port_id] = tx_buffer;
        }
    }

    int slow_func_n = 1;
    lcore_slow_func slow_funcs[] = {
            rxtx_stats_dump,
    };

    int next_lcore_idx = 0;
    for ( ; next_lcore_idx < work_lcore_n; next_lcore_idx++) {
        uint16_t lcore_id = work_lcore_ids[next_lcore_idx];
        setup_lcore(LCORE_TYPE_WORK, lcore_id, work_lcore_main_func, confs[lcore_id], slow_func_n, slow_funcs);
    }
}

static void setup_work_lcore_sync_out_ring(struct rte_ring* ring) {
    for (int i = 0; i < MAX_LCORE; i++) {
        if (lcore_type_array[i] == LCORE_TYPE_WORK) {
            struct work_lcore_conf* cfg = (struct work_lcore_conf*)lcore_array[i]->lcore_cfg;
            cfg->sync_ct_out_ring = ring;
        }
    }
}

static void setup_work_lcore_sync_in_ring(uint16_t lcore_id, struct rte_ring* ring) {
    struct work_lcore_conf* cfg = (struct work_lcore_conf*)lcore_array[lcore_id]->lcore_cfg;
    cfg->sync_ct_in_ring = ring;
}

static void conf_session_sync_lcore(void) {
    int sync_lcore_n = 0;
    uint16_t sync_lcore_id;
    struct session_sync_lcore_conf* conf;

    for (int i = 0; i < MAX_LCORE; i++) {
        if (lcore_type_array[i] == LCORE_TYPE_SESSION_SYNC) {
            conf = rte_zmalloc("lcore_conf", sizeof(struct session_sync_lcore_conf), RTE_CACHE_LINE_SIZE);
            if (conf == NULL) {
                rte_exit(EXIT_FAILURE, "%s: no memory\n", __func__);
            }
            sync_lcore_id = i;
            ++sync_lcore_n;
        }
    }

    if (sync_lcore_n > 1) {
        rte_exit(EXIT_FAILURE, "%s: only support one sync lcore, conf has %d lcore\n", __func__, sync_lcore_n);
    }

    session_sync_lcore_id = sync_lcore_id;

    // setup ct/arp pkt in ring
    char ring_name[64];
    struct rte_ring* pkt_in_ring;
    bzero(ring_name, sizeof(ring_name));
    sprintf(ring_name, "sync_pkt_in_ring_%d", sync_lcore_id);
    pkt_in_ring = rte_ring_create(ring_name, MAX_RING_SIZE, 0, RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (NULL == pkt_in_ring) {
        rte_exit(EXIT_FAILURE, "%s: create sync pkt in ring for lcore %d failed\n", __func__, sync_lcore_id);
    }
    conf->pkt_in_ring = pkt_in_ring;
    setup_lcore_pkt_in_ring(sync_lcore_id, pkt_in_ring);

    // setup ct out ring
    struct rte_ring* sync_out_ring;
    bzero(ring_name, sizeof(ring_name));
    sprintf(ring_name, "sync_out_ring_%d", sync_lcore_id);
    sync_out_ring =  rte_ring_create(ring_name, MAX_RING_SIZE, 0, RING_F_MP_RTS_ENQ | RING_F_SC_DEQ);
    if (NULL == sync_out_ring) {
        rte_exit(EXIT_FAILURE, "%s: create sync ct out ring for lcore %d failed\n", __func__, sync_lcore_id);
    }
    conf->pending_ring = sync_out_ring;
    setup_work_lcore_sync_out_ring(sync_out_ring);

    // setup worker ct in ring
    struct rte_ring* sync_in_ring;
    for (int i = 0; i < MAX_LCORE; i++) {
        if (lcore_type_array[i] == LCORE_TYPE_WORK) {
            bzero(ring_name, sizeof(ring_name));
            sprintf(ring_name, "sync_in_ring_%d", i);
            sync_in_ring = rte_ring_create(ring_name, MAX_RING_SIZE, 0, RING_F_SP_ENQ | RING_F_SC_DEQ);
            if (NULL == sync_in_ring) {
                rte_exit(EXIT_FAILURE, "%s: create sync ct in ring for lcore %d failed\n", __func__, i);
            }
            conf->ct_in_rings[i] = sync_in_ring;
            setup_work_lcore_sync_in_ring(i, sync_in_ring);
        }
    }

    int slow_func_n = 2;
    lcore_slow_func slow_funcs[] = {
            rxtx_stats_dump,
            flush_sync_skb,
    };

    setup_lcore(LCORE_TYPE_SESSION_SYNC, sync_lcore_id, session_sync_lcore_main_func, conf, slow_func_n, slow_funcs);
}

static void conf_keepalive_lcore(void) {
    int keepalive_lcore_n = 0;
    struct keepalive_lcore_conf* conf;

    for (int i = 0; i < MAX_LCORE; i++) {
        if (lcore_type_array[i] != LCORE_TYPE_KEEPALIVE)
            continue;

        ++keepalive_lcore_n;
        if (keepalive_lcore_n > 1) {
            rte_exit(EXIT_FAILURE, "%s: only support one keepalive lcore, %d is keepalive lcore\n", __func__, keepalive_lcore_n);
        }

        keepalive_lcore_id = i;
        conf = rte_zmalloc("lcore_conf", sizeof(struct keepalive_lcore_conf), RTE_CACHE_LINE_SIZE);
        if (conf == NULL) {
            rte_exit(EXIT_FAILURE, "%s: no memory\n", __func__);
        }
    }

    // setup keepalive pkt in ring
    char ring_name[64];
    struct rte_ring* pkt_in_ring;
    bzero(ring_name, sizeof(ring_name));
    sprintf(ring_name, "keepalive_pkt_in_ring_%d", keepalive_lcore_id);
    pkt_in_ring = rte_ring_create(ring_name, MAX_RING_SIZE, 0, RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (NULL == pkt_in_ring) {
        rte_exit(EXIT_FAILURE, "%s: create keepalive pkt in ring for lcore %d failed\n", __func__, keepalive_lcore_id);
    }
    conf->pkt_in_ring = pkt_in_ring;
    setup_lcore_pkt_in_ring(keepalive_lcore_id, pkt_in_ring);

    int slow_func_n = 1;
    lcore_slow_func slow_funcs[] = {
            rxtx_stats_dump,
    };

    setup_lcore(LCORE_TYPE_KEEPALIVE, keepalive_lcore_id, keepalive_lcore_main_func, conf, slow_func_n, slow_funcs);
}

void conf_lcores(void) {
    conf_rx_lcore();
    conf_work_lcore(); // 必须先初始化rx lcore后才能初始化work lcore
    conf_session_sync_lcore(); // 必须先初始化work lcore后才能初始化session sync lcore
    conf_keepalive_lcore();
}

void start_lcores(void) {
     int ret = rte_eal_mp_remote_launch(lcore_loop, NULL, CALL_MAIN);
     if (ret != 0) {
         rte_exit(EXIT_FAILURE, "%s: launch lcore failed\n", __func__);
     }
}

void lcore_module_init(void) {
    ETHER_TYPE_ARP_BE = ntohs(RTE_ETHER_TYPE_ARP);
    ETHER_TYPE_IPV4_BE = ntohs(RTE_ETHER_TYPE_IPV4);
    create_rcu_lock();
    init_lcore_parser();
}
