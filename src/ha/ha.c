//
// Created by tedqu on 25-3-11.
//

#include <rte_hash_crc.h>
#include <rte_malloc.h>
#include <toml.h>
#include "../common/util.h"
#include "../common/log.h"
#include "../common/conf.h"
#include "../inet/ipv4.h"
#include "../inet/tcp.h"
#include "ha.h"

#define MAX_RS_DETECT_BUCKET 512

#define DETECT_INTERVAL 3
#define DETECT_RCV_TIMEOUT 1

extern struct rte_mempool *socket_pkt_mbuf_pool[2];
static struct list_head detects[MAX_RS_DETECT_BUCKET];
static struct ha_ctx ha_ctx;
static struct conf_item ha_conf_parser;

static void tcp_rs_do_detect(struct rte_timer *timer, void *arg);
static struct detect_rs* find_detect_rs(uint8_t proto, uint32_t rs_ip, uint16_t rs_port);

static struct sk_buff* gen_tcp_detect_skb(uint16_t dst_port) {
    struct sk_buff *skb;
    struct rte_tcp_hdr *tcp;

    skb = (struct sk_buff*) rte_pktmbuf_alloc(ha_ctx.ha_mbuf_pool);
    if (NULL == skb) {
        RTE_LOG(ERR, NAT_LB, "%s, alloc skb failed, %s\n", __func__, rte_strerror(rte_errno));
        return NULL;
    }

    skb->flags |= SKB_KEEPALIVE;
    tcp = (struct rte_tcp_hdr*)rte_pktmbuf_append(&skb->mbuf, sizeof(struct rte_tcp_hdr));
    bzero(tcp, sizeof(struct rte_tcp_hdr));
    tcp->src_port = ha_ctx.src_port;
    tcp->dst_port = dst_port;
    tcp->sent_seq = htonl(ha_ctx.seq);
    tcp->recv_ack = 0;
    tcp->data_off = (5 << 4);
    tcp->tcp_flags = RTE_TCP_SYN_FLAG;
    tcp->rx_win = htons(ha_ctx.rcv_size);
    skb->calc_l4_checksum = true;
    return skb;
}

static void tcp_rs_rcv_timeout(struct rte_timer *timer, void *arg) {
    struct detect_rs *rs;

    rs = (struct detect_rs*)(arg);
    // RTE_LOG(DEBUG, NAT_LB, "%s: rs timeout, rs_ip=%s,rs_port=%d\n", __func__, be_ip_to_str(rs->rs_ip), ntohs(rs->rs_port));
    rs->rs_status = FAILED;
    rte_timer_reset(&rs->timer, rte_get_timer_hz() * DETECT_INTERVAL,
                    SINGLE, ha_ctx.lcore_id, tcp_rs_do_detect, rs);
}

static void tcp_rs_do_detect(struct rte_timer *timer, void *arg) {
    struct detect_rs *rs;
    struct sk_buff *skb;
    struct flow4 fl4;
    int ret;

    rs = (struct detect_rs*)(arg);
    // RTE_LOG(DEBUG, NAT_LB, "%s: do detect, rs_ip=%s,rs_port=%d\n", __func__, be_ip_to_str(rs->rs_ip), ntohs(rs->rs_port));
    skb = gen_tcp_detect_skb(rs->rs_port);
    if (NULL == skb) {
        goto failed;
    }

    ret = rte_timer_reset(&rs->timer, rte_get_timer_hz() * DETECT_RCV_TIMEOUT,
                    SINGLE, ha_ctx.lcore_id, tcp_rs_rcv_timeout, rs);
    if (ret != NAT_LB_OK) {
        RTE_LOG(ERR, NAT_LB, "%s: reset timer failed %s, rs_ip=%s,rs_port=%d\n", __func__, rte_strerror(rte_errno), be_ip_to_str(rs->rs_ip), ntohs(rs->rs_port));
    }
    bzero(&fl4, sizeof(struct flow4));
    fl4.flc.proto = IPPROTO_TCP;
    fl4.dst_addr = rs->rs_ip;
    fl4.src_addr = ha_ctx.src_ip;
    ipv4_local_out(skb, &fl4);
    return;

failed:
    rte_timer_reset(&rs->timer, rte_get_timer_hz() * DETECT_INTERVAL,
                    SINGLE, ha_ctx.lcore_id, tcp_rs_do_detect, rs);
}

static struct sk_buff* gen_tcp_reset_skb(uint32_t seq, uint32_t ack, struct detect_rs *rs) {
    struct sk_buff *skb;
    struct rte_tcp_hdr *tcp;

    skb = (struct sk_buff*) rte_pktmbuf_alloc(ha_ctx.ha_mbuf_pool);
    if (NULL == skb) {
        RTE_LOG(ERR, NAT_LB, "%s, alloc skb failed, %s\n", __func__, rte_strerror(rte_errno));
        return NULL;
    }
    skb->flags |= SKB_KEEPALIVE;

    tcp = (struct rte_tcp_hdr*)rte_pktmbuf_append(&skb->mbuf, sizeof(struct rte_tcp_hdr));
    bzero(tcp, sizeof(struct rte_tcp_hdr));
    tcp->src_port = ha_ctx.src_port;
    tcp->dst_port = rs->rs_port;
    tcp->tcp_flags = RTE_TCP_RST_FLAG;
    tcp->sent_seq = htonl(seq);
    tcp->recv_ack = htonl(ack);
    tcp->rx_win = htons(ha_ctx.rcv_size);
    tcp->data_off = (5<<4);
    skb->calc_l4_checksum = true;
    return skb;
}

static void tcp_rs_reset(struct tcp_hdr *tcp, struct detect_rs *rs) {
    struct sk_buff *skb;
    struct flow4 fl4;

    // RTE_LOG(DEBUG, NAT_LB, "%s: send rst, rs_ip=%s,rs_port=%d\n", __func__, be_ip_to_str(rs->rs_ip), ntohs(rs->rs_port));
    skb = gen_tcp_reset_skb(ntohl(tcp->ack_seq) + 1, ntohl(tcp->seq) + 1, rs);
    if (NULL == skb) {
        RTE_LOG(ERR, NAT_LB, "%s: send tcp rst failed\n", __func__ );
        return;
    }

    bzero(&fl4, sizeof(struct flow4));
    fl4.flc.proto = IPPROTO_TCP;
    fl4.dst_addr = rs->rs_ip;
    fl4.src_addr = ha_ctx.src_ip;
    ipv4_local_out(skb, &fl4);
}

static void tcp_rs_rst_rcv(struct tcp_hdr *tcp, struct detect_rs *rs) {
    // RTE_LOG(DEBUG, NAT_LB, "%s: rcv rst, rs_ip=%s,rs_port=%d\n", __func__, be_ip_to_str(rs->rs_ip), ntohs(rs->rs_port));
    rs->rs_status = FAILED;
    rte_timer_reset(&rs->timer, rte_get_timer_hz() * DETECT_INTERVAL,
                    SINGLE, ha_ctx.lcore_id, tcp_rs_do_detect, rs);
}

static void tcp_rs_ack_rcv(struct tcp_hdr *tcp, struct detect_rs *rs) {
    // RTE_LOG(DEBUG, NAT_LB, "%s: rcv ack, rs_ip=%s,rs_port=%d\n", __func__, be_ip_to_str(rs->rs_ip), ntohs(rs->rs_port));
    rs->rs_status = HEALTHY;
    rte_timer_reset(&rs->timer, rte_get_timer_hz() * DETECT_INTERVAL,
                    SINGLE, ha_ctx.lcore_id, tcp_rs_do_detect, rs);
    tcp_rs_reset(tcp, rs);
}

static int ha_pkt_rcv(struct tcp_hdr *tcp, struct sk_buff *skb) {
    struct detect_rs *rs;
    struct rte_ipv4_hdr *iph;

    // RTE_LOG(DEBUG, NAT_LB, "%s: rcv ha pkt\n", __func__);

    iph = (struct rte_ipv4_hdr*)skb->iph;
    rs = find_detect_rs(IPPROTO_TCP, iph->src_addr, tcp->source);
    if (NULL == rs) {
        RTE_LOG(ERR, NAT_LB, "%s: no rs found for dst_ip %s, dst_port %d\n", __func__, be_ip_to_str(iph->src_addr), ntohs(tcp->source));
        return NAT_LB_NOT_EXIST;
    }

    if (tcp->rst) {
        tcp_rs_rst_rcv(tcp, rs);
    } else if (tcp->syn && tcp->ack) {
        tcp_rs_ack_rcv(tcp, rs);
    }
    return NAT_LB_OK;
}

static void udp_rs_do_detect(struct rte_timer *timer, void *arg) {

}

static void udp_rs_unreachable_rcv(struct detect_rs *detect) {

}

static void udp_rs_rcv_timeout(struct rte_timer *timer, void *arg) {

}

static uint32_t get_detect_rs_hash(uint8_t proto, uint32_t rs_ip, uint16_t rs_port) {
    return rte_hash_crc_4byte(rs_port, (proto << 16) | rs_port) % MAX_RS_DETECT_BUCKET;
}

static struct detect_rs* find_detect_rs(uint8_t proto, uint32_t rs_ip, uint16_t rs_port) {
    struct detect_rs *rs;
    uint32_t hash;

    hash = get_detect_rs_hash(proto, rs_ip, rs_port);
    list_for_each_entry(rs, &detects[hash], node) {
        if (rs->proto == proto &&
            rs->rs_ip == rs_ip &&
            rs->rs_port == rs_port) {
            return rs;
        }
    }
    return NULL;
}

static struct detect_rs* detect_rs_alloc(void) {
    struct detect_rs *rs;

    rs = rte_zmalloc("detect", sizeof(struct detect_rs), RTE_CACHE_LINE_SIZE);
    if (NULL == rs) {
        RTE_LOG(ERR, NAT_LB, "%s: no memory\n", __func__ );
        return NULL;
    }
    return rs;
}

int add_detect_rs(uint8_t proto, uint32_t rs_ip, uint16_t rs_port) {
    struct detect_rs *rs;
    uint32_t hash;
    rte_timer_cb_t detect_cb;

    rs = find_detect_rs(proto, rs_ip, rs_port);
    if (NULL != rs) {
        return NAT_LB_EXIST;
    }

    rs = detect_rs_alloc();
    if (NULL == rs) {
        return NAT_LB_NOMEM;
    }

    INIT_LIST_HEAD(&rs->node);
    rs->proto = proto;
    rs->rs_ip = rs_ip;
    rs->rs_port = rs_port;
    rte_timer_init(&rs->timer);
    rs->rs_status = UNKNOWN;
    rs->detect_stage = TO_DETECT;
    hash = get_detect_rs_hash(proto, rs_ip, rs_port);
    list_add(&rs->node, &detects[hash]);

    if (proto == IPPROTO_UDP) {
        detect_cb = udp_rs_do_detect;
    } else {
        detect_cb = tcp_rs_do_detect;
    }
    rte_timer_reset(&rs->timer, rte_get_timer_hz() * DETECT_INTERVAL, SINGLE,
                    ha_ctx.lcore_id, detect_cb, rs);
    return NAT_LB_OK;
}

int remove_detect_rs(uint8_t proto, uint32_t rs_ip, uint16_t rs_port) {
    struct detect_rs *rs;

    rs = find_detect_rs(proto, rs_ip, rs_port);
    if (NULL == rs) {
        return NAT_LB_NOT_EXIST;
    }

    list_del(&rs->node);
    rte_timer_stop(&rs->timer);
    rte_free(rs);
    return NAT_LB_OK;
}

static struct tcp_pkt_handler ha_pkt_handler;

static const char* ha_item_name[3] = {
        "src_ip",
        "src_port_base",
        "lcore_id"
};

static void ha_parse_func(struct conf_item *item, toml_table_t *table) {
    toml_datum_t src_ip = toml_string_in(table, ha_item_name[0]);
    toml_datum_t src_port = toml_int_in(table, ha_item_name[1]);
    toml_datum_t lcore_id = toml_int_in(table, ha_item_name[2]);
    RTE_LOG(INFO, NAT_LB, "%s: add ha, src_ip=%s,src_port_base=%d,lcore_id=%d\n", __func__, src_ip.u.s, src_port.u.i, lcore_id.u.i);

    uint32_t src_ip_be = ip_to_int_be(src_ip.u.s);
    uint16_t src_port_be = htons(src_port.u.i);

    ha_ctx.src_ip = src_ip_be;
    ha_ctx.src_port = src_port_be;
    ha_ctx.lcore_id = lcore_id.u.i;
    add_ip_group(IP_TYPE_KEEPALIVE, ha_ctx.src_ip); // 用于分流健康检查报文

    // 注册tcp 6000端口处理函数
    INIT_LIST_HEAD(&ha_pkt_handler.node);
    ha_pkt_handler.port = ha_ctx.src_port;
    ha_pkt_handler.rcv = ha_pkt_rcv;
    tcp_pkt_handler_register(&ha_pkt_handler);
}

static void init_ha_parser(void) {
    char conf_name[] = "ha";
    bzero(&ha_conf_parser, sizeof(ha_conf_parser));

    memcpy(ha_conf_parser.name, conf_name, strlen(conf_name));
    ha_conf_parser.parse_func = ha_parse_func;
    add_conf_item_parser(&ha_conf_parser);
}

void ha_module_init(uint32_t src_port) {
    int idx = 0;

    for (; idx < MAX_RS_DETECT_BUCKET; idx++) {
        INIT_LIST_HEAD(&detects[idx]);
    }

    init_ha_parser();

    ha_ctx.ha_mbuf_pool = socket_pkt_mbuf_pool[0];
    ha_ctx.seq = 9999;
    ha_ctx.rcv_size = 1600;
}