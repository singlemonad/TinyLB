//
// Created by tedqu on 25-2-27.
//

#include <linux/tcp.h>
#include "../common/util.h"
#include "../common/log.h"
#include "ct.h"

enum ct_tcp_state {
    TCP_CT_NONE = CT_NEW,
    TCP_CT_SYN_SEND = 1,
    TCP_CT_SYN_RCV = 2,
    TCP_CT_ESTABLISHED = 3,
    TCP_CT_FIN_WAIT = 4,
    TCP_CT_CLOSE_WAIT = 5,
    TCP_CT_LAST_ACK = 6,
    TCP_CT_TIME_WAIT = 7,
    TCP_CT_CLOSE = 8,
    TCP_CT_SYN_SEND2 = 9,
    TCP_CT_MAX = 10,
};

enum tcp_bit_set {
    TCP_SYN_SET = 0,
    TCP_SYNACK_SET = 1,
    TCP_FIN_SET = 2,
    TCP_ACK_SET = 3,
    TCP_RST_SET = 4,
    TCP_NONE_SET = 5,
    TCP_BIT_MAX = 6,
};

#define sNO TCP_CT_NONE
#define sSS TCP_CT_SYN_SEND
#define sSR TCP_CT_SYN_RCV
#define sES TCP_CT_ESTABLISHED
#define sFW TCP_CT_FIN_WAIT
#define sCW TCP_CT_CLOSE_WAIT
#define sLA TCP_CT_LAST_ACK
#define sTW TCP_CT_TIME_WAIT
#define sCL TCP_CT_CLOSE
#define sS2 TCP_CT_SYN_SEND2
#define sIV TCP_CT_MAX

static unsigned int tcp_timeouts[TCP_CT_MAX] = {
        [TCP_CT_NONE]		= 0 SECS,
        [TCP_CT_SYN_SEND]	= 60 SECS,
        [TCP_CT_SYN_RCV]	= 60 SECS,
        [TCP_CT_ESTABLISHED]	= 3 HOURS,
        [TCP_CT_FIN_WAIT]	= 2 MINUTES,
        [TCP_CT_CLOSE_WAIT]	= 60 SECS,
        [TCP_CT_LAST_ACK]	= 30 SECS,
        [TCP_CT_TIME_WAIT]	= 2 MINUTES,
        [TCP_CT_CLOSE]		= 10 SECS,
        [TCP_CT_SYN_SEND2]	= 60 SECS,
};

static const uint8_t tcp_ct_state_transfer_map[CT_DRI_COUNT][TCP_BIT_MAX][TCP_CT_MAX] = {
/* original */
        {
                /* sNO、sSS、sSR、sES、sFW、sCW、sLA、sTM、sCL、sS2 */
/* SYN */       {sSS, sSS, sSR, sES, sFW, sCW, sLA, sSS, sSS, sS2},
/* SYNACK */    { sNO, sSS, sSR, sES, sFW, sCW, sLA, sTW, sCL, sSR},
/* FIN */      { sNO, sSS, sFW, sFW, sLA, sLA, sLA, sTW, sCL, sS2 },
/* ACK */       { sES, sS2, sES, sES, sCW, sCW, sTW, sTW, sCL, sS2 },
/* RST */        { sNO, sCL, sCL, sCL, sCL, sCL, sCL, sCL, sCL, sCL },
/* NONE*/    { sNO, sCL, sCL, sCL, sCL, sCL, sCL, sCL, sCL, sCL }
        },

/* reply */
        {
/* SYN */     { sNO, sS2, sSR, sES, sFW, sCW, sLA, sTW, sCL, sS2 },
/* SYNACK */   { sNO, sSR, sSR, sES, sFW, sCW, sLA, sTW, sCL, sSR },
/* FIN */      { sNO, sSS, sFW, sFW, sLA, sLA, sLA, sTW, sCL, sS2 },
/* ACK */      { sNO, sSS, sSR, sES, sCW, sCW, sTW, sTW, sCL, sS2 },
/* RST*/       { sNO, sCL, sCL, sCL, sCL, sCL, sCL, sCL, sCL, sCL },
/* none */    { sNO, sSS, sSR, sES, sFW, sCW, sLA, sTW, sCL, sS2 }
        }
};

static const char *tcp_state_name[] = {
        [sNO] = "NONE",
        [sSS] = "SYN_SENT",
        [sSR] = "SYN_RCV",
        [sES] = "ESTABLISHED",
        [sFW] = "FIN_WAIT",
        [sCW] = "CLOSE_WAIT",
        [sLA] = "LAST_ACK",
        [sTW] = "TIME_WAIT",
        [sCL] = "CLOSE",
        [sS2] = "SYN_SENT2",
};

static unsigned int ct_get_tcp_index(struct tcphdr *tcp) {
    if (tcp->rst) {
        return TCP_RST_SET;
    }
    if (tcp->syn) {
        if (tcp->ack) {
            return TCP_SYNACK_SET;
        }
        return TCP_SYN_SET;
    }
    if (tcp->fin) {
        return TCP_FIN_SET;
    }
    if (tcp->ack) {
        return TCP_ACK_SET;
    }
    return TCP_NONE_SET;
}

static struct ct_tuple tcp_gen_tuple(struct sk_buff *skb, bool reverse) {
    struct rte_ipv4_hdr *iph;
    struct ct_tuple tuple;
    uint16_t *ports;

    iph = rte_pktmbuf_mtod((struct rte_mbuf*)skb, struct rte_ipv4_hdr*);
    tuple.proto = IPPROTO_TCP;
    if (!reverse) {
        tuple.src_addr = iph->src_addr;
        tuple.dst_addr = iph->dst_addr;
        ports = (uint16_t *) &iph[1];
        tuple.ports.src_port = ports[0];
        tuple.ports.dst_port = ports[1];
    } else {
        tuple.src_addr = iph->dst_addr;
        tuple.dst_addr = iph->src_addr;
        ports = (uint16_t *)&iph[1];
        tuple.ports.src_port = ports[1];
        tuple.ports.dst_port = ports[0];
    }
    return tuple;
}

static bool is_tcp_tuple_equal(struct ct_tuple_hash *lhs, struct ct_tuple *rhs) {
    if (lhs->tuple.ports.src_port == rhs->ports.src_port &&
        lhs->tuple.ports.dst_port == rhs->ports.dst_port) {
        return true;
    }
    return false;
}

static int tcp_pkt_in(struct sk_buff *skb, struct per_lcore_ct_ctx *ctx) {
    struct rte_ipv4_hdr *iph = rte_pktmbuf_mtod((struct rte_mbuf*)skb, struct rte_ipv4_hdr*);
    unsigned int index = ct_get_tcp_index((struct tcphdr*)&iph[1]);
    unsigned int new_state = tcp_ct_state_transfer_map[ctx->tuple_hash->tuple.dir][index][ctx->ct->state];
    if (ctx->ct->state != new_state) {
        LOG_BUFF(buff);
        RTE_LOG(INFO, CT, "State transfer %s->%s, CT(%s).\n", tcp_state_name[ctx->ct->state], tcp_state_name[new_state], ct_to_str(ctx->ct, buff));
    }
    ctx->ct->state = new_state;
    ctx->ct->timeout = tcp_timeouts[ctx->ct->state];
    return NAT_LB_OK;
}

static int tcp_pkt_new(struct sk_buff *skb, struct per_lcore_ct_ctx *ctx) {
    if (ctx->ct->state == CT_NEW) {
        LOG_BUFF(buff);
        RTE_LOG(INFO, CT, "State transfer %s->%s, CT(%s).\n", tcp_state_name[ctx->ct->state], tcp_state_name[TCP_CT_SYN_SEND], ct_to_str(ctx->ct, buff));

        ctx->ct->state = TCP_CT_SYN_SEND;
    }
    return NAT_LB_OK;
}

struct ct_l4_proto tcp_l4_proto = {
        .gen_tuple = tcp_gen_tuple,
        .is_tuple_equal = is_tcp_tuple_equal,
        .pkt_in = tcp_pkt_in,
        .pkt_new = tcp_pkt_new,
};
