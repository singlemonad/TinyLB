//
// Created by tedqu on 24-9-12.
//

#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <rte_ip.h>
#include <rte_icmp.h>
#include "icmp.h"
#include "../common/util.h"
#include "../ipv4/ipv4.h"

#define MAX_ICMP_CTRL

struct icmp_handler {
    int (*handler)(sk_buff_t *skb, struct rte_ipv4_hdr *iph);
};

static int icmp_echo(sk_buff_t *skb, struct rte_ipv4_hdr *iph) {
    struct rte_icmp_hdr *ich;
    uint16_t c_sum;
    struct flow4 fl4;

    ich = rte_pktmbuf_mtod((struct rte_mbuf*)skb, struct rte_icmp_hdr*);
    ich->icmp_type = RTE_IP_ICMP_ECHO_REPLY;
    ich->icmp_cksum = 0;
    c_sum = rte_raw_cksum(ich, skb->mbuf.pkt_len);
    ich->icmp_cksum = (c_sum == 0xffff) ? c_sum : ~c_sum;

    memset(&fl4, 0, sizeof(struct flow4));
    fl4.src_addr = iph->dst_addr;
    fl4.dst_addr = iph->src_addr;
    fl4.flc.proto = IPPROTO_ICMP;

    return ipv4_local_out(skb, &fl4);
}

static struct icmp_handler icmp_ctrl[MAX_ICMP_CTRL] = {
        [ICMP_ECHO] = {
            .handler = icmp_echo
        }
};

static int icmp_rcv(sk_buff_t *skb, struct rte_ipv4_hdr *iph) {
    struct rte_icmp_hdr *ich;
    unsigned char icmp_type;
    struct icmp_handler *handler;

    ich = rte_pktmbuf_mtod((struct rte_mbuf*)skb, struct rte_icmp_hdr*);

    icmp_type = ich->icmp_type;
    handler = &icmp_ctrl[icmp_type];
    if (NULL == handler) {
        goto drop;
    }
    return handler->handler(skb, iph);

drop:
    rte_pktmbuf_free((struct rte_mbuf*)skb);

    return NAT_LB_OK;
}

static struct l4_handler icmp_proto = {
        .rcv = icmp_rcv,
};

void icmp_init(void) {
    inet_register_l4_handler(&icmp_proto, IPPROTO_ICMP);
}
