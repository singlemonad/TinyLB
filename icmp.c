//
// Created by tedqu on 24-9-12.
//

#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <rte_ip.h>
#include <rte_icmp.h>
#include "icmp.h"
#include "common.h"
#include "inet.h"
#include "flow.h"
#include "dev.h"
#include "ipv4_out.h"

#define MAX_ICMP_CTRL

struct icmp_handler {
    bool is_error;
    int (*handler)(struct rte_mbuf*, struct rte_ipv4_hdr *iph);
};

static int icmp_echo(struct rte_mbuf *mbuf, struct rte_ipv4_hdr *iph) {
    struct rte_icmp_hdr *ich;
    uint16_t c_sum;
    struct flow4 fl4;

    ich = rte_pktmbuf_mtod(mbuf, struct rte_icmp_hdr*);
    ich->icmp_type = RTE_IP_ICMP_ECHO_REPLY;
    ich->icmp_cksum = 0;
    c_sum = rte_raw_cksum(ich, mbuf->pkt_len);
    ich->icmp_cksum = (c_sum == 0xffff) ? c_sum : ~c_sum;

    memset(&fl4, 0, sizeof(struct flow4));
    fl4.src_addr = iph->dst_addr;
    fl4.dst_addr = iph->src_addr;
    fl4.flc.flc_oif = get_port_by_id(mbuf->port);
    fl4.flc.proto = IPPROTO_ICMP;

    return ipv4_xmit(mbuf, &fl4);

    return NAT_LB_OK;
}

static struct icmp_handler icmp_ctrl[MAX_ICMP_CTRL] = {
        [ICMP_ECHO] = {
            .handler = icmp_echo
        }
};

static int icmp_rcv(struct rte_mbuf *mbuf, struct rte_ipv4_hdr *iph) {
    struct rte_icmp_hdr *ich;
    unsigned char icmp_type;
    struct icmp_handler *handler;

    ich = rte_pktmbuf_mtod(mbuf, struct rte_icmp_hdr*);

    icmp_type = ich->icmp_type;
    handler = &icmp_ctrl[icmp_type];
    if (NULL == handler) {
        goto drop;
    }
    return handler->handler(mbuf, iph);

drop:
    rte_pktmbuf_free(mbuf);

    return NAT_LB_OK;
}

static struct inet_protocol icmp_proto = {
        .handler = icmp_rcv,
};

void icmp_init(void) {
    register_protocol(&icmp_proto, IPPROTO_ICMP);
}
