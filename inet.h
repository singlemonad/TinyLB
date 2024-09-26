//
// Created by tedqu on 24-9-12.
//

#ifndef NAT_LB_INET_H
#define NAT_LB_INET_H

#include <rte_mbuf.h>
#include <rte_ip.h>
#include "skb.h"

#define DEFAULT_TIME_LIVE_TTL 64

struct inet_protocol {
    int (*handler)(sk_buff_t *skb, struct rte_ipv4_hdr *iph);
};

int register_protocol(struct inet_protocol *proto, unsigned char protocol);
struct inet_protocol* get_protocol(unsigned char protocol);

#endif //NAT_LB_INET_H
