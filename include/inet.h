//
// Created by tedqu on 24-9-12.
//

#ifndef NAT_LB_INET_H
#define NAT_LB_INET_H

#include <rte_mbuf.h>
#include <rte_ip.h>
#include "skb.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DEFAULT_TIME_LIVE_TTL 64

struct l3_handler {
    int (*rcv) (sk_buff_t *skb);
};


void inet_register_l3_handler(struct l3_handler *handler, uint16_t pkt_type);
int inet_pkt_rcv(sk_buff_t *skb);

#endif //NAT_LB_INET_H
