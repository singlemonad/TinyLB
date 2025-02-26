//
// Created by tedqu on 24-9-9.
//

#ifndef NAT_LB_IPV4_H
#define NAT_LB_IPV4_H

#include "../common/skb.h"

#ifdef __cplusplus
extern "C" {
#endif

struct l4_handler {
    int (*rcv)(sk_buff_t *skb, struct rte_ipv4_hdr *iph);
};

void ipv4_init(void);
int ipv4_local_out(sk_buff_t *skb, struct flow4 *fl4);
int ipv4_output(sk_buff_t *skb, struct rt_cache *rt);
int inet_register_l4_handler(struct l4_handler *handler, unsigned char protocol);

#endif //NAT_LB_IPV4_H
