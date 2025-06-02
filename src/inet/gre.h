//
// Created by tedqu on 25-3-5.
//

#ifndef NAT_LB_GRE_H
#define NAT_LB_GRE_H

#include "../common/skb.h"

void gre_init(void);
int uncap_gre(sk_buff_t *skb, struct rte_ipv4_hdr *iph);

#endif //NAT_LB_GRE_H
