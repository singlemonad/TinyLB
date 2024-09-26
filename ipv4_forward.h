//
// Created by tedqu on 24-9-10.
//

#ifndef NAT_LB_IPV4_FORWARD_H
#define NAT_LB_IPV4_FORWARD_H

#include <rte_mbuf.h>
#include "route.h"
#include "skb.h"

int ipv4_forward(sk_buff_t *skb);

#endif //NAT_LB_IPV4_FORWARD_H
