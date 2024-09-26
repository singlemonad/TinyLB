//
// Created by tedqu on 24-9-10.
//

#ifndef NAT_LB_IPV4_OUT_H
#define NAT_LB_IPV4_OUT_H

#include <rte_mbuf.h>
#include "route.h"
#include "flow.h"
#include "skb.h"

int ipv4_xmit(sk_buff_t *skb, struct flow4 *fl4);
int ipv4_output(sk_buff_t *skb);

#endif //NAT_LB_IPV4_OUT_H
