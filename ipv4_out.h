//
// Created by tedqu on 24-9-10.
//

#ifndef NAT_LB_IPV4_OUT_H
#define NAT_LB_IPV4_OUT_H

#include <rte_mbuf.h>
#include "route.h"
#include "flow.h"

int ipv4_xmit(struct rte_mbuf *mbuf, struct flow4 *fl4);
int ipv4_output(struct rte_mbuf *mbuf, struct route_entry *rt_entry);

#endif //NAT_LB_IPV4_OUT_H
