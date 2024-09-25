//
// Created by tedqu on 24-9-10.
//

#ifndef NAT_LB_IPV4_FORWARD_H
#define NAT_LB_IPV4_FORWARD_H

#include <rte_mbuf.h>
#include "route.h"

int ipv4_forward(struct rte_mbuf *mbuf, struct route_entry *rt_entry);

#endif //NAT_LB_IPV4_FORWARD_H
