//
// Created by tedqu on 24-9-10.
//

#include "ipv4_out.h"
#include "ipv4_forward.h"

int ipv4_forward(struct rte_mbuf *mbuf, struct route_entry *rt_entry) {
    return ipv4_output(mbuf, rt_entry);
}