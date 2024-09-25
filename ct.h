//
// Created by tedqu on 24-9-15.
//

#ifndef NAT_LB_CT_H
#define NAT_LB_CT_H

#define CT_DRI_ORIGINAL 0
#define CT_DRI_REPLY 1
#define CT_DRI_COUNT 2

#include <inttypes.h>
#include "list.h"
#include "route.h"

struct ct_tuple{
    uint32_t  src_addr;
    uint32_t dst_addr;

    union {
        struct {
            uint16_t src_port;
            uint16_t dst_port;
        }ports;

        struct {
            uint8_t type;
            uint8_t code;
        }icmp;
    };

    uint32_t gre_key;

    uint8_t dir;
};

struct ct_tuple_hash {
    struct ct_tuple tuple;
    struct list_head tuple_node;
};

struct ct_session {
    struct ct_tuple_hash tuple_hash[CT_DRI_COUNT];

    uint8_t state;
    struct route_entry *rt_entry;
};


void ct_init(void);
struct ct_session* ct_find(struct rte_mbuf* mbuf);
struct ct_session* ct_new(struct rte_mbuf *mbuf);

#define TUPLE_TO_CT(t) \
    (struct ct_session*)container_of(t, struct ct_session, tuple_hash[(t)->tuple.dir]);

#endif //NAT_LB_CT_H
