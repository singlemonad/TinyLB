//
// Created by tedqu on 24-9-9.
//

#ifndef NAT_LB_FLOW_H
#define NAT_LB_FLOW_H

#include "dev.h"

#ifdef __cplusplus
extern "C" {
#endif

union flow_ul {
    struct {
        uint16_t src_port;
        uint16_t dst_port;
    }ports;

    struct {
        uint8_t type;
        uint8_t code;
    }icmp;

    uint32_t gre_key;
};

struct flow_common {
    struct dev_port *flc_oif;
    struct dev_port *flc_iif;
    uint8_t tos;
    uint8_t proto;
    uint8_t scope;
    uint8_t ttl;
    uint32_t mark;
    uint32_t flag;
};

struct flow4 {
    struct flow_common flc;
    uint32_t src_addr;
    uint32_t dst_addr;
    union flow_ul fl_ul;
};

#endif //NAT_LB_FLOW_H
