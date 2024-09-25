//
// Created by tedqu on 24-9-9.
//

#ifndef NAT_LB_ROUTE_H
#define NAT_LB_ROUTE_H

#include "list.h"
#include "flow.h"
#include "dev.h"

#define RTF_LOCAL 0x0001
#define RTF_FORWARD 0x0002

struct route_entry {
    uint32_t id;
    uint32_t dst_addr; // 目的地址
    uint16_t mask; // 掩码
    unsigned long mtu;
    uint32_t gw; // 0表示直连路由，非0表示下一跳网关地址
    uint32_t src; // 源地址
    struct dev_port *port; // 出口设备
    uint16_t metric;
    uint32_t flags;
    struct list_head route_list_node;
};

void route_init(int socket_id);

int route_add(uint32_t dst_addr, uint16_t mask, unsigned long mtu, uint32_t gw,
              uint32_t src, struct dev_port *port, uint16_t metric, uint32_t flags);

int route_del(uint32_t dst_addr, uint16_t mask);

/* Client -> NAT-LB -> RS */
struct route_entry* route_ingress_lockup(struct flow4* fl);

/* RS -> NAT-LB -> Client */
struct route_entry* route_egress_lockup(struct  flow4* fl);

#endif //NAT_LB_ROUTE_H
