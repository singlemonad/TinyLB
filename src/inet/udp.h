//
// Created by tedqu on 25-3-7.
//

#ifndef NAT_LB_UDP_H
#define NAT_LB_UDP_H

#include "../common/list.h"
#include "../common/skb.h"

struct udp_out_args {
    uint32_t src_ip;
    uint16_t src_port;
    uint32_t dst_ip;
    uint16_t dst_port;
};

typedef int(*udp_handler)(struct sk_buff *skb);

struct udp_pkt_handler {
    struct list_head node;
    uint16_t port;
    udp_handler rcv;
};

void udp_init(void);
int udp_out(struct sk_buff *skb, struct udp_out_args *args);
void udp_pkt_handler_register(struct udp_pkt_handler *handler);

#endif //NAT_LB_UDP_H
