//
// Created by tedqu on 25-3-12.
//

#ifndef NAT_LB_TCP_H
#define NAT_LB_TCP_H

#include "../common/skb.h"

struct tcp_hdr {
    uint16_t source;
    uint16_t dest;
    uint32_t seq;
    uint32_t ack_seq;
    uint16_t res1:4,
            doff:4,
            fin:1,
            syn:1,
            rst:1,
            psh:1,
            ack:1,
            urg:1,
            ece:1,
            cwr:1;
    uint16_t window;
    uint16_t check;
    uint16_t urg_ptr;
};

typedef int(*tcp_handler)(struct tcp_hdr *tcp, struct sk_buff *skb);

struct tcp_pkt_handler {
    struct list_head node;
    uint16_t port;
    tcp_handler rcv;
};

void tcp_pkt_handler_register(struct tcp_pkt_handler *handler);
void tcp_init(void);
int send_syn(uint32_t src_ip, uint16_t src_port, uint32_t dst_ip, uint16_t dst_port);
int send_rst(uint32_t src_ip, uint16_t src_port, uint32_t dst_ip, uint16_t dst_port);

#endif //NAT_LB_TCP_H

