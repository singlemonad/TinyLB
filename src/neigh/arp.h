//
// Created by tedqu on 24-9-15.
//

#ifndef NAT_LB_ARP_H
#define NAT_LB_ARP_H

#include "../common/skb.h"

struct dev_port;

#ifdef __cplusplus
extern "C" {
#endif

void arp_init(void);
int arp_send(struct dev_port *port, uint32_t src_ip, uint32_t dst_ip);

#endif //NAT_LB_ARP_H
