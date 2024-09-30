//
// Created by tedqu on 24-9-30.
//

#ifndef NAT_LB_SA_POOL_H
#define NAT_LB_SA_POOL_H

#include <inttypes.h>
#include "list.h"

#define PORT_MIN  49152
#define PORT_MAX  65535
#define PORT_BIT_MAP_SIZE  ((PORT_MAX - PORT_MIN) / 8)

typedef struct snat_addr {
    uint32_t snat_ip;
    uint8_t port_bit_map[PORT_BIT_MAP_SIZE];
}snat_addr_t;

typedef struct sa {
    uint32_t dst_ip;
    uint16_t dst_port;
    snat_addr_t *snat_addr;
    struct list_head sa_node;
}sa_t;

int snat_addr_add(uint32_t dst_ip, uint16_t dst_port, uint32_t snat_ip);
int snat_addr_del(uint32_t dst_ip, uint16_t dst_port);
int snat_addr_get(uint32_t dst_ip, uint16_t dst_port, uint32_t *snat_ip, uint16_t *snat_port);
void sa_pool_init(void);

#endif //NAT_LB_SA_POOL_H
