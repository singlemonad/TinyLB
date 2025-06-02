//
// Created by tedqu on 24-9-30.
//

#ifndef NAT_LB_SA_POOL_H
#define NAT_LB_SA_POOL_H

#include <inttypes.h>
#include "../common/list.h"
#include "svc.h"

#ifdef __cplusplus
extern "C" {
#endif


int snat_addr_add(unsigned lcore_id, uint32_t snat_ip);
int snat_addr_del(unsigned lcore_id, uint32_t snat_ip);
int snat_addr_get(uint16_t proto, uint32_t rs_ip, uint16_t rs_port, struct snat_pool_array* snat_pools, uint32_t *snat_ip, uint16_t *snat_port);
void snat_addr_free(unsigned lcore_id, uint32_t snat_ip ,uint16_t snat_port);
unsigned snat_addr_lcore(uint32_t snat_ip);
void sa_pool_init(void);
int create_snat_pool_for_rs(struct rs* rs);

#endif //NAT_LB_SA_POOL_H
