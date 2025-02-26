//
// Created by tedqu on 24-9-7.
//

#ifndef NAT_LB_COMMON_H
#define NAT_LB_COMMON_H

#include <inttypes.h>
#include "skb.h"

#ifdef __cplusplus
extern "C" {
#endif

#define  likely(x)        __builtin_expect(!!(x), 1)
#define  unlikely(x)      __builtin_expect(!!(x), 0)

enum {
    NAT_LB_OK = 0,
    NAT_LB_INVALID = -1,
    NAT_LB_EXIST = -2,
    NAT_LB_NOMEM = -3,
    NAT_LB_NOT_EXIST = -4,
    NAT_LB_NO_ROUTE = -5,
    NAT_LB_CT_MISS = -6,
    NAT_LB_NO_SNAT_PORT = -7,
};

void show_pkt(sk_buff_t *pkt);
uint32_t ip_to_int(char *str);
void show_ip(rte_be32_t addr);

#endif //NAT_LB_COMMON_H
