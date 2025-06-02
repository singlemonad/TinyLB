//
// Created by tedqu on 24-9-7.
//

#ifndef NAT_LB_UTIL_H
#define NAT_LB_UTIL_H

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
    NAT_LB_FAILED = -8,
    NAT_LB_DROP = -9,
};

#define LOG_BUFF(name) \
    char name[1024]; memset(name, 0, 1024)

void print_pkt(sk_buff_t *pkt);
void print_ip(rte_be32_t addr);
uint32_t be_ip_to_int(char *str);
char* ip_to_str(uint32_t ip);
uint32_t ip_to_int(char *addr);
char* be_ip_to_str(uint32_t ip);
char* protocol_to_str(uint8_t proto);
void hex_str_to_mac(char *dst, char *src);
void print_mac(struct rte_ether_addr *addr);

uint32_t ip_to_int_be(char *addr);

#endif //NAT_LB_UTIL_H
