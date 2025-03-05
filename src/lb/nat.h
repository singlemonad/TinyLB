//
// Created by tedqu on 25-3-4.
//

#ifndef NAT_LB_NAT_H
#define NAT_LB_NAT_H

#include "../common/skb.h"
#include "../ct/ct.h"

typedef int(*rewrite_func)(struct sk_buff *skb, void *arg);

enum rewrite_type {
    SNAT_REWRITE,
    DNAT_REWRITE,
    INVALID_REWRITE,
};

struct rewrite {
    enum rewrite_type rewrite_type;
    enum ct_ext_type ext_type;
    rewrite_func func;
};

struct snat_rewrite_data {
    uint32_t src_ip;
    uint32_t port;
};

struct dnat_rewrite_data{
    uint32_t dst_ip;
    uint16_t port;
};

int dnat(sk_buff_t *skb, void *arg);
int snat(sk_buff_t *skb, void *arg);

#endif //NAT_LB_NAT_H
