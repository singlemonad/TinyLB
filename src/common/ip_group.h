//
// Created by tedqu on 25-4-8.
//

#ifndef NAT_LB_IP_GROUP_H
#define NAT_LB_IP_GROUP_H

#include <inttypes.h>
#include "list.h"
#include "const.h"

struct sk_buff;

#define SKB_MAX_RECEIVER 4

enum ip_type {
    IP_TYPE_INVALID = 0,
    IP_TYPE_SVC = 1,
    IP_TYPE_SNAT = 2,
    IP_TYPE_SESSION_SYNC = 3,
    IP_TYPE_KEEPALIVE = 4,
    IP_TYPE_MAX = 5,
};

struct ip_group {
    enum ip_type type;
    uint32_t ip;
    struct list_head node;
};

struct original_skb_dis_arg {
    int work_lcore_n;
    uint16_t work_lcores[MAX_LCORE];
};

typedef uint16_t (*dispatch_func)(struct sk_buff* skb, void* arg);

int add_ip_group(enum ip_type type, uint32_t ip);
enum ip_type get_ip_group_type(uint32_t ip);
int get_rcv_lcore_id(struct sk_buff* skb, void* arg);
void ip_group_module_init(void);

#endif //NAT_LB_IP_GROUP_H
