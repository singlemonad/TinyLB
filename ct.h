//
// Created by tedqu on 24-9-15.
//

#ifndef NAT_LB_CT_H
#define NAT_LB_CT_H

#define CT_DRI_ORIGINAL 0
#define CT_DRI_REPLY 1
#define CT_DRI_COUNT 2

#define MAX_CT_ACTION 8

#include <inttypes.h>
#include "list.h"
#include "route.h"
#include "skb.h"

struct sk_buff;
struct sk_ext_info;

enum ct_tcp_state {
    TCP_CT_NONE = 0,
    TCP_CT_SYN_SEND = 1,
    TCP_CT_SYN_RCV = 2,
    TCP_CT_ESTABLISHED = 3,
    TCP_CT_FIN_WAIT = 4,
    TCP_CT_CLOSE_WAIT = 5,
    TCP_CT_LAST_ACK = 6,
    TCP_CT_TIME_WAIT = 7,
    TCP_CT_CLOSE = 8,
    TCP_CT_SYN_SEND2 = 9,
    TCP_CT_MAX = 10,
};

enum tcp_bit_set {
    TCP_SYN_SET = 0,
    TCP_SYNACK_SET = 1,
    TCP_FIN_SET = 2,
    TCP_ACK_SET = 3,
    TCP_RST_SET = 4,
    TCP_NONE_SET = 5,
    TCP_BIT_MAX = 6,
};

#define sNO TCP_CT_NONE
#define sSS TCP_CT_SYN_SEND
#define sSR TCP_CT_SYN_RCV
#define sES TCP_CT_ESTABLISHED
#define sFW TCP_CT_FIN_WAIT
#define sCW TCP_CT_CLOSE_WAIT
#define sLA TCP_CT_LAST_ACK
#define sTW TCP_CT_TIME_WAIT
#define sS2 TCP_CT_SYN_SEND2
#define sIV TCP_CT_MAX

enum ct_action_type {
    CT_ACTION_DNAT = 0,
    CT_ACTION_SNAT = 1,
};

typedef struct ct_action {
    int (*handler)(struct sk_buff *skb, struct sk_ext_info *ext);
}ct_action_t;

typedef struct dnat_action_data {
    uint32_t dst_ip;
    uint16_t port;
}dnat_action_data_t;

typedef struct snat_action_data {
    uint32_t src_ip;
    uint32_t port;
}snat_action_data_t;

struct ct_tuple{
    uint32_t  src_addr;
    uint32_t dst_addr;

    union {
        struct {
            uint16_t src_port;
            uint16_t dst_port;
        }ports;

        struct {
            uint8_t type;
            uint8_t code;
        }icmp;
    };

    uint32_t gre_key;

    uint8_t dir;
};

struct ct_tuple_hash {
    struct ct_tuple tuple;
    struct list_head tuple_node;
};

struct ct_session {
    struct ct_tuple_hash tuple_hash[CT_DRI_COUNT];

    uint8_t state;
    struct route_entry *rt_entry;
    int acl_action;

    int action_cnt;
    ct_action_t actions[MAX_CT_ACTION];
    void *action_data[MAX_CT_ACTION];

    uint32_t orig_src_ip;
    uint16_t orig_src_port;
    uint32_t vip;
    uint16_t vport;
};

void ct_init(void);
struct ct_session* ct_find(struct sk_buff *skb, struct sk_ext_info *ext);
struct ct_session* ct_new(struct sk_buff *skb);
int do_dnat(struct sk_buff *skb, struct sk_ext_info *ext);
int do_snat(struct sk_buff *skb, struct sk_ext_info *ext);
int reinsert_ct(struct sk_buff *skb, struct sk_ext_info *ext);
int do_reply_nat(struct sk_buff *skb, struct sk_ext_info *ext);
int ct_delete(struct ct_session *ct);

#define TUPLE_TO_CT(t) \
    (struct ct_session*)container_of(t, struct ct_session, tuple_hash[(t)->tuple.dir]);

#endif //NAT_LB_CT_H
