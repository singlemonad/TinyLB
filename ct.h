//
// Created by tedqu on 24-9-15.
//

#ifndef NAT_LB_CT_H
#define NAT_LB_CT_H

#define CT_DRI_ORIGINAL 0
#define CT_DRI_REPLY 1
#define CT_DRI_COUNT 2

#include <inttypes.h>
#include "list.h"
#include "route.h"
#include "skb.h"

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
};


void ct_init(void);
struct ct_session* ct_find(sk_buff_t *skb);
struct ct_session* ct_new(sk_buff_t *skb);

#define TUPLE_TO_CT(t) \
    (struct ct_session*)container_of(t, struct ct_session, tuple_hash[(t)->tuple.dir]);

#endif //NAT_LB_CT_H
