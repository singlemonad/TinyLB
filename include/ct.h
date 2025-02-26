//
// Created by tedqu on 24-9-15.
//

#ifndef NAT_LB_CT_H
#define NAT_LB_CT_H

#include <inttypes.h>
#include <rte_timer.h>
#include "list.h"
#include "route.h"
#include "skb.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CT_DRI_ORIGINAL 0
#define CT_DRI_REPLY 1
#define CT_DRI_COUNT 2

#define MAX_CT_ACTION 8

struct sk_buff;
struct per_cpu_ctx;

enum ct_state {
    CT_NEW = 0,
    CT_NORMAL = 1,
};

enum ct_tcp_state {
    TCP_CT_NONE = CT_NEW,
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

enum ct_udp_state {
    UDP_CT_NONE = CT_NEW,
    UDP_CT_NORMAL = TCP_CT_ESTABLISHED,
    UDP_CT_MAX,
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
#define sCL TCP_CT_CLOSE
#define sS2 TCP_CT_SYN_SEND2
#define sIV TCP_CT_MAX

enum ct_action_type {
    CT_ACTION_DNAT = 0,
    CT_ACTION_SNAT = 1,
};

enum ct_ext_type {
    CT_EXT_DNAT = 0,
    CT_EXT_SNAT = 1,
    CT_EXT_ACL_ACTION = 3,
    CT_EXT_ROUTE = 4,
};

typedef struct dnat_action_data {
    uint32_t dst_ip;
    uint16_t port;
}dnat_action_data_t;

typedef struct snat_action_data {
    uint32_t src_ip;
    uint32_t port;
}snat_action_data_t;

struct ct_tuple{
    uint32_t proto;
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
    uint8_t dir;
};

struct ct_tuple_hash {
    struct ct_tuple tuple;
    struct list_head tuple_node;
};

struct ct_session {
    struct ct_tuple_hash tuple_hash[CT_DRI_COUNT];
    uint32_t ref;
    uint8_t state;

    uint32_t timeout;
    uint64_t real_timeout;
    struct rte_timer timer;

    uint8_t extension[0];
};

struct ct_ext{
    uint32_t length;
    uint32_t offset;
};

#define TUPLE_TO_CT(t) \
    (struct ct_session*)container_of(t, struct ct_session, tuple_hash[(t)->tuple.dir]);

void ct_ext_register(uint8_t index, uint32_t length);
void ct_ext_data_put(struct ct_session *ct, uint8_t index, void *data);
void* ct_ext_data_get(uint8_t index, struct ct_session *ct);
void ct_module_init(void);
struct per_cpu_ctx *get_per_cpu_ctx(void);
void put_per_cpu_ctx(void);

#endif //NAT_LB_CT_H
