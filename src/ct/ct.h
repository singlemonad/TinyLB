//
// Created by tedqu on 24-9-15.
//

#ifndef NAT_LB_CT_H
#define NAT_LB_CT_H

#include <inttypes.h>
#include <rte_timer.h>
#include "../common/list.h"
#include "../route/route.h"
#include "../common/skb.h"
#include "../common/lcore.h"

#ifdef __cplusplus
extern "C" {
#endif

#define HZ	1000
#define SECS * HZ
#define MINUTES * 60 SECS
#define HOURS * 60 MINUTES

#define CT_DRI_ORIGINAL 0
#define CT_DRI_REPLY 1
#define CT_DRI_COUNT 2

#define MAX_CT_ACTION 8

enum ct_state {
    CT_NEW = 0,
    CT_NORMAL = 1,
    CT_ESTABLISHED = 3,
};

enum ct_ext_type {
    CT_EXT_DNAT = 0,
    CT_EXT_SNAT,
    CT_EXT_ACL_ACTION,
    CT_EXT_ROUTE,
    CT_EXT_MAX,
};

enum ct_flag {
    CT_FLAG_SNAT = 1,
    CT_FLAG_DNAT = 1 << 1,
    CT_FLAG_NEED_SYNC = 1 << 2,
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
    uint16_t proto;
    uint8_t dir;
};

struct ct_tuple_hash {
    struct ct_tuple tuple;
    struct list_head tuple_node;
}__rte_cache_aligned;

struct ct_session {
    struct ct_tuple_hash tuple_hash[CT_DRI_COUNT];
    uint32_t ref;
    uint8_t state;
    uint8_t flags;
    uint32_t timeout;
    uint64_t real_timeout;
    struct rte_timer timer;
    uint32_t ext_flags;
    uint16_t worker;

    uint8_t extension[0];
}__rte_cache_aligned;

typedef void(*sync_ext_push)(struct sk_buff *skb, struct ct_session *ct);
typedef void(*sync_ext_pop)(struct sk_buff *skb, uint32_t length, struct ct_session *ct);
typedef uint32_t (*ext_dump)(char *buff, struct ct_session *ct);

struct ct_ext{
    enum ct_ext_type type;
    bool need_sync;
    uint32_t length;
    uint32_t offset;
    sync_ext_push sync_ext_push_func;
    sync_ext_pop sync_ext_pop_func;
    ext_dump dump_func;
};

struct ct_l4_proto {
    struct ct_tuple (*gen_tuple)(struct sk_buff *skb, bool reverse);
    bool (*is_tuple_equal)(struct ct_tuple_hash *lhs, struct ct_tuple *rhs);
    int (*pkt_in)(struct sk_buff *skb, struct per_lcore_ct_ctx* ctx);
    int (*pkt_new)(struct sk_buff *skb, struct per_lcore_ct_ctx* ctx);
}__rte_cache_aligned;

#define TUPLE_TO_CT(t) \
    (struct ct_session*)container_of(t, struct ct_session, tuple_hash[(t)->tuple.dir]);

void ct_module_init(void);
void ct_ext_register(struct ct_ext* ext);
void* ct_ext_data_get(uint8_t index, struct ct_session *ct);
char* ct_to_str(struct ct_session* ct, char *buff);
struct ct_session* ct_alloc(void);
bool ct_deref(struct ct_session *ct);
void process_sync_in_ct(struct ct_session* ct);
bool ct_tuple_in_use(uint8_t proto, uint32_t src_ip, uint16_t src_port, uint32_t dst_port, uint32_t dst_ip);

#endif //NAT_LB_CT_H
