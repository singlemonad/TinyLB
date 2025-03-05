//
// Created by tedqu on 24-9-15.
//

// CT模块设计
// 一、用例
// 1、连接跟踪
//  1）包在处理流程中通过调用CT模块对外提供的接口进入CT模块
//  2）CT模块查找连接表，如果未找到，新建连接；如果找到，更新连接状态
//  3）CT模块设置对应的连接为全局变量，后续模块可以通过连接获取对应信息
// 2. 连接扩展信息维护
//  1）其他模块可以通过CT模块提供的扩展能力设置、获取扩展信息
// 二、关键问题
// 1、如何根据包信息维护4层状态机？-- rfc
// 2、提供通用机制维护扩展信息 -- 提供注册机制
// 3、连接应该在什么时候插入到连接表？-- original方向在创建时插入，reply方向在过完其他模块后在ct_confirm中插入，会话定时器在ct_confirm中更新
// 4、其他模块如果修改了连接信息如何处理？
//  1）original方向的tuple在ct_in生成并插入，没有场景需要修改original方向的tuple信息
//  2）reply方向的tuple在ct_in生成后在ct_confirm插入，ct_in后续模块可以修改reply方向的tuple信息，ct_confirm会将修改后的tuple插入连接表
// 5、work线程和定时器可能并发操作连接表，如何实现并发安全？

// 问题
// 1. worker线程和定时器可能并发操作ct表，需要实现线程安全
// 2. 如果包在中间被丢弃，没有走到ct_confirm，ct不会提交，如何处理这种场景？
// 3. origin方向的ct提交时如何处理reply方向的ct？
// 4. 4层状态机的流转，需要看协议rfc确认

#ifndef NAT_LB_CT_H
#define NAT_LB_CT_H

#include <inttypes.h>
#include <rte_timer.h>
#include "../common/list.h"
#include "../route/route.h"
#include "../common/skb.h"
#include "../common/thread.h"

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

struct ct_l4_proto {
    struct ct_tuple (*gen_tuple)(struct sk_buff *skb, bool reverse);
    bool (*is_tuple_equal)(struct ct_tuple_hash *lhs, struct ct_tuple *rhs);
    int (*pkt_in)(struct sk_buff *skb, struct per_lcore_ct_ctx* ctx);
    int (*pkt_new)(struct sk_buff *skb, struct per_lcore_ct_ctx* ctx);
};

#define TUPLE_TO_CT(t) \
    (struct ct_session*)container_of(t, struct ct_session, tuple_hash[(t)->tuple.dir]);

void ct_module_init(void);
void ct_ext_register(uint8_t index, uint32_t length);
void* ct_ext_data_get(uint8_t index, struct ct_session *ct);
char* ct_to_str(struct ct_session* ct, char *buff);

#endif //NAT_LB_CT_H
