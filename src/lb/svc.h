//
// Created by tedqu on 24-9-29.
//

#ifndef NAT_LB_SVC_H
#define NAT_LB_SVC_H

#include <inttypes.h>
#include "../common/list.h"
#include "schedule.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SVC_SCHED_DATA_LEN 64
#define PORT_MIN  1024
#define PORT_MAX  65535

#define MAX_SA_POOL_BUCKETS 8
#define MAX_SNAT_IP_PER_RS 4

enum svc_type {
    SVC_UNDERLAY = 0,
    SVC_OVERLAY_GRE,
    SVC_OVERLAY_VXLAN,
};

struct sched_data {
    uint8_t data[SVC_SCHED_DATA_LEN];
};

typedef struct svc {
    enum svc_type type;
    uint8_t proto;
    uint32_t vip;
    uint16_t vport;
    struct list_head svc_node;
    struct list_head rs_list;
    int rs_cnt;
    struct scheduler* scheduler;
    struct sched_data sch_data[MAX_LCORE];
}svc_t;

typedef struct snat_ip {
    unsigned lcore_id;
    uint32_t ip;
    struct list_head sa_node;
}snat_ip_t;

typedef struct snat_pool {
    uint16_t next_port;
    uint32_t snat_ip;
}snat_pool_t;

typedef struct snat_pool_array {
    int cnt;
    int next_idx;
    snat_pool_t* snat_ips[MAX_SNAT_IP_PER_RS];
}snat_pool_array_t;

typedef struct rs {
    struct list_head rs_node;
    uint32_t rs_ip;
    uint16_t rs_port;
    uint16_t weight;
    struct snat_pool_array snat_ips[MAX_LCORE];
}rs_t;

void svc_init(void);
int svc_add(uint8_t proto, uint32_t vip, uint32_t vport);
int svc_del(uint8_t proto, uint32_t vip, uint32_t vport);
svc_t* svc_find(uint8_t proto, uint32_t vip, uint32_t vport);
int rs_add(svc_t *svc, uint32_t rs_ip, uint16_t rs_port, uint16_t weight);
int rs_del(svc_t *svc, uint32_t rs_ip, uint16_t rs_port);
rs_t* rs_find(svc_t *svc, uint32_t rs_ip, uint16_t rs_port);
rs_t* rs_schedule(struct svc* svc, struct sk_buff* skb, uint8_t proto, uint32_t vip, uint32_t vport);

#endif //NAT_LB_SVC_H
