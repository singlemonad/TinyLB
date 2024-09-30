//
// Created by tedqu on 24-9-29.
//

#ifndef NAT_LB_SVC_H
#define NAT_LB_SVC_H

#include <inttypes.h>
#include "list.h"

#define MAX_RS_BUCKETS 8

typedef struct rs {
    uint32_t rs_ip;
    uint16_t rs_port;
    struct list_head rs_node;
}rs_t;

typedef struct svc {
    uint32_t vip;
    uint16_t vport;
    struct list_head svc_node;

    struct list_head rs_list;
    int rs_cnt;

    int next_schedule_rs;
}svc_t;

void svc_init(void);
int svc_add(uint32_t vip, uint32_t vport);
int svc_del(uint32_t vip, uint32_t vport);
svc_t* svc_find(uint32_t vip, uint32_t vport);
int rs_add(svc_t *svc, uint32_t rs_ip, uint16_t rs_port);
int rs_del(svc_t *svc, uint32_t rs_ip, uint16_t rs_port);
rs_t* rs_find(svc_t *svc, uint32_t rs_ip, uint16_t rs_port);
rs_t* rs_schedule(uint32_t vip, uint32_t vport);

#endif //NAT_LB_SVC_H
